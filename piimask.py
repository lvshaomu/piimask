#!/usr/bin/env python3
"""
piimask — format-preserving PII masking for CSV / JSON / text.

Why this exists
---------------
Every "PII scrubber" I tried breaks the thing downstream depends on:

  * It turns 13812345678 into ***, and your importer rejects the row.
  * It breaks the ID-card check character, so validation fails in staging.
  * It breaks the bank-card Luhn digit, so the payment sandbox rejects the file.
  * It fuzzes every cell independently, so you can no longer JOIN orders to customers.
  * It re-randomises on every run, so two test environments disagree.

piimask keeps the *shape*:

  1. A masked phone number is still 11 digits starting with 1[3-9].
  2. A masked Chinese ID still passes the ISO 7064 MOD 11-2 check character.
  3. A masked bank card still passes Luhn and keeps its BIN prefix.
  4. The same input value maps to the same output value for the whole run, so joins survive.
  5. The mapping is deterministic and keyed (HMAC-SHA256): same secret + same input => same
     output, and without the secret you cannot reverse the mapping from the published file.

Zero dependencies. CSV / JSON / plain text run on the Python standard library alone.

Usage
-----
    python piimask.py --in customers.csv --out clean/ --report
    python piimask.py --in exports/ --out clean/ --policy mask --report
    python piimask.py --in dump.json --out clean/ --only email,phone_cn

Exit codes
----------
    0  ran and produced output
    2  --strict and at least one input file produced zero replacements
    1  bad arguments / unreadable input
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------- checksums

ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
ID_CHECK = "10X98765432"


def valid_cn_id(s: str) -> bool:
    """17 digits + ISO 7064 MOD 11-2 check character."""
    if not re.fullmatch(r"\d{17}[\dXx]", s or ""):
        return False
    total = sum(int(s[i]) * ID_WEIGHTS[i] for i in range(17))
    return ID_CHECK[total % 11] == s[17].upper()


def valid_luhn(s: str) -> bool:
    if not s.isdigit() or not (13 <= len(s) <= 19):
        return False
    total, parity = 0, len(s) % 2
    for i, ch in enumerate(s):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# --------------------------------------------------------------------------- detectors

PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "phone_cn": re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    "id_card_cn": re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"),
    "bank_card": re.compile(r"(?<!\d)\d{13,19}(?!\d)"),
    "ipv4": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
}

DEFAULT_ORDER = ["email", "id_card_cn", "phone_cn", "bank_card", "ipv4"]


def _valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# --------------------------------------------------------------------------- masking


class Masker:
    """Deterministic, keyed, format-preserving masking."""

    def __init__(self, secret: bytes, policy: str = "fake"):
        if policy not in ("fake", "mask"):
            raise ValueError("policy must be 'fake' or 'mask'")
        self.secret = secret
        self.policy = policy
        self.cache: dict[tuple[str, str], str] = {}
        self.counts: dict[str, int] = {}

    # -- deterministic primitives -------------------------------------------------
    def _digest(self, kind: str, value: str) -> bytes:
        return hmac.new(self.secret, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).digest()

    def _digit_stream(self, kind: str, value: str, n: int) -> str:
        """Deterministic stream of decimal digits, length n."""
        out, block, counter = [], b"", 0
        while sum(len(x) for x in out) < n:
            block = self._digest(f"{kind}#{counter}", value)
            out.append("".join(f"{b:02d}"[-1] for b in block))
            counter += 1
        return "".join(out)[:n]

    # -- per-kind fakes -----------------------------------------------------------
    def _fake_phone(self, v: str) -> str:
        # keep 1[3-9] prefix, replace the remaining 9 digits
        return v[:3] + self._digit_stream("phone", v, 8)

    def _fake_cn_id(self, v: str) -> str:
        body = self._digit_stream("idcard", v, 17)
        total = sum(int(body[i]) * ID_WEIGHTS[i] for i in range(17))
        return body + ID_CHECK[total % 11]

    def _fake_bank(self, v: str) -> str:
        n = len(v)
        keep = 6 if n >= 10 else 0            # keep the BIN prefix so the issuer still resolves
        stem = v[:keep] + self._digit_stream("bank", v, n - keep - 1)
        for d in range(10):                    # find the Luhn check digit
            cand = stem + str(d)
            if valid_luhn(cand):
                return cand
        return stem + "0"

    def _fake_email(self, v: str) -> str:
        local, _, domain = v.partition("@")
        h = self._digest("email", v).hex()[:10]
        return f"u{h}@{domain}"

    def _fake_ipv4(self, v: str) -> str:
        d = self._digest("ip", v)
        return f"10.{d[0]}.{d[1]}.{max(1, d[2])}"

    # -- policy dispatch ----------------------------------------------------------
    def mask(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key in self.cache:
            return self.cache[key]
        self.counts[kind] = self.counts.get(kind, 0) + 1

        if self.policy == "mask":
            out = self._shape_mask(kind, value)
        else:
            out = {
                "email": self._fake_email,
                "phone_cn": self._fake_phone,
                "id_card_cn": self._fake_cn_id,
                "bank_card": self._fake_bank,
                "ipv4": self._fake_ipv4,
            }[kind](value)

        self.cache[key] = out
        return out

    @staticmethod
    def _shape_mask(kind: str, v: str) -> str:
        if kind == "email":
            local, _, domain = v.partition("@")
            keep = local[:1] if local else ""
            return f"{keep}{'*' * max(3, len(local) - 1)}@{domain}"
        if kind == "ipv4":
            return "*.*.*.*"
        if len(v) <= 4:
            return "*" * len(v)
        head, tail = v[:3], v[-2:]
        return head + "*" * (len(v) - 5) + tail

    # -- text walker --------------------------------------------------------------
    def mask_text(self, text: str, enabled: list[str], loose: bool = False) -> tuple[str, int]:
        hits = 0

        def replace(kind: str) -> None:
            nonlocal text, hits

            def _sub(m: re.Match) -> str:
                nonlocal hits
                raw = m.group(0)
                if kind == "id_card_cn" and not loose and not valid_cn_id(raw):
                    return raw
                if kind == "bank_card":
                    # do not double-handle 18-digit numbers already claimed as CN IDs
                    if not loose and valid_cn_id(raw):
                        return raw
                    if not loose and not valid_luhn(raw):
                        return raw
                if kind == "ipv4" and not _valid_ipv4(raw):
                    return raw
                hits += 1
                return self.mask(kind, raw)

            text = PATTERNS[kind].sub(_sub, text)

        for kind in enabled:
            replace(kind)
        return text, hits


# --------------------------------------------------------------------------- file I/O

TEXT_EXTS = {".txt", ".log", ".md", ".csv", ".tsv", ".json"}


def mask_csv(text: str, masker: Masker, enabled: list[str], loose: bool) -> tuple[str, int]:
    buf_in = io.StringIO(text)
    buf_out = io.StringIO()
    reader = csv.reader(buf_in)
    writer = csv.writer(buf_out)
    hits = 0
    for row in reader:
        new_row = []
        for cell in row:
            masked, h = masker.mask_text(cell, enabled, loose)
            hits += h
            new_row.append(masked)
        writer.writerow(new_row)
    return buf_out.getvalue(), hits


def mask_json(text: str, masker: Masker, enabled: list[str], loose: bool) -> tuple[str, int]:
    data = json.loads(text)
    hits = 0

    def walk(node):
        nonlocal hits
        if isinstance(node, str):
            masked, h = masker.mask_text(node, enabled, loose)
            hits += h
            return masked
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    return json.dumps(walk(data), ensure_ascii=False, indent=2), hits


def iter_files(src: Path):
    if src.is_file():
        yield src
        return
    for p in sorted(src.rglob("*")):
        if p.is_file() and p.suffix.lower() in TEXT_EXTS:
            yield p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Format-preserving PII masking for CSV / JSON / text (stdlib only)."
    )
    ap.add_argument("--in", dest="src", required=True, help="file or folder")
    ap.add_argument("--out", required=True, help="output folder")
    ap.add_argument("--policy", default="fake", choices=["fake", "mask"],
                    help="fake = format-preserving & checksum-valid (default); mask = show the shape")
    ap.add_argument("--only", default="", help="comma list from: " + ",".join(DEFAULT_ORDER))
    ap.add_argument("--secret-file", default="", help="key file; omit for a stable per-machine key")
    ap.add_argument("--loose", action="store_true", help="skip checksum validation (catches forged numbers, more false positives)")
    ap.add_argument("--report", action="store_true", help="write report.txt next to the output")
    ap.add_argument("--strict", action="store_true", help="exit 2 if any file produced zero hits")
    args = ap.parse_args(argv)

    src = Path(args.src)
    if not src.exists():
        print(f"error: no such path: {src}", file=sys.stderr)
        return 1

    enabled = [k for k in (args.only.split(",") if args.only else DEFAULT_ORDER) if k]
    unknown = [k for k in enabled if k not in PATTERNS]
    if unknown:
        print(f"error: unknown detector(s): {', '.join(unknown)}", file=sys.stderr)
        return 1

    if args.secret_file:
        secret = Path(args.secret_file).read_bytes()
    else:
        # stable per-machine key so reruns agree without shipping a secret file
        seed = f"piimask:{os.uname().nodename if hasattr(os, 'uname') else os.environ.get('COMPUTERNAME', 'host')}"
        secret = hashlib.sha256(seed.encode()).digest()

    masker = Masker(secret, args.policy)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    report: list[str] = []
    empty_files: list[str] = []
    total = 0

    for f in iter_files(src):
        raw = f.read_text(encoding="utf-8", errors="replace")
        suffix = f.suffix.lower()
        try:
            if suffix == ".json":
                masked, hits = mask_json(raw, masker, enabled, args.loose)
            elif suffix in (".csv", ".tsv"):
                masked, hits = mask_csv(raw, masker, enabled, args.loose)
            else:
                masked, hits = masker.mask_text(raw, enabled, args.loose)
        except json.JSONDecodeError:
            masked, hits = masker.mask_text(raw, enabled, args.loose)

        out_path = out_dir / f"{f.stem}.masked{f.suffix}"
        out_path.write_text(masked, encoding="utf-8")
        total += hits
        if hits == 0:
            empty_files.append(str(f))
        report.append(f"{f}  ->  {out_path}  ({hits} replacements)")
        print(f"{hits:6d}  {f} -> {out_path}")

    by_kind = ", ".join(f"{k}={v}" for k, v in sorted(masker.counts.items())) or "none"
    summary = [
        "piimask report",
        "=" * 40,
        f"policy        : {args.policy}",
        f"detectors     : {', '.join(enabled)}",
        f"space         : {'loose (no checksum)' if args.loose else 'strict checksum'}",
        f"replacements  : {total}",
        f"by kind       : {by_kind}",
        f"files with 0  : {len(empty_files)}",
    ] + report

    text = "\n".join(summary)
    if args.report:
        (out_dir / "report.txt").write_text(text, encoding="utf-8")
    print()
    print(text)

    if args.strict and empty_files:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
