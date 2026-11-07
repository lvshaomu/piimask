# piimask

[![tests](https://github.com/lvshaomu/piimask/actions/workflows/tests.yml/badge.svg)](https://github.com/lvshaomu/piimask/actions/workflows/tests.yml)

**Format-preserving PII masking for CSV / JSON / text.** Zero dependencies.

Mask phone numbers, emails, Chinese ID cards, bank cards and IPv4 addresses so that a file can
leave your laptop — for a demo, a staging environment, a contractor, or an LLM prompt — and still
**import, validate and join** on the other side.

```bash
python piimask.py --in customers.csv --out clean/ --report
```

```
name,phone,id_no,email
张三,13893525401,494626517976288038,u72765aad12@example.com
```

Every value above is fake. Every value is still usable.

---

## The problem with regex-replace

Most PII scrubbing breaks the thing the receiving system depends on:

| Naive scrubber | piimask |
|---|---|
| `13812345678` → `***` — your importer rejects the row | still 11 digits, still starts with `1[3-9]` |
| breaks the ID-card check character — staging validation fails | the fake ID **passes ISO 7064 MOD 11-2** |
| breaks the bank-card Luhn digit — the payment sandbox rejects the file | the fake card **passes Luhn** and keeps its BIN prefix |
| every cell fuzzed independently — you can no longer `JOIN` orders to customers | same input → same output for the whole run |
| re-randomised on every run — two test environments disagree | deterministic and keyed: same secret → same output |
| `\d{18}` matches anything — hundreds of false positives | ID cards and cards are **validated by checksum**, not by shape |
| anyone with the file can invert it | without the secret the mapping is not reversible (HMAC-SHA256) |

That last row matters most when the destination is an LLM: you want realistic-looking data that
preserves relational structure, because otherwise the model is answering questions about `***`.

## Install

Single file, standard library only. Python 3.9+.

```bash
git clone https://github.com/lvshaomu/piimask
cd piimask
python piimask.py --help
```

## Quick start

```bash
# one file
python piimask.py --in customers.csv --out clean/

# a whole folder, recursively, with a report
python piimask.py --in exports/ --out clean/ --report

# keep the shape instead of generating realistic fakes
python piimask.py --in dump.json --out clean/ --policy mask

# only certain detectors
python piimask.py --in logs.txt --out clean/ --only email,phone_cn
```

## What it detects

| Kind | Detector | What the fake keeps |
|---|---|---|
| `phone_cn` | `1[3-9]` + 9 digits | 11 digits, `1[3-9]` prefix |
| `id_card_cn` | 17 digits + ISO 7064 MOD 11-2 | a valid check character |
| `bank_card` | 13–19 digits + Luhn | valid Luhn, same length, same BIN |
| `email` | RFC-ish | same domain, hashed local part |
| `ipv4` | dotted quad, octets ≤ 255 | a `10.x.x.x` private address |

Checksum validation is the reason this tool doesn't drown you in false positives: an 18-digit
order number is not an ID card, and a 16-digit SKU is not a bank card.

## Policies

| `--policy` | Output for `13812345678` | Use when |
|---|---|---|
| `fake` *(default)* | `13893525401` | the file must still import and validate |
| `mask` | `138******78` | a human needs to eyeball the shape |

## Options

| Flag | Meaning |
|---|---|
| `--in FILE_OR_DIR` | one file, or a folder scanned recursively |
| `--out DIR` | output folder; each file becomes `<name>.masked<ext>` |
| `--policy fake\|mask` | see above (default `fake`) |
| `--only a,b,c` | limit detectors |
| `--secret-file FILE` | fixed key; omit for a stable per-machine key |
| `--loose` | skip checksum validation — catches forged numbers, more false positives |
| `--report` | write `report.txt` next to the output |
| `--strict` | exit `2` if any input file produced zero replacements |

`--strict` is what makes this safe to drop into a CI step or an export cron: a silent no-op is a
failure, not a success.

## Supported files

`.csv` `.tsv` `.json` `.txt` `.log` `.md` — all on the standard library.

## Determinism and reversibility

The mapping is `HMAC-SHA256(secret, kind:value)` truncated into the value's own alphabet. So:

* the same secret and input always produce the same output (reruns agree, environments agree);
* a different secret produces a different output;
* you cannot recover the original from the published file without the secret.

If you need to **reverse** a run (for example, to restore the real values into a report), keep the
secret. If you need a per-run mapping instead, use `--secret-file` with a freshly generated key and
store it separately from the output.

## Tests

```bash
python test_piimask.py
```

18 assertions covering checksum validity after masking, determinism, key separation, joinability,
CLI round-trips for CSV and JSON, and the `mask` policy.

---

## Also available

There is a larger version with `.xlsx` and `.docx` support, four policies
(`fake` / `mask` / `token` / `hash`), a restore map and a column-header-driven name detector —
packaged for people who need it on spreadsheets, not just text files.

Live page: [DataMask on csvtriage.com](https://csvtriage.com/p/datamask.html).

That is not required to use this repo. This one is MIT and stays MIT.

## License

MIT — see [LICENSE](LICENSE).
