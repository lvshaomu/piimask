#!/usr/bin/env python3
"""piimask 自测：校验位正确性 + 确定性 + 密钥隔离。全部断言，无第三方依赖。"""
import subprocess, sys, os, tempfile, json, csv, io
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import piimask
from piimask import Masker, valid_cn_id, valid_luhn, ID_WEIGHTS, ID_CHECK

FAILED = []


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        FAILED.append(name)


def make_valid_cn_id():
    """构造一个校验位正确的中国身份证号。"""
    body = "11010519491231002"          # 17 位
    total = sum(int(body[i]) * ID_WEIGHTS[i] for i in range(17))
    return body + ID_CHECK[total % 11]


def make_valid_luhn(n=16, prefix="622202"):
    stem = prefix + "0" * (n - len(prefix) - 1)
    for d in range(10):
        cand = stem + str(d)
        if valid_luhn(cand):
            return cand
    raise AssertionError("no luhn digit found")


def main():
    # 1) 校验位：真身份证
    real_id = make_valid_cn_id()
    check(f"构造的身份证通过 ISO 7064: {real_id}", valid_cn_id(real_id))

    # 2) 掩码后身份证仍然通过校验
    m = Masker(b"test-secret", "fake")
    fake_id = m.mask("id_card_cn", real_id)
    check(f"掩码后身份证仍通过校验: {fake_id}", valid_cn_id(fake_id))
    check("掩码后身份证与原值不同", fake_id != real_id)
    check("掩码后身份证仍是 18 位", len(fake_id) == 18)

    # 3) 掩码后银行卡仍通过 Luhn 且保留 BIN
    real_bank = make_valid_luhn(16, "622202")
    fake_bank = m.mask("bank_card", real_bank)
    check(f"掩码后银行卡通过 Luhn: {fake_bank}", valid_luhn(fake_bank))
    check("掩码后银行卡保留 BIN 前缀", fake_bank.startswith("622202"))
    check("掩码后银行卡长度不变", len(fake_bank) == len(real_bank))

    # 4) 手机号：前缀保留、11 位
    fake_phone = m.mask("phone_cn", "13812345678")
    check(f"掩码后手机号 11 位且 1[3-9] 开头: {fake_phone}",
          len(fake_phone) == 11 and fake_phone[0] == "1" and fake_phone[1] in "3456789")

    # 5) 确定性：同 secret 同输入 => 同输出
    m2 = Masker(b"test-secret", "fake")
    check("同 secret 重跑结果一致", m2.mask("id_card_cn", real_id) == fake_id)

    # 6) 密钥隔离：不同 secret => 不同输出
    m3 = Masker(b"other-secret", "fake")
    check("不同 secret 输出不同", m3.mask("id_card_cn", real_id) != fake_id)

    # 7) 可 JOIN：同值在同一次运行里映射一致
    check("同值两次掩码一致（可 JOIN）",
          m.mask("phone_cn", "13812345678") == m.mask("phone_cn", "13812345678"))

    # 8) mask 策略保留形状
    mm = Masker(b"k", "mask")
    shaped = mm.mask("phone_cn", "13812345678")
    check(f"mask 策略输出: {shaped}", set(shaped) <= set("0123456789*") and "*" in shaped)

    # 9) CLI 端到端：csv 输入 → masked 输出存在
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "in"
        out = Path(td) / "out"
        src.mkdir()
        (src / "a.csv").write_text(
            "name,phone,id\n张三,13812345678," + real_id + "\n", encoding="utf-8")
        rc = piimask.main(["--in", str(src), "--out", str(out), "--report"])
        check(f"CLI 退出码 0（实际 {rc}）", rc == 0)
        masked_csv = (out / "a.masked.csv").read_text(encoding="utf-8")
        check("CLI 输出包含 masked 文件", "masked" in str(list(out.iterdir())[0]))
        check("CLI 掩码后原身份证不再出现", real_id not in masked_csv)
        check("CLI 掩码后原手机号不再出现", "13812345678" not in masked_csv)
        check("CLI 生成 report.txt", (out / "report.txt").exists())

    # 10) JSON 端到端
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "in"
        out = Path(td) / "out"
        src.mkdir()
        (src / "d.json").write_text(
            json.dumps({"user": {"email": "a@b.com", "note": "call 13812345678"}},
                       ensure_ascii=False), encoding="utf-8")
        rc = piimask.main(["--in", str(src), "--out", str(out)])
        masked = (out / "d.masked.json").read_text(encoding="utf-8")
        check("JSON 掩码后原邮箱不再出现", "a@b.com" not in masked)
        check("JSON 掩码后原手机号不再出现", "13812345678" not in masked)
        check("JSON 结构保留（键仍在）", '"user"' in masked and '"note"' in masked)

    print()
    if FAILED:
        print(f"共 {len(FAILED)} 项失败: {FAILED}")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
