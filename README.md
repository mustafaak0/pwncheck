# 🔐 PwnCheck

> Password strength analyzer & breach checker — entropy math meets real-world breach data. Zero dependencies, pure Python stdlib.

[![Python](https://img.shields.io/badge/Python-3.9%2B-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-00E676?style=for-the-badge&labelColor=0D1117)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-0D1117?style=for-the-badge&labelColor=00E676)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mustafaak0-0D1117?style=for-the-badge&logo=github&logoColor=00E676)](https://github.com/mustafaak0)

## 🎯 What It Does

| Check | Detail |
|-------|--------|
| 🧮 **Entropy** | charset-pool Shannon entropy, then **effective bits** after penalties |
| 🕵️ **Pattern penalties** | top-common passwords (leet-normalized!), keyboard walks (`qwerty`), repeats (`aaa`), sequences (`abcd`, `4321`), years, digits-only |
| 🌐 **Breach lookup** | [HaveIBeenPwned](https://haveibeenpwned.com) via **k-anonymity** — only a 5-char SHA-1 prefix ever leaves your machine |
| ⏱️ **Crack-time table** | estimates against single RTX 4090 hashcat rates: NTLM → MD5 → SHA → bcrypt → argon2id |
| 📋 **Audit mode** | `batch` scores a whole password list, caps scores for anything breach-corpus-visible |

## 🚀 Usage

```bash
python pwncheck.py check "P@ssw0rd123"
python pwncheck.py check                 # hidden prompt
python pwncheck.py check --offline "x"   # skip network
python pwncheck.py batch audit.txt       # score a list
```

```
╭─ PwnCheck report ────────────────────────────────────────
│ password : ***********  (11 chars)
│ charset  : 92 symbols/pool
│ entropy  : 71.8 bits raw → 41.8 bits effective
│ penalty  : -30  contains common password 'password'
│ score    : 63/100  →  STRONG
│ HIBP     : ⚠ seen in 400,398 known breaches
│ override : score capped → 25/100 (CRITICAL) — real-world breach beats entropy math
│ crack time (1x RTX 4090):
│    argon2id 11.8 years   bcrypt 3.2 years
│    MD5      11.3 secs    NTLM   2.9 secs
╰──────────────────────────────────────────────────────────
```

## 🧪 Verified Results (live HIBP)

| Password | Score | HIBP breaches |
|----------|------:|--------------:|
| `password` | 0 → **CRITICAL** | 52,372,427 |
| `qwerty12345` | 0 → **CRITICAL** | 1,839,112 |
| `Mustafa1966` | 44→25 (common name + year) | 203 |
| `Xk9#mQ2$vLp7!Rwz` | **100 LEGENDARY** | 0 |
| `correcthorsebatterystaple` | 100→25 ⚠ | 4,173 |

That last row is the classic lesson: the famous
[xkcd #936](https://xkcd.com/936/) passphrase has *massive* entropy but is
**in every wordlist** because everyone used it. **Real-world breach data
beats entropy math** — which is exactly why PwnCheck caps the score.

## 🧠 How k-anonymity Protects You

```
1. SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
2. send ONLY first 5 chars → api.pwnedpasswords.com/range/5BAA6
3. API returns every suffix starting with 5BAA6 (≈800 hashes)
4. match locally → your full hash never crossed the wire
```

## 📊 Benchmark Rates

Approximate single RTX 4090 hashcat speeds: NTLM 650 GH/s · MD5 164 GH/s ·
SHA-1 68 GH/s · SHA-256 22 GH/s · SHA-512 6.6 GH/s · bcrypt 18.5 kH/s ·
argon2id 5 kH/s. (Order-of-magnitude estimates for education.)

## 🔒 Privacy

- breach check is **opt-in per invocation** (`--offline` skips it)
- no logging, no telemetry, no third-party libraries
- works fully offline minus the HIBP lookup

## ⚖️ Disclaimer

For auditing **your own** passwords and teaching secure-password hygiene.
Don't run it against credentials you don't own.

---

<div align="center">

*Entropy is a theory. Breach corpora are the reality.*

</div>
