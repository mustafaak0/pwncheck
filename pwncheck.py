#!/usr/bin/env python3
"""
PwnCheck — password strength analyzer & breach checker (pure stdlib).

Offline analysis:
  - charset detection & Shannon entropy
  - real-world penalties: common passwords (leet-normalized), keyboard
    walks, sequences, repeats, years, digits-only
  - crack-time estimation against hashcat RTX 4090 benchmark rates

Online check (optional):
  - HaveIBeenPwned range API using k-anonymity — your password never
    leaves the machine, only a 5-char SHA-1 prefix is sent.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import re
import string
import sys
import urllib.request
from pathlib import Path

COMMON_LIST = Path(__file__).parent / "data" / "common_passwords.txt"

# approximate single RTX 4090 hashcat rates (hashes/second)
CRACK_RATES = {
    "NTLM":        650.0e9,
    "MD5":         164.0e9,
    "SHA-1":        68.0e9,
    "SHA-256":      22.0e9,
    "SHA-512":       6.6e9,
    "bcrypt":       18.5e3,
    "argon2id":      5.0e3,
}

LEET = {"4": "a", "@": "a", "13": "b", "8": "b", "3": "e", "6": "g", "9": "g",
        "1": "i", "!": "i", "|": "l", "0": "o", "5": "s", "$": "s", "7": "t",
        "+": "t", "2": "z"}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


# ----------------------------------------------------------------------------
# loading helpers
# ----------------------------------------------------------------------------

def load_common() -> set[str]:
    if COMMON_LIST.exists():
        return {w.strip().lower() for w in COMMON_LIST.read_text(encoding="utf-8").splitlines() if w.strip()}
    return set()


def normalize(pw: str) -> str:
    """Lowercase + de-leet ('P@ssw0rd' -> 'password')."""
    out, i = [], 0
    s = pw.lower()
    while i < len(s):
        if s[i:i + 2] in LEET:
            out.append(LEET[s[i:i + 2]])
            i += 2
        else:
            out.append(LEET.get(s[i], s[i]))
            i += 1
    return "".join(out)


# ----------------------------------------------------------------------------
# analysis
# ----------------------------------------------------------------------------

def charset_size(pw: str) -> int:
    pools = [(string.ascii_lowercase, 26), (string.ascii_uppercase, 26),
             (string.digits, 10),
             ("!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~", 30), (None, 100)]  # None → other/unicode
    total = 0
    for chars, size in pools:
        if chars is None:
            known = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~"
            if any(c not in known for c in pw):
                total += size
        elif any(c in chars for c in pw):
            total += size
    return total


def find_penalties(pw: str, common: set[str]) -> list[tuple[str, int]]:
    n = normalize(pw)
    low = pw.lower()
    penalties: list[tuple[str, int]] = []

    if n in common or low in common:
        penalties.append(("top-common password (after leet-normalization)", 45))
    else:
        hit = next((w for w in common if len(w) >= 5 and w in n), None)
        if hit:
            penalties.append((f"contains common password '{hit}'", 30))

    if re.search(r"(.)\1{2,}", pw):
        penalties.append(("repeated character runs (aaa, 111)", 10))

    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            walk = row[i:i + 5]
            if walk in low or walk[::-1] in low:
                penalties.append(("keyboard walk / qwerty pattern", 20))
                break

    if pw.isdigit():
        penalties.append(("digits only", 15))
        if re.search(r"(19|20)\d{2}", pw):
            penalties.append(("looks like a year", 8))
    elif re.search(r"(19|20)\d{2}", pw):
        penalties.append(("contains a year", 6))

    # alphabetical runs like abcd / 3210
    runs = sum(1 for i in range(len(pw) - 3)
               if all(ord(pw[i + k + 1]) - ord(pw[i + k]) == 1 for k in range(3))
               or all(ord(pw[i + k + 1]) - ord(pw[i + k]) == -1 for k in range(3)))
    if runs:
        penalties.append(("sequential runs (abcd, 4321)", 12))

    return penalties


def analyze(pw: str, common: set[str]) -> dict:
    size = charset_size(pw)
    raw_bits = len(pw) * math.log2(size) if size else 0.0
    penalties = find_penalties(pw, common)
    eff_bits = max(0.0, raw_bits - sum(p for _, p in penalties))
    guesses = 2 ** min(eff_bits, 256) / 2

    times = {name: guesses / rate for name, rate in CRACK_RATES.items()}
    score = max(0, min(100, round(eff_bits * 1.5)))
    verdict = ("CRITICAL" if score < 20 else "WEAK" if score < 40 else
               "FAIR" if score < 60 else "STRONG" if score < 80 else "LEGENDARY")
    return {"charset": size, "raw_bits": raw_bits, "penalties": penalties,
            "eff_bits": eff_bits, "score": score, "verdict": verdict, "times": times}


def hibp_count(pw: str) -> int | None:
    """Breached count via k-anonymity; None on network error."""
    try:
        sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{sha1[:5]}",
            headers={"User-Agent": "PwnCheck-educational-tool"})
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode()
        for line in body.splitlines():
            suffix, count = line.split(":")
            if suffix == sha1[5:]:
                return int(count)
        return 0
    except (OSError, ValueError):
        return None


# ----------------------------------------------------------------------------
# output
# ----------------------------------------------------------------------------

def human_time(sec: float) -> str:
    if sec < 1:
        return "instant"
    units = [("year", 31557600.0), ("month", 2629800.0), ("day", 86400.0),
             ("hour", 3600.0), ("min", 60.0), ("sec", 1.0)]
    for name, size in units:
        if sec >= size:
            v = sec / size
            if v > 1e12:
                return f"{v / 1e9:.0f} billion {name}s"
            return f"{v:,.1f} {name}s"
    return "instant"


def report(pw: str, offline: bool) -> None:
    common = load_common()
    r = analyze(pw, common)
    print("╭─ PwnCheck report " + "─" * 40)
    print(f"│ password : {'*' * len(pw)}  ({len(pw)} chars)")
    print(f"│ charset  : {r['charset']} symbols/pool")
    print(f"│ entropy  : {r['raw_bits']:.1f} bits raw → {r['eff_bits']:.1f} bits effective")
    for why, pen in r["penalties"]:
        print(f"│ penalty  : -{pen:>2}  {why}")
    if not r["penalties"]:
        print("│ penalty  : none — no recognizable patterns, nice.")
    print(f"│ score    : {r['score']}/100  →  {r['verdict']}")

    if not offline:
        count = hibp_count(pw)
        if count is None:
            print("│ HIBP     : unreachable (network blocked?) — offline results only")
        elif count:
            verdict = "CRITICAL" if count > 10_000 else "WEAK"
            print(f"│ HIBP     : ⚠ seen in {count:,} known breaches")
            print(f"│ override : score capped → {min(r['score'], 25)}/100 ({verdict}) — real-world breach beats entropy math")
        else:
            print("│ HIBP     : ✔ not found in known breach corpora")

    print("│ crack time (1x RTX 4090, worst hashtypes first):")
    for name in ("argon2id", "bcrypt", "SHA-512", "SHA-256", "SHA-1", "MD5", "NTLM"):
        print(f"│    {name:<8} {human_time(r['times'][name])}")
    print("╰" + "─" * 58)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> None:
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")

    p = argparse.ArgumentParser(description="PwnCheck — password strength & breach analyzer (stdlib only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="analyze one password")
    c.add_argument("password", nargs="?", help="omit for a hidden prompt")
    c.add_argument("--offline", action="store_true", help="skip the HIBP breach check")

    b = sub.add_parser("batch", help="analyze passwords from a file (audit mode)")
    b.add_argument("file")
    b.add_argument("--offline", action="store_true")

    args = p.parse_args()

    if args.cmd == "check":
        pw = args.password or getpass.getpass("password> ")
        report(pw, args.offline)
    else:
        lines = Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines()
        common = load_common()
        print(f"{'password':<28}{'score':>9}  {'verdict':<10}{'HIBP':>14}")
        print("-" * 60)
        for pw in (l.strip() for l in lines if l.strip()):
            r = analyze(pw, common)
            cnt = None if args.offline else hibp_count(pw)
            if cnt is None:
                hib = "—" if args.offline else "err"
            else:
                hib = f"{cnt:,}"
            score = f"{r['score']}→{min(r['score'], 25)}" if cnt else str(r["score"])
            print(f"{pw[:26]:<28}{score:>9}  {r['verdict']:<10}{hib:>14}")


if __name__ == "__main__":
    main()
