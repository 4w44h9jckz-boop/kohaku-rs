#!/usr/bin/env python3
"""Fail if a tracked file names one of the owner's private repositories.

The names are held only as SHA-256 hashes of their lowercase spelling, so this check names
nothing itself. Every token of every tracked text file is hashed as written, and in lowercase
when it is capitalized, and looked up. A token is a run of letters, digits, hyphens and
underscores. Written in capitals, the two-letter name is the abbreviation of account
abstraction, not a pointer, so a token in capitals is not lowercased. Nor is a token a pointer
right after a double quote or a dot, as in Yul's `verbatim_3i_0o(hex"aa", ...)` or the entry
point `0x00...aa`, and such tokens are skipped.

Usage: python3 scripts/check_private_names.py   (from the repository root; exit 1 on a match)
"""
import hashlib
import re
import subprocess
import sys

HASHES = {
    "56b6b7de8479ddcb9ad3bcef005008a316b4c5d35fa035ebd9a9a59e67457e4f",
    "b93df56252ba24bc7e00ee347df726dd2d2489824c6cecc1f5bc1b480562c455",
    "961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506",
    "f95b812d3aca261fab7e8a53e4e0c5fdeaff585873c93ddbe7ebdaeeb970bb9b",
    "bf776270176c7c3573211f52bcf87433e96448c1507c58845689b14501a11478",
    "25c53c0acb448bfa257df9c4aa39c883209fd0eb4852bc62b5e29b5b98b88986",
    "2530467418c6eee8c45943f4bf78ca20ecce0cbcfd429f350fb9ffbf961bfb60",
    "c83e8c9b67765aff1bbc172da4f574f9e76ddbef6175793629b88ef3ea7478f2",
    "637585967eec911d261c8e19c95240637144bf7e7814d599a7daba176edb9931",
    "c53cf1ff2dc337714990f603ab100c18c6b0d25f06cf7e575045118253cdd8fe",
    "573eceabfab2d795d6b375f1b9c3f0d12e3eeb12d78dd4276886e6d4be990bdd",
    "fd8d4dfc98c2ee7fe853ce4cdc209ad0a3210435b7b6f3e09e7d2c6de303b273",
    "e9a1079182ff8c9ac16fae1bde3cf8aceb9f79091845d9c5f4aa3ab35f89cab3",
}
# Generated files whose contents are not prose: lockfiles and captured chain data.
SKIP = re.compile(r"(^|/)(package-lock\.json|Cargo\.lock)$|(^|/)fixtures/")
TOKEN = re.compile(r"[A-Za-z0-9_-]+")


def main() -> int:
    files = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    found = 0
    for path in files.decode().split("\0"):
        if not path or SKIP.search(path):
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for m in TOKEN.finditer(line):
                if m.start() > 0 and line[m.start() - 1] in "\".":
                    continue
                t = m.group()
                forms = {t, t.lower()} if t[:1].isupper() and t[1:].islower() else {t}
                if any(hashlib.sha256(f.encode()).hexdigest() in HASHES for f in forms):
                    print(f"{path}:{n}: a private repository's name")
                    found += 1
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
