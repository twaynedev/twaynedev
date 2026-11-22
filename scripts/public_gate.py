#!/usr/bin/env python3
"""Public gate: fail when a tracked file names a lab host or a storage path under the server root.

This repository is public. The list is kept as patterns (a path prefix and the lab's host-naming
shape), and more can be loaded from the PUBLIC_GATE_EXTRA_PATTERNS environment variable (one
regular expression per line, set from a CI secret), so no real name has to be written here.
The report gives file, line and rule number only, never the matched text.
Usage: public_gate.py FILE...   Exit 0 clean, 1 found, 2 bad pattern.
"""
import os
import re
import sys

BUILTIN = [
    r"/sr[v]/",            # storage path prefix
    r"\bai-[0-9]{2}\b",    # lab host-naming shape
    r"\.ts\.net\b",        # Tailscale names
]


def load_patterns():
    pats = list(BUILTIN)
    pats += [p for p in os.environ.get("PUBLIC_GATE_EXTRA_PATTERNS", "").splitlines() if p.strip()]
    try:
        return [re.compile(p, re.IGNORECASE) for p in pats]
    except re.error:
        print("public-gate: an extra pattern is not a valid regular expression", file=sys.stderr)
        sys.exit(2)


def scan(path, patterns):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    if b"\x00" in data:
        return []
    hits = []
    for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        for i, p in enumerate(patterns, 1):
            if p.search(line):
                hits.append((path, n, i))
    return hits


def main(argv):
    patterns = load_patterns()
    hits = [h for f in argv for h in scan(f, patterns)]
    for path, n, rule in hits:
        print(f"{path}:{n}: public-gate rule {rule} matched (text withheld)")
    if hits:
        print("public-gate: failed; host names and storage paths must not be public")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
