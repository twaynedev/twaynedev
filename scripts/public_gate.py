#!/usr/bin/env python3
"""Public gate: fail when a tracked file or path names a lab host or a server-root storage path.

This repository is public. The list is kept as patterns, never as names, and more patterns load
from the PUBLIC_GATE_EXTRA_PATTERNS environment variable (one regular expression per line).
Fork coverage: CI passes that variable from a repository secret to the gate step only. Pull
requests from forks get no secrets, so they are checked against the built-in patterns alone.

The gate fails closed: a file it cannot read, decode or vet (unreadable, undecodable, binary,
UTF-16 without a byte-order mark, a symlink, a directory) is a failure, not a pass.
Output gives a file, a line number and a rule number. A path or line that itself contains a
match is never printed.

Each pattern gets PUBLIC_GATE_TIMEOUT seconds per file (default 2); on expiry the gate fails.
Usage: public_gate.py FILE...   Exit 0 clean, 1 found or not vettable, 2 bad pattern.
"""
import codecs
import os
import re
import signal
import sys

BUILTIN = [
    r"(?<![A-Za-z0-9_.-])(?:/|%2f|\\x2f|\\u002f)sr[v](?![A-Za-z0-9_-])",  # storage root, bare too
    r"(?<![A-Za-z0-9])ai[-_.]?[0-9]{2,3}(?![A-Za-z0-9])",  # lab host-naming shape
    r"\.ts\.net(?![A-Za-z0-9])",  # Tailscale names
]
BOMS = [
    (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
    (codecs.BOM_UTF8, "utf-8-sig"),
]


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout


def load_patterns():
    pats = list(BUILTIN)
    pats += [p for p in os.environ.get("PUBLIC_GATE_EXTRA_PATTERNS", "").splitlines() if p.strip()]
    try:
        return [re.compile(p, re.IGNORECASE) for p in pats]
    except re.error:
        print("public-gate: an extra pattern is not a valid regular expression", file=sys.stderr)
        sys.exit(2)


def timeout_seconds():
    try:
        return float(os.environ.get("PUBLIC_GATE_TIMEOUT", "2"))
    except ValueError:
        return 2.0


def decode(data):
    for bom, codec in BOMS:
        if data.startswith(bom):
            return data.decode(codec)
    if b"\x00" in data:
        raise ValueError("binary or UTF-16 without a byte-order mark")
    return data.decode("utf-8")


def search(pattern, text, limit):
    """Line numbers where pattern matches, bounded in time."""
    signal.setitimer(signal.ITIMER_REAL, limit)
    try:
        return [n for n, line in enumerate(text.split("\n"), 1) if pattern.search(line)]
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def check(path, label, patterns, limit):
    """Return a list of report lines for one file; empty means clean."""
    problems = []
    try:
        if os.path.islink(path):
            return [f"{label}: symlink, not vettable"]
        with open(path, "rb") as fh:
            data = fh.read()
        text = decode(data)
    except (OSError, ValueError, UnicodeError) as exc:
        return [f"{label}: unreadable or undecodable ({type(exc).__name__}), not vettable"]
    for i, pat in enumerate(patterns, 1):
        try:
            lines = search(pat, text, limit)
        except Timeout:
            problems.append(f"{label}: rule {i} timed out, not vettable")
            continue
        problems += [f"{label}:{n}: rule {i} matched, text withheld" for n in lines]
    return problems


def main(argv):
    patterns = load_patterns()
    limit = timeout_seconds()
    signal.signal(signal.SIGALRM, _alarm)
    report = []
    for k, path in enumerate(argv, 1):
        try:
            path_hit = any(p.search(path) for p in patterns)
        except Exception:
            path_hit = True
        label = f"<path #{k} withheld>" if path_hit else path
        if path_hit:
            report.append(f"{label}: rule matched in the path itself")
        report += check(path, label, patterns, limit)
    for line in report:
        print(f"public-gate: {line}")
    if report:
        print("public-gate: failed; host names and storage paths must not be public")
    return 1 if report else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
