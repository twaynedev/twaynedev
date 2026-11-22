"""Tests for scripts/public_gate.py. Fixtures are built at run time from fragments, so this
file never holds a string the gate forbids (the gate scans every tracked file, this one too)."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "public_gate.py"

HOST = "ai" + "-" + "01"
STORAGE = "/" + "srv" + "/" + "data"


def run_gate(files, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != "PUBLIC_GATE_EXTRA_PATTERNS"}
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-I", str(GATE), *map(str, files)],
        capture_output=True, text=True, env=env,
    )


class PublicGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = self.dir / name
        p.write_text(text)
        return p

    def test_host_name_fails(self):
        f = self.write("a.md", f"run it on {HOST} please\n")
        r = run_gate([f])
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.md:1", r.stdout)

    def test_storage_path_fails(self):
        f = self.write("b.md", f"see {STORAGE}\n")
        self.assertEqual(run_gate([f]).returncode, 1)

    def test_output_never_echoes_the_match(self):
        f = self.write("c.md", f"{HOST} {STORAGE}\n")
        r = run_gate([f])
        self.assertNotIn(HOST, r.stdout + r.stderr)
        self.assertNotIn(STORAGE, r.stdout + r.stderr)

    def test_clean_text_passes(self):
        f = self.write("d.md", "the lab's knowledge server\n")
        self.assertEqual(run_gate([f]).returncode, 0)

    def test_near_miss_passes(self):
        # one-token twins of the forbidden shapes
        f = self.write("e.md", "ai-tools and /srvx and ai01 and /usr/srv\n")
        self.assertEqual(run_gate([f]).returncode, 0)

    def test_extra_patterns_from_env(self):
        f = self.write("f.md", "codename zebra\n")
        self.assertEqual(run_gate([f]).returncode, 0)
        r = run_gate([f], {"PUBLIC_GATE_EXTRA_PATTERNS": "zebra\nother"})
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("zebra", r.stdout + r.stderr)

    def test_binary_file_is_skipped(self):
        p = self.dir / "g.bin"
        p.write_bytes(b"\x00\xff" + HOST.encode())
        self.assertEqual(run_gate([p]).returncode, 0)

    def test_cleaned_repo_passes(self):
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
        r = run_gate([ROOT / t for t in tracked])
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
