"""Tests for scripts/public_gate.py.

Every forbidden value here is synthetic: it has the shape the gate looks for but is not a real
host or path. The gate scans every tracked file, this one too, so fixtures are assembled at run
time from fragments.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "public_gate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
HOOKS = ROOT / ".pre-commit-config.yaml"

HOST = "ai" + "-" + "77"
STORAGE = "/" + "srv" + "/" + "example-root"
ROOT_BARE = "/" + "srv"


def run_gate(files, extra_env=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PUBLIC_GATE")}
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-I", str(GATE), *map(str, files)],
        capture_output=True, text=True, env=env, timeout=60,
    )


def out(r):
    return r.stdout + r.stderr


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text, mode="w"):
        p = self.dir / name
        p.write_text(text) if mode == "w" else p.write_bytes(text)
        return p


class Patterns(Base):
    def test_host_name_fails(self):
        r = run_gate([self.write("a.md", f"run it on {HOST} please\n")])
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.md:1", r.stdout)

    def test_host_variants_fail(self):
        for text in (HOST.upper(), HOST.replace("-", "_"), "ai" + "-077", HOST + ".local", "x " + HOST + ","):
            with self.subTest(text=len(text)):
                self.assertEqual(run_gate([self.write("v.md", text + "\n")]).returncode, 1)

    def test_storage_path_fails(self):
        self.assertEqual(run_gate([self.write("b.md", f"see {STORAGE}\n")]).returncode, 1)

    def test_bare_storage_root_fails(self):
        for text in (ROOT_BARE, ROOT_BARE + ",", "(" + ROOT_BARE + ")", "`" + ROOT_BARE + "`"):
            with self.subTest(text=len(text)):
                self.assertEqual(run_gate([self.write("r.md", text + "\n")]).returncode, 1)

    def test_encoded_storage_root_fails(self):
        for text in ("%2F" + "srv" + "%2Fx", "\\x2f" + "srv" + "/x", "\\u002f" + "srv"):
            with self.subTest(text=len(text)):
                self.assertEqual(run_gate([self.write("e.md", text + "\n")]).returncode, 1)

    def test_clean_text_passes(self):
        self.assertEqual(run_gate([self.write("d.md", "the lab's knowledge server\n")]).returncode, 0)

    def test_near_miss_twins_pass(self):
        f = self.write("n.md", "ai-tools /" + "srv" + "x /usr/" + "srv" + " ai-7 ai-7777 mai-77\n")
        r = run_gate([f])
        self.assertEqual(r.returncode, 0, out(r))


class Redaction(Base):
    def test_content_match_not_echoed(self):
        r = run_gate([self.write("c.md", f"{HOST} {STORAGE}\n")])
        for secret in (HOST, STORAGE, ROOT_BARE):
            self.assertNotIn(secret, out(r))

    def test_tracked_path_is_checked_and_withheld(self):
        f = self.write(f"notes-{HOST}.md", "clean\n")
        r = run_gate([f])
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(HOST, out(r))

    def test_path_directory_match_withheld(self):
        d = self.dir / f"{HOST}-dir"
        d.mkdir()
        (d / "x.md").write_text(f"{STORAGE}\n")
        r = run_gate([d / "x.md"])
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(HOST, out(r))
        self.assertNotIn(STORAGE, out(r))

    def test_extra_patterns_from_env_not_echoed(self):
        f = self.write("f.md", "codename zebra\n")
        self.assertEqual(run_gate([f]).returncode, 0)
        r = run_gate([f], {"PUBLIC_GATE_EXTRA_PATTERNS": "zebra\nother"})
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("zebra", out(r))


class FailClosed(Base):
    def test_utf16_with_bom_is_scanned(self):
        f = self.write("u16.md", (f"see {HOST}\n").encode("utf-16"), "b")
        self.assertEqual(run_gate([f]).returncode, 1)

    def test_utf16_without_bom_fails_closed(self):
        f = self.write("u16n.md", (f"see {HOST}\n").encode("utf-16-le"), "b")
        r = run_gate([f])
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(HOST, out(r))

    def test_undecodable_fails_closed(self):
        self.assertEqual(run_gate([self.write("bad.md", b"\xff\xfe\xfa abc", "b")]).returncode, 1)

    def test_binary_with_nul_fails_closed(self):
        f = self.write("g.bin", b"\x00\x01" + HOST.encode(), "b")
        r = run_gate([f])
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(HOST, out(r))

    def test_symlink_fails_closed(self):
        clean = self.write("target.md", "clean\n")
        link = self.dir / "link.md"
        link.symlink_to(clean)
        self.assertEqual(run_gate([link]).returncode, 1)

    def test_symlink_target_match_not_echoed(self):
        link = self.dir / "link2.md"
        link.symlink_to(STORAGE)
        r = run_gate([link])
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(STORAGE, out(r))

    def test_missing_file_fails_closed(self):
        r = run_gate([self.dir / "nope.md"])
        self.assertEqual(r.returncode, 1)

    def test_directory_fails_closed(self):
        self.assertEqual(run_gate([self.dir]).returncode, 1)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads anything")
    def test_unreadable_file_fails_closed(self):
        f = self.write("locked.md", "clean\n")
        f.chmod(0)
        try:
            self.assertEqual(run_gate([f]).returncode, 1)
        finally:
            f.chmod(0o600)

    def test_slow_pattern_is_bounded(self):
        f = self.write("slow.md", "a" * 60 + "!\n")
        r = run_gate([f], {"PUBLIC_GATE_EXTRA_PATTERNS": "(a+)+$", "PUBLIC_GATE_TIMEOUT": "0.5"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("timed out", out(r))

    def test_bad_pattern_exits_2(self):
        f = self.write("p.md", "x\n")
        self.assertEqual(run_gate([f], {"PUBLIC_GATE_EXTRA_PATTERNS": "("}).returncode, 2)


class GitInputs(Base):
    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.dir, capture_output=True, check=True)

    def test_cleaned_repo_passes(self):
        z = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        tracked = [ROOT / p for p in z.decode().split("\0") if p]
        self.assertTrue(tracked)
        r = run_gate(tracked)
        self.assertEqual(r.returncode, 0, out(r))

    def test_spaced_filename_reaches_the_gate_intact(self):
        self.git("init", "-q")
        (self.dir / "my notes.md").write_text(f"{STORAGE}\n")
        self.git("add", "-A")
        z = self.git("ls-files", "-z").stdout.decode().split("\0")
        names = [n for n in z if n]
        self.assertEqual(names, ["my notes.md"])
        r = subprocess.run(
            [sys.executable, "-I", str(GATE), *names], cwd=self.dir, capture_output=True, text=True
        )
        self.assertEqual(r.returncode, 1)


class Wiring(Base):
    def test_hook_runs_isolated_and_covers_symlinks(self):
        text = HOOKS.read_text()
        self.assertRegex(text, r"entry: python3 -I scripts/public_gate\.py")
        self.assertRegex(text, r"types_or: \[[^\]]*symlink[^\]]*\]")

    def pre_commit_runs(self):
        return re.findall(r"^\s*-?\s*run: (pre-commit run .*)$", WORKFLOW.read_text(), re.M)

    def test_ci_never_prints_diffs(self):
        runs = self.pre_commit_runs()
        self.assertTrue(runs)
        for cmd in runs:
            self.assertNotIn("--show-diff-on-failure", cmd)

    def test_secret_reaches_only_the_gate_step(self):
        text = WORKFLOW.read_text()
        self.assertEqual(text.count("secrets.PUBLIC_GATE_EXTRA_PATTERNS"), 1)
        steps = re.split(r"(?m)^      - ", text)
        holders = [s for s in steps if "secrets.PUBLIC_GATE_EXTRA_PATTERNS" in s]
        self.assertEqual(len(holders), 1)
        self.assertIn("pre-commit run public-gate", holders[0])
        self.assertNotIn("--all-files --color=always", holders[0])

    @unittest.skipUnless(shutil.which("pre-commit"), "pre-commit not installed")
    def test_failure_path_with_a_fixer_active_prints_no_match(self):
        # The CI commands themselves, run against a repo whose fixer rewrites a file that also
        # holds a synthetic marker in its name and its content.
        d = self.dir
        (d / "fixer.py").write_text(
            "import sys\nfor f in sys.argv[1:]:\n"
            "    t = open(f).read()\n    n = '\\n'.join(l.rstrip() for l in t.split('\\n'))\n"
            "    if n != t:\n        open(f, 'w').write(n)\n        print('fixed one file')\n        sys.exit(1)\n"
        )
        (d / ".pre-commit-config.yaml").write_text(
            "repos:\n- repo: local\n  hooks:\n"
            "  - id: fixer\n    name: fixer\n    entry: python3 -I fixer.py\n    language: system\n    types: [text]\n"
            "  - id: public-gate\n    name: public-gate\n"
            f"    entry: python3 -I {GATE}\n    language: system\n    types_or: [file, symlink]\n"
        )
        (d / f"{HOST}.md").write_text(f"see {STORAGE}   \n")
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        for cmd in self.pre_commit_runs():
            env = {k: v for k, v in os.environ.items() if k != "SKIP"}
            if "public-gate" not in cmd:
                env["SKIP"] = "public-gate"
            r = subprocess.run(cmd.split(), cwd=d, capture_output=True, text=True, env=env, timeout=120)
            self.assertNotEqual(r.returncode, 0, "the fixer or the gate must fail")
            for secret in (HOST, STORAGE, ROOT_BARE):
                self.assertNotIn(secret, out(r), cmd)


if __name__ == "__main__":
    unittest.main()
