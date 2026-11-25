#!/usr/bin/env python3
"""Real-kernel regression tests for the dedicated test-root safety boundary."""
import os
import signal
import subprocess
import unittest

from cgroup_fixture import TEST_ROOT, test_root


class TestRootSafety(unittest.TestCase):
    def tearDown(self):
        self.assertFalse(TEST_ROOT.exists(), "fixture root must not leak")

    def test_existing_root_is_never_adopted_or_killed(self):
        with test_root():
            identity = TEST_ROOT.stat()
            child = subprocess.Popen(["sleep", "120"])
            try:
                (TEST_ROOT / "cgroup.procs").write_text(f"{child.pid}\n")
                with self.assertRaises(FileExistsError):
                    with test_root():
                        self.fail("a second owner acquired the existing root")
                current = TEST_ROOT.stat()
                self.assertEqual((current.st_dev, current.st_ino), (identity.st_dev, identity.st_ino))
                self.assertIsNone(child.poll(), "refused acquisition must not kill another owner's process")
            finally:
                child.kill()
                child.wait(timeout=5)

    def test_failed_body_kills_only_its_fixture_and_removes_it(self):
        child = None
        try:
            with self.assertRaisesRegex(RuntimeError, "injected fixture failure"):
                with test_root():
                    scope = TEST_ROOT / "failed-child"
                    scope.mkdir()
                    child = subprocess.Popen(["sleep", "120"])
                    (scope / "cgroup.procs").write_text(f"{child.pid}\n")
                    raise RuntimeError("injected fixture failure")
            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_successful_body_cannot_hide_leaked_children(self):
        with self.assertRaisesRegex(AssertionError, "left cgroup fixtures behind"):
            with test_root():
                (TEST_ROOT / "leaked-child").mkdir()


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("run tests/cgroup.sh to build unprivileged and test as root")
    unittest.main()
