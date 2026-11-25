#!/usr/bin/env python3
"""Own one fixed, disposable cgroup root; never adopt an existing hierarchy."""
import contextlib
import os
from pathlib import Path
import subprocess
import sys
import time


TEST_ROOT = Path("/sys/fs/cgroup/sglogin-tests")


@contextlib.contextmanager
def test_root():
    if os.geteuid() != 0:
        raise RuntimeError("run the built tests through the noninteractive root harness")
    mount = TEST_ROOT.parent
    if mount.resolve(strict=True) != mount:
        raise RuntimeError("cgroup mount path must not contain symlinks")
    filesystem = subprocess.check_output(["stat", "-f", "-c", "%T", mount], text=True).strip()
    if filesystem != "cgroup2fs":
        raise RuntimeError("/sys/fs/cgroup must be a writable cgroup-v2 mount")
    # Atomic exclusive creation: a previous run or an unrelated owner is never
    # reused, killed or swept. No exception before this succeeds owns the path.
    TEST_ROOT.mkdir(mode=0o700)
    identity = TEST_ROOT.stat()
    success = False
    try:
        yield TEST_ROOT
        success = True
    finally:
        current = TEST_ROOT.lstat()
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise RuntimeError("test cgroup root was replaced; refusing cleanup")
        leftovers = [entry for entry in TEST_ROOT.iterdir() if entry.is_dir()]
        # Only our freshly created root is eligible for recursive kill/removal.
        # Neither this Python process nor the invoking shell is moved into it.
        (TEST_ROOT / "cgroup.kill").write_text("1\n")
        deadline = time.monotonic() + 10
        while "populated 0" not in (TEST_ROOT / "cgroup.events").read_text():
            if time.monotonic() >= deadline:
                raise RuntimeError("test cgroup did not drain; retained for inspection")
            time.sleep(0.02)
        for directory, _, _ in os.walk(TEST_ROOT, topdown=False):
            Path(directory).rmdir()
        if success and leftovers:
            raise AssertionError("test left cgroup fixtures behind: " + repr(leftovers))


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: cgroup_fixture.py BUILT_TEST [ARG ...]")
    with test_root():
        result = subprocess.run(sys.argv[1:], check=False)
        if result.returncode:
            raise SystemExit(result.returncode if result.returncode > 0 else 1)


if __name__ == "__main__":
    main()
