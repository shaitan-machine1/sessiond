#!/usr/bin/env python3
"""Private mount namespace and a harness-owned constant disposable cgroup root.

No installed PAM writes, live hierarchy discovery, service activation or hardware.
The invoking shell builds all executables as the ordinary user first.
"""
import ctypes
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from cgroup_fixture import test_root


class Skip(Exception):
    pass


def wait_for(predicate, label, seconds=12):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f"deadline: {label}")
        time.sleep(0.02)


def main(parent):
    assert os.geteuid() == 0
    repo, built, uid = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
    assert os.readlink("/proc/self/ns/mnt") != os.readlink(f"/proc/{os.getppid()}/ns/mnt"), (
        "run tests/root-e2e.sh: a private mount namespace is mandatory"
    )
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0  # child subreaper: verify orphan reaping
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    user = pwd.getpwuid(uid).pw_name
    work = Path(tempfile.mkdtemp(prefix="sessiond-root-e2e."))
    work.chmod(0o711)
    root = parent / ("sessiond-test-" + uuid.uuid4().hex)
    root.mkdir()  # every cgroup effect, including cleanup, is BELOW this fresh child
    (root / "daemon-control").mkdir()
    processes, logs = [], []
    daemon = None
    adopted = []
    env = dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS=f"unix:path={work}/bus")
    endpoint = ["busctl", "--address=" + env["DBUS_SYSTEM_BUS_ADDRESS"], "--json=short", "call", "org.SGLogin.Sessiond1", "/org/SGLogin/Sessiond1", "org.SGLogin.Sessiond1.Manager"]

    def spawn(args, log=None, interactive=False):
        stream = open(work / log, "a") if log else None
        if stream:
            logs.append(stream)
        process = subprocess.Popen([str(arg) for arg in args], env=env, stdin=subprocess.PIPE if interactive else subprocess.DEVNULL, stdout=subprocess.PIPE if interactive else stream, stderr=stream, text=True, bufsize=1)
        processes.append(process)
        return process

    def read(process):
        assert select.select([process.stdout], [], [], 8)[0], "host response timeout"
        response = process.stdout.readline().strip()
        assert response, f"host exited: {process.poll()}"
        return response.split()

    def command(process, text):
        process.stdin.write(text + "\n")
        process.stdin.flush()
        return read(process)

    def call(method, *args):
        result = subprocess.run(endpoint + [method] + list(args), env=env, text=True, capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)["data"] if result.stdout.strip() else []

    def start(min_uid=4294967295, launcher=None):
        nonlocal daemon
        config = f'''cgroup_root = "{root}"
runtime_parent = "{work}/runtime"
state_dir = "{work}/state"
[session]
close_grace = "100ms"
[session.shutdown]
mode = "scope"
master_timeout = "100ms"
scope_timeout = "200ms"
[user_service_manager]
min_uid = {min_uid}
launcher = "{launcher or repo / 'target/debug/sessiond-user-launcher'}"
ready_timeout = "5s"
[user_service_manager.shutdown]
mode = "master"
master_timeout = "200ms"
scope_timeout = "200ms"
'''
        (work / "sessiond.conf").write_text(config)
        daemon = spawn([built / "host", "exec", root / "daemon-control", repo / "target/debug/sessiond", "--config", work / "sessiond.conf"], "daemon.log")
        def owns():
            assert daemon.poll() is None, "daemon failed"
            result = subprocess.run(endpoint + ["ListSessions"], env=env, capture_output=True, timeout=2)
            return result.returncode == 0
        wait_for(owns, "private daemon ownership")

    def stop(crash=False):
        nonlocal daemon
        if crash:
            daemon.kill()
        else:
            daemon.terminate()
        daemon.wait(timeout=15)
        daemon = None

    def host(pam=False, runtime="none"):
        args = [built / "host", "pam" if pam else "local", root, uid, user]
        if pam:
            args += ["login", work / "pam.d", runtime]
        process = spawn(args, "host.log", True)
        opened = read(process)
        assert opened[0] == "OPEN" and int(opened[2]) == uid and int(opened[3]) == process.pid
        assert command(process, "duplicate") == ["DUPLICATE"]
        return process, opened[1]

    def ready(process):
        result = command(process, "ready")
        if result[:2] == ["ERROR", "13"]:
            raise Skip("readiness failed: ProcessFD support/setup prerequisites must be checked in daemon.log")
        assert result[0] == "INFO" and result[2:] == [str(uid), str(work / "runtime" / str(uid))], result
        return result

    def scope(sid):
        return root / "sessiond/user" / str(uid) / "session" / sid

    def close(sid, process):
        call("CloseSession", "s", sid)
        assert not scope(sid).exists()  # tree completion, not shared cleanup
        process.wait(timeout=5)

    try:
        pamdir = work / "pam.d"
        pamdir.mkdir()
        fragment = (repo / "dist/pam/sessiond-session").read_text().replace("pam_sessiond_core.so", str(repo / "target/debug/libpam_sessiond_core.so") + f" cgroup_root={root}").replace("pam_sessiond_ready.so", str(repo / "target/debug/libpam_sessiond_ready.so"))
        (pamdir / "sessiond-session").write_text(fragment)
        (pamdir / "login").write_text("session include sessiond-session\n")
        (pamdir / "sessiond-user").write_text(f"session required {built}/private-pam.so\n")
        # /etc/pam.d is changed ONLY in this already-private mount namespace.
        subprocess.run(["mount", "--bind", pamdir, "/etc/pam.d"], check=True)
        policy = repo / "dist/dbus/org.SGLogin.Sessiond1.conf"
        (work / "bus.conf").write_text(f'''<busconfig><type>system</type><listen>unix:path={work}/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow send_type="method_call"/><allow send_type="method_return"/><allow send_type="error"/><allow send_type="signal"/><allow receive_type="method_call"/><allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/></policy><include>{policy}</include></busconfig>''')
        spawn(["dbus-daemon", "--nofork", "--config-file=" + str(work / "bus.conf")], "bus.log")
        wait_for(lambda: (work / "bus").exists(), "private bus")
        # Required core succeeds with no daemon; optional readiness clears stale
        # runtime but preserves authoritative SID. No manager/runtime is created.
        first, sid = host(pam=True)
        assert scope(sid).exists() and not (work / "runtime").exists()
        assert command(first, "ready")[0] == "ERROR" and first.poll() is None
        failedhost, hidden_sid = host(pam=True)
        start(launcher="/definitely/missing/sessiond-launcher")
        assert call("ListSessions") == [[]]
        assert command(failedhost, "quit") == ["CLOSED", "0"]
        assert failedhost.wait(timeout=5) == 0
        wait_for(lambda: not scope(hidden_sid).exists(), "optional readiness failure followed by caller-resolved close")
        original = ready(first)
        assert ready(first) == original
        assert command(first, "attrs") == original
        assert command(first, "self-close")[:2] == ["ERROR", "1"] and first.poll() is None
        assert command(first, "nested") == ["NESTED"]
        assert command(first, "lookup") == original
        assert command(first, "duplicate") == ["DUPLICATE"]
        assert not (root / "sessiond/user" / str(uid) / "service").exists()
        close(sid, first)
        wait_for(lambda: not (work / "runtime" / str(uid)).exists(), "deferred runtime cleanup")
        # Successful real PAM readiness publishes only validated runtime and seat.
        pamhost, sid = host(pam=True, runtime=str(work / "runtime" / str(uid)))
        attrs = call("GetSessionAttrs", "s", sid)[0]
        assert attrs.get("XDG_SEAT") == "supplied-unverified-seat", attrs
        assert command(pamhost, "quit") == ["CLOSED", "0"]
        assert pamhost.wait(timeout=5) == 0
        wait_for(lambda: not scope(sid).exists(), "core schedules close, ready close is a no-op")
        downhost, sid = host()
        ready(downhost)
        stop()
        downhost.kill()
        downhost.wait(timeout=5)
        assert scope(sid).exists()
        start()
        assert scope(sid).exists() and call("ListSessions") == [[]]
        trigger, trigger_sid = host()
        ready(trigger)
        close(trigger_sid, trigger)
        wait_for(lambda: not scope(sid).exists(), "closure-triggered cleanup of death during daemon downtime")
        # Recent untracked roots survive; age expiry alone never triggers cleanup.
        partial = uuid.uuid4().hex
        session_parent = root / "sessiond/user" / str(uid) / "session"
        session_parent.mkdir(parents=True, exist_ok=True)
        scope(partial).mkdir()
        stop()
        start()
        assert scope(partial).exists()
        time.sleep(10.1)
        stop()
        start()
        assert scope(partial).exists()
        trigger, trigger_sid = host()
        ready(trigger)
        close(trigger_sid, trigger)
        wait_for(lambda: not scope(partial).exists(), "expired initializer cleanup at next actual closure")
        stop()
        # Eligible manager: actual ready byte, UID/GID, FD/secret isolation,
        # reuse across sessions AND daemon death; no duplicate manager.
        start(min_uid=0)
        one, sid1 = host()
        ready(one)
        marker = work / "runtime" / str(uid) / "manager-instance"
        manager, descendant = map(int, marker.read_text().split())
        worker = call("GetSessionMasterPid", "s", sid1)[0]  # session master, independently queried
        assert worker == one.pid
        service_record = os.getxattr(root / "sessiond/user" / str(uid) / "service", "user.scoped.target.master").decode().split(":")
        old_worker = int(service_record[1])
        adopted += [old_worker, descendant]
        two, sid2 = host()
        ready(two)
        assert marker.read_text().split() == [str(manager), str(descendant)]
        stop(crash=True)
        start(min_uid=0)
        ready(two)
        assert marker.read_text().split() == [str(manager), str(descendant)]
        close(sid1, one)
        assert marker.exists()  # another actual root retains resources
        close(sid2, two)
        wait_for(lambda: not marker.parent.exists(), "manager drain before runtime removal")
        for pid in adopted:
            waited, _ = os.waitpid(pid, 0)
            assert waited == pid  # explicit adoption/reaping, not setsid folklore
        adopted.clear()
        print("real-cgroup local/PAM/readiness/restart/manager/drain tests passed")
    finally:
        if (root / "cgroup.kill").exists():
            (root / "cgroup.kill").write_text("1\n")
        for process in reversed(processes):
            if process.poll() is None:
                process.kill()
            process.wait(timeout=15)
        for pid in adopted:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        for stream in logs:
            stream.close()
        wait_for(lambda: "populated 0" in (root / "cgroup.events").read_text(), "fixture drain")
        for directory, _, _ in os.walk(root, topdown=False):
            Path(directory).rmdir()
        if sys.exc_info()[0]:
            for log in work.glob("*.log"):
                print(f"--- {log.name}\n{log.read_text()[-12000:]}", file=sys.stderr)
        shutil.rmtree(work)


if __name__ == "__main__":
    try:
        with test_root() as parent:
            main(parent)
    except Skip as error:
        print(f"SKIP: {error}", file=sys.stderr)
        sys.exit(77)
