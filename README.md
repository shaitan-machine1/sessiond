# sessiond

Local session creation and daemon-owned readiness, teardown and reconciliation.
Linux cgroup-v2 containment is authoritative; there is no session database.

## Components and lifecycle

- **lib-scoped**: synchronous, daemonless, D-Bus/PAM-free containment, process
  tracking, bounded opaque attributes and caller-driven observation.
- **lib-sessiond**: synchronous local self-opening, shared protocol types,
  blocking Rust client and dynamic C SDK. No executor or lifecycle locks.
- **sessiond**: Tokio server, four fixed effect workers, bounded admission,
  per-UID effect lanes and a root-controlled lifetime singleton
  lock. Only the daemon reads full lifecycle configuration.
- **pam-sessiond-core**: required local open and authoritative `XDG_SESSION_ID`;
  close resolves current membership and schedules daemon teardown without waiting.
- **pam-sessiond-ready**: optional-in-PAM readiness and validated
  `XDG_RUNTIME_DIR`; close is a no-op.
- **sessiond-user-launcher**: private synchronous PAM host, credential-exec stage
  and foreground-manager reaper. It has no public SDK/scoped dependency.

`open_session(uid)` requires root, creates a new session, moves **only its caller**
into it and records exact target `master`. It works without a daemon, account
lookup, runtime directory or manager. SID/UID are local identity, not readiness.
Already-contained callers (including nested members) get `AlreadyInSession`.
Concurrent opens **within one process are unsupported**; no runtime guard is
provided. Independent hosts may open concurrently for the same UID.

```text
sessiond/user/<uid>/session/<sid>
sessiond/user/<uid>/service
```

Logical UID comes from this root-controlled ancestry, not master credentials,
filesystem ownership, environment or attributes. Private inventory includes every
scope. Public metadata exposes a session only when its scope exists, protected
`ready=1` is stored, and its recorded exact master is alive. Unready/dead-master
roots are absent from public queries, without query-triggered cleanup. Runtime
path is a first-class field, with master tracking and opaque attributes queried
separately. Generic attributes, including SID/runtime-like names, are inert.
`ready` is the sole reserved key: only sessiond commits it. Initial local SDK
attributes reserve space for it; PAM core copies only supplied `XDG_SEAT` before
readiness. Required-core failure returns a PAM error; its dedicated host must end
rather than continue or reuse the failed session host.

## D-Bus

```text
org.SGLogin.Sessiond1
/org/SGLogin/Sessiond1
org.SGLogin.Sessiond1.Manager
```

See [`dist/dbus/org.SGLogin.Sessiond1.xml`](dist/dbus/org.SGLogin.Sessiond1.xml).
The complete methods are `ListSessions`, `GetSession`, `GetSessionByPid`,
`GetSessionMasterPid`, `GetSessionAttrs`, `EnsureSessionReady`,
`UpdateSessionAttrs`, `ScheduleCloseSession` and `CloseSession`. There are no
legacy endpoints, aliases or remote-open method.

Mutations require root. Readiness and caller-resolved scheduled close require the bus's authenticated
**ProcessFD** connection credential; a numeric bus PID is never a substitute.
A bus lacking ProcessFD fails readiness before effects, but does not prevent
local opening or ordinary queries. Readiness privately resolves/pins even an
unready caller, ensures runtime/eligible manager under its UID lane, prepares its
result and validates caller/scope/master before atomically committing `ready=1`
as its final fallible initialization step. Lost replies do not undo that commit.
Manager failure alone does not invalidate an already-ready session.

`ScheduleCloseSession()` takes no SID: it resolves the authenticated caller's
private enclosing scope and returns after bounded admission, even if that scope
is unready. Configured close grace defaults to 10s; zero disables grace. Retries
never extend the first deadline. `CloseSession(sid)` bypasses remaining grace.
`CloseSession` waits for actual **session-tree removal only**, not subsequent
manager/runtime cleanup. Blocking close from inside the target subtree is
rejected. Pending/timeouts/disconnects do not cancel admitted effects. Queues and
reply waiters are bounded; overload returns `Busy`.

Only the daemon emits `SessionNew` after successful readiness and `SessionRemoved`
after actual tree removal. Local opening, startup discovery and attribute patches
do not emit new-session signals. Hints are best effort, not durable/exactly-once
records; initial PAM seat copying precedes `SessionNew`. Never-ready tree removal
emits no external lifecycle signal. Clients pin a
verified root unique owner, subscribe before querying and pump explicitly.
Owner replacement or overflow requires a new verified client and fresh inventory.

## Reconciliation and restart

Only actual session closure triggers/coalesces separate per-UID reconciliation.
Startup, local open, readiness, queries and master death do not trigger it.
Session masters are not continuously watched: their exit immediately makes a
session publicly invalid and cleanup-eligible, but removal waits for a normal
closure-triggered pass or explicit/scheduled close. Missing tracking is eligible
when its directory **mtime is at least ten seconds old**; younger/future mtimes
are not expired. Live unready hosts are not killed merely for unreadiness.
Malformed records/I/O failures are errors, not invented absence or death.
A reconciliation pass is fail-fast, has no autonomous retry, and does not enqueue
another pass for its own closures. A later external closure triggers a new pass.

Re-inventory before shared cleanup. With no valid sessions or linger retention, drain
and remove the manager first, remove runtime last, then prune only empty
containers. Invalid roots do not retain shared resources, but their ancestors
must remain while those roots physically exist.
A runtime deletion failure retains the UID container for later discovery. There
is no autonomous retry loop, cleanup journal or unrelated-domain sweep. A host
that dies before contacting sessiond may wait until the next normal trigger.

Grace deadlines/completion results are memory-only. Restart queries actual
scope/marker/master state without running reconciliation or restoring grace intent;
that host can need a new explicit close. A singleton lock is retained until
accepted effects quiesce even on bus loss. Live manager workers survive daemon
loss and are reused through exact service-master tracking, not restarted blindly.
Orphan adoption/reaping belongs to the parent subreaper/PID 1; a new daemon cannot
wait for an already-adopted unrelated child. The private harness verifies this
with its own subreaper. Direct children remain reaped while their daemon lives.

## Manager and configuration

See [`dist/sessiond.conf`](dist/sessiond.conf). Default `min_uid = 1000` skips
manager work below the threshold, **not runtime setup or existing-resource
cleanup**. Zero enables every UID. Below-threshold readiness does not require a
working launcher/manager or writable home. NSS lookup runs in a fresh exec'd
helper, never an async/blocking worker's address space.

For eligible UIDs, reuse a live service `master`; otherwise fully drain stale
service state before replacement. The daemon places/records its direct worker
before authorizing private PAM. Arbitrary PAM runs only after that exec/gate;
credential changes run in another exec stage with controlled environment and FD
inheritance. The manager supplies an actual readiness byte and is reaped using
its own transferred pidfd, not recycled numeric-PID/process-group authority.

Select the foreground manager at build time with
`SESSIOND_USER_SERVICE_MANAGER` (default `/usr/libexec/user-service-manager`):

```text
user-service-manager --ready-fd 3
```

The private PAM service defaults to `sessiond-user`; it must not include either
public module or `sessiond-session`. See [`dist/pam/README.md`](dist/pam/README.md).
No module synthesizes `DBUS_SESSION_BUS_ADDRESS`.

## Build and validation

```sh
cargo build --workspace --locked
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
./tests/pam-syslog.sh
./tests/private-bus.sh
```

SDK ABI/staging instructions: [`crates/lib-sessiond/README.md`](crates/lib-sessiond/README.md).
The private-bus test uses ordinary directory fixtures, not real-cgroup evidence.
PAM tests use private configuration only; no installed PAM/service changes.
Build as an ordinary user. Root phases use already-built artifacts and
noninteractive `sudo`; missing prerequisites return **77 (skip)**, not success.

Real-cgroup tests require an **explicitly supplied disposable delegated parent**:

```sh
LIB_SCOPED_TEST_ROOT=/sys/fs/cgroup/DISPOSABLE_PARENT \
  cargo test -p lib-scoped --test cgroup -- --ignored
LIB_SCOPED_TEST_ROOT=/sys/fs/cgroup/DISPOSABLE_PARENT ./tests/root-e2e.sh
```

The root harness uses only a fresh child of that parent and a private mount
namespace for private PAM, verifies local open/readiness/PAM/restart/manager reuse,
FD/credential boundaries and subtree drain. It never guesses a live hierarchy.
No build or synthetic/headless test establishes deployment or desktop acceptance.
