# sessiond

Synchronous session lifecycle and daemonless cgroup-v2 containment.

## Workspace

- `lib-scoped`: explicit containment domains, tracked process identities,
  signalling, subtree termination, and caller-owned blocking observation. It
  has no D-Bus, locks, hidden threads, or automatic cleanup.
- `lib-sessiond`: per-UID file locking, containment-derived inventory, local PAM
  open, secure runtime handling, launcher coordination, synchronous D-Bus
  clients/signals, and the daemon's complete teardown algorithm.
- `pam_sessiond`: opens locally through `lib-sessiond`; on close it resolves its
  current containment and asks the daemon to schedule teardown.
- `sessiond`: blocking `dbus`/`dbus-crossroads` service with bounded cleanup and
  reply workers plus one multi-watch observer thread.
- `sessiond-user-launcher`: detached manager PAM host and manager child reaper.
- `pam-ffi`: shared minimal Linux-PAM bindings.

`pam_sessiond` accepts `fail_open`, `timeout=DURATION`, and an absolute
`config=PATH` override (the default is `/etc/sessiond.conf`). The saved SID is
convenience only; close always resolves the caller's current containment.

There is no scoped daemon or `OpenSession` RPC. Authoritative session state is:

```text
sessiond/user/<uid>/session/<sid>
sessiond/user/<uid>/service
```

Inventory is lock-free and reports SID, UID, and the recorded leader identity
without probing liveness. Startup discovery is read-only and never sweeps old
state. Close scheduling/coalescing and completion results exist only in daemon
memory.

## D-Bus

The retained interface is:

```text
org.decoupling.sessiond1
/org/decoupling/sessiond1
org.decoupling.sessiond1.Manager
```

Methods:

- `CloseSession`: scheduling-only compatibility method;
- `ScheduleCloseSession`: scheduling-only;
- `CloseSessionAndWait`: blocking administrative completion;
- `ListSessions`: legacy SID/UID adapter over containment inventory.

Mutating methods verify root bus credentials. `SessionNew` may be sent directly
by a root PAM connection, while `SessionRemoved` is sent by daemon cleanup.
Listeners must match type/interface/path/member without a sender constraint.

## Manager startup

A new manager is launched only when no recorded live `manager` PAM host can be
reused. The launcher pins the service-scope generation, detaches after exec,
self-migrates, separately assigns target `manager`, opens its private PAM
session, starts the configured manager as the target user, and reports one-byte
manager readiness. The original PAM host reaps only the short-lived helper.

The manager executable is selected at build time with
`SESSIOND_USER_SERVICE_MANAGER` and defaults to
`/usr/libexec/user-service-manager`. It is invoked as:

```text
user-service-manager --ready-fd 3
```

The private PAM service defaults to `sessiond-user` and is configurable as
`user_service_manager.pam_service`. No user bus address is synthesized.

## Build and test

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Real cgroup tests for `lib-scoped` are opt-in and require an explicitly
throwaway delegated parent:

```sh
LIB_SCOPED_TEST_ROOT=/sys/fs/cgroup/DISPOSABLE_PARENT \
  cargo test -p lib-scoped --test cgroup -- --ignored
```

Root integration tests use a private bus and disposable cgroup tree. The main
scenario covers concurrent opens, daemon restart with stale initial discovery,
leader-exit observation, optional-PAM manager-start failure, scheduled PAM
close, and blocking administrative close:

```sh
./tests/root-e2e.sh
./tests/pam-syslog.sh
```

They require passwordless `sudo`; missing prerequisites return status 77.
Distribution service/activation cutover is intentionally outside this source
migration.
