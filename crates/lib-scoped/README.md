# lib-scoped

Synchronous containment library, migrated into sessiond's workspace from the
standalone scoped repository. Includes the former scope-id identifier types.
There is no D-Bus transport, lock, automatic GC, runtime, or library-owned thread.

## Ownership and identifiers

`Domain::open(cgroup_root, name)` pins an existing domain directory.
`Domain::create(...)` explicitly creates one domain if absent. Neither creates
missing ancestors. All `ScopeId`s include the domain, for example
`sessiond/user/1000/session/0123`. APIs reject traversal and IDs outside the
selected domain. Path components and control files are opened without following
symlinks; multi-step operations use pinned descriptors. The library acts with
the caller's permissions and does not introduce unprivileged creation policy.

`pin_scope` exposes a descriptor-backed `ScopeHandle` for coordination that
must not follow a replacement generation at the same path.

Callers synchronize cooperating mutations and exclude outside writers during
transactions. A descriptor pins an instance, not an administrative lock: raw
administration can still disrupt another caller. Cgroup2 and `/proc` must use
compatible cgroup/PID namespaces. Isolated roots below the cgroup2 mount are
mapped using mountinfo; independently remapped namespaces are not supported.

## Mutations

- `create_scope`: exactly one mkdir, requiring its parent; existing is distinct.
- `move_process`: numeric-PID migration only. Caller controls PID lifetime.
- `assign_target`: separately captures PID/start time and publishes one complete
  `v2:PID:START_TIME` xattr using `XATTR_CREATE`; existing names are errors. No
  pidfd is acquired. The old pending/active v1 format is rejected, not migrated.
- `terminate_target` / `kill_target`: pin the recorded instance with a pidfd and
  validate exact membership before signalling. Never signal a bare PID.
- `terminate_scope`: reject self-freezing, request/confirm subtree freezing with
  a one-second deadline, recursively pin/validate members, queue SIGTERM, thaw.
  Ordinary errors attempt thaw and remain errors; process death may leave the
  subtree frozen. Retrying termination recovers without a public thaw API.
- `kill_scope`: cgroup.kill only; no wait or removal.
- `remove_scope`: exactly one rmdir, missing-idempotent, nonrecursive. Never
  remove control files manually. After confirmed drain callers remove unknown
  descendants deepest-first, then the root.

Generic I/O errors never prove absence. Neither kill nor termination proves
that processes exited. Uninterruptible processes can prevent cleanup.

## Queries and observation

`read_target_identity` reads the recorded PID/start time without liveness
checks. `target_status` distinguishes untracked, running, and exited processes;
it checks identity/liveness but deliberately does not require present membership.
`target_exists` additionally checks exact membership. None repairs tracking.
Missing or corrupt target records do not prevent whole-subtree operations.

`watch_target` attaches to one recorded process instance and reports actual
exit, not migration or tracking replacement. Missing tracking is an error,
not a fabricated exit. `watch_scope` reports whole-subtree emptiness, including
initially empty or confirmed missing instances. Watches never follow replacement
scope paths or target bindings. Events carry instance/identity information for
caller revalidation before mutation.

`Observer` combines watches with blocking poll and an eventfd control handle.
The caller owns any command queue and observer thread. Watches are one-shot,
including initial completion; remove/rearm explicitly. `Error::Watch` identifies
a failed watch token without consuming other watches' completions. An unchanged
readiness notification cannot cause an unbounded busy loop. Only
`TargetExited` and `ScopeEmpty` are completion event kinds.

## Validation

```sh
cargo test -p lib-scoped
cargo clippy -p lib-scoped --all-targets -- -D warnings
cargo tree -p lib-scoped -e normal
```

Plain-directory tests cover structure, safe path handling, metadata, failure
paths and observation; they do not emulate cgroup kernel behavior. Real-kernel
tests are explicitly opt-in and create only unique domains under an
administrator-provided disposable/delegated parent:

```sh
LIB_SCOPED_TEST_ROOT=/sys/fs/cgroup/DISPOSABLE_PARENT \
  cargo test -p lib-scoped --test cgroup -- --ignored
```

Those tests require migration, freezer, kill and xattr permissions. They never
scan or clean production domains. The former standalone daemon/API repository
is retired; maintained consumers use this crate directly.
