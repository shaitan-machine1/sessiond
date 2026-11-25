# lib-sessiond

Synchronous Rust/C SDK; no executor, hidden thread, PAM dependency or client
lifecycle lock. Full lifecycle policy belongs to the sessiond daemon.

## Rust

- `open_session(uid)` / `open_session_with_options(uid, &OpenOptions)` locally
  create containment, move only the privileged caller and record exact `master`.
  `OpenedSession` supplies SID/UID, not runtime/manager readiness.
- `OpenOptions.cgroup_root` defaults to `/sys/fs/cgroup`; use an explicit absolute
  disposable root for tests. No bus/account lookup is needed to open.
- Already-contained masters **or members**, including nested scopes and different
  requested UIDs, get `AlreadyInSession`. Concurrent opens within one process are
  unsupported by contract, without runtime enforcement. Use independent hosts.
- `bus::Client` provides all nine methods from the SGLogin sessiond interface.
  `SessionInfo` has SID, UID and runtime directory; master PID/start and opaque
  attributes have separate queries. Queries never fall back to local inventory.
- Call `ensure_session_ready()` separately after opening. It resolves the actual
  connection process, requiring the bus's authenticated ProcessFD. Missing bus
  support is an explicit readiness failure, not a numeric-PID fallback.
- `schedule_close_session` accepts/coalesces natural-exit grace; `close_session`
  waits only for session-tree removal, not shared-resource cleanup. Pending,
  timeout or disconnect is not successful cleanup and does not cancel effects.
- Clients verify/pin the daemon's **root unique owner**. Use an explicit
  `Bus::Address` for private tests. Timeouts are finite, in `(0, 3600s]`.
- `subscribe()` before inventory, then call `next_event(wait)` explicitly. Only
  authenticated `SessionNew`/`SessionRemoved` hints are accepted. Owner change or
  bounded-queue overflow invalidates the client: create a new verified client,
  subscribe and query fresh inventory. Hints are not durable/exactly-once logs.

Client connections belong to their creating process; do not inherit/use them
across fork. Serialize access externally. No public pidfd/process-identity type
or daemon lifecycle/configuration helper is exposed. Generic attributes do not
supply authoritative SID/runtime values.

Features: `local-open`, `blocking-client`, `c-api` (default includes all three),
plus `wire-serde` for server-side protocol types. `--no-default-features` excludes
transport/local-opening facilities. The daemon consumes protocol types without
constructing a client or linking PAM.

## C ABI and explicit staging

Header: [`include/sessiond.h`](include/sessiond.h). Opaque clients, owned results,
matching frees, fixed-width identity fields and numeric error codes are specified
there. Strings are UTF-8/NUL-free; failed pointer outputs are NULL. Named remote
errors are preserved. Local-open results have a NULL runtime pointer.

Unexpected panics at ordinary C entry points **abort the embedding host**; they
are not caught or converted into success. Test this only in disposable children.
Ordinary errors return normally and have owned diagnostic allocations.

Cargo emits `target/debug/liblib_sessiond.so` with SONAME `libsessiond.so.0`.
The explicit staged mapping is:

```sh
cargo build -p lib-sessiond --locked
stage=$(mktemp -d)
install -Dm755 target/debug/liblib_sessiond.so "$stage/usr/lib/libsessiond.so.0"
ln -s libsessiond.so.0 "$stage/usr/lib/libsessiond.so"
install -Dm644 crates/lib-sessiond/include/sessiond.h "$stage/usr/include/sessiond.h"
./tests/sdk-smoke.sh "$stage"
```

This compiles/links/runs a C consumer against staged artifacts, checks SONAME and
exports and rejects PAM/executor runtime dependencies. It never installs on the
host or performs a valid open against the host's default containment root.
`tests/private-bus.sh` additionally exercises private-bus C queries/patches.
ABI major 0 is development-stage, without compatibility aliases.
