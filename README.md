# sessiond

Phase 1 session lifecycle stack:

- `sessiond`: root system-bus service implementing `OpenSession`, asynchronous
  idempotent `CloseSession`, `ListSessions`, lifecycle signals, restart
  reconstruction and separate leader/scope escalation budgets;
- `pam_sessiond`: Rust `cdylib` with hand-written libpam FFI, finite D-Bus
  timeout, PAM environment setup, PAM-data session ID and `fail_open`;
- `sessiond-user-launcher`: a dedicated single-threaded PAM/credential/process
  launcher tracked as target `manager`;
- `user-service-manager`: s6/s6-rc entrypoint and a default per-user D-Bus
  longrun.

The workspace pins `scope-id` from the exact SSH tag `v0.1.0` and uses
zbus 6. UUIDv7 session IDs are lowercase 32-digit hex strings.

## Build and test

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Unit tests use fake scoped/runtime/launcher backends, including two concurrent
sessions sharing one manager, last-session cleanup, shutdown ordering and
unsafe runtime-path rejection. Root-required end-to-end tests are committed
and use private D-Bus/cgroup state without a display, seat or VT:

```sh
./tests/root-e2e.sh
./tests/root-user-launcher-e2e.sh
```

`root-e2e.sh` builds the sibling scoped checkout (override with
`SCOPED_REPO=/path/to/scoped`), exercises real cgroup migration, shared-manager
and clean/unclean session teardown, and calls the installed build of
`pam_sessiond` through a temporary PAM configuration. Both scripts require
passwordless `sudo`; they return status 77 when prerequisites are unavailable.

## Install

Install the binaries under `/usr/bin` and `/usr/libexec/sessiond`, the PAM
module in the distribution module directory, and the files under `dist/`:

- D-Bus policy `org.decoupling.sessiond1.conf`;
- `/etc/sessiond/sessiond.toml`;
- `/etc/pam.d/sessiond-user` (must not recurse into `pam_sessiond`/`pam_aclad`);
- the system s6 longrun, ordered after scoped and system D-Bus;
- a compiled s6-rc database generated from `dist/s6-user/source`.

Install `pam_sessiond` before modules consuming `XDG_RUNTIME_DIR`. See
`dist/pam/README.md`. Live TTY/SSH/SDDM verification remains M5 work.
