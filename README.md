# sessiond

Phase 1 session lifecycle stack:

- `sessiond`: root system-bus service implementing `OpenSession`, asynchronous
  idempotent `CloseSession`, `ListSessions`, lifecycle signals, restart
  reconstruction and separate leader/scope escalation budgets;
- `pam_sessiond`: Rust `cdylib` with hand-written libpam FFI, finite D-Bus
  timeout, `XDG_RUNTIME_DIR`/`XDG_SESSION_ID` PAM environment setup, PAM-data
  session ID and `fail_open`; failures are reported with service context
  through `pam_syslog()` using a constant format string;
- `sessiond-api`: typed zbus proxies and protocol constants for external
  administrative clients;
- `sessiond-user-launcher`: a dedicated single-threaded PAM/credential/process
  launcher tracked as target `manager`.

The user service manager is a separate package implementing the interface
below. Sessiond does not ship an s6 graph or a user D-Bus service.

The workspace pins `scope-id` from the exact SSH tag `v0.1.0` and uses
zbus 6. UUIDv7 session IDs are lowercase 32-digit hex strings.

Administrative presentation belongs to the separate unified `loginctl`
repository. This repository intentionally ships no component-specific CLI;
sessiond's D-Bus policy and peer credentials remain the authorization
boundary.

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
./tests/pam-syslog.sh
```

`root-e2e.sh` builds the sibling scoped checkout (override with
`SCOPED_REPO=/path/to/scoped`), exercises real cgroup migration, shared-manager
and clean/unclean session teardown, and calls the installed build of
`pam_sessiond` through a temporary PAM configuration. Both scripts require
passwordless `sudo`; they return status 77 when prerequisites are unavailable.
`pam-syslog.sh` interposes a test logger to verify that a system-bus failure
reaches `pam_syslog()` with the literal `%s` format and contextual text.

## User service manager interface

The manager executable path is selected at build time with the
`SESSIOND_USER_SERVICE_MANAGER` build environment variable and defaults to
`/usr/libexec/user-service-manager`. It is not configurable through the daemon
configuration or runtime environment.

After its private PAM and credential setup, `sessiond-user-launcher` invokes:

```text
/usr/libexec/user-service-manager --ready-fd 3
```

The manager remains in the foreground for the lifetime of its service graph.
It writes one readiness byte of any value to fd 3. The launcher reads exactly
one byte, retries interrupted reads, treats EOF or read failure as startup
failure, and closes the pipe immediately without draining. Sessiond enforces
the configured readiness timeout around the privileged launcher. The manager
must handle `SIGTERM` by stopping its graph and exiting.

The manager receives `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`,
`XDG_CONFIG_HOME`, and `XDG_RUNTIME_DIR`. The launcher does not synthesize
`DBUS_SESSION_BUS_ADDRESS` or pass `SESSIOND_READY_FD`.

## Install

Install `sessiond` under `/usr/bin`, the launcher under
`/usr/libexec/sessiond`, the PAM module in the distribution module directory,
and the following files under `dist/`:

- D-Bus policy `org.decoupling.sessiond1.conf`;
- `/etc/sessiond.conf`;
- `/etc/pam.d/sessiond-user` (must not recurse into `pam_sessiond`/`pam_aclad`).

The Artix system service definition and the selected user service manager are
packaged separately.

Install `pam_sessiond` before modules consuming `XDG_RUNTIME_DIR`, including
`pam_env` when its configuration derives values from the runtime directory.
`pam_sessiond` deliberately does not set the legacy `DBUS_SESSION_BUS_ADDRESS`;
distributions or administrators may derive it in `pam_env.conf`. See
`dist/pam/README.md`. Live TTY/SSH/SDDM verification remains M5 work.
