# Public and private PAM stacks

The source-owned `/etc/pam.d/sessiond-session` include is:

```pam
session required pam_sessiond_core.so
session optional pam_sessiond_ready.so timeout=30s
```

Map `libpam_sessiond_core.so` and `libpam_sessiond_ready.so` from the build to the
corresponding distribution module names above. Install/stage the named include,
private `sessiond-user` stack and modules separately; nothing activates PAM
implicitly. Explicit activation belongs to the administrator, e.g. loginctl's
managed `session include sessiond-session` block before session `pam_env.so`.

Core resolves the final PAM UID, locally self-opens and overwrites
`XDG_SESSION_ID` with actual local identity, even when a stale value was supplied.
It succeeds without sessiond, runtime or manager. Core errors are actual errors:
`required` fails the overall stack, though later entries can still execute.
There is no `fail_open` or full-daemon `config=PATH` option. Minimal options are
`cgroup_root=/absolute/path` (must match the daemon) and `timeout=DURATION` for
close's blocking transport; concurrent opening within one host is unsupported.

Readiness first removes any supplied `XDG_RUNTIME_DIR`, even before option
parsing or connecting. It then ensures daemon readiness, copies only supplied
PAM `XDG_SEAT` into opaque session attributes when present, and publishes runtime
from validated `SessionInfo`. The supplied seat is not independently verified.
Its only option is `timeout=DURATION`. Bus ProcessFD support is required for
readiness, not for local core open.

After successful initial unsetting, any readiness/attribute/publication error
leaves runtime absent and never restores stale values. Core SID remains intact.
A failure to unset is itself an error, not successful sanitation. Optional policy
can still permit overall PAM success, without runtime, manager or seat metadata;
applications must tolerate this. Unexpected panics abort the PAM host by design.

Only core close resolves current PID/start membership through sessiond and calls
`ScheduleCloseSession`, without waiting for teardown. Readiness close does
nothing. Missing daemon is an actual close error, not silently `NoSession`.

Neither module sets `DBUS_SESSION_BUS_ADDRESS`. Administrators may arrange a
later `pam_env.so` entry, for example:

```text
DBUS_SESSION_BUS_ADDRESS DEFAULT=unix:path=${XDG_RUNTIME_DIR}/bus
```

That example presupposes a usable runtime; handle optional-readiness absence in
the surrounding application/PAM policy. `pam_env.so` is not in the sessiond
fragment and loginctl does not validate this fragment, modules or runtime policy.

**Private `sessiond-user` must never include `sessiond-session` or invoke either
public module.** This would recurse during a UID's pending manager readiness.
The daemon places/records its exec'd private PAM worker before authorizing PAM;
manager credential changes happen in a second exec stage. No installed PAM
changes, module migration or service activation follows from a source/package
build. Tests use only disposable configuration/private mount namespaces.
