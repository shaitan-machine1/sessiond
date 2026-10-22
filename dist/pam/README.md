Install `libpam_sessiond.so` in the distribution PAM module directory. Add it
before consumers of XDG environment values, normally as:

    -session optional pam_sessiond.so fail_open timeout=30s

`pam_sessiond` sets `XDG_RUNTIME_DIR` and `XDG_SESSION_ID`; it deliberately does
not set the legacy `DBUS_SESSION_BUS_ADDRESS`. A distribution or administrator
may define it in `/etc/security/pam_env.conf`:

    DBUS_SESSION_BUS_ADDRESS DEFAULT=unix:path=${XDG_RUNTIME_DIR}/bus

That requires the distribution's `pam_env.so` session entry to run after
`pam_sessiond`. `pam_env.so` is not part of the sessiond integration fragment.

Deployments preferring strict session management may use `required` and omit
`fail_open`. The dedicated `/etc/pam.d/sessiond-user` stack is internal and must
never contain `pam_sessiond` or `pam_aclad`, which would recurse.
