Install `libpam_sessiond.so` in the distribution PAM module directory. Add it
before consumers of XDG environment values, normally as:

    -session optional pam_sessiond.so fail_open timeout=30s

Deployments preferring strict session management may use `required` and omit
`fail_open`. The dedicated `/etc/pam.d/sessiond-user` stack must never contain
`pam_sessiond` or `pam_aclad`, which would recurse.
