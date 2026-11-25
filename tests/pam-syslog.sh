#!/bin/bash
# Actual modules, private PAM stacks: real errors, literal-format logging,
# optional readiness failure, non-UTF8 stale runtime sanitization and failed unset.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for command in cargo cc; do command -v "$command" >/dev/null || exit 77; done
[[ $EUID != 0 ]] || { echo 'build as a normal user' >&2; exit 77; }
cargo build --manifest-path "$repo/Cargo.toml" --locked -p pam-sessiond-core -p pam-sessiond-ready
work=$(mktemp -d /tmp/sessiond-pam-syslog.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir "$work/pam.d"
cat >"$work/shim.c" <<'EOF'
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int pam_putenv(pam_handle_t *pamh, const char *record) {
    if (getenv("FAIL_PAM_UNSET") && !strcmp(record,"XDG_RUNTIME_DIR")) return PAM_BUF_ERR;
    int (*original)(pam_handle_t *, const char *) = dlsym(RTLD_NEXT, "pam_putenv");
    return original(pamh, record);
}
void pam_syslog(const pam_handle_t *pamh, int priority, const char *format, ...) {
    (void)pamh; (void)priority;
    FILE *file = fopen(getenv("PAM_SYSLOG_CAPTURE"), "a"); if (!file) return;
    fprintf(file, "format=%s\nmessage=", format);
    va_list args; va_start(args,format); vfprintf(file,format,args); va_end(args); fputc('\n',file); fclose(file);
}
EOF
cat >"$work/app.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int conversation(int n, const struct pam_message **m, struct pam_response **r, void *d) { (void)n;(void)m;(void)d;*r=NULL;return PAM_CONV_ERR; }
int main(int argc, char **argv) {
    if (argc != 5) return 64;
    struct pam_conv conv = {conversation,NULL}; pam_handle_t *h = NULL;
    int s = pam_start_confdir(argv[1], argv[2], &conv, argv[3], &h); if (s) return 1;
    if (pam_putenv(h,"XDG_RUNTIME_DIR=\xff") || pam_putenv(h,"XDG_SESSION_ID=unchanged") || pam_putenv(h,"UNRELATED=keep")) return 2;
    s = pam_open_session(h,0);
    int good = strcmp(argv[4],"required") == 0 ? s != PAM_SUCCESS : s == PAM_SUCCESS;
    if (strcmp(argv[4],"optional") == 0) good = good && !pam_getenv(h,"XDG_RUNTIME_DIR");
    if (strcmp(argv[4],"failed-unset") == 0) good = good && pam_getenv(h,"XDG_RUNTIME_DIR") != NULL;
    good = good && !strcmp(pam_getenv(h,"XDG_SESSION_ID"),"unchanged") && !strcmp(pam_getenv(h,"UNRELATED"),"keep");
    pam_end(h,s); return good ? 0 : 3;
}
EOF
cc -shared -fPIC -Wall -Wextra -Werror "$work/shim.c" -ldl -o "$work/shim.so"
cc -Wall -Wextra -Werror "$work/app.c" -lpam -o "$work/app"
printf 'session required %s fail_open\n' "$repo/target/debug/libpam_sessiond_core.so" >"$work/pam.d/core"
printf 'session required pam_permit.so\nsession optional %s unknown=%%s\n' "$repo/target/debug/libpam_sessiond_ready.so" >"$work/pam.d/ready"
export PAM_SYSLOG_CAPTURE="$work/syslog" LD_PRELOAD="$work/shim.so"
"$work/app" core "$(id -un)" "$work/pam.d" required
"$work/app" ready "$(id -un)" "$work/pam.d" optional
FAIL_PAM_UNSET=1 "$work/app" ready "$(id -un)" "$work/pam.d" failed-unset
unset LD_PRELOAD
grep -Fx 'format=%s' "$work/syslog"
grep -Fx 'message=pam_sessiond_core: unknown core option: fail_open' "$work/syslog"
grep -Fx 'message=pam_sessiond_ready: unknown readiness option: unknown=%s' "$work/syslog"
grep -Fx 'message=pam_sessiond_ready: PAM environment operation failed: BUF_ERR' "$work/syslog"
echo 'actual PAM module failure, sanitization and safe-log tests passed'
