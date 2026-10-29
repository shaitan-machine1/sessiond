#!/bin/bash
# Verify pam-sessiond routes contextual failures through pam_syslog with "%s".
set -euo pipefail

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for command in cargo cc; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 77; }
done
cargo build --manifest-path "$repo/Cargo.toml" -p pam-sessiond

work=$(mktemp -d /tmp/pam-sessiond-syslog.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir "$work/pam.d"
cat >"$work/shim.c" <<'EOF'
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void pam_syslog(const pam_handle_t *pamh, int priority, const char *format, ...) {
    (void)pamh;
    (void)priority;
    FILE *file = fopen(getenv("PAM_SYSLOG_CAPTURE"), "a");
    if (file == NULL) return;
    fprintf(file, "format=%s\nmessage=", format);
    va_list arguments;
    va_start(arguments, format);
    vfprintf(file, format, arguments);
    va_end(arguments);
    fputc('\n', file);
    fclose(file);
}
EOF
cat >"$work/app.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdlib.h>

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)count; (void)messages; (void)data; *responses = NULL; return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *handle = NULL;
    int status = pam_start_confdir("sessiond-syslog", argv[1], &conv, argv[2], &handle);
    if (status != PAM_SUCCESS) return 1;
    status = pam_open_session(handle, 0);
    pam_end(handle, status);
    return status == PAM_SUCCESS ? 0 : 2;
}
EOF
cc -shared -fPIC "$work/shim.c" -o "$work/shim.so"
cc "$work/app.c" -lpam -o "$work/app"
printf 'session required %s fail_open timeout=50ms\n' \
    "$repo/target/debug/libpam_sessiond.so" >"$work/pam.d/sessiond-syslog"

capture="$work/syslog"
PAM_SYSLOG_CAPTURE="$capture" \
LD_PRELOAD="$work/shim.so" \
    "$work/app" "$(id -un)" "$work/pam.d"

grep -Fx 'format=%s' "$capture"
grep -Fx 'message=session mutation requires effective UID 0' "$capture"
if grep -q 'pam_sessiond:' "$capture"; then
    echo "legacy stderr prefix unexpectedly reached pam_syslog" >&2
    exit 1
fi

echo "pam-sessiond pam_syslog diagnostic test passed"
