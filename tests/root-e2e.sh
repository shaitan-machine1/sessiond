#!/bin/bash
# Real scoped/cgroup/private-D-Bus and pam_sessiond integration.
set -euo pipefail

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scoped_repo=${SCOPED_REPO:-"$repo/../scoped"}
for command in cargo cc dbus-daemon busctl pgrep sudo; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 77; }
done
[ -x "$scoped_repo/target/debug/scoped" ] || cargo build --manifest-path "$scoped_repo/Cargo.toml" -p scoped
cargo build --manifest-path "$repo/Cargo.toml" --workspace --bins --example hold-session
cargo build --manifest-path "$repo/Cargo.toml" -p pam-sessiond
sudo -n true || { echo "passwordless sudo is required" >&2; exit 77; }

work=$(mktemp -d /tmp/sessiond-root-e2e.XXXXXX)
chmod 755 "$work"
cgroup="sessiond-root-e2e-$$"
cat >"$work/bus.conf" <<EOF
<busconfig><type>system</type><listen>unix:path=$work/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_type="method_call"/><allow send_type="method_return"/><allow send_type="error"/><allow send_type="signal"/><allow receive_type="method_call"/><allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/></policy></busconfig>
EOF
cat >"$work/launcher.c" <<'EOF'
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void handler(int signal) { (void)signal; stop = 1; }
int main(void) {
    char byte;
    if (read(3, &byte, 1) != 1 || byte != 1) return 1;
    byte = 1;
    if (write(4, &byte, 1) != 1) return 2;
    signal(SIGTERM, handler);
    while (!stop) pause();
    return 0;
}
EOF
cc "$work/launcher.c" -o "$work/test-launcher"
cat >"$work/pam-app.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)count; (void)messages; (void)data; *responses = NULL; return PAM_CONV_ERR;
}
int main(int argc, char **argv) {
    if (argc != 4) return 64;
    struct pam_conv conversation_data = {conversation, NULL};
    pam_handle_t *handle = NULL;
    int status = pam_start_confdir(argv[1], "root", &conversation_data, argv[3], &handle);
    if (status != PAM_SUCCESS) return 1;
    status = pam_open_session(handle, 0);
    if (status != PAM_SUCCESS) { fprintf(stderr, "open: %s\n", pam_strerror(handle, status)); pam_end(handle, status); return 2; }
    const char *sid = pam_getenv(handle, "XDG_SESSION_ID");
    const char *runtime = pam_getenv(handle, "XDG_RUNTIME_DIR");
    const char *legacy_bus = pam_getenv(handle, "DBUS_SESSION_BUS_ADDRESS");
    if (sid == NULL || strlen(sid) != 32 || runtime == NULL || legacy_bus != NULL) return 3;
    FILE *result = fopen(argv[2], "w");
    if (result == NULL) return 4;
    fprintf(result, "%s\n%s\n", sid, runtime);
    fclose(result);
    sleep(1);
    status = pam_close_session(handle, 0);
    pam_end(handle, status);
    return status == PAM_SUCCESS ? 0 : 5;
}
EOF
cc "$work/pam-app.c" -lpam -o "$work/pam-app"
mkdir "$work/pam.d"
printf 'session required %s timeout=5s\n' "$repo/target/debug/libpam_sessiond.so" >"$work/pam.d/sessiond-e2e"
cat >"$work/sessiond.conf" <<EOF
runtime_parent = "$work/user"
state_dir = "$work/state"
linger = false
[session]
open_timeout = "5s"
[session.shutdown]
mode = "scope"
leader_timeout = "100ms"
scope_timeout = "1s"
[user_service_manager]
launcher = "$work/test-launcher"
ready_timeout = "5s"
[user_service_manager.shutdown]
mode = "leader"
leader_timeout = "1s"
scope_timeout = "1s"
EOF

bus_pid=$(dbus-daemon --config-file="$work/bus.conf" --fork --print-pid)
address="unix:path=$work/bus"
scoped_wrapper= sessiond_wrapper= first_wrapper= second_wrapper= pam_wrapper= cli_wrapper=
first_pid= second_pid= pam_pid= cli_pid=
cleanup() {
    status=$?
    trap - EXIT
    set +e
    [ -n "$first_pid" ] && sudo kill -KILL "$first_pid" 2>/dev/null
    [ -n "$second_pid" ] && sudo kill -KILL "$second_pid" 2>/dev/null
    [ -n "$pam_pid" ] && sudo kill -KILL "$pam_pid" 2>/dev/null
    [ -n "$cli_pid" ] && sudo kill -KILL "$cli_pid" 2>/dev/null
    [ -n "$sessiond_wrapper" ] && sudo kill "$sessiond_wrapper" 2>/dev/null
    [ -n "$scoped_wrapper" ] && sudo kill "$scoped_wrapper" 2>/dev/null
    wait 2>/dev/null
    kill "$bus_pid" 2>/dev/null
    sudo find "/sys/fs/cgroup/$cgroup" -depth -type d -exec rmdir {} \; 2>/dev/null
    if [ "$status" -ne 0 ]; then
        for log in "$work"/*.log; do [ -f "$log" ] && { echo "--- $log" >&2; sudo tail -100 "$log" >&2; }; done
    fi
    sudo rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
wait_name() {
    name=$1
    for _ in $(seq 1 100); do
        busctl --address="$address" list 2>/dev/null | grep -q "$name" && return 0
        sleep .05
    done
    echo "timed out waiting for $name" >&2
    return 1
}
wait_file() {
    file=$1
    for _ in $(seq 1 100); do sudo test -f "$file" && return 0; sleep .05; done
    echo "timed out waiting for $file" >&2
    return 1
}

sudo mkdir "/sys/fs/cgroup/$cgroup"
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$scoped_repo/target/debug/scoped" --bus system --scope-root "$cgroup" >"$work/scoped.log" 2>&1 & scoped_wrapper=$!
wait_name org.decoupling.scoped1
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/sessiond" --bus system --config "$work/sessiond.conf" >"$work/sessiond.log" 2>&1 & sessiond_wrapper=$!
wait_name org.decoupling.sessiond1

# Session inventory is public and initially empty.
empty_output=$(busctl --address="$address" call org.decoupling.sessiond1 \
    /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
[ "$empty_output" = "a(su) 0" ]

# Two sessions share one user manager. Losing one tracked PAM host must only
# remove that session; normal close of the last removes the manager/runtime.
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/examples/hold-session" 0 "$work/first.sid" >"$work/first.log" 2>&1 & first_wrapper=$!
wait_file "$work/first.sid"
first_pid=$(pgrep -P "$first_wrapper" -f hold-session)
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/examples/hold-session" 0 "$work/second.sid" >"$work/second.log" 2>&1 & second_wrapper=$!
wait_file "$work/second.sid"
second_pid=$(pgrep -P "$second_wrapper" -f hold-session)
result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
echo "$result" | grep -q '^a(su) 2 '
first_sid=$(sudo head -n 1 "$work/first.sid")
second_sid=$(sudo head -n 1 "$work/second.sid")
echo "$result" | grep -q "$first_sid"
echo "$result" | grep -q "$second_sid"
if busctl --address="$address" call org.decoupling.sessiond1 \
    /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager \
    CloseSession s "$first_sid" >"$work/nonroot-close.log" 2>&1; then
    echo "non-root CloseSession unexpectedly succeeded" >&2
    exit 1
fi
grep -q 'root-only' "$work/nonroot-close.log"
[ "$(sudo find "/sys/fs/cgroup/$cgroup/sessiond/user/0/session" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 2 ]
[ "$(sudo cat "/sys/fs/cgroup/$cgroup/sessiond/user/0/service/cgroup.procs" | wc -l)" -eq 1 ]
sudo kill -KILL "$first_pid"
wait "$first_wrapper" || true
first_pid= first_wrapper=
for _ in $(seq 1 200); do
    result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
    echo "$result" | grep -q '^a(su) 1 ' && break
    sleep .05
done
echo "$result" | grep -q '^a(su) 1 '
sudo kill -INT "$second_pid"
wait "$second_wrapper" || true
second_pid= second_wrapper=
for _ in $(seq 1 200); do [ ! -e "$work/user/0" ] && break; sleep .05; done
[ ! -e "$work/user/0" ]

# Exercise the real PAM module and verify its transaction environment and
# synchronous open/close lifecycle against the same daemons.
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$work/pam-app" sessiond-e2e "$work/pam-result" "$work/pam.d" >"$work/pam.log" 2>&1 & pam_wrapper=$!
wait_file "$work/pam-result"
pam_pid=$(pgrep -P "$pam_wrapper" -f pam-app)
sudo awk 'NR==1 { if (length($0) != 32) exit 1 } NR==2 { if ($0 !~ "/user/0$") exit 1 }' "$work/pam-result"
wait "$pam_wrapper"
pam_pid= pam_wrapper=
for _ in $(seq 1 200); do [ ! -e "$work/user/0" ] && break; sleep .05; done
[ ! -e "$work/user/0" ]

# Root can request asynchronous closure through D-Bus, and the daemon drains
# the disposable scope.
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/examples/hold-session" 0 "$work/cli.sid" >"$work/cli-session.log" 2>&1 & cli_wrapper=$!
wait_file "$work/cli.sid"
cli_pid=$(pgrep -P "$cli_wrapper" -f hold-session)
cli_sid=$(sudo head -n 1 "$work/cli.sid")
sudo busctl --address="$address" call org.decoupling.sessiond1 \
    /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager \
    CloseSession s "$cli_sid" >/dev/null
for _ in $(seq 1 200); do
    ! kill -0 "$cli_wrapper" 2>/dev/null && break
    sleep .05
done
if kill -0 "$cli_wrapper" 2>/dev/null; then
    echo "timed out waiting for CloseSession to drain $cli_sid" >&2
    exit 1
fi
wait "$cli_wrapper" || true
cli_pid= cli_wrapper=
for _ in $(seq 1 200); do
    result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
    echo "$result" | grep -q '^a(su) 0$' && break
    sleep .05
done
echo "$result" | grep -q '^a(su) 0$'

echo "sessiond root/private-D-Bus/scoped/PAM end-to-end tests passed"
