#!/bin/bash
# Real daemonless containment, synchronous D-Bus, PAM, and cleanup integration.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for command in cargo cc dbus-daemon busctl sudo; do command -v "$command" >/dev/null || exit 77; done
sudo -n true || exit 77
work=$(mktemp -d /tmp/sessiond-root-e2e.XXXXXX)
cgroup="sessiond-root-e2e-$$"
pam_service="sessiond-user-e2e-$$"
cat >"$work/manager.c" <<'EOF'
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void handler(int signal) { (void)signal; stop = 1; }
int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--ready-fd") != 0 || strcmp(argv[2], "3") != 0) return 64;
    char byte = 1; if (write(3, &byte, 1) != 1) return 1; close(3);
    signal(SIGTERM, handler); signal(SIGINT, handler); signal(SIGHUP, handler);
    while (!stop) pause(); return 0;
}
EOF
cc "$work/manager.c" -o "$work/manager"
SESSIOND_USER_SERVICE_MANAGER="$work/manager" cargo build --manifest-path "$repo/Cargo.toml" --workspace --bins --example hold-session
SESSIOND_USER_SERVICE_MANAGER="$work/manager" cargo build --manifest-path "$repo/Cargo.toml" -p pam-sessiond
cat >"$work/bus.conf" <<EOF
<busconfig><type>system</type><listen>unix:path=$work/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_type="method_call"/><allow send_type="method_return"/><allow send_type="error"/><allow send_type="signal"/><allow receive_type="method_call"/><allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/></policy></busconfig>
EOF
cat >"$work/pam-app.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int conversation(int n, const struct pam_message **m, struct pam_response **r, void *d) { (void)n;(void)m;(void)d;*r=NULL;return PAM_CONV_ERR; }
int main(int argc, char **argv) {
    if (argc != 4) return 64; struct pam_conv conv={conversation,NULL}; pam_handle_t *h=NULL;
    int s=pam_start_confdir(argv[1],"root",&conv,argv[3],&h); if(s!=PAM_SUCCESS)return 1;
    s=pam_open_session(h,0); if(s!=PAM_SUCCESS){pam_end(h,s);return 2;}
    const char *sid=pam_getenv(h,"XDG_SESSION_ID"), *runtime=pam_getenv(h,"XDG_RUNTIME_DIR");
    if(!sid||strlen(sid)!=32||!runtime)return 3; FILE *f=fopen(argv[2],"w"); if(!f)return 4;
    fprintf(f,"%s\n%s\n",sid,runtime); fclose(f); sleep(1);
    s=pam_close_session(h,0); pam_end(h,s); return s==PAM_SUCCESS?0:5;
}
EOF
cc "$work/pam-app.c" -lpam -o "$work/pam-app"
cat >"$work/pam-fail-open.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdio.h>
#include <unistd.h>
static int conversation(int n, const struct pam_message **m, struct pam_response **r, void *d) { (void)n;(void)m;(void)d;*r=NULL;return PAM_CONV_ERR; }
int main(int argc, char **argv) {
    if (argc != 4) return 64; struct pam_conv conv={conversation,NULL}; pam_handle_t *h=NULL;
    int s=pam_start_confdir(argv[1],"root",&conv,argv[3],&h); if(s!=PAM_SUCCESS)return 1;
    s=pam_open_session(h,0); if(s!=PAM_SUCCESS){pam_end(h,s);return 2;}
    if(pam_getenv(h,"XDG_SESSION_ID")||pam_getenv(h,"XDG_RUNTIME_DIR"))return 3;
    FILE *f=fopen(argv[2],"w"); if(!f)return 4; fputs("open survived\n",f); fclose(f); sleep(1);
    s=pam_close_session(h,0); pam_end(h,s); return s==PAM_SUCCESS?0:5;
}
EOF
cc "$work/pam-fail-open.c" -lpam -o "$work/pam-fail-open"
mkdir "$work/pam.d"
printf 'session required %s timeout=5s config=%s\n' "$repo/target/debug/libpam_sessiond.so" "$work/sessiond.conf" >"$work/pam.d/sessiond-e2e"
printf 'session required %s fail_open timeout=5s config=%s\n' "$repo/target/debug/libpam_sessiond.so" "$work/fail-open.conf" >"$work/pam.d/sessiond-fail-open"
cat >"$work/sessiond.conf" <<EOF
cgroup_root = "/sys/fs/cgroup/$cgroup"
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
launcher = "$repo/target/debug/sessiond-user-launcher"
pam_service = "$pam_service"
ready_timeout = "5s"
[user_service_manager.shutdown]
mode = "leader"
leader_timeout = "1s"
scope_timeout = "1s"
EOF
sed 's#^launcher = .*#launcher = "/definitely/missing/sessiond-launcher"#' "$work/sessiond.conf" >"$work/fail-open.conf"
sudo chown -R root:root "$work"
sudo chmod 1777 "$work"
printf 'session required pam_permit.so\n' | sudo tee "/etc/pam.d/$pam_service" >/dev/null
sudo mkdir "/sys/fs/cgroup/$cgroup"
bus_pid=$(sudo dbus-daemon --config-file="$work/bus.conf" --fork --print-pid)
address="unix:path=$work/bus"
daemon= hold1= hold2= pam_process=
cleanup() {
    status=$?; trap - EXIT; set +e
    [ -n "$hold1" ] && sudo kill -KILL "$hold1" 2>/dev/null
    [ -n "$hold2" ] && sudo kill -KILL "$hold2" 2>/dev/null
    [ -n "$pam_process" ] && sudo kill -KILL "$pam_process" 2>/dev/null
    [ -n "$daemon" ] && sudo kill "$daemon" 2>/dev/null
    sudo kill "$bus_pid" 2>/dev/null
    sudo rm -f "/etc/pam.d/$pam_service"
    sudo sh -c 'echo 1 > "$1/cgroup.kill"' sh "/sys/fs/cgroup/$cgroup" 2>/dev/null
    sudo find "/sys/fs/cgroup/$cgroup" -depth -type d -exec rmdir {} \; 2>/dev/null
    [ "$status" -eq 0 ] || sudo sh -c 'for f in "$1"/*.log; do [ -f "$f" ] && { echo "--- $f"; tail -100 "$f"; }; done' sh "$work" >&2
    sudo rm -rf "$work"; exit "$status"
}
trap cleanup EXIT
wait_name() { for _ in $(seq 1 100); do busctl --address="$address" list --acquired 2>/dev/null | grep -q "$1" && return; sleep .05; done; return 1; }
wait_name_gone() { for _ in $(seq 1 100); do busctl --address="$address" list --acquired 2>/dev/null | grep -q "$1" || return 0; sleep .05; done; return 1; }
wait_file() { for _ in $(seq 1 100); do sudo test -f "$1" && return; sleep .05; done; return 1; }
start_daemon() {
    sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/sessiond" --bus system --config "$work/sessiond.conf" >>"$work/sessiond.log" 2>&1 & daemon=$!
    wait_name org.decoupling.sessiond1
}
stop_daemon() {
    sudo kill "$daemon"; wait "$daemon" || true; daemon=
    wait_name_gone org.decoupling.sessiond1
}
start_daemon
[ "$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)" = "a(su) 0" ]

sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/examples/hold-session" 0 "$work/one" "$work/sessiond.conf" >"$work/one.log" 2>&1 & hold1=$!
wait_file "$work/one"; sid1=$(sudo head -n1 "$work/one")
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/examples/hold-session" 0 "$work/two" "$work/sessiond.conf" >"$work/two.log" 2>&1 & hold2=$!
wait_file "$work/two"; sid2=$(sudo head -n1 "$work/two")
result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
echo "$result" | grep -q '^a(su) 2 '
if busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager CloseSession s "$sid1" >"$work/nonroot.log" 2>&1; then exit 1; fi
grep -q root-only "$work/nonroot.log"
# Kill one leader while sessiond is down. Restart discovery must remain
# read-only: the stale initial target stays until an explicit close, while the
# other live leader is armed for subsequent exit observation.
stop_daemon
leader1=$(sudo head -n1 "/sys/fs/cgroup/$cgroup/sessiond/user/0/session/$sid1/cgroup.procs")
sudo kill -KILL "$leader1"; wait "$hold1" || true; hold1=
start_daemon
sleep 1
result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
echo "$result" | grep -q '^a(su) 2 '
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager CloseSessionAndWait s "$sid1" >/dev/null
result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
echo "$result" | grep -q '^a(su) 1 '
echo "$result" | grep -q "$sid2"
leader2=$(sudo head -n1 "/sys/fs/cgroup/$cgroup/sessiond/user/0/session/$sid2/cgroup.procs")
sudo kill -INT "$leader2"
for _ in $(seq 1 200); do sudo test ! -e "$work/user/0" && break; sleep .05; done
sudo test ! -e "$work/user/0"
hold1= hold2=

sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$work/pam-app" sessiond-e2e "$work/pam-result" "$work/pam.d" >"$work/pam.log" 2>&1 & pam_process=$!
wait_file "$work/pam-result"; wait "$pam_process" || true; pam_process=
for _ in $(seq 1 200); do sudo test ! -e "$work/user/0" && break; sleep .05; done
sudo test ! -e "$work/user/0"

# A manager-launch failure under optional PAM leaves the contained host alive,
# publishes no session environment, and remains closable through containment.
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$work/pam-fail-open" sessiond-fail-open "$work/fail-open-result" "$work/pam.d" >"$work/fail-open.log" 2>&1 & pam_process=$!
wait_file "$work/fail-open-result"
result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)
echo "$result" | grep -q '^a(su) 1 '
wait "$pam_process"; pam_process=
for _ in $(seq 1 200); do result=$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions); [ "$result" = "a(su) 0" ] && break; sleep .05; done
[ "$result" = "a(su) 0" ]
sudo test ! -e "$work/user/0"

sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/examples/hold-session" 0 "$work/admin" "$work/sessiond.conf" >"$work/admin.log" 2>&1 & hold1=$!
wait_file "$work/admin"; sid=$(sudo head -n1 "$work/admin")
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager CloseSessionAndWait s "$sid" >/dev/null
wait "$hold1" || true; hold1=
[ "$(busctl --address="$address" call org.decoupling.sessiond1 /org/decoupling/sessiond1 org.decoupling.sessiond1.Manager ListSessions)" = "a(su) 0" ]
echo "sessiond root end-to-end tests passed"
