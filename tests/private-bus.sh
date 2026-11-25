#!/bin/bash
# Root-owned PRIVATE bus + ordinary-directory inventory. Never touch real cgroups
# or installed PAM. Build only as the normal user; root phase uses built artifacts.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [[ ${1-} != --root ]]; then
    for command in cargo cc sudo dbus-daemon busctl runuser; do command -v "$command" >/dev/null || exit 77; done
    [[ $EUID != 0 ]] || { echo 'build as a normal user' >&2; exit 77; }
    sudo -n true || exit 77
    cargo build --manifest-path "$repo/Cargo.toml" --workspace --locked
    stage=$(mktemp -d /tmp/sessiond-private-stage.XXXXXX)
    trap 'rm -rf "$stage"' EXIT
    install -Dm755 "$repo/target/debug/liblib_sessiond.so" "$stage/usr/lib/libsessiond.so.0"
    ln -s libsessiond.so.0 "$stage/usr/lib/libsessiond.so"
    install -Dm644 "$repo/crates/lib-sessiond/include/sessiond.h" "$stage/usr/include/sessiond.h"
    "$repo/tests/sdk-smoke.sh" "$stage"
    cc -std=c11 -Wall -Wextra -Werror -I"$stage/usr/include" "$repo/tests/sdk-smoke.c" -L"$stage/usr/lib" -Wl,-rpath,"$stage/usr/lib" -lsessiond -o "$stage/smoke"
    sudo -n "$0" --root "$repo/target/debug" "$stage"
    exit
fi
[[ $EUID == 0 && $# == 3 && $2 == /* && $3 == /* ]] || exit 64
bins=$2 stage=$3
work=$(mktemp -d /tmp/sessiond-private-bus.XXXXXX)
bus= daemon=
cleanup() {
    local status=$?; trap - EXIT; set +e
    [[ -z $daemon ]] || { kill -TERM "$daemon" 2>/dev/null; wait "$daemon"; }
    [[ -z $bus ]] || { kill -TERM "$bus" 2>/dev/null; wait "$bus"; }
    if [[ $status != 0 ]]; then for log in "$work"/*.log; do [[ ! -f $log ]] || tail -100 "$log" >&2; done; fi
    rm -rf "$work"; exit "$status"
}
trap cleanup EXIT
chmod 711 "$work"
mkdir "$work/cgroups"
cat >"$work/bus.conf" <<EOF
<busconfig><type>system</type><listen>unix:path=$work/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow send_type="method_call"/><allow send_type="method_return"/><allow send_type="error"/><allow send_type="signal"/><allow receive_type="method_call"/><allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/></policy><include>$repo/dist/dbus/org.SGLogin.Sessiond1.conf</include></busconfig>
EOF
cat >"$work/sessiond.conf" <<EOF
cgroup_root = "$work/cgroups"
runtime_parent = "$work/user"
state_dir = "$work/state"
EOF
dbus-daemon --nofork --config-file="$work/bus.conf" >"$work/bus.log" 2>&1 & bus=$!
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$work/bus"
for _ in $(seq 1 100); do [[ ! -S $work/bus ]] || break; sleep .02; done
"$bins/sessiond" --config "$work/sessiond.conf" >"$work/daemon.log" 2>&1 & daemon=$!
for _ in $(seq 1 100); do busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" list --acquired 2>/dev/null | grep -q org.SGLogin.Sessiond1 && break; sleep .02; done
"$stage/smoke" "$DBUS_SYSTEM_BUS_ADDRESS"
# Stable lock cannot be replaced, and a second daemon does not acquire a bus name.
if "$bins/sessiond" --config "$work/sessiond.conf" >"$work/duplicate.log" 2>&1; then exit 1; fi
call=(busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call org.SGLogin.Sessiond1 /org/SGLogin/Sessiond1 org.SGLogin.Sessiond1.Manager)
if runuser -u nobody -- "${call[@]}" EnsureSessionReady >"$work/nonroot.log" 2>&1; then exit 1; fi
grep -q root-only "$work/nonroot.log"
# All nine method names are advertised; obsolete aliases are not dispatchable.
xml=$(busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call org.SGLogin.Sessiond1 /org/SGLogin/Sessiond1 org.freedesktop.DBus.Introspectable Introspect)
[[ $xml == *EnsureSessionReady* && $xml != *CloseSessionAndWait* && $xml != *OpenSession* ]]
if "${call[@]}" CloseSessionAndWait s 0123456789abcdef0123456789abcdef >"$work/alias.log" 2>&1; then exit 1; fi
# Discover a recent PARTIAL session on restart, without inferring readiness,
# requiring a master or emitting SessionNew. Only fixture directories are used.
kill -TERM "$daemon"; wait "$daemon"; daemon=
sid=0123456789abcdef0123456789abcdef
mkdir -p "$work/cgroups/sessiond/user/1000/session/$sid"
"$bins/sessiond" --config "$work/sessiond.conf" >>"$work/daemon.log" 2>&1 & daemon=$!
for _ in $(seq 1 100); do busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" list --acquired 2>/dev/null | grep -q org.SGLogin.Sessiond1 && break; sleep .02; done
"$stage/smoke" "$DBUS_SYSTEM_BUS_ADDRESS" "$sid"
[[ ! -e $work/user && -d $work/cgroups/sessiond/user/1000/session/$sid ]]
echo 'private-bus daemon/C SDK tests passed (no real-cgroup acceptance)'
