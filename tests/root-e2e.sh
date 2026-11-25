#!/bin/bash
# Fixed disposable test root, no installed PAM edits or privileged builds. The only
# /etc/pam.d mount is in a PRIVATE namespace destroyed with the test processes.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $EUID != 0 ]] || { echo 'build as an ordinary user' >&2; exit 77; }
for command in cargo cc sudo dbus-daemon busctl python3 unshare mount; do command -v "$command" >/dev/null || exit 77; done
sudo -n true || exit 77
sudo -n unshare --mount --propagation private true || { echo 'SKIP: private mount namespace unavailable' >&2; exit 77; }
"$repo/tests/cgroup.sh"
work=$(mktemp -d /tmp/sessiond-root-build.XXXXXX)
trap 'rm -rf "$work"' EXIT
cc -Wall -Wextra -Werror -DTEST_UID="$(id -u)" -DTEST_GID="$(id -g)" "$repo/tests/root-manager.c" -o "$work/manager"
cc -shared -fPIC -Wall -Wextra -Werror "$repo/tests/root-private-pam.c" -lpam -o "$work/private-pam.so"
SESSIOND_USER_SERVICE_MANAGER="$work/manager" cargo build --manifest-path "$repo/Cargo.toml" --workspace --locked
install -m755 "$repo/target/debug/liblib_sessiond.so" "$work/libsessiond.so.0"
ln -s libsessiond.so.0 "$work/libsessiond.so"
cc -Wall -Wextra -Werror -I"$repo/crates/lib-sessiond/include" "$repo/tests/root-e2e.c" -L"$work" -Wl,-rpath,"$work" -lsessiond -lpam -o "$work/host"
sudo -n unshare --mount --propagation private python3 -B "$repo/tests/root-e2e.py" "$repo" "$work" "$(id -u)"
