#!/bin/bash
# Exercise the production launcher gate, readiness fd, PAM lifetime and signals.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for command in cargo cc sudo; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 77; }
done
sudo -n true || { echo "passwordless sudo is required" >&2; exit 77; }
cargo build --manifest-path "$repo/Cargo.toml" -p sessiond-user-launcher
work=$(mktemp -d /tmp/sessiond-launcher-e2e.XXXXXX)
pam_service="sessiond-user-e2e-$$"
cleanup() {
    status=$?
    trap - EXIT
    sudo rm -f "/etc/pam.d/$pam_service"
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
printf 'session required pam_permit.so\n' | sudo tee "/etc/pam.d/$pam_service" >/dev/null
cat >"$work/entrypoint" <<'EOF'
#!/bin/sh
set -eu
eval "printf '\001' >&$SESSIOND_READY_FD"
eval "exec $SESSIOND_READY_FD>&-"
trap 'exit 0' TERM INT HUP
while :; do sleep 1; done
EOF
chmod +x "$work/entrypoint"
cat >"$work/harness.c" <<'EOF'
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
static void close_unless_fixed(int fd) { if (fd != 3 && fd != 4) close(fd); }
int main(int argc, char **argv) {
    if (argc != 4) return 64;
    int gate[2], ready[2];
    if (pipe(gate) || pipe(ready)) return 1;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        if (dup2(gate[0], 3) < 0 || dup2(ready[1], 4) < 0) _exit(126);
        close_unless_fixed(gate[0]); close_unless_fixed(gate[1]);
        close_unless_fixed(ready[0]); close_unless_fixed(ready[1]);
        execl(argv[1], argv[1], "--uid", "0", "--runtime-dir", "/tmp",
              "--entrypoint", argv[2], "--pam-service", argv[3], NULL);
        _exit(127);
    }
    close(gate[0]); close(ready[1]);
    char byte = 1;
    if (write(gate[1], &byte, 1) != 1) return 3;
    close(gate[1]);
    if (read(ready[0], &byte, 1) != 1 || byte != 1) return 4;
    if (kill(child, SIGTERM) < 0) return 5;
    int status;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 6;
    return 0;
}
EOF
cc "$work/harness.c" -o "$work/harness"
sudo "$work/harness" "$repo/target/debug/sessiond-user-launcher" "$work/entrypoint" "$pam_service"
echo "sessiond-user-launcher end-to-end test passed"
