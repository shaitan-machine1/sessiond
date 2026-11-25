#!/bin/bash
# Build unprivileged; only the already-built real-kernel probe runs as root.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $EUID != 0 ]] || { echo 'build as an ordinary user' >&2; exit 77; }
for command in cargo sudo python3 stat; do command -v "$command" >/dev/null || exit 77; done
sudo -n true || exit 77
artifacts=$(mktemp /tmp/lib-scoped-cgroup-build.XXXXXX)
trap 'rm -f "$artifacts"' EXIT
cargo test --manifest-path "$repo/Cargo.toml" --locked -p lib-scoped --test cgroup \
    --no-run --message-format=json > "$artifacts"
probe=$(python3 - "$artifacts" <<'PY'
import json
import sys
from pathlib import Path
artifacts = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
probes = [item["executable"] for item in artifacts
          if item.get("reason") == "compiler-artifact" and item.get("executable")
          and item["target"]["name"] == "cgroup" and item["profile"]["test"]]
assert len(probes) == 1, probes
print(probes[0])
PY
)
sudo -n python3 -B "$repo/tests/cgroup_fixture_test.py"
sudo -n python3 -B "$repo/tests/cgroup_fixture.py" "$probe" --ignored --nocapture
