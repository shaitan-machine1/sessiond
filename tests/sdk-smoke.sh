#!/bin/bash
# No installation: PREFIX must contain usr/{include,lib} from a staged package.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $# == 1 && $1 == /* ]] || { echo 'usage: sdk-smoke.sh /absolute/staged-prefix' >&2; exit 64; }
for command in cc readelf nm; do command -v "$command" >/dev/null || exit 77; done
prefix=$1
library="$prefix/usr/lib/libsessiond.so.0"
[[ -f $library && -f $prefix/usr/include/sessiond.h && -L $prefix/usr/lib/libsessiond.so ]] || exit 1
readelf -d "$library" | grep -q 'Library soname: \[libsessiond.so.0\]'
if readelf -d "$library" | grep NEEDED | grep -Eiq 'pam|tokio|zbus'; then echo 'SDK acquired a forbidden dependency' >&2; exit 1; fi
nm -D --defined-only "$library" | grep -q ' sessiond_ensure_session_ready$'
work=$(mktemp -d /tmp/sessiond-sdk-smoke.XXXXXX)
trap 'rm -rf "$work"' EXIT
cc -std=c11 -Wall -Wextra -Werror -I"$prefix/usr/include" "$repo/tests/sdk-smoke.c" \
    -L"$prefix/usr/lib" -Wl,-rpath,"$prefix/usr/lib" -lsessiond -o "$work/smoke"
"$work/smoke"
