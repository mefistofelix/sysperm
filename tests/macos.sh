#!/usr/bin/env bash
set -euo pipefail
BIN=${BIN:-./sysperm.exe}
U=sysperm_ci_user
G=sysperm_ci_group
ROOT=${TMPDIR:-/tmp}/sysperm-ci-$$
cleanup(){ sudo "$BIN" user "$U" --absent >/dev/null 2>&1 || true; sudo "$BIN" group "$G" --absent >/dev/null 2>&1 || true; sudo rm -rf "$ROOT"; }
trap cleanup EXIT

sudo "$BIN" group "$G"
sudo "$BIN" user "$U" --group "$G" --shell /bin/sh
id "$U" >/dev/null
dseditgroup -o checkmember -m "$U" "$G" | grep -qi yes

mkdir -p "$ROOT/sub"
touch "$ROOT/sub/file"
sudo "$BIN" perm "$ROOT" 'u=rwX' 'g=rX' 'o='
sudo "$BIN" perm "$ROOT" "user:$U+rx" --no-recursive
ls -le "$ROOT" | grep -q "$U"

sudo "$BIN" user "$U" --absent
! id "$U" >/dev/null 2>&1
sudo "$BIN" group "$G" --absent
