#!/usr/bin/env bash
set -euo pipefail
BIN=${BIN:-./sysperm.exe}
U=sysperm_ci_user
G=sysperm_ci_group
G2=sysperm_ci_group2
ROOT=${TMPDIR:-/tmp}/sysperm-ci-$$
cleanup(){ sudo "$BIN" user "$U" --absent >/dev/null 2>&1 || true; sudo "$BIN" group "$G" --absent >/dev/null 2>&1 || true; sudo "$BIN" group "$G2" --absent >/dev/null 2>&1 || true; sudo rm -rf "$ROOT"; }
trap cleanup EXIT

AUTO1=$(sudo "$BIN" pwd)
AUTO2=$(sudo "$BIN" pwd)
test "$AUTO1" = "$AUTO2"
sudo "$BIN" user "$U" -g "$G,$G2"
for _ in 1 2 3 4 5; do
  id "$U" >/dev/null 2>&1 && break
  sleep 1
done
id "$U" >/dev/null
test "$(id -gn "$U")" = "$G"
test "$(dscl . -read "/Users/$U" UserShell | awk '{print $2}')" = /bin/zsh
dscl . -authonly "$U" "$AUTO1"
sudo "$BIN" user "$U" -pg "$G2" -p sysperm-ci-password-2
test "$(id -gn "$U")" = "$G2"
dscl . -authonly "$U" sysperm-ci-password-2
for _ in 1 2 3 4 5; do
  dseditgroup -o checkmember -m "$U" "$G" | grep -qi yes && break
  sleep 1
done
dseditgroup -o checkmember -m "$U" "$G" | grep -qi yes
out=$(sudo "$BIN" exec "$U" -- /bin/sh -c 'printf "%s:%s" "$(id -un)" "$1"' sh 'arg with spaces')
test "$out" = "$U:arg with spaces"
if sudo "$BIN" exec "$U" -- /bin/sh -c 'exit 23'; then exit 1; else test $? -eq 23; fi

mkdir -p "$ROOT/sub"
touch "$ROOT/sub/file"
sudo "$BIN" chown "$U:$G" "$ROOT"
test "$(stat -f '%Su:%Sg' "$ROOT")" = "$U:$G"
sudo "$BIN" perm "$ROOT" 'u=rwX' 'g=rX' 'o='
sudo "$BIN" perm "$ROOT" "user:$U+rx" --no-recursive
ls -led "$ROOT" | grep -q "$U"

sudo "$BIN" user "$U" --absent
! id "$U" >/dev/null 2>&1
sudo "$BIN" group "$G" --absent
sudo "$BIN" group "$G2" --absent
