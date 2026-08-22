#!/usr/bin/env bash
set -euo pipefail
BIN=${BIN:-./sysperm.exe}
run_sysperm() {
  if [ -n "${APE_LOADER:-}" ]; then
    "$APE_LOADER" "$BIN" "$@"
  else
    "$BIN" "$@"
  fi
}
sudo_sysperm() {
  if [ "$(id -u)" -eq 0 ]; then
    run_sysperm "$@"
  elif [ -n "${APE_LOADER:-}" ]; then
    sudo "$APE_LOADER" "$BIN" "$@"
  else
    sudo "$BIN" "$@"
  fi
}
for cmd in useradd usermod userdel groupadd groupdel getent; do
  command -v "$cmd" >/dev/null || { echo "missing required command: $cmd" >&2; exit 1; }
done
U=sysperm_ci_user
G=sysperm_ci_group
ROOT=${TMPDIR:-/tmp}/sysperm-ci-$$
cleanup(){ sudo_sysperm user "$U" --absent >/dev/null 2>&1 || true; sudo_sysperm group "$G" --absent >/dev/null 2>&1 || true; if [ "$(id -u)" -eq 0 ]; then rm -rf "$ROOT"; else sudo rm -rf "$ROOT"; fi; }
trap cleanup EXIT

sudo_sysperm group "$G"
sudo_sysperm user "$U" --group "$G" --shell /bin/sh
getent passwd "$U" >/dev/null
getent group "$G" | grep -q "$U"

mkdir -p "$ROOT/sub"
touch "$ROOT/sub/file"
sudo_sysperm perm "$ROOT" 'u=rwX' 'g=rX' 'o='
stat -c '%A' "$ROOT" | grep -q '^drw[rwx-]*'
# Default Linux behavior: setgid on directories.
test $(( $(stat -c '%a' "$ROOT") / 1000 % 10 & 2 )) -ne 0

if command -v setfacl >/dev/null 2>&1; then
  sudo_sysperm perm "$ROOT" "user:$U=rx"
  getfacl -cp "$ROOT" | grep -Eq "^user:$U:r-x$"
  getfacl -cp "$ROOT" | grep -Eq "^default:user:$U:r-x$"
fi

sudo_sysperm user "$U" --absent
! getent passwd "$U" >/dev/null 2>&1
sudo_sysperm group "$G" --absent
! getent group "$G" >/dev/null 2>&1
