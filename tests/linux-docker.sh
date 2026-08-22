#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

run_distro() {
  name=$1
  image=$2
  install=$3
  printf '\n=== Linux container: %s (%s) ===\n' "$name" "$image"
  docker run --rm --privileged \
    -v "$ROOT:/work" -w /work \
    "$image" /bin/sh -lc "$install && chmod +x sysperm.exe tests/linux.sh && BIN=./sysperm.exe bash ./tests/linux.sh"
}

run_distro ubuntu-22.04 ubuntu:22.04 \
  'apt-get update && apt-get install -y acl passwd sudo libc-bin bash'
run_distro ubuntu-24.04 ubuntu:24.04 \
  'apt-get update && apt-get install -y acl passwd sudo libc-bin bash'
run_distro debian-12 debian:12 \
  'apt-get update && apt-get install -y acl passwd sudo libc-bin bash'
run_distro alpine-3.24 alpine:3.24 \
  'apk add --no-cache acl shadow sudo bash musl-utils'
run_distro almalinux-9 almalinux:9 \
  'dnf install -y acl shadow-utils passwd sudo glibc-common bash'
run_distro opensuse-tumbleweed opensuse/tumbleweed:latest \
  'ok=; for i in 1 2 3; do zypper clean -a; if zypper --non-interactive refresh && zypper --non-interactive install acl shadow sudo glibc bash; then ok=1; break; fi; sleep 5; done; test "$ok" = 1'
