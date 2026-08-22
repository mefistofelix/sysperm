#!/usr/bin/env bash
# Windows: run this script from WSL, e.g.:
#   wsl.exe --cd "%CD%" bash ./build.sh
# Linux/macOS: run directly:
#   bash ./build.sh
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BUILD="$ROOT/build"
TMP="$BUILD/tmp"
COSMOCC="$BUILD/cosmocc"
OUT="$ROOT/sysperm.exe"
COSMOCC_URL="https://cosmo.zip/pub/cosmocc/cosmocc.zip"
HOST_OS=$(uname -s 2>/dev/null || true)

fail() {
  printf 'build.sh: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing host command: $1"
}

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    fail "root access is required for the WSL APE workaround"
  fi
}

fetch() {
  url=$1
  out=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$out" "$url"
  else
    fail "need curl or wget"
  fi
}

case "$HOST_OS" in
  Linux|Darwin) ;;
  *) fail "unsupported build host: $HOST_OS (use WSL on Windows)" ;;
esac

IS_WSL=0
if [ "$HOST_OS" = Linux ]; then
  case "$(uname -r 2>/dev/null || true)" in
    *[Mm]icrosoft*|*WSL*) IS_WSL=1 ;;
  esac
fi

need unzip
need find
if [ "$IS_WSL" -eq 1 ]; then
  need install
  need cmp
fi

mkdir -p "$BUILD" "$TMP"

# WSL's Windows-executable interop can steal Cosmopolitan APE helper launches.
# Disable it for this WSL instance and install Cosmopolitan's native APE loader.
if [ "$IS_WSL" -eq 1 ]; then
  INTEROP=/proc/sys/fs/binfmt_misc/WSLInterop
  if [ -e "$INTEROP" ] && grep -q '^enabled' "$INTEROP" 2>/dev/null; then
    if [ -w "$INTEROP" ]; then
      printf '%s\n' -1 >"$INTEROP"
    else
      printf '%s\n' -1 | as_root tee "$INTEROP" >/dev/null
    fi
  fi
fi

if [ ! -x "$COSMOCC/bin/cosmocc" ]; then
  archive="$TMP/cosmocc.zip"
  unpack="$TMP/cosmocc.unpack"
  rm -rf "$unpack"
  mkdir -p "$unpack"
  printf 'Downloading cosmocc...\n'
  fetch "$COSMOCC_URL" "$archive"
  unzip -q "$archive" -d "$unpack"

  toolroot="$unpack"
  if [ ! -f "$toolroot/bin/cosmocc" ]; then
    candidate=$(find "$unpack" -path '*/bin/cosmocc' -print -quit)
    [ -n "$candidate" ] || fail "unexpected cosmocc.zip layout"
    toolroot=$(cd -- "$(dirname -- "$candidate")/.." && pwd)
  fi

  rm -rf "$COSMOCC"
  mv "$toolroot" "$COSMOCC"
  chmod +x "$COSMOCC/bin/cosmocc"
  [ -x "$COSMOCC/bin/cosmocc" ] || fail "cosmocc driver is not executable"
fi

# GCC/binutils helpers spawned by cosmocc locate sibling tools such as cc1/ld via PATH.
export PATH="$COSMOCC/bin:$PATH"

if [ "$IS_WSL" -eq 1 ]; then
  case "$(uname -m)" in
    x86_64|amd64) APE="$COSMOCC/bin/ape-x86_64.elf" ;;
    aarch64|arm64) APE="$COSMOCC/bin/ape-aarch64.elf" ;;
    *) fail "unsupported WSL architecture: $(uname -m)" ;;
  esac
  [ -f "$APE" ] || fail "cosmocc archive is missing $(basename "$APE")"
  if [ ! -x /usr/bin/ape ] || ! cmp -s "$APE" /usr/bin/ape; then
    as_root install -m 0755 "$APE" /usr/bin/ape
  fi
fi

printf 'Building fat x86_64+aarch64 APE...\n'
"$COSMOCC/bin/cosmocc" -mcosmo -O2 -o "$OUT" "$ROOT/src/main.c"
chmod 0755 "$OUT"
printf 'Built %s\n' "$OUT"
