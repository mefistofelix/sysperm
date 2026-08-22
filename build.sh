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
COSMO_SRC="$BUILD/cosmopolitan-src"
COSMO_APP="$COSMO_SRC/examples/sysperm.c"
X86_DBG="$COSMO_SRC/o//examples/sysperm.dbg"
ARM_DBG="$COSMO_SRC/o/aarch64/examples/sysperm.dbg"
OUT="$ROOT/sysperm.exe"

COSMOCC_URL="https://cosmo.zip/pub/cosmos/zip/cosmocc.zip"
COSMO_SOURCE_URL="https://github.com/jart/cosmopolitan/archive/refs/heads/master.tar.gz"
HOST_OS=$(uname -s 2>/dev/null || true)
JOBS=${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || printf '4')}

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
  Linux) MAKE_CMD=${MAKE:-make} ;;
  Darwin) MAKE_CMD=${MAKE:-gmake} ;;
  *) fail "unsupported build host: $HOST_OS (use WSL on Windows)" ;;
esac

IS_WSL=0
if [ "$HOST_OS" = Linux ]; then
  case "$(uname -r 2>/dev/null || true)" in
    *[Mm]icrosoft*|*WSL*) IS_WSL=1 ;;
  esac
fi

need tar
need unzip
need "$MAKE_CMD"
need find
if [ "$IS_WSL" -eq 1 ]; then
  need install
  need cmp
fi

mkdir -p "$BUILD" "$TMP"

# WSL's Windows-executable interop can steal Cosmopolitan APE helper launches.
# These workarounds are intentionally no-ops on normal Linux and macOS.
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
    candidate=$(find "$unpack" -type f -path '*/bin/cosmocc' -print -quit)
    [ -n "$candidate" ] || fail "unexpected cosmocc.zip layout"
    toolroot=$(cd -- "$(dirname -- "$candidate")/.." && pwd)
  fi

  rm -rf "$COSMOCC"
  mv "$toolroot" "$COSMOCC"
  chmod +x "$COSMOCC/bin/cosmocc"
  [ -x "$COSMOCC/bin/cosmocc" ] || fail "cosmocc driver is not executable"
fi

# WSL also needs a native APE loader after WSLInterop is disabled.
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

# Keep downloaded Cosmopolitan source isolated under build/.
if [ ! -f "$COSMO_SRC/Makefile" ]; then
  archive="$TMP/cosmopolitan-master.tar.gz"
  unpack="$TMP/cosmopolitan.unpack"
  rm -rf "$unpack"
  mkdir -p "$unpack"
  printf 'Downloading Cosmopolitan source...\n'
  fetch "$COSMO_SOURCE_URL" "$archive"
  tar -xzf "$archive" -C "$unpack"
  [ -f "$unpack/cosmopolitan-master/Makefile" ] || fail "unexpected Cosmopolitan source archive layout"
  rm -rf "$COSMO_SRC"
  mv "$unpack/cosmopolitan-master" "$COSMO_SRC"
  rm -rf "$unpack"
fi

# Current Cosmopolitan source expects a pinned bootstrap compiler directory.
mkdir -p "$COSMO_SRC/.cosmocc"
if [ ! -e "$COSMO_SRC/.cosmocc/3.9.2" ] && [ ! -L "$COSMO_SRC/.cosmocc/3.9.2" ]; then
  ln -s "$COSMOCC" "$COSMO_SRC/.cosmocc/3.9.2"
fi

cp "$ROOT/src/main.c" "$COSMO_APP"

printf 'Building sysperm slice (x86_64)...\n'
(
  cd "$COSMO_SRC"
  "$MAKE_CMD" SHELL=/bin/bash -j"$JOBS" o//examples/sysperm.dbg
)

printf 'Building sysperm slice (arm64)...\n'
(
  cd "$COSMO_SRC"
  "$MAKE_CMD" SHELL=/bin/bash -j"$JOBS" MODE=aarch64 o/aarch64/examples/sysperm.dbg
)

[ -f "$X86_DBG" ] || fail "missing x86_64 linked slice"
[ -f "$ARM_DBG" ] || fail "missing arm64 linked slice"

printf 'Fat-linking sysperm.exe...\n'
"$COSMOCC/bin/apelink" \
  -V -1 \
  -l "$COSMOCC/bin/ape-x86_64.elf" \
  -l "$COSMOCC/bin/ape-aarch64.elf" \
  -M "$COSMOCC/bin/ape-m1.c" \
  -o "$OUT" \
  "$X86_DBG" \
  "$ARM_DBG"
"$COSMOCC/bin/pecheck" "$OUT"

chmod 0755 "$OUT"
printf 'Built %s\n' "$OUT"
