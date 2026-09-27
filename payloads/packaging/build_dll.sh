#!/usr/bin/env bash
# Build the benign bootstrap DLL for the phase-1 run.
# Output keeps the ".jpg" masquerade name (maps to T1036 compareForfor.jpg).
#
# Requires x86_64-w64-mingw32-gcc  (Kali: sudo apt install gcc-mingw-w64-x86-64)
# Usage (from repo root):  ./payloads/packaging/build_dll.sh [source.c] [output.jpg]
set -euo pipefail

SRC="${1:-payloads/dll/c0015_bootstrap_dll.c}"
OUT="${2:-c0015-comparefor.jpg}"

command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || {
    echo "error: x86_64-w64-mingw32-gcc not found (install: sudo apt install gcc-mingw-w64-x86-64)" >&2
    exit 1
}

x86_64-w64-mingw32-gcc -shared -O2 -o "$OUT" "$SRC" -lshlwapi
echo "built: $OUT"
sha256sum "$OUT"
# Put the DLL into a publish dir for the phase-1 HTTP server to serve:
mkdir -p build/out
cp "$OUT" build/out/
echo "staged to HTTP publish dir: build/out/$OUT"