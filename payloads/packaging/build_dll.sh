#!/usr/bin/env bash
# Build the benign bootstrap DLL for the phase-1 run.
# Output keeps the ".jpg" masquerade name (maps to T1036 compareForfor.jpg).
#
# Location-independent: the default source path is resolved relative to THIS
# script, so it works whether you run it from the repo root or from
# payloads/packaging/ (as long as payloads/dll/c0015_bootstrap_dll.c exists).
#
# Requires x86_64-w64-mingw32-gcc  (Kali: sudo apt install gcc-mingw-w64-x86-64)
# Usage (from payloads/packaging or repo root):  ./build_dll.sh [source.c] [output.jpg]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$SCRIPT_DIR/../dll/c0015_bootstrap_dll.c}"
OUT="${2:-c0015-comparefor.jpg}"

command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || {
    echo "error: x86_64-w64-mingw32-gcc not found (install: sudo apt install gcc-mingw-w64-x86-64)" >&2
    exit 1
}

if [ ! -f "$SRC" ]; then
    echo "error: DLL source not found: $SRC" >&2
    echo "Make sure payloads/dll/c0015_bootstrap_dll.c exists on this machine (copy the repo/missing file)." >&2
    echo "Or pass the path explicitly: $0 /path/to/c0015_bootstrap_dll.c" >&2
    exit 1
fi

echo "building: $SRC -> $OUT"
x86_64-w64-mingw32-gcc -shared -O2 -o "$OUT" "$SRC" -lshlwapi
echo "built: $OUT"
sha256sum "$OUT"

# Stage into build/out relative to the current working directory, so the
# caller can pass the absolute path of build/out to launch_servers.ps1.
mkdir -p build/out
cp "$OUT" build/out/
echo "staged to HTTP publish dir: $(pwd)/build/out ($OUT)"
echo "pass this publish dir to launch_servers.ps1: -PublishDir $(pwd)/build/out"