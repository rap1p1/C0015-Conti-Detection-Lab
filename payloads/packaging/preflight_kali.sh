#!/bin/bash
# ============================================================
# preflight_kali.sh — entry-chain P0 build gate, runs INSIDE Kali
# via vmrun as root. Builds the DLL payloads + prints hashes.
# ============================================================
set +e
echo "== kali preflight $(date -u) =="
id
echo "--- toolchain ---"
for t in x86_64-w64-mingw32-gcc john hashcat git; do
  if command -v $t >/dev/null 2>&1; then echo "$t: $(command -v $t)"; else echo "$t: MISSING"; fi
done

REPO=""
for d in /root/C0015-Conti-Detection-Lab "$HOME/C0015-Conti-Detection-Lab"; do
  if [ -d "$d/.git" ]; then REPO="$d"; break; fi
done
echo "repo: ${REPO:-NONE}"

if [ -n "$REPO" ]; then
  cd "$REPO" || exit 1
  git fetch --quiet 2>/dev/null; git pull --rebase --quiet 2>/dev/null
  echo "--- build comparefor.jpg (bootstrap DLL, S1) ---"
  ./payloads/packaging/build_dll.sh 2>&1 || echo "build_dll.sh FAILED"
  echo "--- build 143 surrogate (S8) ---"
  x86_64-w64-mingw32-gcc -shared -o /tmp/c0015_143_surrogate.dll payloads/dll/c0015_143_surrogate.c -luser32 -lshlwapi 2>&1 || echo "143 build FAILED"
  mkdir -p /root/build/out
  cp -f build/out/c0015-comparefor.jpg /root/build/out/ 2>/dev/null
  echo "--- hashes ---"
  sha256sum /tmp/c0015_143_surrogate.dll build/out/c0015-comparefor.jpg 2>/dev/null
  echo "--- relics ---"
  ls -la /tmp/c0015_143_surrogate.dll build/out/c0015-comparefor.jpg 2>/dev/null
else
  echo "NO REPO ON KALI - need: git clone repo (payloads build chain) or scp the source from the C2 host"
fi
echo "== kali preflight end =="
