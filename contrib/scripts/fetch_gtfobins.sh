#!/bin/sh
# Fetch GTFOBins API JSON once and save to contrib/gtfobins.json.
# Run manually or via: make fetch-gtfobins
# OWO uses this file at runtime (no real-time API calls).

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${SCRIPT_DIR}/../gtfobins.json"
URL="https://gtfobins.org/api.json"

echo "Fetching $URL -> $OUT"
curl -sSfL -o "$OUT" "$URL"
echo "Done. $(wc -c < "$OUT") bytes written to $OUT"
