#!/bin/bash
# Test EDR: generate exec + file events untuk monitoring.
# Cara pakai:
#   Terminal 1: sudo ./bin/edr-client -config config.yaml
#   Terminal 2: ./scripts/test-benign-malicious.sh
# Cek Terminal 1 dan /var/log/edr/alerts.jsonl untuk event.

set -e
echo "=== 1. Exec biasa ==="
ls -la /tmp
echo "hello"
cat /etc/hostname
whoami
/bin/true

echo ""
echo "=== 2. Exec dari /tmp, curl, LD_PRELOAD (untuk cek visibility) ==="
cp -f /bin/echo /tmp/edr_test_echo 2>/dev/null || true
/tmp/edr_test_echo "exec from tmp"
curl -s -o /tmp/edr_test_dl https://example.com 2>/dev/null || true
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libc.so.6 ls /tmp 2>/dev/null || true

echo ""
echo "=== Selesai. Cek Terminal 1 dan alerts.jsonl ==="
