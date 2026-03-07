#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop  edr-client.service 2>/dev/null || true
    systemctl disable edr-client.service 2>/dev/null || true
fi
