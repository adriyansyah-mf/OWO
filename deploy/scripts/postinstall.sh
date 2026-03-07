#!/bin/sh
set -e

# Create empty env file if not present (user sets NATS_URL here)
if [ ! -f /etc/edr/env ]; then
    cat > /etc/edr/env <<'EOF'
# OWO EDR Agent environment overrides.
# Uncomment and set NATS_URL to point to your EDR backend.
# NATS_URL=nats://your-edr-server:4222
EOF
fi

# Set default ebpf_path in config if it's the example file
if grep -q 'ebpf_path:' /etc/edr/edr.yaml 2>/dev/null; then
    sed -i 's|# ebpf_path: /usr/lib/edr/bpf|ebpf_path: /usr/lib/edr/bpf|' /etc/edr/edr.yaml
fi

# Reload systemd and enable service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable edr-client.service
    echo "OWO EDR agent installed. Edit /etc/edr/edr.yaml and /etc/edr/env, then:"
    echo "  systemctl start edr-client"
fi
