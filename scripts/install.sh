#!/bin/sh
# OWO EDR Agent — one-line installer
#
# Usage (minimal):
#   curl -fsSL https://github.com/adriyansyah-mf/OWO/releases/latest/download/install.sh | sudo sh
#
# Usage (with config):
#   curl -fsSL https://github.com/adriyansyah-mf/OWO/releases/latest/download/install.sh | \
#     sudo NATS_URL=nats://10.0.0.1:4222 \
#          TENANT_ID=acme \
#          EDR_GROUP=servers \
#          sh
#
# Environment variables:
#   NATS_URL      NATS server URL (default: nats://127.0.0.1:4222)
#   TENANT_ID     Tenant/org identifier (default: default)
#   EDR_GROUP     Agent group label   (default: "")
#   EDR_VERSION   Package version to install (default: latest)
#   RELEASE_URL   Base URL for package downloads
#                 (default: https://github.com/your-org/owo-edr/releases/download)
#   SKIP_START    Set to "1" to install but not start the service

set -e

# ── Defaults ────────────────────────────────────────────────────────────────
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
TENANT_ID="${TENANT_ID:-default}"
EDR_GROUP="${EDR_GROUP:-}"
EDR_VERSION="${EDR_VERSION:-latest}"
RELEASE_URL="${RELEASE_URL:-https://github.com/adriyansyah-mf/OWO/releases/download}"
SKIP_START="${SKIP_START:-0}"

# ── Helpers ──────────────────────────────────────────────────────────────────
info()  { printf '\033[1;34m[EDR]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[OK ]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31m[ERR]\033[0m %s\n' "$*" >&2; exit 1; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die "This installer must be run as root (use sudo)."
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_LIKE="${ID_LIKE:-}"
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
    else
        die "Unsupported OS. Install manually from: $RELEASE_URL"
    fi
}

detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  PKG_ARCH="amd64";;
        aarch64) PKG_ARCH="arm64";;
        *)        die "Unsupported architecture: $ARCH";;
    esac
}

resolve_version() {
    if [ "$EDR_VERSION" = "latest" ]; then
        # Try to resolve latest from GitHub API
        if command -v curl >/dev/null 2>&1; then
            EDR_VERSION=$(curl -fsSL "https://api.github.com/repos/your-org/owo-edr/releases/latest" \
                2>/dev/null | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true)
        fi
        # Fallback to hardcoded version
        EDR_VERSION="${EDR_VERSION:-v0.1.0}"
    fi
    info "Installing version: $EDR_VERSION"
}

download() {
    URL="$1"
    DEST="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$DEST" "$URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$DEST" "$URL"
    else
        die "Neither curl nor wget found. Install one and retry."
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
need_root
detect_os
detect_arch
resolve_version

info "Detected OS: $OS_ID / arch: $ARCH"

# Determine package type
PKG_TYPE=""
case "$OS_ID" in
    debian|ubuntu|linuxmint|pop|kali|parrot)
        PKG_TYPE="deb";;
    rhel|centos|fedora|rocky|alma|oracle|amzn)
        PKG_TYPE="rpm";;
    *)
        # Check ID_LIKE
        case "$OS_LIKE" in
            *debian*) PKG_TYPE="deb";;
            *rhel*|*fedora*)   PKG_TYPE="rpm";;
            *) die "Cannot determine package type for OS: $OS_ID. Set PKG_TYPE=deb or PKG_TYPE=rpm and retry.";;
        esac;;
esac

# nFPM uses bare version numbers (no 'v' prefix) for package filenames
PKG_VERSION="${EDR_VERSION#v}"
PKG_FILE="edr-client_${PKG_VERSION}_${PKG_ARCH}.${PKG_TYPE}"
PKG_URL="${RELEASE_URL}/v${PKG_VERSION}/${PKG_FILE}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading $PKG_FILE..."
download "$PKG_URL" "$TMPDIR/$PKG_FILE"

info "Installing package..."
case "$PKG_TYPE" in
    deb) dpkg -i "$TMPDIR/$PKG_FILE";;
    rpm) rpm -Uvh --force "$TMPDIR/$PKG_FILE";;
esac

# ── Configure ────────────────────────────────────────────────────────────────
info "Writing /etc/edr/env..."
cat > /etc/edr/env <<EOF
NATS_URL=${NATS_URL}
EOF

info "Updating /etc/edr/edr.yaml..."
# Patch NATS URL and tenant_id in the config
sed -i "s|url: nats://127.0.0.1:4222|url: ${NATS_URL}|" /etc/edr/edr.yaml
sed -i "s|tenant_id: default|tenant_id: ${TENANT_ID}|" /etc/edr/edr.yaml

if [ -n "$EDR_GROUP" ]; then
    sed -i "s|# group: servers|group: ${EDR_GROUP}|" /etc/edr/edr.yaml
fi

# Ensure ebpf_path points to the package-installed .o files
sed -i 's|# ebpf_path: /usr/lib/edr/bpf|ebpf_path: /usr/lib/edr/bpf|' /etc/edr/edr.yaml

# ── Start ─────────────────────────────────────────────────────────────────────
if [ "$SKIP_START" != "1" ]; then
    info "Enabling and starting edr-client service..."
    systemctl daemon-reload
    systemctl enable --now edr-client.service
    sleep 2
    if systemctl is-active --quiet edr-client.service; then
        ok "EDR agent is running!"
    else
        warn "Service may have failed to start. Check: journalctl -u edr-client -n 50"
    fi
else
    info "Skipping service start (SKIP_START=1). Start manually:"
    info "  systemctl enable --now edr-client"
fi

ok "Installation complete."
info "Config:  /etc/edr/edr.yaml"
info "Env:     /etc/edr/env"
info "Logs:    journalctl -u edr-client -f"
info "Status:  systemctl status edr-client"
