#!/bin/bash
# =============================================================================
# setup.sh — Install basic tools on any distro
# San Antonio College — SWCCDC 2026
#
# Run this FIRST on any Linux box. It makes sure you have the tools
# the other scripts need. Works on Debian, RHEL, Alpine, FreeBSD.
#
# Usage: sudo ./setup.sh
# =============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./setup.sh"
    exit 1
fi

echo "=== Installing essential tools ==="

if command -v apt-get >/dev/null 2>&1; then
    echo "Debian/Ubuntu detected"
    apt-get update -q
    apt-get install -y bash vim nano sudo net-tools lsof curl wget auditd

elif command -v yum >/dev/null 2>&1; then
    echo "RHEL/CentOS detected"
    yum install -y bash vim nano sudo net-tools lsof curl wget audit

elif command -v dnf >/dev/null 2>&1; then
    echo "Fedora detected"
    dnf install -y bash vim nano sudo net-tools lsof curl wget audit

elif command -v apk >/dev/null 2>&1; then
    echo "Alpine detected"
    sed -i 's/#\(.*\/community\)/\1/' /etc/apk/repositories
    apk update
    apk add bash vim nano sudo shadow net-tools lsof curl wget

elif command -v pkg >/dev/null 2>&1; then
    echo "FreeBSD detected"
    pkg update
    pkg install -y bash vim nano sudo lsof curl wget

else
    echo "Unknown distro — install tools manually: vim nano sudo net-tools lsof curl"
fi

echo ""
echo "[+] Setup complete. Run inventory.sh next."
