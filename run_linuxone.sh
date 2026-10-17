#!/usr/bin/env bash
# ==============================================================================
# LogMind: Startup Script for IBM LinuxONE (s390x)
# Works on RHEL 8/9, Ubuntu 20.04/22.04/24.04, SLES on s390x
# ==============================================================================

set -e

echo "=================================================================="
echo "      LogMind - Security Analyst Enclave on IBM LinuxONE         "
echo "=================================================================="

# 1. Architecture Check
ARCH=$(uname -m)
echo "[*] Detected System Architecture: ${ARCH}"

if [ "${ARCH}" = "s390x" ] || [ "${ARCH}" = "s390" ]; then
    echo "[✓] Confirmed native IBM Z / LinuxONE hardware (s390x)!"
    if [ -f /proc/cpuinfo ]; then
        echo "[*] Mainframe Hardware Info:"
        grep -E "vendor_id|machine|features" /proc/cpuinfo | head -n 3 || true
    fi
else
    echo "[!] Warning: Host architecture is ${ARCH}, not s390x."
    echo "[*] Running in Development / Emulation mode."
fi

# 2. Setup PATH and Pip
export PATH="$HOME/.local/bin:$PATH"

if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
elif [ -f "$HOME/.local/bin/pip" ]; then
    PIP_CMD="$HOME/.local/bin/pip"
else
    echo "[*] Bootstrapping pip..."
    curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    python3 /tmp/get-pip.py --user
    PIP_CMD="$HOME/.local/bin/pip"
fi

echo "[*] Installing Python dependencies via ${PIP_CMD}..."
${PIP_CMD} install --user -r requirements.txt

# 5. Start Application Server
PORT=${PORT:-8000}
HOST=${HOST:-0.0.0.0}

echo ""
echo "=================================================================="
echo " [✓] LogMind Gateway active and listening on: http://${HOST}:${PORT}"
echo "=================================================================="
echo " If you are connected via SSH, forward port 8000 to your laptop:"
echo "   ssh -L 8000:localhost:8000 <user>@<linuxone-ip>"
echo " Then open: http://localhost:8000 in your browser."
echo "=================================================================="
echo ""

exec python3 -m uvicorn backend.main:app --host "${HOST}" --port "${PORT}"
