#!/bin/bash
cd "$(dirname "$0")/.."

INTERFACE="Wi-Fi"
HOST="127.0.0.1"
PORT="10808"

cleanup() {
    echo ""
    echo "[INFO] Disabling macOS system SOCKS proxy on $INTERFACE..."
    networksetup -setsocksfirewallproxystate "$INTERFACE" off 2>/dev/null
    echo "[INFO] Proxy disabled. Network restored."
    exit 0
}

trap cleanup INT TERM EXIT

echo "[INFO] Enabling macOS system SOCKS proxy ($HOST:$PORT) on $INTERFACE..."
networksetup -setsocksfirewallproxy "$INTERFACE" "$HOST" "$PORT"
networksetup -setsocksfirewallproxystate "$INTERFACE" on

python3 src/proxy/desync_proxy.py --host "$HOST" --port "$PORT" --domains domains.txt
