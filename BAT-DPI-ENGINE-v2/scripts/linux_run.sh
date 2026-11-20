#!/bin/bash
cd "$(dirname "$0")/.."
python3 src/proxy/desync_proxy.py --host 127.0.0.1 --port 10808 --domains domains.txt
