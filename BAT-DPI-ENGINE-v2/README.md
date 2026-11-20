# BAT-DPI-ENGINE v2.0 (Mid-SNI Desynchronization Toolkit)

Cross-platform **L4/L7 Deep Packet Inspection (DPI) Desynchronization Toolkit** written in **C** (Windows kernel-mode packet filtering via `WinDivert`) and **Python** (zero-dependency asynchronous SOCKS5 desync proxy for macOS, Linux, and Windows).

### What's New in v2.0
* **Dynamic TLS SNI Parser (`find_sni_split_offset` / `find_sni_mid_offset`):** Automatically parses TLS 1.2/1.3 `ClientHello` extensions (`0x0000`), locates the exact byte range of the target hostname (e.g., `*.googlevideo.com`), and splits the TCP payload directly in the middle of the domain string.
* **Domain Whitelist Routing (`domains.txt`):** Applies packet desynchronization selectively to target domains (YouTube, GoogleVideo CDN, Telegram, Discord, OpenAI, Anthropic, Gemini, GitHub) while passing domestic traffic untouched without overhead.
* **macOS One-Click Auto-Proxy (`scripts/mac_auto_run.sh`):** Automatically configures `networksetup` SOCKS settings on `Wi-Fi` and cleanly reverts them on exit (`Ctrl+C`).

---

## Repository Structure

```text
BAT-DPI-ENGINE/
├── src/
│   ├── windows/
│   │   └── dpi_engine.c       # C kernel-level desync (WinDivert: Fake TTL + Bad Checksum + Mid-SNI Split + QUIC Drop)
│   └── proxy/
│       └── desync_proxy.py    # Python AsyncIO SOCKS5 proxy (Mid-SNI Split + TCP_NODELAY + POSIX MSG_OOB)
├── scripts/
│   ├── mac_auto_run.sh        # macOS one-click launcher with automatic networksetup cleanup
│   ├── linux_run.sh           # Linux launcher
│   ├── win_build.bat          # MinGW-w64 (GCC) build script for Windows
│   └── win_run.bat            # Windows Administrator launcher
├── domains.txt                # Configurable target domain list
├── .gitignore
├── LICENSE
└── README.md
```

---

## Quick Start

### 1. macOS (MacBook)
```bash
chmod +x scripts/mac_auto_run.sh
./scripts/mac_auto_run.sh
```
*(Tip: For YouTube video streams on macOS/Windows browsers, disable **QUIC / HTTP/3** in browser flags so video chunks use TCP/TLS instead of UDP).*

### 2. Windows (Native WinDivert Mode)
1. Download **WinDivert 2.2 (x64)** from `basil00/Divert` and copy `windivert.h`, `WinDivert.dll`, `WinDivert.lib`, and `WinDivert64.sys` into `src/windows/`.
2. Run `scripts/win_build.bat` to compile `bat_dpi_engine.exe`.
3. Right-click `scripts/win_run.bat` -> **Run as administrator**.

### 3. Linux
```bash
chmod +x scripts/linux_run.sh
./scripts/linux_run.sh
# Point your browser or client to SOCKS5 127.0.0.1:10808
```
