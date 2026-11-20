#!/usr/bin/env python3
"""
BAT-DPI-ENGINE v2.0 // Smart SNI-Aware Desync Proxy (macOS / Linux / Windows)

Features:
- Dynamic SNI (Server Name Indication) parsing inside TLS ClientHello packets.
- Mid-SNI TCP segmentation (splits directly inside the domain name to defeat stateful DPI).
- Nagle's algorithm bypass (TCP_NODELAY) + POSIX TCP Urgent (MSG_OOB) injection.
- Configurable target domain list (YouTube, GoogleVideo, AI services, etc.) with selective bypass.
"""

import argparse
import asyncio
import os
import platform
import socket
import struct
import sys
from typing import Optional, Set


DEFAULT_TARGETS = {
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "youtu.be",
    "telegram.org",
    "t.me",
    "tdesktop.com",
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "gemini.google.com",
    "aistudio.google.com",
    "midjourney.com",
    "huggingface.co",
    "discord.com",
    "discordapp.com",
    "discord.gg",
    "github.com",
}


def load_target_domains(filepath: Optional[str]) -> Set[str]:
    domains = set(DEFAULT_TARGETS)
    if filepath and os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
    return domains


def is_target_domain(host: str, targets: Set[str]) -> bool:
    host = host.lower().strip(".")
    for target in targets:
        if host == target or host.endswith("." + target):
            return True
    return False


def find_sni_split_offset(tls_payload: bytes, fallback_pos: int = 2) -> int:
    """
    Parses TLS 1.2/1.3 ClientHello to locate the exact SNI extension offset
    and returns a split index right in the middle of the domain name.
    """
    try:
        # TLS Record Header: 5 bytes (0x16 = Handshake, Version, Length)
        if len(tls_payload) < 43 or tls_payload[0] != 0x16 or tls_payload[5] != 0x01:
            return fallback_pos

        # Skip Record Header (5) + Handshake Header (4) + Client Version (2) + Random (32) = 43
        idx = 43
        if idx >= len(tls_payload):
            return fallback_pos

        # Session ID
        session_id_len = tls_payload[idx]
        idx += 1 + session_id_len
        if idx + 2 > len(tls_payload):
            return fallback_pos

        # Cipher Suites
        cipher_suites_len = struct.unpack("!H", tls_payload[idx : idx + 2])[0]
        idx += 2 + cipher_suites_len
        if idx + 1 > len(tls_payload):
            return fallback_pos

        # Compression Methods
        comp_methods_len = tls_payload[idx]
        idx += 1 + comp_methods_len
        if idx + 2 > len(tls_payload):
            return fallback_pos

        # Extensions Total Length
        ext_total_len = struct.unpack("!H", tls_payload[idx : idx + 2])[0]
        idx += 2
        ext_end = min(idx + ext_total_len, len(tls_payload))

        while idx + 4 <= ext_end:
            ext_type = struct.unpack("!H", tls_payload[idx : idx + 2])[0]
            ext_len = struct.unpack("!H", tls_payload[idx + 2 : idx + 4])[0]
            idx += 4

            # Extension Type 0x0000 = Server Name Indication (SNI)
            if ext_type == 0x0000 and idx + 5 <= ext_end:
                # Server Name List Length (2) + Name Type (1) + Name Length (2)
                name_len = struct.unpack("!H", tls_payload[idx + 3 : idx + 5])[0]
                name_start = idx + 5
                if name_start + name_len <= ext_end and name_len > 2:
                    # Split right in the middle of the SNI hostname
                    return name_start + (name_len // 2)
            idx += ext_len
    except Exception:
        pass

    return fallback_pos


async def relay_plain(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(32768)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def relay_desync(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    should_desync: bool,
    use_oob: bool,
) -> None:
    is_first_chunk = True
    try:
        while True:
            chunk = await reader.read(32768)
            if not chunk:
                break

            if is_first_chunk and should_desync and len(chunk) > 10 and chunk[0] == 0x16 and chunk[5] == 0x01:
                is_first_chunk = False
                sock = writer.get_extra_info("socket")
                if sock is not None:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                split_pos = find_sni_split_offset(chunk, fallback_pos=2)
                part1 = chunk[:split_pos]
                part2 = chunk[split_pos:]

                writer.write(part1)
                await writer.drain()

                if use_oob and sock is not None and sys.platform != "win32":
                    try:
                        sock.send(b"a", socket.MSG_OOB)
                    except Exception:
                        pass

                await asyncio.sleep(0.012)
                writer.write(part2)
                await writer.drain()
                print(f"[SNI-DESYNC] Split at byte {split_pos}/{len(chunk)} -> {target_host}")
            else:
                is_first_chunk = False
                writer.write(chunk)
                await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_socks5_client(
    c_reader: asyncio.StreamReader,
    c_writer: asyncio.StreamWriter,
    targets: Set[str],
    desync_all: bool,
    use_oob: bool,
) -> None:
    r_writer = None
    try:
        header = await c_reader.readexactly(2)
        ver, nmethods = header[0], header[1]
        if ver != 0x05:
            c_writer.close()
            return
        await c_reader.readexactly(nmethods)
        c_writer.write(b"\x05\x00")
        await c_writer.drain()

        req = await c_reader.readexactly(4)
        _, cmd, _, atyp = req[0], req[1], req[2], req[3]
        if cmd != 0x01:
            c_writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await c_writer.drain()
            c_writer.close()
            return

        if atyp == 0x01:
            host = socket.inet_ntoa(await c_reader.readexactly(4))
        elif atyp == 0x03:
            domain_len = (await c_reader.readexactly(1))[0]
            host = (await c_reader.readexactly(domain_len)).decode("utf-8", errors="ignore")
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, await c_reader.readexactly(16))
        else:
            c_writer.close()
            return

        port = struct.unpack("!H", await c_reader.readexactly(2))[0]

        try:
            r_reader, r_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
        except Exception:
            c_writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            await c_writer.drain()
            c_writer.close()
            return

        c_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await c_writer.drain()

        apply_desync = desync_all or is_target_domain(host, targets)

        await asyncio.gather(
            relay_desync(c_reader, r_writer, host, apply_desync, use_oob),
            relay_plain(r_reader, c_writer),
        )
    except Exception:
        pass
    finally:
        try:
            c_writer.close()
        except Exception:
            pass
        if r_writer is not None:
            try:
                r_writer.close()
            except Exception:
                pass


async def run_server(host: str, port: int, targets: Set[str], desync_all: bool, use_oob: bool) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle_socks5_client(r, w, targets, desync_all, use_oob),
        host,
        port,
    )
    print("=" * 68)
    print(f" BAT-DPI-ENGINE v2.0 // SNI-AWARE DESYNC PROXY ({platform.system()})")
    print("=" * 68)
    print(f"[INFO] Listening on : {host}:{port}")
    print(f"[INFO] Mode         : {'ALL HTTPS TRAFFIC' if desync_all else f'TARGET LIST ({len(targets)} domains)'}")
    print(f"[INFO] Strategy     : Mid-SNI TLS Segmentation + TCP_NODELAY + OOB={'ON' if use_oob else 'OFF'}")
    print("[INFO] Press Ctrl+C to stop.\n")

    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="BAT-DPI-ENGINE v2.0 SNI-Aware Desync Proxy")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=10808, help="Bind port (default: 10808)")
    parser.add_argument("--domains", default="domains.txt", help="Path to custom domain list")
    parser.add_argument("--all", action="store_true", help="Apply desync to ALL TLS connections (not only domain list)")
    parser.add_argument("--no-oob", action="store_true", help="Disable TCP MSG_OOB injection")
    args = parser.parse_args()

    targets = load_target_domains(args.domains)

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(run_server(args.host, args.port, targets, args.all, not args.no_oob))
    except KeyboardInterrupt:
        print("\n[INFO] Proxy stopped.")


if __name__ == "__main__":
    main()
