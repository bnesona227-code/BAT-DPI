/**
 * BAT-DPI-ENGINE v2.0 // Windows Kernel-Level SNI-Aware Desynchronizer (C + WinDivert)
 *
 * Parses TLS ClientHello SNI offset dynamically and applies:
 *  1. Decoy (Fake) TLS ClientHello injection with low IP TTL and corrupted TCP checksum.
 *  2. Mid-SNI TCP segmentation (splits directly inside the Server Name Indication string).
 *  3. Outbound QUIC (UDP/443) drop to enforce TCP/TLS fallback for video streams.
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF 0xFFFF
#define DEFAULT_FAKE_TTL 3

static const UINT8 fake_tls_client_hello[] = {
    0x16, 0x03, 0x01, 0x00, 0x41, 0x01, 0x00, 0x00, 0x3d, 0x03, 0x03,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00,
    0x00, 0x09, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
};

static inline BOOL is_tls_client_hello(const UINT8 *data, UINT len) {
    return (len > 43 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01);
}

// Finds the middle byte offset of the SNI hostname inside TLS ClientHello
static UINT find_sni_mid_offset(const UINT8 *data, UINT len) {
    UINT idx = 43;
    if (idx >= len) return 2;

    // Session ID
    UINT8 sid_len = data[idx];
    idx += 1 + sid_len;
    if (idx + 2 > len) return 2;

    // Cipher Suites
    UINT16 cs_len = (data[idx] << 8) | data[idx + 1];
    idx += 2 + cs_len;
    if (idx + 1 > len) return 2;

    // Compression Methods
    UINT8 cm_len = data[idx];
    idx += 1 + cm_len;
    if (idx + 2 > len) return 2;

    // Extensions
    UINT16 ext_total = (data[idx] << 8) | data[idx + 1];
    idx += 2;
    UINT ext_end = idx + ext_total;
    if (ext_end > len) ext_end = len;

    while (idx + 4 <= ext_end) {
        UINT16 ext_type = (data[idx] << 8) | data[idx + 1];
        UINT16 ext_len = (data[idx + 2] << 8) | data[idx + 3];
        idx += 4;

        if (ext_type == 0x0000 && idx + 5 <= ext_end) {
            UINT16 name_len = (data[idx + 3] << 8) | data[idx + 4];
            UINT name_start = idx + 5;
            if (name_start + name_len <= ext_end && name_len > 2) {
                return name_start + (name_len / 2);
            }
        }
        idx += ext_len;
    }
    return 2;
}

static void inject_fake_client_hello(HANDLE handle, const UINT8 *orig_packet, UINT hdr_len,
                                     const WINDIVERT_ADDRESS *addr, UINT8 fake_ttl) {
    UINT8 fake_pkt[MAXBUF];
    UINT fake_payload_len = sizeof(fake_tls_client_hello);
    UINT fake_total_len = hdr_len + fake_payload_len;

    if (fake_total_len > MAXBUF) return;

    memcpy(fake_pkt, orig_packet, hdr_len);
    memcpy(fake_pkt + hdr_len, fake_tls_client_hello, fake_payload_len);

    PWINDIVERT_IPHDR ip_hdr = NULL;
    PWINDIVERT_TCPHDR tcp_hdr = NULL;
    WinDivertHelperParsePacket(fake_pkt, fake_total_len, &ip_hdr, NULL, NULL, NULL, NULL,
                               &tcp_hdr, NULL, NULL, NULL, NULL, NULL);

    if (ip_hdr && tcp_hdr) {
        ip_hdr->Length = htons((UINT16)fake_total_len);
        ip_hdr->TTL = fake_ttl;
        WinDivertHelperCalcChecksums(fake_pkt, fake_total_len, (PWINDIVERT_ADDRESS)addr, 0);
        tcp_hdr->Checksum ^= 0xFFFF;
        WinDivertSend(handle, fake_pkt, fake_total_len, NULL, addr);
    }
}

int main(int argc, char *argv[]) {
    UINT8 fake_ttl = DEFAULT_FAKE_TTL;
    BOOL drop_quic = TRUE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-quic-drop") == 0) drop_quic = FALSE;
        else if (strncmp(argv[i], "--ttl=", 6) == 0) fake_ttl = (UINT8)atoi(argv[i] + 6);
    }

    const char *filter =
        "outbound and ((tcp.DstPort == 443 and tcp.PayloadLength > 0) or "
        "(udp.DstPort == 443 and udp.PayloadLength > 0))";

    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[ERROR] WinDivertOpen failed (code %lu). Run as Administrator.\n", GetLastError());
        return 1;
    }

    printf("=================================================================\n");
    printf(" BAT-DPI-ENGINE v2.0 // MID-SNI KERNEL DESYNC (WinDivert)\n");
    printf("=================================================================\n");
    printf("[INFO] Mode: Fake(TTL=%u, BadSum) + Mid-SNI Split + DropQUIC=%s\n",
           fake_ttl, drop_quic ? "ON" : "OFF");
    printf("[INFO] Press Ctrl+C to stop.\n\n");

    UINT8 packet[MAXBUF];
    UINT packet_len = 0;
    WINDIVERT_ADDRESS addr;

    while (TRUE) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) continue;

        PWINDIVERT_IPHDR ip_hdr = NULL;
        PWINDIVERT_TCPHDR tcp_hdr = NULL;
        PWINDIVERT_UDPHDR udp_hdr = NULL;
        PVOID payload = NULL;
        UINT payload_len = 0;

        WinDivertHelperParsePacket(packet, packet_len, &ip_hdr, NULL, NULL, NULL, NULL,
                                   &tcp_hdr, &udp_hdr, &payload, &payload_len, NULL, NULL);

        if (drop_quic && udp_hdr != NULL) continue;

        UINT8 *data = (UINT8 *)payload;
        if (ip_hdr != NULL && tcp_hdr != NULL && is_tls_client_hello(data, payload_len)) {
            UINT hdr_len = packet_len - payload_len;
            UINT split_pos = find_sni_mid_offset(data, payload_len);

            printf("[SNI-DESYNC] ClientHello (%u B) -> Fake(TTL=%u) + Split at SNI byte %u\n",
                   payload_len, fake_ttl, split_pos);

            inject_fake_client_hello(handle, packet, hdr_len, &addr, fake_ttl);

            if (payload_len > split_pos && split_pos > 0) {
                UINT pkt1_len = hdr_len + split_pos;
                ip_hdr->Length = htons((UINT16)pkt1_len);
                WinDivertHelperCalcChecksums(packet, pkt1_len, &addr, 0);
                WinDivertSend(handle, packet, pkt1_len, NULL, &addr);

                UINT pkt2_payload_len = payload_len - split_pos;
                UINT pkt2_len = hdr_len + pkt2_payload_len;
                memmove(data, data + split_pos, pkt2_payload_len);

                ip_hdr->Length = htons((UINT16)pkt2_len);
                tcp_hdr->SeqNum = htonl(ntohl(tcp_hdr->SeqNum) + split_pos);
                WinDivertHelperCalcChecksums(packet, pkt2_len, &addr, 0);
                WinDivertSend(handle, packet, pkt2_len, NULL, &addr);
                continue;
            }
        }

        WinDivertSend(handle, packet, packet_len, NULL, &addr);
    }

    WinDivertClose(handle);
    return 0;
}
