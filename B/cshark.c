#include "cshark.h"

typedef struct {
    struct pcap_pkthdr header;
    u_char *data;
} StoredPacket;

StoredPacket *packet_store[MAX_PACKETS];
int packet_count = 0;
unsigned long long pkt_id = 0;

volatile sig_atomic_t g_capturing = 0;
pcap_t *g_handle = NULL;

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void free_stored_packets() {
    for (int i = 0; i < MAX_PACKETS; i++) {
        if (packet_store[i]) {
            free(packet_store[i]->data);
            free(packet_store[i]);
            packet_store[i] = NULL;
        }
    }
    packet_count = 0;
}

const char* app_protocol(uint16_t port) {
    switch (port) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 53: return "DNS";
        case 67: case 68: return "DHCP";
        case 69: return "TFTP";
        case 123: return "NTP";
        default: return "Unknown";
    }
}

// Hex dump WITH offset (for full packet inspection)
void print_hex_ascii_with_offset(const u_char *data, int len) {
    for (int i = 0; i < len; i += 16) {
        printf("0x%04x  ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
        }
        printf(" ");
        for (int j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
}

// Hex dump WITHOUT offset (for payload display in packet_handler)
void print_hex_ascii(const u_char *data, int len) {
    for (int i = 0; i < len; i += 16) {
        // Print hex values
        for (int j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02X ", data[i + j]);
            else
                printf("   ");
        }
        printf(" ");
        // Print ASCII
        for (int j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
}

void decode_tcp(const u_char *payload, int length) {
    if (length < 20) return;

    uint16_t src_port = ntohs(*(uint16_t *)(payload));
    uint16_t dst_port = ntohs(*(uint16_t *)(payload + 2));
    uint32_t seq = ntohl(*(uint32_t *)(payload + 4));
    uint32_t ack = ntohl(*(uint32_t *)(payload + 8));
    uint8_t data_offset = payload[12] >> 4;
    uint8_t flags_byte = payload[13];
    uint16_t window = ntohs(*(uint16_t *)(payload + 14));
    uint16_t checksum = ntohs(*(uint16_t *)(payload + 16));

    int fin = flags_byte & 0x01;
    int syn = (flags_byte >> 1) & 0x01;
    int rst = (flags_byte >> 2) & 0x01;
    int psh = (flags_byte >> 3) & 0x01;
    int ack_flag = (flags_byte >> 4) & 0x01;
    int urg = (flags_byte >> 5) & 0x01;

    // Build flags string with commas
    char flags_str[64] = {0};
    int first = 1;

    if (syn) {
        strcat(flags_str, "SYN");
        first = 0;
    }
    if (ack_flag) {
        if (!first) strcat(flags_str, ",");
        strcat(flags_str, "ACK");
        first = 0;
    }
    if (fin) {
        if (!first) strcat(flags_str, ",");
        strcat(flags_str, "FIN");
        first = 0;
    }
    if (rst) {
        if (!first) strcat(flags_str, ",");
        strcat(flags_str, "RST");
        first = 0;
    }
    if (psh) {
        if (!first) strcat(flags_str, ",");
        strcat(flags_str, "PSH");
        first = 0;
    }
    if (urg) {
        if (!first) strcat(flags_str, ",");
        strcat(flags_str, "URG");
        first = 0;
    }

    // Determine which port to show protocol for
    const char *src_proto = (src_port == 80 || src_port == 443 || src_port == 53) ? app_protocol(src_port) : "";
    const char *dst_proto = (dst_port == 80 || dst_port == 443 || dst_port == 53) ? app_protocol(dst_port) : "";

    if (strlen(src_proto) > 0 && strcmp(src_proto, "Unknown") != 0) {
        printf("L4 (TCP): Src Port: %u (%s) | Dst Port: %u | Seq: %u | Ack: %u | Flags: [%s]\n",
               src_port, src_proto, dst_port, seq, ack, flags_str);
    } else if (strlen(dst_proto) > 0 && strcmp(dst_proto, "Unknown") != 0) {
        printf("L4 (TCP): Src Port: %u | Dst Port: %u (%s) | Seq: %u | Ack: %u | Flags: [%s]\n",
               src_port, dst_port, dst_proto, seq, ack, flags_str);
    } else {
        printf("L4 (TCP): Src Port: %u | Dst Port: %u | Seq: %u | Ack: %u | Flags: [%s]\n",
               src_port, dst_port, seq, ack, flags_str);
    }

    printf("Window: %u | Checksum: 0x%04X | Header Length: %u bytes\n",
           window, checksum, data_offset*4);

    int payload_len = length - data_offset*4;
    if (payload_len > 0) {
        printf("L7 (Payload): Identified as %s on port %u - %d bytes\n",
               (dst_port==80||src_port==80)?"HTTP":
               (dst_port==443||src_port==443)?"HTTPS/TLS":
               (dst_port==53||src_port==53)?"DNS":
               "Unknown",
               (dst_port==80||dst_port==443||dst_port==53) ? dst_port : src_port,
               payload_len);
        printf("Data (first 64 bytes):\n");
        print_hex_ascii(payload + data_offset*4, payload_len < 64 ? payload_len : 64);
    }
}

void decode_udp(const u_char *payload, int length) {
    if (length < 8) return;

    uint16_t src_port = ntohs(*(uint16_t *)(payload));
    uint16_t dst_port = ntohs(*(uint16_t *)(payload + 2));
    uint16_t udp_len = ntohs(*(uint16_t *)(payload + 4));
    uint16_t checksum = ntohs(*(uint16_t *)(payload + 6));

    // Determine which port to show protocol for
    const char *src_proto = (src_port == 53 || src_port == 67 || src_port == 68 || src_port == 69 || src_port == 123) ? app_protocol(src_port) : "";
    const char *dst_proto = (dst_port == 53 || dst_port == 67 || dst_port == 68 || dst_port == 69 || dst_port == 123) ? app_protocol(dst_port) : "";

    if (strlen(src_proto) > 0 && strcmp(src_proto, "Unknown") != 0) {
        printf("L4 (UDP): Src Port: %u (%s) | Dst Port: %u | Length: %u | Checksum: 0x%04X\n",
               src_port, src_proto, dst_port, udp_len, checksum);
    } else if (strlen(dst_proto) > 0 && strcmp(dst_proto, "Unknown") != 0) {
        printf("L4 (UDP): Src Port: %u | Dst Port: %u (%s) | Length: %u | Checksum: 0x%04X\n",
               src_port, dst_port, dst_proto, udp_len, checksum);
    } else {
        printf("L4 (UDP): Src Port: %u | Dst Port: %u | Length: %u | Checksum: 0x%04X\n",
               src_port, dst_port, udp_len, checksum);
    }

    int payload_len = udp_len - 8;
    if (payload_len > 0) {
        printf("L7 (Payload): Identified as %s on port %u - %d bytes\n",
               (dst_port==53||src_port==53)?"DNS":
               (dst_port==67||dst_port==68||src_port==67||src_port==68)?"DHCP":
               (dst_port==69||src_port==69)?"TFTP":
               (dst_port==123||src_port==123)?"NTP":
               "Unknown",
               (dst_port==53||dst_port==67||dst_port==68||dst_port==69||dst_port==123) ? dst_port : src_port,
               payload_len);
        printf("Data (first 64 bytes):\n");
        print_hex_ascii(payload + 8, payload_len < 64 ? payload_len : 64);
    }
}

void print_packet_summary() {
    if (packet_count == 0) {
        printf("[C-Shark] No packets captured in last session.\n");
        return;
    }

    printf("\n--- Last Session Packets ---\n");
    for (int i = 0; i < packet_count; i++) {
        StoredPacket *p = packet_store[i];
        const struct pcap_pkthdr *h = &p->header;

        time_t sec = h->ts.tv_sec;
        struct tm tm_info;
        char timebuf[64];
        localtime_r(&sec, &tm_info);
        strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm_info);

        const u_char *eth = p->data;
        uint16_t eth_type = (eth[12] << 8) | eth[13];

        char l3_info[64] = {0};
        char l4_info[64] = {0};

        if (eth_type == 0x0800 && h->caplen >= 34) {
            uint8_t proto = eth[23];
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, eth + 26, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, eth + 30, dst_ip, sizeof(dst_ip));
            snprintf(l3_info, sizeof(l3_info), "IPv4 %s -> %s", src_ip, dst_ip);
            snprintf(l4_info, sizeof(l4_info), "%s", proto==6?"TCP":"UDP");
        } else if (eth_type == 0x86DD && h->caplen >= 54) {
            snprintf(l3_info, sizeof(l3_info), "IPv6");
            snprintf(l4_info, sizeof(l4_info), "N/A");
        } else if (eth_type == 0x0806 && h->caplen >= 28) {
            snprintf(l3_info, sizeof(l3_info), "ARP");
            snprintf(l4_info, sizeof(l4_info), "N/A");
        } else {
            snprintf(l3_info, sizeof(l3_info), "Unknown");
            snprintf(l4_info, sizeof(l4_info), "N/A");
        }

        printf("ID: %d | Time: %s.%06ld | Len: %u | %s | %s\n",
               i + 1, timebuf, (long)h->ts.tv_usec, (unsigned)h->caplen, l3_info, l4_info);
    }
}

// NEW: Detailed inspection function with raw hex values
void inspect_packet_detailed(int id) {
    if (id < 1 || id > packet_count) {
        printf("[C-Shark] Invalid Packet ID.\n");
        return;
    }

    StoredPacket *p = packet_store[id - 1];
    const struct pcap_pkthdr *h = &p->header;
    const u_char *bytes = p->data;

    printf("\n========================================\n");
    printf("=== PACKET #%d DETAILED INSPECTION ===\n", id);
    printf("========================================\n\n");

    time_t sec = h->ts.tv_sec;
    struct tm tm_info;
    char timebuf[64];
    localtime_r(&sec, &tm_info);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);

    printf("Capture Timestamp: %s.%06ld\n", timebuf, (long)h->ts.tv_usec);
    printf("Capture Length: %u bytes\n", (unsigned)h->caplen);
    printf("Original Length: %u bytes\n\n", (unsigned)h->len);

    // 1. Full Raw Packet Dump
    printf("========================================\n");
    printf("=== RAW PACKET DATA (Full Hex Dump) ===\n");
    printf("========================================\n");
    print_hex_ascii_with_offset(bytes, h->caplen);

    // 2. Ethernet Layer
    printf("\n========================================\n");
    printf("=== LAYER 2: ETHERNET HEADER ===\n");
    printf("========================================\n");

    const u_char *eth = bytes;
    uint16_t eth_type = (eth[12] << 8) | eth[13];

    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);
    printf("  Raw bytes: %02X %02X %02X %02X %02X %02X\n",
           eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);

    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]);
    printf("  Raw bytes: %02X %02X %02X %02X %02X %02X\n",
           eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]);

    printf("EtherType: 0x%04X", eth_type);
    if (eth_type == 0x0800) printf(" (IPv4)\n");
    else if (eth_type == 0x86DD) printf(" (IPv6)\n");
    else if (eth_type == 0x0806) printf(" (ARP)\n");
    else printf(" (Unknown)\n");
    printf("  Raw bytes: %02X %02X\n", eth[12], eth[13]);

    const u_char *payload = bytes + 14;
    unsigned int payload_len = h->caplen - 14;

    // 3. IPv4 Layer
    if (eth_type == 0x0800 && payload_len >= 20) {
        printf("\n========================================\n");
        printf("=== LAYER 3: IPv4 HEADER ===\n");
        printf("========================================\n");

        uint8_t ver_ihl = payload[0];
        uint8_t version = ver_ihl >> 4;
        uint8_t ihl = ver_ihl & 0x0F;
        uint8_t tos = payload[1];
        uint16_t total_len = ntohs(*(uint16_t *)(payload + 2));
        uint16_t pkt_id_field = ntohs(*(uint16_t *)(payload + 4));
        uint16_t flags_frag = ntohs(*(uint16_t *)(payload + 6));
        uint8_t flags = flags_frag >> 13;
        uint16_t frag_offset = flags_frag & 0x1FFF;
        uint8_t ttl = payload[8];
        uint8_t proto = payload[9];
        uint16_t checksum = ntohs(*(uint16_t *)(payload + 10));

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, payload + 12, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, payload + 16, dst_ip, sizeof(dst_ip));

        printf("Version/IHL: 0x%02X\n", ver_ihl);
        printf("  Version: %d, Header Length: %d bytes (%d words)\n", version, ihl*4, ihl);

        printf("Type of Service: 0x%02X\n", tos);

        printf("Total Length: 0x%04X (%d bytes)\n", total_len, total_len);
        printf("  Raw bytes: %02X %02X\n", payload[2], payload[3]);

        printf("Identification: 0x%04X\n", pkt_id_field);
        printf("  Raw bytes: %02X %02X\n", payload[4], payload[5]);

        printf("Flags/Fragment Offset: 0x%04X\n", flags_frag);
        printf("  Flags: 0x%X (", flags);
        if (flags & 0x02) printf("DF-Don't Fragment ");
        if (flags & 0x01) printf("MF-More Fragments");
        printf(")\n");
        printf("  Fragment Offset: %d\n", frag_offset);
        printf("  Raw bytes: %02X %02X\n", payload[6], payload[7]);

        printf("Time to Live (TTL): 0x%02X (%d)\n", ttl, ttl);

        printf("Protocol: 0x%02X", proto);
        if (proto == 6) printf(" (TCP)\n");
        else if (proto == 17) printf(" (UDP)\n");
        else if (proto == 1) printf(" (ICMP)\n");
        else printf(" (Unknown)\n");

        printf("Header Checksum: 0x%04X\n", checksum);
        printf("  Raw bytes: %02X %02X\n", payload[10], payload[11]);

        printf("Source IP: %s\n", src_ip);
        printf("  Raw bytes: %02X %02X %02X %02X\n",
               payload[12], payload[13], payload[14], payload[15]);

        printf("Destination IP: %s\n", dst_ip);
        printf("  Raw bytes: %02X %02X %02X %02X\n",
               payload[16], payload[17], payload[18], payload[19]);

        // TCP Layer
        if (proto == 6 && total_len - ihl*4 >= 20) {
            printf("\n========================================\n");
            printf("=== LAYER 4: TCP HEADER ===\n");
            printf("========================================\n");

            const u_char *tcp = payload + ihl*4;
            uint16_t src_port = ntohs(*(uint16_t *)(tcp));
            uint16_t dst_port = ntohs(*(uint16_t *)(tcp + 2));
            uint32_t seq = ntohl(*(uint32_t *)(tcp + 4));
            uint32_t ack_num = ntohl(*(uint32_t *)(tcp + 8));
            uint8_t data_offset = tcp[12] >> 4;
            uint8_t flags_byte = tcp[13];
            uint16_t window = ntohs(*(uint16_t *)(tcp + 14));
            uint16_t tcp_checksum = ntohs(*(uint16_t *)(tcp + 16));
            uint16_t urgent = ntohs(*(uint16_t *)(tcp + 18));

            printf("Source Port: 0x%04X (%d", src_port, src_port);
            const char *src_proto = app_protocol(src_port);
            if (strcmp(src_proto, "Unknown") != 0) printf(" - %s", src_proto);
            printf(")\n");
            printf("  Raw bytes: %02X %02X\n", tcp[0], tcp[1]);

            printf("Destination Port: 0x%04X (%d", dst_port, dst_port);
            const char *dst_proto = app_protocol(dst_port);
            if (strcmp(dst_proto, "Unknown") != 0) printf(" - %s", dst_proto);
            printf(")\n");
            printf("  Raw bytes: %02X %02X\n", tcp[2], tcp[3]);

            printf("Sequence Number: 0x%08X (%u)\n", seq, seq);
            printf("  Raw bytes: %02X %02X %02X %02X\n", tcp[4], tcp[5], tcp[6], tcp[7]);

            printf("Acknowledgment Number: 0x%08X (%u)\n", ack_num, ack_num);
            printf("  Raw bytes: %02X %02X %02X %02X\n", tcp[8], tcp[9], tcp[10], tcp[11]);

            printf("Data Offset: 0x%X (%d bytes, %d words)\n", data_offset, data_offset*4, data_offset);
            printf("  Raw byte: %02X (upper nibble)\n", tcp[12]);

            printf("Flags: 0x%02X [", flags_byte);
            int first = 1;
            if (flags_byte & 0x02) { printf("%sSYN", first?"":","); first=0; }
            if (flags_byte & 0x10) { printf("%sACK", first?"":","); first=0; }
            if (flags_byte & 0x01) { printf("%sFIN", first?"":","); first=0; }
            if (flags_byte & 0x04) { printf("%sRST", first?"":","); first=0; }
            if (flags_byte & 0x08) { printf("%sPSH", first?"":","); first=0; }
            if (flags_byte & 0x20) { printf("%sURG", first?"":","); first=0; }
            printf("]\n");
            printf("  Raw byte: %02X\n", tcp[13]);

            printf("Window Size: 0x%04X (%d)\n", window, window);
            printf("  Raw bytes: %02X %02X\n", tcp[14], tcp[15]);

            printf("Checksum: 0x%04X\n", tcp_checksum);
            printf("  Raw bytes: %02X %02X\n", tcp[16], tcp[17]);

            printf("Urgent Pointer: 0x%04X (%d)\n", urgent, urgent);
            printf("  Raw bytes: %02X %02X\n", tcp[18], tcp[19]);

            // Payload
            int tcp_payload_len = total_len - ihl*4 - data_offset*4;
            if (tcp_payload_len > 0) {
                printf("\n========================================\n");
                printf("=== APPLICATION LAYER PAYLOAD ===\n");
                printf("========================================\n");
                printf("Payload Length: %d bytes\n", tcp_payload_len);
                printf("Protocol: %s\n",
                       (dst_port==80||src_port==80)?"HTTP":
                       (dst_port==443||src_port==443)?"HTTPS/TLS":
                       "Unknown");
                printf("\nPayload Data:\n");
                print_hex_ascii_with_offset(tcp + data_offset*4, tcp_payload_len < 256 ? tcp_payload_len : 256);
            }
        }
        // UDP Layer
        else if (proto == 17 && total_len - ihl*4 >= 8) {
            printf("\n========================================\n");
            printf("=== LAYER 4: UDP HEADER ===\n");
            printf("========================================\n");

            const u_char *udp = payload + ihl*4;
            uint16_t src_port = ntohs(*(uint16_t *)(udp));
            uint16_t dst_port = ntohs(*(uint16_t *)(udp + 2));
            uint16_t udp_len = ntohs(*(uint16_t *)(udp + 4));
            uint16_t udp_checksum = ntohs(*(uint16_t *)(udp + 6));

            printf("Source Port: 0x%04X (%d", src_port, src_port);
            const char *src_proto = app_protocol(src_port);
            if (strcmp(src_proto, "Unknown") != 0) printf(" - %s", src_proto);
            printf(")\n");
            printf("  Raw bytes: %02X %02X\n", udp[0], udp[1]);

            printf("Destination Port: 0x%04X (%d", dst_port, dst_port);
            const char *dst_proto = app_protocol(dst_port);
            if (strcmp(dst_proto, "Unknown") != 0) printf(" - %s", dst_proto);
            printf(")\n");
            printf("  Raw bytes: %02X %02X\n", udp[2], udp[3]);

            printf("Length: 0x%04X (%d bytes)\n", udp_len, udp_len);
            printf("  Raw bytes: %02X %02X\n", udp[4], udp[5]);

            printf("Checksum: 0x%04X\n", udp_checksum);
            printf("  Raw bytes: %02X %02X\n", udp[6], udp[7]);

            // Payload
            int udp_payload_len = udp_len - 8;
            if (udp_payload_len > 0) {
                printf("\n========================================\n");
                printf("=== APPLICATION LAYER PAYLOAD ===\n");
                printf("========================================\n");
                printf("Payload Length: %d bytes\n", udp_payload_len);
                printf("Protocol: %s\n",
                       (dst_port==53||src_port==53)?"DNS":
                       (dst_port==67||dst_port==68)?"DHCP":
                       "Unknown");
                printf("\nPayload Data:\n");
                print_hex_ascii_with_offset(udp + 8, udp_payload_len < 256 ? udp_payload_len : 256);
            }
        }
    }
    // IPv6 Layer
    else if (eth_type == 0x86DD && payload_len >= 40) {
        printf("\n========================================\n");
        printf("=== LAYER 3: IPv6 HEADER ===\n");
        printf("========================================\n");

        uint32_t ver_tc_fl = ntohl(*(uint32_t *)payload);
        uint8_t version = ver_tc_fl >> 28;
        uint8_t traffic_class = (ver_tc_fl >> 20) & 0xFF;
        uint32_t flow_label = ver_tc_fl & 0xFFFFF;
        uint16_t payload_length = ntohs(*(uint16_t *)(payload + 4));
        uint8_t next_header = payload[6];
        uint8_t hop_limit = payload[7];

        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, payload + 8, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, payload + 24, dst_ip, sizeof(dst_ip));

        printf("Version/Traffic Class/Flow Label: 0x%08X\n", ver_tc_fl);
        printf("  Version: %d\n", version);
        printf("  Traffic Class: 0x%02X (%d)\n", traffic_class, traffic_class);
        printf("  Flow Label: 0x%05X (%d)\n", flow_label, flow_label);
        printf("  Raw bytes: %02X %02X %02X %02X\n", payload[0], payload[1], payload[2], payload[3]);

        printf("Payload Length: 0x%04X (%d bytes)\n", payload_length, payload_length);
        printf("  Raw bytes: %02X %02X\n", payload[4], payload[5]);

        printf("Next Header: 0x%02X", next_header);
        if (next_header == 6) printf(" (TCP)\n");
        else if (next_header == 17) printf(" (UDP)\n");
        else if (next_header == 58) printf(" (ICMPv6)\n");
        else printf(" (Unknown)\n");

        printf("Hop Limit: 0x%02X (%d)\n", hop_limit, hop_limit);

        printf("Source IPv6 Address: %s\n", src_ip);
        printf("  Raw bytes: ");
        for (int i = 8; i < 24; i++) printf("%02X ", payload[i]);
        printf("\n");

        printf("Destination IPv6 Address: %s\n", dst_ip);
        printf("  Raw bytes: ");
        for (int i = 24; i < 40; i++) printf("%02X ", payload[i]);
        printf("\n");

        const u_char *transport = payload + 40;
        int transport_len = payload_length;

        // TCP over IPv6
        if (next_header == 6 && transport_len >= 20) {
            printf("\n========================================\n");
            printf("=== LAYER 4: TCP HEADER ===\n");
            printf("========================================\n");

            uint16_t src_port = ntohs(*(uint16_t *)(transport));
            uint16_t dst_port = ntohs(*(uint16_t *)(transport + 2));
            uint32_t seq = ntohl(*(uint32_t *)(transport + 4));
            uint32_t ack_num = ntohl(*(uint32_t *)(transport + 8));
            uint8_t data_offset = transport[12] >> 4;
            uint8_t flags_byte = transport[13];
            uint16_t window = ntohs(*(uint16_t *)(transport + 14));
            uint16_t tcp_checksum = ntohs(*(uint16_t *)(transport + 16));

            printf("Source Port: 0x%04X (%d", src_port, src_port);
            const char *src_proto = app_protocol(src_port);
            if (strcmp(src_proto, "Unknown") != 0) printf(" - %s", src_proto);
            printf(")\n");

            printf("Destination Port: 0x%04X (%d", dst_port, dst_port);
            const char *dst_proto = app_protocol(dst_port);
            if (strcmp(dst_proto, "Unknown") != 0) printf(" - %s", dst_proto);
            printf(")\n");

            printf("Sequence Number: 0x%08X (%u)\n", seq, seq);
            printf("Acknowledgment Number: 0x%08X (%u)\n", ack_num, ack_num);
            printf("Data Offset: 0x%X (%d bytes)\n", data_offset, data_offset*4);

            printf("Flags: 0x%02X [", flags_byte);
            int first = 1;
            if (flags_byte & 0x02) { printf("%sSYN", first?"":","); first=0; }
            if (flags_byte & 0x10) { printf("%sACK", first?"":","); first=0; }
            if (flags_byte & 0x01) { printf("%sFIN", first?"":","); first=0; }
            if (flags_byte & 0x04) { printf("%sRST", first?"":","); first=0; }
            if (flags_byte & 0x08) { printf("%sPSH", first?"":","); first=0; }
            if (flags_byte & 0x20) { printf("%sURG", first?"":","); first=0; }
            printf("]\n");

            printf("Window Size: 0x%04X (%d)\n", window, window);
            printf("Checksum: 0x%04X\n", tcp_checksum);

            int tcp_payload_len = transport_len - data_offset*4;
            if (tcp_payload_len > 0) {
                printf("\n========================================\n");
                printf("=== APPLICATION LAYER PAYLOAD ===\n");
                printf("========================================\n");
                printf("Payload Length: %d bytes\n", tcp_payload_len);
                printf("\nPayload Data:\n");
                print_hex_ascii_with_offset(transport + data_offset*4, tcp_payload_len < 256 ? tcp_payload_len : 256);
            }
        }
        // UDP over IPv6
        else if (next_header == 17 && transport_len >= 8) {
            printf("\n========================================\n");
            printf("=== LAYER 4: UDP HEADER ===\n");
            printf("========================================\n");

            uint16_t src_port = ntohs(*(uint16_t *)(transport));
            uint16_t dst_port = ntohs(*(uint16_t *)(transport + 2));
            uint16_t udp_len = ntohs(*(uint16_t *)(transport + 4));
            uint16_t udp_checksum = ntohs(*(uint16_t *)(transport + 6));

            printf("Source Port: 0x%04X (%d", src_port, src_port);
            const char *src_proto = app_protocol(src_port);
            if (strcmp(src_proto, "Unknown") != 0) printf(" - %s", src_proto);
            printf(")\n");

            printf("Destination Port: 0x%04X (%d", dst_port, dst_port);
            const char *dst_proto = app_protocol(dst_port);
            if (strcmp(dst_proto, "Unknown") != 0) printf(" - %s", dst_proto);
            printf(")\n");

            printf("Length: 0x%04X (%d bytes)\n", udp_len, udp_len);
            printf("Checksum: 0x%04X\n", udp_checksum);

            int udp_payload_len = udp_len - 8;
            if (udp_payload_len > 0) {
                printf("\n========================================\n");
                printf("=== APPLICATION LAYER PAYLOAD ===\n");
                printf("========================================\n");
                printf("Payload Length: %d bytes\n", udp_payload_len);
                printf("\nPayload Data:\n");
                print_hex_ascii_with_offset(transport + 8, udp_payload_len < 256 ? udp_payload_len : 256);
            }
        }
    }
    // ARP Layer
    else if (eth_type == 0x0806 && payload_len >= 28) {
        printf("\n========================================\n");
        printf("=== LAYER 3: ARP HEADER ===\n");
        printf("========================================\n");

        uint16_t htype = ntohs(*(uint16_t *)(payload + 0));
        uint16_t ptype = ntohs(*(uint16_t *)(payload + 2));
        uint8_t hlen = payload[4];
        uint8_t plen = payload[5];
        uint16_t oper = ntohs(*(uint16_t *)(payload + 6));

        printf("Hardware Type: 0x%04X (%d", htype, htype);
        if (htype == 1) printf(" - Ethernet");
        printf(")\n");
        printf("  Raw bytes: %02X %02X\n", payload[0], payload[1]);

        printf("Protocol Type: 0x%04X", ptype);
        if (ptype == 0x0800) printf(" (IPv4)");
        printf("\n");
        printf("  Raw bytes: %02X %02X\n", payload[2], payload[3]);

        printf("Hardware Length: 0x%02X (%d bytes)\n", hlen, hlen);
        printf("Protocol Length: 0x%02X (%d bytes)\n", plen, plen);

        printf("Operation: 0x%04X", oper);
        if (oper == 1) printf(" (Request)");
        else if (oper == 2) printf(" (Reply)");
        printf("\n");
        printf("  Raw bytes: %02X %02X\n", payload[6], payload[7]);

        printf("\nSender Hardware Address (MAC): %02X:%02X:%02X:%02X:%02X:%02X\n",
               payload[8], payload[9], payload[10], payload[11], payload[12], payload[13]);
        printf("  Raw bytes: %02X %02X %02X %02X %02X %02X\n",
               payload[8], payload[9], payload[10], payload[11], payload[12], payload[13]);

        printf("Sender Protocol Address (IP): %u.%u.%u.%u\n",
               payload[14], payload[15], payload[16], payload[17]);
        printf("  Raw bytes: %02X %02X %02X %02X\n",
               payload[14], payload[15], payload[16], payload[17]);

        printf("Target Hardware Address (MAC): %02X:%02X:%02X:%02X:%02X:%02X\n",
               payload[18], payload[19], payload[20], payload[21], payload[22], payload[23]);
        printf("  Raw bytes: %02X %02X %02X %02X %02X %02X\n",
               payload[18], payload[19], payload[20], payload[21], payload[22], payload[23]);

        printf("Target Protocol Address (IP): %u.%u.%u.%u\n",
               payload[24], payload[25], payload[26], payload[27]);
        printf("  Raw bytes: %02X %02X %02X %02X\n",
               payload[24], payload[25], payload[26], payload[27]);
    }

    printf("\n========================================\n");
    printf("=== END OF PACKET INSPECTION ===\n");
    printf("========================================\n");
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    pkt_id++;

    printf("\n-----------------------------------------\n");
    printf("Packet #%llu | Timestamp: %ld.%06ld | Length: %u bytes\n",
           pkt_id, (long)h->ts.tv_sec, (long)h->ts.tv_usec, (unsigned)h->caplen);

    const u_char *eth = bytes;
    uint16_t eth_type = (eth[12] << 8) | eth[13];

    printf("L2 (Ethernet): Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X | Src MAC: %02X:%02X:%02X:%02X:%02X:%02X |\n",
           eth[0], eth[1], eth[2], eth[3], eth[4], eth[5],
           eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]);
    printf("EtherType: %s (0x%04X)\n",
           eth_type==0x0800?"IPv4":eth_type==0x86DD?"IPv6":eth_type==0x0806?"ARP":"Unknown", eth_type);

    const u_char *payload = bytes + 14;
    unsigned int payload_len = h->caplen - 14;

    // IPv4
    if (eth_type == 0x0800 && payload_len >= 20) {
        uint8_t ihl = payload[0] & 0x0F;
        uint8_t ttl = payload[8];
        uint8_t proto = payload[9];
        uint16_t total_len = ntohs(*(uint16_t *)(payload + 2));
        uint16_t pkt_id_field = ntohs(*(uint16_t *)(payload + 4));
        //uint16_t flags_frag = ntohs(*(uint16_t *)(payload + 6));
        //uint8_t flags = flags_frag >> 13;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, payload + 12, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, payload + 16, dst_ip, sizeof(dst_ip));

        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) |\n",
               src_ip, dst_ip,
               proto==6?"TCP":proto==17?"UDP":proto==1?"ICMP":"Unknown",
               proto);
        printf("TTL: %u\n", ttl);
        printf("ID: 0x%04X | Total Length: %u | Header Length: %u bytes\n",
               pkt_id_field, total_len, ihl*4);

        const u_char *transport = payload + ihl*4;
        int transport_len = total_len - ihl*4;

        if (proto == 6) decode_tcp(transport, transport_len);
        else if (proto == 17) decode_udp(transport, transport_len);
    }
    // IPv6
    else if (eth_type == 0x86DD && payload_len >= 40) {
        uint32_t ver_tc_fl = ntohl(*(uint32_t *)payload);
        uint8_t traffic_class = (ver_tc_fl >> 20) & 0xFF;
        uint32_t flow_label = ver_tc_fl & 0xFFFFF;
        uint16_t payload_length = ntohs(*(uint16_t *)(payload + 4));
        uint8_t next_header = payload[6];
        uint8_t hop_limit = payload[7];

        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, payload + 8, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, payload + 24, dst_ip, sizeof(dst_ip));

        printf("L3 (IPv6): Src IP: %s | Dst IP: %s |\n", src_ip, dst_ip);
        printf("Next Header: %s (%d) | Hop Limit: %u | Traffic Class: %u | Flow Label: 0x%05X | Payload Length: %u\n",
               next_header==6?"TCP":next_header==17?"UDP":next_header==58?"ICMPv6":"Unknown",
               next_header, hop_limit, traffic_class, flow_label, payload_length);

        const u_char *transport = payload + 40;
        int transport_len = payload_length;

        if (next_header == 6) decode_tcp(transport, transport_len);
        else if (next_header == 17) decode_udp(transport, transport_len);
    }
    // ARP
    else if (eth_type == 0x0806 && payload_len >= 28) {
        uint16_t htype = ntohs(*(uint16_t *)(payload + 0));
        uint16_t ptype = ntohs(*(uint16_t *)(payload + 2));
        uint8_t hlen = payload[4];
        uint8_t plen = payload[5];
        uint16_t oper = ntohs(*(uint16_t *)(payload + 6));
        const char *op_str = (oper==1)?"Request":(oper==2)?"Reply":"Unknown";

        printf("L3 (ARP): Operation: %s (%d) | Sender IP: %u.%u.%u.%u | Target IP: %u.%u.%u.%u\n",
               op_str, oper,
               payload[14], payload[15], payload[16], payload[17],
               payload[24], payload[25], payload[26], payload[27]);
        printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               payload[8],payload[9],payload[10],payload[11],payload[12],payload[13],
               payload[18],payload[19],payload[20],payload[21],payload[22],payload[23]);
        printf("HW Type: %u | Proto Type: 0x%04X | HW Len: %u | Proto Len: %u\n",
               htype, ptype, hlen, plen);
    }

    // Store packet
    if (packet_count < MAX_PACKETS) {
        StoredPacket *sp = (StoredPacket *)malloc(sizeof(StoredPacket));
        sp->header = *h;
        sp->data = (u_char *)malloc(h->caplen);
        memcpy(sp->data, bytes, h->caplen);
        packet_store[packet_count++] = sp;
    }
}

void sigint_handler(int signum) {
    (void)signum;
    if (g_capturing && g_handle) {
        fprintf(stdout, "\n[C-Shark] Ctrl+C received: stopping capture and returning to main menu...\n");
        pcap_breakloop(g_handle);
    } else {
        fprintf(stdout, "\n[C-Shark] Ctrl+C received: returning to main menu...\n");
    }
}

int list_devices(pcap_if_t **alldevsp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[C-Shark] Error finding devices: %s\n", errbuf);
        return -1;
    }

    if (!alldevs) {
        printf("[C-Shark] No interfaces found.\n");
        *alldevsp = NULL;
        return 0;
    }

    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces... Found!\n\n");

    int i = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        i++;
        printf("%d. %s", i, d->name);
        if (d->description && strlen(d->description) > 0) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }

    *alldevsp = alldevs;
    return i;
}

int get_input_line(char *buf, size_t bufsz) {
    if (!fgets(buf, (int)bufsz, stdin)) {
        if (feof(stdin)) return 1;
        return -1;
    }
    size_t L = strlen(buf);
    if (L > 0 && buf[L-1] == '\n') buf[L-1] = '\0';
    return 0;
}

int main() {
    signal(SIGINT, sigint_handler);

    char inbuf[256];

    while (1) {
        pcap_if_t *alldevs = NULL;
        int devcount = list_devices(&alldevs);
        if (devcount <= 0) {
            fprintf(stderr, "[C-Shark] No devices to select. Exiting.\n");
            return 1;
        }

        printf("\nSelect an interface to sniff (1-%d): ", devcount);
        fflush(stdout);
        int r = get_input_line(inbuf, sizeof(inbuf));
        if (r == 1) {
            printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
            pcap_freealldevs(alldevs);
            return 0;
        } else if (r == -1) {
            fprintf(stderr, "[C-Shark] Input read error. Exiting.\n");
            pcap_freealldevs(alldevs);
            return 1;
        }

        int choice = atoi(inbuf);
        if (choice < 1) {
            printf("[C-Shark] Invalid selection. Try again.\n\n");
            pcap_freealldevs(alldevs);
            continue;
        }
        pcap_if_t *selected = alldevs;
        for (int i = 1; i < choice && selected; ++i) selected = selected->next;
        if (!selected) {
            printf("[C-Shark] Selection out of range. Try again.\n\n");
            pcap_freealldevs(alldevs);
            continue;
        }

        printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", selected->name);
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Inspect Last Session\n");
        printf("4. Exit C-Shark\n");
        printf("\nSelect an option (1-4): ");
        fflush(stdout);

        r = get_input_line(inbuf, sizeof(inbuf));
        if (r == 1) {
            printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
            pcap_freealldevs(alldevs);
            return 0;
        } else if (r == -1) {
            fprintf(stderr, "[C-Shark] Input read error. Returning to interface selection.\n\n");
            pcap_freealldevs(alldevs);
            continue;
        }

        int opt = atoi(inbuf);
        if (opt == 4) {
            printf("[C-Shark] Exiting. Goodbye.\n");
            pcap_freealldevs(alldevs);
            return 0;
        } else if (opt == 1) {
            free_stored_packets();
            pkt_id = 0;
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *adhandle = pcap_open_live(selected->name, 65536, 1, 1000, errbuf);
            if (!adhandle) {
                fprintf(stderr, "[C-Shark] Unable to open device %s: %s\n", selected->name, errbuf);
                pcap_freealldevs(alldevs);
                continue;
            }

            printf("\n[C-Shark] Starting capture on '%s'.\n", selected->name);
            printf("[C-Shark] Press Ctrl+C to stop capture and return to menu. Ctrl+D anywhere to exit.\n");

            g_handle = adhandle;
            g_capturing = 1;
            int ret = pcap_loop(adhandle, -1, packet_handler, NULL);
            if (ret == 0) {
            } else if (ret == -1) {
                fprintf(stderr, "[C-Shark] Error during capture: %s\n", pcap_geterr(adhandle));
            } else if (ret == -2) {
            }

            g_capturing = 0;
            g_handle = NULL;

            pcap_close(adhandle);

            printf("\n[C-Shark] Capture stopped. Returning to main menu...\n\n");
            pcap_freealldevs(alldevs);
            continue;
        } else if (opt == 2) {
            free_stored_packets();
            pkt_id = 0;
            printf("\n[C-Shark] Enter a filter (HTTP, HTTPS, DNS, ARP, TCP, UDP): ");
            fflush(stdout);
            r = get_input_line(inbuf, sizeof(inbuf));
            if (r != 0) {
                printf("\n[C-Shark] Input cancelled. Returning to main menu.\n\n");
                pcap_freealldevs(alldevs);
                continue;
            }

            char filter_exp[128] = {0};
            if (strcasecmp(inbuf, "HTTP") == 0) {
                snprintf(filter_exp, sizeof(filter_exp), "tcp port 80");
            } else if (strcasecmp(inbuf, "HTTPS") == 0) {
                snprintf(filter_exp, sizeof(filter_exp), "tcp port 443");
            } else if (strcasecmp(inbuf, "DNS") == 0) {
                snprintf(filter_exp, sizeof(filter_exp), "udp port 53");
            } else if (strcasecmp(inbuf, "ARP") == 0) {
                snprintf(filter_exp, sizeof(filter_exp), "arp");
            } else if (strcasecmp(inbuf, "TCP") == 0) {
                snprintf(filter_exp, sizeof(filter_exp), "tcp");
            } else if (strcasecmp(inbuf, "UDP") == 0) {
                snprintf(filter_exp, sizeof(filter_exp), "udp");
            } else {
                printf("[C-Shark] Unknown filter '%s'. Returning to menu.\n\n", inbuf);
                pcap_freealldevs(alldevs);
                continue;
            }

            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *adhandle = pcap_open_live(selected->name, 65536, 1, 1000, errbuf);
            if (!adhandle) {
                fprintf(stderr, "[C-Shark] Unable to open device %s: %s\n", selected->name, errbuf);
                pcap_freealldevs(alldevs);
                continue;
            }

            struct bpf_program fp;
            if (pcap_compile(adhandle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
                fprintf(stderr, "[C-Shark] Error compiling filter '%s': %s\n", filter_exp, pcap_geterr(adhandle));
                pcap_close(adhandle);
                pcap_freealldevs(alldevs);
                continue;
            }

            if (pcap_setfilter(adhandle, &fp) == -1) {
                fprintf(stderr, "[C-Shark] Error setting filter: %s\n", pcap_geterr(adhandle));
                pcap_freecode(&fp);
                pcap_close(adhandle);
                pcap_freealldevs(alldevs);
                continue;
            }

            pcap_freecode(&fp);

            printf("\n[C-Shark] Starting capture on '%s' with filter '%s'.\n", selected->name, filter_exp);
            printf("[C-Shark] Press Ctrl+C to stop capture and return to menu.\n");

            g_handle = adhandle;
            g_capturing = 1;
            int ret = pcap_loop(adhandle, -1, packet_handler, NULL);
            if (ret == -1) {
                fprintf(stderr, "[C-Shark] Error during capture: %s\n", pcap_geterr(adhandle));
            }

            g_capturing = 0;
            g_handle = NULL;
            pcap_close(adhandle);

            printf("\n[C-Shark] Capture stopped. Returning to main menu...\n\n");
            pcap_freealldevs(alldevs);
        } else if (opt == 3) {
            if (packet_count == 0) {
                printf("[C-Shark] No packets captured in last session.\n\n");
                pcap_freealldevs(alldevs);
                continue;
            }

            print_packet_summary();

            printf("\nEnter Packet ID to inspect in detail (0 to return): ");
            fflush(stdout);
            char inbuf2[32];
            if (get_input_line(inbuf2, sizeof(inbuf2)) != 0) {
                printf("[C-Shark] Input cancelled.\n\n");
                pcap_freealldevs(alldevs);
                continue;
            }

            int pkt_id_inspect = atoi(inbuf2);
            if (pkt_id_inspect == 0) {
                pcap_freealldevs(alldevs);
                continue;
            }

            inspect_packet_detailed(pkt_id_inspect);

            printf("\nPress Enter to return to main menu...");
            get_input_line(inbuf2, sizeof(inbuf2));
            printf("\n");
            pcap_freealldevs(alldevs);
        } else {
            printf("[C-Shark] Invalid option. Try again.\n\n");
            pcap_freealldevs(alldevs);
        }
    }

    free_stored_packets();
    return 0;
}