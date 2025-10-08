#ifndef CSHARK_H
#define CSHARK_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <signal.h>
#include <time.h>

#define MAX_PACKETS 10000

// ✅ Packet storage structure
typedef struct {
    struct pcap_pkthdr header;
    const u_char *packet;
    u_char *packet_copy;
} PacketInfo;

// ✅ Function declarations
int list_devices(pcap_if_t **alldevsp); // Updated to match the definition
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_summary();
void inspect_packet_detailed(int index);
void print_hex_ascii_with_offset(const u_char *data, int length);
void decode_tcp(const u_char *packet, int offset);
void decode_udp(const u_char *packet, int offset);
void free_stored_packets();
void sigint_handler(int sig);
const char *app_protocol(uint16_t port); // Updated to match the definition

// ✅ Global variables
extern PacketInfo *stored_packets[MAX_PACKETS];
extern int packet_count;
extern volatile int stop_capture;

#endif // CSHARK_H
