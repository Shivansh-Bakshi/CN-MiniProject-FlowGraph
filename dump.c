#include "utils/includes.h"                 // System Includes

#include "utils/global.h"                   // Global Variables

#include "utils/t_protocols.h"              // Transport Layer Protocol Definitions

#include "utils/filter/filter_t.h"          // filter_t data type
#include "utils/filter/filterutils.h"       // PrintFilter, FilterPacket

#include "utils/process/packetlog.h"        // Log Packet contents into log file
#include "utils/process/packetflow.h"       // PrintPacketFlow

#include "utils/process/Flow/flow_t.h"      // flow_t and flowhead_t


void PrintUsage(const char*);
void PacketHandler(u_char*, const struct pcap_pkthdr*, const u_char*);
void ProcessPacket(const u_char* , int, int);

filter_t filt;
int firstPack = 0;

int main(int argc, char const *argv[])
{
    // Print Process ID to check Memory Usage
    printf("Process ID: %d\n", getpid());

    if (argc != 5) {
        PrintUsage(argv[0]);
        return -1;
    }

    // Validate arguments as valid IP Addresses
    struct in_addr s_ip;
    int s_valid = inet_pton(AF_INET, argv[1], &s_ip);
    if (s_valid != 1) {
        printf("Given IP1 is not a valid IP Address\n");
    }
    struct in_addr d_ip;
    int d_valid = inet_pton(AF_INET, argv[2], &d_ip);
    if (d_valid != 1) {
        printf("Given IP2 is not a valid IP Address\n");
    }

    // Validate Transport Layer Protocol between TCP and ICMP
    int tp_valid = 0;
    if ((strcasecmp(argv[3], "TCP") == 0) || (strcasecmp(argv[3], "ICMP") == 0)) {
        tp_valid = 1;
    }
    else {
        printf("Given Transport Layer Protocol is not valid\n");
    }
    if (s_valid != 1 || d_valid != 1 || tp_valid != 1) {
        PrintUsage(argv[0]);
        return -1;
    }

    filt.source_ip = s_ip;
    filt.dest_ip = d_ip;
    if ((strcasecmp(argv[3], "TCP") == 0)) {
        filt.trans_protocol = T_TCP;
    }
    else if ((strcasecmp(argv[3], "ICMP") == 0)) {
        filt.trans_protocol = T_ICMP;
    }

    printf("Applying Filter:\n");
    PrintFilter(&filt);

    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    fp = pcap_open_offline(argv[4], errbuf);
    if (fp == NULL) {
        printf("pcap_open_offline() failed: %s\n", errbuf);
        return -1;
    }

    logfile = fopen("log.txt", "w");
    if (logfile == NULL)
    {
        printf("Unable to create log.txt file.\n");
    }
    printf("Starting...\n\n");

    flowhead_t fhd;
    fhd.ip1 = s_ip;
    fhd.ip2 = d_ip;
    PrintHeader(&fhd);

    if (pcap_loop(fp, 0, PacketHandler, NULL) < 0) {
        printf("pcap_loop() failed: %s\n", pcap_geterr(fp));
    }

    printf("Finished\n");
    return 0;
}

void PrintUsage(const char* bin)
{
    printf("Usage: ");
    printf("%s {IP Address 1} {IP Address 2} {Transport Layer Protocol (TCP or ICMP)} {Packet Dump filename}\n", bin);
    printf("Too see all packets to/from an IP Address, set both IP Address 1 = IP Address 2\n");
}

void PacketHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    int direction = FilterPacket(packet, pkthdr->len, &filt);
    if (direction != FILTER_REJECT) {
        if (firstPack == 0) {
            firstPack = 1;
            memcpy(&start, &(pkthdr->ts), sizeof(struct timeval));
        }
        memcpy(&end, &(pkthdr->ts), sizeof(struct timeval));
        ProcessPacket(packet, pkthdr->len, direction);
    }
}

void ProcessPacket(const u_char *buffer, int size, int direction)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
    case T_ICMP: //ICMP Protocol
        ++icmp;
        log_icmp_packet(buffer, size);
        PrintPacketFlow(buffer, size, T_ICMP, direction, 0);
        break;

    case T_TCP: //TCP Protocol
        ++tcp;
        log_tcp_packet(buffer, size);
        PrintPacketFlow(buffer, size, T_TCP, direction, 0);
        break;

    // case T_UDP: //UDP Protocol
    //     ++udp;
    //     log_udp_packet(buffer, size);
    //     break;

    default: //Some Other Protocol like ARP etc.
        ++others;
        break;
    }
    // printf("TCP : %d   UDP : %d   ICMP : %d   Others : %d   Total : %d\n", tcp, udp, icmp, others, total);
}
