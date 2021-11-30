#include "utils/includes.h"                 // System Includes

#include "utils/global.h"                   // Global Variables

#include "utils/kbhit.h"                    // Get Keyboard Hit (_kbhit)

#include "utils/t_protocols.h"              // Transport Layer Protocol Definitions

#include "utils/filter/filter_t.h"          // filter_t data type
#include "utils/filter/filterutils.h"       // PrintFilter, FilterPacket

#include "utils/process/packetlog.h"        // Log Packet contents into log file
#include "utils/process/packetflow.h"       // PrintPacketFlow

#include "utils/process/Flow/flow_t.h"      // flow_t and flowhead_t

void PrintUsage(const char*);
void ProcessPacket(const unsigned char* , int, int);

int main(int argc, char const *argv[])
{
    // Print Process ID to check Memory Usage
    printf("Process ID: %d\n", getpid());

    if (argc != 4) {
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

    int saddr_size, data_size;
    struct sockaddr saddr;
    filter_t filt;
    int direction;

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

    unsigned char *buffer = (unsigned char *)malloc(MAX_PACKET_SIZE);

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

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_raw < 0)
    {
        perror("Socket Error");
        return -1;
    }
    
    gettimeofday(&start, NULL);
    while (!_kbhit())
    {
        saddr_size = sizeof(saddr);

        data_size = recvfrom(sock_raw, buffer, MAX_PACKET_SIZE, 0, &saddr, (socklen_t *)&saddr_size);
        if (data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return -1;
        }

        // We only want to process packets that are in our filter
        // of IP Addresses
        direction = FilterPacket(buffer, data_size, &filt);
        if (direction != FILTER_REJECT) {
            ProcessPacket(buffer, data_size, direction);
        }
    }
    close(sock_raw);
    printf("Finished\n");
    return 0;
}

void PrintUsage(const char* bin)
{
    printf("Usage: ");
    printf("%s {IP Address 1} {IP Address 2} {Transport Layer Protocol (TCP or ICMP)}\n", bin);
    printf("Too see all packets to/from an IP Address, set both IP Address 1 = IP Address 2\n");
}

void ProcessPacket(const unsigned char *buffer, int size, int direction)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
    case T_ICMP: //ICMP Protocol
        ++icmp;
        log_icmp_packet(buffer, size);
        PrintPacketFlow(buffer, size, T_ICMP, direction, 1);
        break;

    case T_TCP: //TCP Protocol
        ++tcp;
        log_tcp_packet(buffer, size);
        PrintPacketFlow(buffer, size, T_TCP, direction, 1);
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
