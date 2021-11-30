#ifndef PACKET_FLOW_H__
#define PACKET_FLOW_H__

#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>

#include "../t_protocols.h"
#include "../global.h"

#include "Flow/flow_t.h"
#include "Flow/flowutils.h"

void PrintICMPFlow(const unsigned char *, int, int, int);
void PrintTCPFlow(const unsigned char *, int, int, int);

void PrintPacketFlow(const unsigned char *buffer, int size, int protocol, int direction, int isRealtime)
{
    if (protocol == T_ICMP) {
        PrintICMPFlow(buffer, size, direction, isRealtime);
    }
    else if (protocol == T_TCP) {
        PrintTCPFlow(buffer, size, direction, isRealtime);
    }
}

void PrintICMPFlow(const unsigned char *buffer, int size, int direction, int isRealTime)
{
    double timestamp;
    if (isRealTime == 1){
        gettimeofday(&end, NULL);
    }
    timestamp = (double)(end.tv_usec - start.tv_usec) / 1000000 + (double)(end.tv_sec - start.tv_sec);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    char message[MAX_MESSAGE_LEN];
    char comment[MAX_COMMENT_LEN];

    sprintf(message, "[ICMP] Type:%d", (unsigned int)(icmph->type));
    sprintf(comment, "Identification: %d; TTL: %d", ntohs(iph->id), (unsigned int)(iph->ttl));

    flow_t fl;
    fl.timestamp_ms = timestamp;
    fl.port_source = 0;
    fl.port_dest = 0;
    fl.tl_protocol = T_ICMP;
    fl.direction = direction;
    strcpy(fl.message, message);
    strcpy(fl.comment, comment);

    PrintFlow(&fl);
}

void PrintTCPFlow(const unsigned char *buffer, int size, int direction, int isRealTime)
{
    double timestamp;
    if (isRealTime == 1) {
        gettimeofday(&end, NULL);
    }
    timestamp = (double)(end.tv_usec - start.tv_usec) / 1000000 + (double)(end.tv_sec - start.tv_sec);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    char message[MAX_MESSAGE_LEN];
    strcpy(message, "");

    if ((unsigned int)tcph->syn == 1) {
        strcat(message, "SYN,");
    }
    if ((unsigned int)tcph->ack == 1) {
        strcat(message, "ACK,");
    }
    if ((unsigned int)tcph->psh == 1) {
        strcat(message, "PSH,");
    }
    strcat(message, "Len:");
    char hdrLen[6];
    sprintf(hdrLen, "%d", tcph->doff * 4);
    strcat(message, hdrLen);

    char comment[MAX_COMMENT_LEN];
    sprintf(comment, "Seq: %u; Ack: %u", ntohl(tcph->seq), ntohl(tcph->ack_seq));

    flow_t fl;
    fl.timestamp_ms = timestamp;
    fl.port_source = ntohs(tcph->source);
    fl.port_dest = ntohs(tcph->dest);
    fl.tl_protocol = T_TCP;
    fl.direction = direction;
    strcpy(fl.message, message);
    strcpy(fl.comment, comment);

    PrintFlow(&fl);
}
#endif