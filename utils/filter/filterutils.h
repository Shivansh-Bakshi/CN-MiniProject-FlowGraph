#ifndef FILTERUTILS_H__
#define FILTERUTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>

#include "filter_t.h"

#define FILTER_FORWARD 0
#define FILTER_BACKWARD 1
#define FILTER_REJECT -1

void PrintFilter(filter_t* filt)
{
    printf("Source IP Address: %s\n", inet_ntoa(filt->source_ip));
    printf("Destination IP Address: %s\n", inet_ntoa(filt->dest_ip));
    printf("Transport Layer Protocol: %d\n", filt->trans_protocol);
}

int FilterPacket(const unsigned char *buffer, int size, filter_t* filt)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    if (iph->protocol != filt->trans_protocol) {
        return FILTER_REJECT;
    }

    char* s_ip = (char*)malloc(sizeof(struct in_addr));
    char* d_ip = (char*)malloc(sizeof(struct in_addr));

    char* f_s_ip = (char*)malloc(sizeof(struct in_addr));
    char* f_d_ip = (char*)malloc(sizeof(struct in_addr));

    int sourceMatch = 0;
    int destMatch = 0;
    int req = 0;
    int resp = 0;
    struct sockaddr_in s_temp, d_temp;

    memset(&s_temp, 0, sizeof(s_temp));
    s_temp.sin_addr.s_addr = iph->saddr;

    memset(&d_temp, 0, sizeof(d_temp));
    d_temp.sin_addr.s_addr = iph->daddr;

    strcpy(s_ip, inet_ntoa(s_temp.sin_addr));
    strcpy(d_ip, inet_ntoa(d_temp.sin_addr));
    strcpy(f_s_ip, inet_ntoa(filt->source_ip));
    strcpy(f_d_ip, inet_ntoa(filt->dest_ip));


    // Check if the packet is valid request or response
    if (strcmp(f_s_ip, s_ip) == 0) {
        sourceMatch = 1;
    }

    if (strcmp(f_d_ip, d_ip) == 0) {
        destMatch = 1;
    }

    if (sourceMatch == 1 && destMatch == 1) {
        return FILTER_FORWARD;
    }
    else {
        if (strcmp(f_s_ip, d_ip) == 0) {
            sourceMatch = 1;
        }

        if (strcmp(f_d_ip, s_ip) == 0) {
            destMatch = 1;
        }

        if (sourceMatch == 1 && destMatch == 1) {
            return FILTER_BACKWARD;
        }
    }
    return FILTER_REJECT;
}

#endif