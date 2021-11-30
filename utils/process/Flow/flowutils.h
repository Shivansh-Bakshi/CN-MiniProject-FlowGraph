#ifndef FLOWUTILS_H__
#define FLOWUTILS_H__

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "../../t_protocols.h"
#include "flow_t.h"

void centerText(char *text, int fieldWidth) {
    int padlen = (fieldWidth - strlen(text)) / 2;
    printf("%*s%s%*s", padlen, "", text, padlen, "");
}

void PrintHeader(flowhead_t* fhd)
{
    char* s_ip = (char*)malloc(sizeof(struct in_addr));
    char* d_ip = (char*)malloc(sizeof(struct in_addr));

    strcpy(s_ip, inet_ntoa(fhd->ip1));
    strcpy(d_ip, inet_ntoa(fhd->ip2));

    printf("---------------------------------------------------------------------\n");
    centerText("Time", 10);
    printf("|");
    centerText(s_ip, 19);
    printf("|");
    centerText(d_ip, 19);
    printf("|\n");
    printf("---------------------------------------------------------------------\n");
}

void PrintFlow(flow_t* fl)
{
    char timestamp[10];
    sprintf(timestamp, "%9f", fl->timestamp_ms);
    centerText(timestamp, 10);
    printf(" |");
    centerText(fl->message, 36);
    printf(" |%-40s\n", fl->comment);


    if (fl->tl_protocol == T_TCP) {
        if (fl->direction == FLOW_FORWARD) {
            printf("%-10c| ", ' ');
            char port[5];
            sprintf(port, "%d", fl->port_source);
            centerText(port, 5);
            printf("  ---------------------> ");
            sprintf(port, "%d", fl->port_dest);
            centerText(port, 5);
            printf(" |\n");

        }
        else if (fl->direction == FLOW_BACKWARD) {
            char port[5];
            printf("%-10c| ", ' ');
            sprintf(port, "%d", fl->port_source);
            centerText(port, 5);
            printf("  <--------------------- ");
            sprintf(port, "%d", fl->port_dest);
            centerText(port, 5);
            printf(" |\n");
        }
    }
    else if (fl->tl_protocol == T_ICMP) {
        if (fl->direction == FLOW_FORWARD) {
            printf("%-10c| ----------------------------------> |\n", ' ');
        }
        else if (fl->direction == FLOW_BACKWARD) {
            printf("%-10c| <---------------------------------- |\n", ' ');
        }
    }
    printf("---------------------------------------------------------------------\n");
}

#endif