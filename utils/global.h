#ifndef GLOBAL_H__
#define GLOBAL_H__

#include "includes.h"

#define MAX_PACKET_SIZE 65536

static FILE *logfile;
static struct sockaddr_in source, dest;
static int tcp = 0, udp = 0, icmp = 0, others = 0, total = 0;

static struct timeval start, end;
#endif