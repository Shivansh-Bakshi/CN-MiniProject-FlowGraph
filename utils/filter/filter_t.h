#ifndef FILTER_T_H__
#define FILTER_T_H__

#include <arpa/inet.h>

#define T_PROTOCOL_SIZE 4

// Data type for filter on packets
typedef struct filter_t {

    // Source IP Address of the packet
    struct in_addr source_ip;

    // Destination IP Address of the packet
    struct in_addr dest_ip;

    // Name of the transport layer protocol used
    // Number - Name matching in t_protocols.h
    uint8_t trans_protocol;
}filter_t;

#endif