#ifndef FLOW_T_H__
#define FLOW_T_H__

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "../../t_protocols.h"

#define MAX_COMMENT_LEN 35
#define MAX_MESSAGE_LEN 20

#define FLOW_FORWARD 0
#define FLOW_BACKWARD 1

// Structure of an individual flow unit in flow graph
// When being printed, it will come as
// | timestamp_ms |                      message                    | comment
// |              | (port_source) --------------------> (port_dest) | 
// 
// Note that the arrow can be the other way around too.
typedef struct flow_t {

    // Timestamp of packet (in ms)
    double timestamp_ms;

    // Source Port Number of the packet
    // It is only printed if the tl_protocol is TCP
    // Else, it is garbage
    int port_source;

    // Destination Port Number of the packet
    // It is only printed if the tl_protocol is TCP
    // Else, it is garbage
    int port_dest;

    // Direction of arrow
    // Set it to FLOW_FORWARD or FLOW_BACKWARD
    int direction;

    // Transport Layer Protocol used by the packet
    int tl_protocol;

    // Messsage
    char message[MAX_MESSAGE_LEN];

    // Comments
    char comment[MAX_COMMENT_LEN];

}flow_t;

typedef struct flowhead_t {
    struct in_addr ip1;
    struct in_addr ip2;
}flowhead_t;

#endif