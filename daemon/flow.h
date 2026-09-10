#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>

enum flow_proto {
    FLOW_UNKNOWN = 0,
    FLOW_TCP = 6,
    FLOW_UDP = 17,
};

struct flow_sample {
    enum flow_proto proto;
    uint64_t packets;
    uint64_t bytes;
    uint64_t small_packets;
    uint64_t large_packets;
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    uint64_t window_ms;
};

struct flow_features {
    double bytes_per_sec;
    double packets_per_sec;
    double avg_packet_size;
    double small_packet_ratio;
    double large_packet_ratio;
    double active_seconds;
};

#endif
