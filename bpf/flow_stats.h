#ifndef FLOW_STATS_H
#define FLOW_STATS_H

#include <linux/types.h>

#define FLOW_PROTO_TCP 6
#define FLOW_PROTO_UDP 17

#define FLOW_CLASS_UNKNOWN 0
#define FLOW_CLASS_REALTIME 1
#define FLOW_CLASS_NORMAL 2
#define FLOW_CLASS_BULK 3

#define FLOW_CLASSID_REALTIME 0x00010010
#define FLOW_CLASSID_NORMAL 0x00010020
#define FLOW_CLASSID_BULK 0x00010030

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 small_packets;
    __u64 large_packets;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
};

struct flow_policy {
    __u32 class_id;
    __u32 updated_at_ms;
};

#endif
