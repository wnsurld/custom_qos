#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdbool.h>
#include <stdint.h>

enum protect_state {
    STATE_IDLE = 0,
    STATE_WATCH,
    STATE_PROTECT,
    STATE_RECOVER,
};

struct detector_config {
    uint64_t trigger_delay_ms;
    uint64_t hold_time_ms;
};

struct detector {
    enum protect_state state;
    uint64_t conflict_since_ms;
    uint64_t protect_since_ms;
};

void detector_init(struct detector *detector);
enum protect_state detector_update(struct detector *detector,
                                   const struct detector_config *config,
                                   bool has_realtime,
                                   bool has_bulk,
                                   uint64_t now_ms);

#endif
