#include "detector.h"

void detector_init(struct detector *detector)
{
    detector->state = STATE_IDLE;
    detector->conflict_since_ms = 0;
    detector->protect_since_ms = 0;
}

enum protect_state detector_update(struct detector *detector,
                                   const struct detector_config *config,
                                   bool has_realtime,
                                   bool has_bulk,
                                   uint64_t now_ms)
{
    bool conflict = has_realtime && has_bulk;

    switch (detector->state) {
    case STATE_IDLE:
        if (conflict) {
            detector->state = STATE_WATCH;
            detector->conflict_since_ms = now_ms;
        }
        break;
    case STATE_WATCH:
        if (!conflict) {
            detector->state = STATE_IDLE;
            detector->conflict_since_ms = 0;
            break;
        }
        if (now_ms - detector->conflict_since_ms >= config->trigger_delay_ms) {
            detector->state = STATE_PROTECT;
            detector->protect_since_ms = now_ms;
        }
        break;
    case STATE_PROTECT:
        if (!conflict && now_ms - detector->protect_since_ms >= config->hold_time_ms) {
            detector->state = STATE_RECOVER;
        }
        break;
    case STATE_RECOVER:
        if (conflict) {
            detector->state = STATE_PROTECT;
            detector->protect_since_ms = now_ms;
        }
        break;
    }

    return detector->state;
}
