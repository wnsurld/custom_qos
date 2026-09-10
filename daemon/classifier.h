#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include "flow.h"

enum traffic_class {
    TRAFFIC_UNKNOWN = 0,
    TRAFFIC_REALTIME,
    TRAFFIC_BULK,
};

struct classifier_config {
    unsigned int realtime_max_kbps;
    unsigned int bulk_min_kbps;
    unsigned int realtime_min_pps;
    unsigned int realtime_max_pps;
    unsigned int realtime_score_threshold;
    unsigned int bulk_score_threshold;
};

struct classification {
    enum traffic_class klass;
    int realtime_score;
    int bulk_score;
    struct flow_features features;
};

struct classification classify_flow(const struct flow_sample *sample,
                                    const struct classifier_config *config);

#endif
