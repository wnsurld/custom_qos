#ifndef BPF_RUNTIME_H
#define BPF_RUNTIME_H

#include <stdbool.h>

#include "classifier.h"

struct bpf_runtime;

struct bpf_runtime_config {
    const char *wan_if;
    const char *bpf_obj_path;
    struct classifier_config classifier;
};

struct bpf_poll_result {
    bool has_realtime;
    bool has_bulk;
    unsigned int realtime_flows;
    unsigned int bulk_flows;
    unsigned int unknown_flows;
    unsigned int total_flows;
};

int bpf_runtime_open(struct bpf_runtime **runtime, const struct bpf_runtime_config *config);
void bpf_runtime_close(struct bpf_runtime *runtime);
int bpf_runtime_poll(struct bpf_runtime *runtime, struct bpf_poll_result *result);

#endif
