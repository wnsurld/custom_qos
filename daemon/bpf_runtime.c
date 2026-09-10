#include "bpf_runtime.h"

#include "classifier.h"
#include "../bpf/flow_stats.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/pkt_cls.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <time.h>

#define MAX_TRACKED_FLOWS 8192
#define FLOW_IDLE_NS (30ULL * 1000ULL * 1000ULL * 1000ULL)

struct previous_flow {
    bool used;
    struct flow_key key;
    struct flow_stats stats;
    uint64_t polled_ms;
};

struct bpf_runtime {
    struct bpf_object *obj;
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;
    struct classifier_config classifier;
    int stats_map_fd;
    int policy_map_fd;
    struct previous_flow previous[MAX_TRACKED_FLOWS];
};

static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

static void raise_memlock_limit(void)
{
    struct rlimit limit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
        fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n", strerror(errno));
    }
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static bool flow_key_equal(const struct flow_key *a, const struct flow_key *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static struct previous_flow *find_previous(struct bpf_runtime *runtime, const struct flow_key *key)
{
    struct previous_flow *empty = NULL;
    size_t i;

    for (i = 0; i < MAX_TRACKED_FLOWS; i++) {
        if (runtime->previous[i].used && flow_key_equal(&runtime->previous[i].key, key)) {
            return &runtime->previous[i];
        }
        if (!runtime->previous[i].used && !empty) {
            empty = &runtime->previous[i];
        }
    }

    return empty;
}

static void forget_previous(struct bpf_runtime *runtime, const struct flow_key *key)
{
    size_t i;

    for (i = 0; i < MAX_TRACKED_FLOWS; i++) {
        if (runtime->previous[i].used && flow_key_equal(&runtime->previous[i].key, key)) {
            memset(&runtime->previous[i], 0, sizeof(runtime->previous[i]));
            return;
        }
    }
}

static enum flow_proto to_flow_proto(__u8 protocol)
{
    if (protocol == FLOW_PROTO_TCP) {
        return FLOW_TCP;
    }
    if (protocol == FLOW_PROTO_UDP) {
        return FLOW_UDP;
    }
    return FLOW_UNKNOWN;
}

static uint64_t delta_counter(uint64_t current, uint64_t previous)
{
    if (current < previous) {
        return 0;
    }
    return current - previous;
}

static struct flow_sample build_sample(const struct flow_key *key,
                                       const struct flow_stats *stats,
                                       const struct previous_flow *prev,
                                       uint64_t now_ms)
{
    uint64_t first_seen_ms = stats->first_seen_ns / 1000000ULL;
    uint64_t last_seen_ms = stats->last_seen_ns / 1000000ULL;
    uint64_t window_ms = prev && prev->used ? now_ms - prev->polled_ms : last_seen_ms - first_seen_ms;
    struct flow_sample sample = {
        .proto = to_flow_proto(key->protocol),
        .packets = prev && prev->used ? delta_counter(stats->packets, prev->stats.packets) : stats->packets,
        .bytes = prev && prev->used ? delta_counter(stats->bytes, prev->stats.bytes) : stats->bytes,
        .small_packets = prev && prev->used
            ? delta_counter(stats->small_packets, prev->stats.small_packets)
            : stats->small_packets,
        .large_packets = prev && prev->used
            ? delta_counter(stats->large_packets, prev->stats.large_packets)
            : stats->large_packets,
        .first_seen_ms = first_seen_ms,
        .last_seen_ms = last_seen_ms,
        .window_ms = window_ms > 0 ? window_ms : 1,
    };

    return sample;
}

static void remember_flow(struct previous_flow *prev,
                          const struct flow_key *key,
                          const struct flow_stats *stats,
                          uint64_t now_ms)
{
    prev->used = true;
    prev->key = *key;
    prev->stats = *stats;
    prev->polled_ms = now_ms;
}

static uint32_t class_id_for_traffic(enum traffic_class klass)
{
    switch (klass) {
    case TRAFFIC_REALTIME:
        return FLOW_CLASSID_REALTIME;
    case TRAFFIC_BULK:
        return FLOW_CLASSID_BULK;
    case TRAFFIC_UNKNOWN:
    default:
        return FLOW_CLASSID_NORMAL;
    }
}

static void update_policy(struct bpf_runtime *runtime,
                          const struct flow_key *key,
                          enum traffic_class klass,
                          uint64_t now_ms)
{
    struct flow_policy policy = {
        .class_id = class_id_for_traffic(klass),
        .updated_at_ms = (uint32_t)now_ms,
    };

    bpf_map_update_elem(runtime->policy_map_fd, key, &policy, BPF_ANY);
}

static int map_iter_error(int ret)
{
    if (ret == 0 || ret == -ENOENT || errno == ENOENT) {
        return 0;
    }
    if (ret < 0) {
        return ret;
    }
    return errno ? -errno : -EIO;
}

int bpf_runtime_open(struct bpf_runtime **out, const struct bpf_runtime_config *config)
{
    struct bpf_runtime *runtime;
    struct bpf_program *prog;
    struct bpf_map *map;
    int ifindex;
    int err;

    runtime = calloc(1, sizeof(*runtime));
    if (!runtime) {
        return -ENOMEM;
    }

    libbpf_set_print(libbpf_log);
    raise_memlock_limit();

    ifindex = if_nametoindex(config->wan_if);
    if (!ifindex) {
        fprintf(stderr, "unknown WAN interface: %s\n", config->wan_if);
        free(runtime);
        return -ENODEV;
    }

    runtime->obj = bpf_object__open_file(config->bpf_obj_path, NULL);
    err = libbpf_get_error(runtime->obj);
    if (err) {
        fprintf(stderr, "failed to open BPF object %s: %s\n",
                config->bpf_obj_path, strerror(-err));
        free(runtime);
        return err;
    }
    runtime->classifier = config->classifier;

    err = bpf_object__load(runtime->obj);
    if (err) {
        fprintf(stderr,
                "failed to load BPF object: %s. Check kernel BPF support, "
                "RLIMIT_MEMLOCK, and required kmods.\n",
                strerror(-err));
        bpf_runtime_close(runtime);
        return err;
    }

    map = bpf_object__find_map_by_name(runtime->obj, "flow_stats_map");
    if (!map) {
        fprintf(stderr, "missing BPF map: flow_stats_map\n");
        bpf_runtime_close(runtime);
        return -ENOENT;
    }
    runtime->stats_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(runtime->obj, "flow_policy_map");
    if (!map) {
        fprintf(stderr, "missing BPF map: flow_policy_map\n");
        bpf_runtime_close(runtime);
        return -ENOENT;
    }
    runtime->policy_map_fd = bpf_map__fd(map);

    prog = bpf_object__find_program_by_name(runtime->obj, "flowmon_tc");
    if (!prog) {
        fprintf(stderr, "missing BPF program: flowmon_tc\n");
        bpf_runtime_close(runtime);
        return -ENOENT;
    }

    runtime->hook.sz = sizeof(runtime->hook);
    runtime->hook.ifindex = ifindex;
    runtime->hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&runtime->hook);
    if (err && err != -EEXIST) {
        fprintf(stderr,
                "failed to create TC ingress hook on %s: %s. "
                "Check clsact support and tc-full/kmod-sched-bpf.\n",
                config->wan_if, strerror(-err));
        bpf_runtime_close(runtime);
        return err;
    }

    runtime->opts.sz = sizeof(runtime->opts);
    runtime->opts.prog_fd = bpf_program__fd(prog);
    runtime->opts.handle = 1;
    runtime->opts.priority = 10;

    bpf_tc_detach(&runtime->hook, &runtime->opts);
    err = bpf_tc_attach(&runtime->hook, &runtime->opts);
    if (err) {
        fprintf(stderr,
                "failed to attach BPF TC program on %s: %s. "
                "Check that clsact exists and no filter already uses handle 1/prio 10.\n",
                config->wan_if, strerror(-err));
        bpf_runtime_close(runtime);
        return err;
    }

    *out = runtime;
    return 0;
}

void bpf_runtime_close(struct bpf_runtime *runtime)
{
    if (!runtime) {
        return;
    }

    if (runtime->opts.sz && runtime->hook.sz) {
        bpf_tc_detach(&runtime->hook, &runtime->opts);
    }
    if (runtime->obj) {
        bpf_object__close(runtime->obj);
    }
    free(runtime);
}

int bpf_runtime_poll(struct bpf_runtime *runtime, struct bpf_poll_result *result)
{
    struct flow_key key;
    struct flow_key next_key;
    uint64_t now = monotonic_ms();
    int ret;

    memset(&key, 0, sizeof(key));
    memset(result, 0, sizeof(*result));

    errno = 0;
    ret = bpf_map_get_next_key(runtime->stats_map_fd, NULL, &next_key);
    while (ret == 0) {
        struct flow_stats stats;
        struct previous_flow *prev;
        bool delete_current = false;

        key = next_key;
        if (bpf_map_lookup_elem(runtime->stats_map_fd, &key, &stats) == 0) {
            prev = find_previous(runtime, &key);
            if (prev) {
                struct flow_sample sample = build_sample(&key, &stats, prev, now);
                struct classification classification = classify_flow(&sample, &runtime->classifier);

                if (classification.klass == TRAFFIC_REALTIME) {
                    result->has_realtime = true;
                    result->realtime_flows++;
                } else if (classification.klass == TRAFFIC_BULK) {
                    result->has_bulk = true;
                    result->bulk_flows++;
                } else {
                    result->unknown_flows++;
                }
                result->total_flows++;

                update_policy(runtime, &key, classification.klass, now);
                remember_flow(prev, &key, &stats, now);
            }

            if (stats.last_seen_ns + FLOW_IDLE_NS < (now * 1000000ULL)) {
                delete_current = true;
            }
        }

        errno = 0;
        ret = bpf_map_get_next_key(runtime->stats_map_fd, &key, &next_key);

        if (delete_current) {
            bpf_map_delete_elem(runtime->stats_map_fd, &key);
            bpf_map_delete_elem(runtime->policy_map_fd, &key);
            forget_previous(runtime, &key);
        }
    }

    return map_iter_error(ret);
}
