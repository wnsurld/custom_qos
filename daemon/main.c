#include "bpf_runtime.h"
#include "classifier.h"
#include "config.h"
#include "controller.h"
#include "detector.h"
#include "util.h"

#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void handle_signal(int signal)
{
    (void)signal;
    stop_requested = 1;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static const char *state_name(enum protect_state state)
{
    switch (state) {
    case STATE_IDLE:
        return "IDLE";
    case STATE_WATCH:
        return "WATCH";
    case STATE_PROTECT:
        return "PROTECT";
    case STATE_RECOVER:
        return "RECOVER";
    }
    return "UNKNOWN";
}

static void read_mock_flow_snapshot(const struct classifier_config *classifier_config,
                                    bool *has_realtime,
                                    bool *has_bulk)
{
    static int tick;
    struct flow_sample realtime = {
        .proto = FLOW_UDP,
        .packets = 80,
        .bytes = 12000,
        .small_packets = 80,
        .large_packets = 0,
        .first_seen_ms = 0,
        .last_seen_ms = 3000,
        .window_ms = 1000,
    };
    struct flow_sample bulk = {
        .proto = FLOW_TCP,
        .packets = 2500,
        .bytes = 3500000,
        .small_packets = 20,
        .large_packets = 2200,
        .first_seen_ms = 0,
        .last_seen_ms = 3000,
        .window_ms = 1000,
    };
    struct classification rt_result = classify_flow(&realtime, classifier_config);
    struct classification bulk_result = classify_flow(&bulk, classifier_config);

    tick++;
    *has_realtime = tick >= 2 && tick <= 16 && rt_result.klass == TRAFFIC_REALTIME;
    *has_bulk = tick >= 3 && tick <= 12 && bulk_result.klass == TRAFFIC_BULK;
}

int main(int argc, char **argv)
{
    const char *wan_if = DEFAULT_WAN_IF;
    const char *bpf_obj_path = "build/flowmon.bpf.o";
    uint64_t poll_interval_ms = DEFAULT_POLL_INTERVAL_MS;
    uint64_t log_interval_ms = DEFAULT_LOG_INTERVAL_MS;
    uint64_t last_log_ms = 0;
    bool mock_mode = false;
    struct bpf_runtime *bpf_runtime = NULL;
    struct detector detector;
    struct controller controller;
    struct detector_config detector_config = {
        .trigger_delay_ms = DEFAULT_TRIGGER_DELAY_MS,
        .hold_time_ms = DEFAULT_HOLD_TIME_MS,
    };
    struct controller_config controller_config = {
        .ifb_if = DEFAULT_IFB_IF,
        .line_rate_mbit = DEFAULT_LINE_RATE_MBIT,
        .protect_rate_mbit = DEFAULT_PROTECT_RATE_MBIT,
        .recover_step_mbit = DEFAULT_RECOVER_STEP_MBIT,
        .dry_run = true,
    };
    struct classifier_config classifier_config = {
        .realtime_max_kbps = DEFAULT_REALTIME_MAX_KBPS,
        .bulk_min_kbps = DEFAULT_BULK_MIN_KBPS,
        .realtime_min_pps = DEFAULT_REALTIME_MIN_PPS,
        .realtime_max_pps = DEFAULT_REALTIME_MAX_PPS,
        .realtime_score_threshold = DEFAULT_REALTIME_SCORE_THRESHOLD,
        .bulk_score_threshold = DEFAULT_BULK_SCORE_THRESHOLD,
    };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--apply") == 0) {
            controller_config.dry_run = false;
        } else if (strcmp(argv[i], "--mock") == 0) {
            mock_mode = true;
        } else if (strcmp(argv[i], "--wan") == 0 && i + 1 < argc) {
            wan_if = argv[++i];
        } else if (strcmp(argv[i], "--ifb") == 0 && i + 1 < argc) {
            controller_config.ifb_if = argv[++i];
        } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
            bpf_obj_path = argv[++i];
        } else if (strcmp(argv[i], "--line-rate") == 0 && i + 1 < argc) {
            controller_config.line_rate_mbit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--protect-rate") == 0 && i + 1 < argc) {
            controller_config.protect_rate_mbit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--recover-step") == 0 && i + 1 < argc) {
            controller_config.recover_step_mbit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--trigger-delay") == 0 && i + 1 < argc) {
            detector_config.trigger_delay_ms = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--hold-time") == 0 && i + 1 < argc) {
            detector_config.hold_time_ms = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--realtime-max-kbps") == 0 && i + 1 < argc) {
            classifier_config.realtime_max_kbps = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--bulk-min-kbps") == 0 && i + 1 < argc) {
            classifier_config.bulk_min_kbps = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--realtime-min-pps") == 0 && i + 1 < argc) {
            classifier_config.realtime_min_pps = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--realtime-max-pps") == 0 && i + 1 < argc) {
            classifier_config.realtime_max_pps = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--realtime-score") == 0 && i + 1 < argc) {
            classifier_config.realtime_score_threshold = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--bulk-score") == 0 && i + 1 < argc) {
            classifier_config.bulk_score_threshold = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--poll-interval") == 0 && i + 1 < argc) {
            poll_interval_ms = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--log-interval") == 0 && i + 1 < argc) {
            log_interval_ms = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else {
            fprintf(stderr,
                    "usage: %s [--mock] [--apply] [--wan IFACE] [--ifb IFACE] "
                    "[--bpf OBJ] [--line-rate MBIT] [--protect-rate MBIT] "
                    "[--recover-step MBIT] [--trigger-delay MS] [--hold-time MS] "
                    "[--realtime-max-kbps KBPS] [--bulk-min-kbps KBPS] "
                    "[--realtime-min-pps PPS] [--realtime-max-pps PPS] "
                    "[--realtime-score N] [--bulk-score N] "
                    "[--poll-interval MS] [--log-interval MS]\n",
                    argv[0]);
            return 2;
        }
    }

    if (controller_config.line_rate_mbit <= 0 ||
        controller_config.protect_rate_mbit <= 0 ||
        controller_config.recover_step_mbit <= 0 ||
        controller_config.protect_rate_mbit > controller_config.line_rate_mbit ||
        detector_config.trigger_delay_ms == 0 ||
        detector_config.hold_time_ms == 0 ||
        classifier_config.realtime_max_kbps == 0 ||
        classifier_config.bulk_min_kbps == 0 ||
        classifier_config.realtime_min_pps > classifier_config.realtime_max_pps ||
        classifier_config.realtime_score_threshold == 0 ||
        classifier_config.bulk_score_threshold == 0 ||
        poll_interval_ms == 0 ||
        log_interval_ms == 0) {
        fprintf(stderr, "invalid configuration\n");
        return 2;
    }

    if (!is_valid_ifname(wan_if) || !is_valid_ifname(controller_config.ifb_if)) {
        fprintf(stderr, "invalid interface name\n");
        return 2;
    }

    detector_init(&detector);
    controller_init(&controller, &controller_config);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (!mock_mode) {
        struct bpf_runtime_config bpf_config = {
            .wan_if = wan_if,
            .bpf_obj_path = bpf_obj_path,
            .classifier = classifier_config,
        };
        int err = bpf_runtime_open(&bpf_runtime, &bpf_config);
        if (err) {
            return 1;
        }
    }

    printf("adaptive latency protection daemon starting (%s, %s)\n",
           controller_config.dry_run ? "dry-run" : "apply",
           mock_mode ? "mock flows" : "BPF map polling");
    printf("wan=%s ifb=%s line_rate=%dmbit protect_rate=%dmbit recover_step=%dmbit\n",
           wan_if, controller_config.ifb_if, controller_config.line_rate_mbit,
           controller_config.protect_rate_mbit, controller_config.recover_step_mbit);
    printf("trigger_delay=%llums hold_time=%llums\n",
           (unsigned long long)detector_config.trigger_delay_ms,
           (unsigned long long)detector_config.hold_time_ms);
    printf("poll_interval=%llums log_interval=%llums\n",
           (unsigned long long)poll_interval_ms,
           (unsigned long long)log_interval_ms);
    printf("classifier realtime_max=%ukbps bulk_min=%ukbps realtime_pps=%u-%u scores(rt=%u bulk=%u)\n",
           classifier_config.realtime_max_kbps, classifier_config.bulk_min_kbps,
           classifier_config.realtime_min_pps, classifier_config.realtime_max_pps,
           classifier_config.realtime_score_threshold, classifier_config.bulk_score_threshold);

    while (!stop_requested) {
        bool has_realtime = false;
        bool has_bulk = false;
        struct bpf_poll_result poll_result = {0};
        enum protect_state state;
        uint64_t loop_now_ms = now_ms();

        if (mock_mode) {
            read_mock_flow_snapshot(&classifier_config, &has_realtime, &has_bulk);
        } else if (bpf_runtime_poll(bpf_runtime, &poll_result) != 0) {
            fprintf(stderr, "failed to poll BPF map\n");
        } else {
            has_realtime = poll_result.has_realtime;
            has_bulk = poll_result.has_bulk;
        }
        state = detector_update(&detector, &detector_config, has_realtime, has_bulk, loop_now_ms);

        if (state == STATE_PROTECT) {
            controller_set_protect(&controller, &controller_config);
        } else if (state == STATE_RECOVER) {
            controller_step_recover(&controller, &controller_config);
            if (controller_is_recovered(&controller, &controller_config)) {
                detector_init(&detector);
                state = STATE_IDLE;
            }
        }

        if (loop_now_ms - last_log_ms >= log_interval_ms) {
            last_log_ms = loop_now_ms;
            if (mock_mode) {
                printf("state=%s realtime=%d bulk=%d bulk_rate=%dmbit\n",
                       state_name(state), has_realtime, has_bulk,
                       controller.current_bulk_rate_mbit);
            } else {
                printf("state=%s realtime=%u bulk=%u unknown=%u total=%u bulk_rate=%dmbit\n",
                       state_name(state), poll_result.realtime_flows, poll_result.bulk_flows,
                       poll_result.unknown_flows, poll_result.total_flows,
                       controller.current_bulk_rate_mbit);
            }
        }

        usleep((useconds_t)(poll_interval_ms * 1000));
    }

    bpf_runtime_close(bpf_runtime);
    printf("adaptive latency protection daemon stopped\n");
    return 0;
}
