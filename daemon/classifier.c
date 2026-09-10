#include "classifier.h"

#include "config.h"

static double ratio(uint64_t part, uint64_t total)
{
    if (total == 0) {
        return 0.0;
    }
    return (double)part / (double)total;
}

static struct flow_features build_features(const struct flow_sample *sample)
{
    double seconds = sample->window_ms > 0 ? (double)sample->window_ms / 1000.0 : 1.0;
    struct flow_features features = {0};

    features.bytes_per_sec = (double)sample->bytes / seconds;
    features.packets_per_sec = (double)sample->packets / seconds;
    features.avg_packet_size = sample->packets > 0
        ? (double)sample->bytes / (double)sample->packets
        : 0.0;
    features.small_packet_ratio = ratio(sample->small_packets, sample->packets);
    features.large_packet_ratio = ratio(sample->large_packets, sample->packets);
    features.active_seconds = sample->last_seen_ms > sample->first_seen_ms
        ? (double)(sample->last_seen_ms - sample->first_seen_ms) / 1000.0
        : 0.0;

    return features;
}

struct classification classify_flow(const struct flow_sample *sample,
                                    const struct classifier_config *config)
{
    struct classification result = {0};
    const double realtime_max_bps = (double)config->realtime_max_kbps * 1024.0;
    const double bulk_min_bps = (double)config->bulk_min_kbps * 1024.0;

    result.features = build_features(sample);

    if (sample->proto == FLOW_UDP) {
        result.realtime_score += 1;
    }
    if (sample->proto == FLOW_TCP) {
        result.bulk_score += 1;
    }

    if (result.features.avg_packet_size <= 350.0) {
        result.realtime_score += 2;
    }
    if (result.features.small_packet_ratio >= 0.60) {
        result.realtime_score += 2;
    }
    if (result.features.bytes_per_sec <= realtime_max_bps) {
        result.realtime_score += 2;
    }
    if (result.features.packets_per_sec >= (double)config->realtime_min_pps &&
        result.features.packets_per_sec <= (double)config->realtime_max_pps) {
        result.realtime_score += 2;
    }

    if (result.features.bytes_per_sec >= bulk_min_bps) {
        result.bulk_score += 3;
    }
    if (result.features.large_packet_ratio >= 0.60) {
        result.bulk_score += 2;
    }
    if (result.features.avg_packet_size >= LARGE_PACKET_BYTES) {
        result.bulk_score += 2;
    }
    if (result.features.active_seconds >= 2.0) {
        result.bulk_score += 1;
    }
    if (result.features.small_packet_ratio < 0.30) {
        result.bulk_score += 1;
    }

    if (result.bulk_score >= (int)config->bulk_score_threshold &&
        result.bulk_score > result.realtime_score) {
        result.klass = TRAFFIC_BULK;
    } else if (result.realtime_score >= (int)config->realtime_score_threshold &&
               result.realtime_score > result.bulk_score) {
        result.klass = TRAFFIC_REALTIME;
    } else {
        result.klass = TRAFFIC_UNKNOWN;
    }

    return result;
}
