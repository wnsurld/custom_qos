#include "controller.h"

#include <stdio.h>
#include <stdlib.h>

static int apply_bulk_rate(const struct controller_config *config, int rate_mbit)
{
    char command[256];

    snprintf(command, sizeof(command),
             "tc class change dev %s parent 1:1 classid 1:30 htb rate %dmbit ceil %dmbit prio 2",
             config->ifb_if, rate_mbit, rate_mbit);

    if (config->dry_run) {
        printf("[dry-run] %s\n", command);
        return 0;
    }

    return system(command);
}

void controller_init(struct controller *controller, const struct controller_config *config)
{
    controller->current_bulk_rate_mbit = config->line_rate_mbit;
}

int controller_set_protect(struct controller *controller, const struct controller_config *config)
{
    if (controller->current_bulk_rate_mbit == config->protect_rate_mbit) {
        return 0;
    }

    controller->current_bulk_rate_mbit = config->protect_rate_mbit;
    return apply_bulk_rate(config, controller->current_bulk_rate_mbit);
}

int controller_step_recover(struct controller *controller, const struct controller_config *config)
{
    int next = controller->current_bulk_rate_mbit + config->recover_step_mbit;

    if (next > config->line_rate_mbit) {
        next = config->line_rate_mbit;
    }

    if (next == controller->current_bulk_rate_mbit) {
        return 0;
    }

    controller->current_bulk_rate_mbit = next;
    return apply_bulk_rate(config, controller->current_bulk_rate_mbit);
}

bool controller_is_recovered(const struct controller *controller,
                             const struct controller_config *config)
{
    return controller->current_bulk_rate_mbit >= config->line_rate_mbit;
}
