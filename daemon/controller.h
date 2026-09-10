#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stdbool.h>

struct controller_config {
    const char *ifb_if;
    int line_rate_mbit;
    int protect_rate_mbit;
    int recover_step_mbit;
    bool dry_run;
};

struct controller {
    int current_bulk_rate_mbit;
};

void controller_init(struct controller *controller, const struct controller_config *config);
int controller_set_protect(struct controller *controller, const struct controller_config *config);
int controller_step_recover(struct controller *controller, const struct controller_config *config);
bool controller_is_recovered(const struct controller *controller,
                             const struct controller_config *config);

#endif
