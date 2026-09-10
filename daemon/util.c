#include "util.h"

#include <ctype.h>
#include <stddef.h>

bool is_valid_ifname(const char *name)
{
    size_t len = 0;

    if (!name || !name[0]) {
        return false;
    }

    for (; name[len]; len++) {
        unsigned char c = (unsigned char)name[len];

        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' || c == '@')) {
            return false;
        }
    }

    return len < 16;
}
