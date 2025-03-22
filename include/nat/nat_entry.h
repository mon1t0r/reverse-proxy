#ifndef REV_PROXY_NAT_ENTRY_H
#define REV_PROXY_NAT_ENTRY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

struct nat_entry {
    uint16_t port_src;
    uint32_t addr_src;
    uint16_t port_alloc;
    time_t alloc_time;
};

bool nat_entries_equal(struct nat_entry *entry_1, struct nat_entry *entry_2);

#endif
