#include "nat/nat_entry.h"

bool nat_entries_equal(struct nat_entry *entry_1, struct nat_entry *entry_2)
{
    if(entry_1->port_alloc != entry_2->port_alloc) {
        return false;
    }

    if(entry_1->addr_src != entry_2->addr_src) {
        return false;
    }

    if(entry_1->port_src != entry_2->port_src) {
        return false;
    }

    return true;
}
