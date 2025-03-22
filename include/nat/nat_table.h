#ifndef REV_PROXY_NAT_TABLE_H
#define REV_PROXY_NAT_TABLE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "nat/nat_entry.h"

typedef struct nat_table nat_table;

nat_table *nat_table_alloc(size_t size);

struct nat_entry *nat_table_insert(nat_table *table, struct nat_entry entry);

struct nat_entry *nat_table_get_by_src(nat_table *table, uint16_t port_src, uint32_t addr_src);

struct nat_entry *nat_table_get_by_alloc(nat_table *table, uint16_t port_alloc);

void nat_table_free(nat_table *table);

#endif
