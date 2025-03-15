#ifndef REV_PROXY_NAT_TABLE_H
#define REV_PROXY_NAT_TABLE_H

#include <stdint.h>
#include <time.h>

struct nat_entry {
    uint16_t src_port;
    uint32_t src_ip;
    uint16_t alloc_port;
    time_t alloc_time;
};

struct nat_node {
    struct nat_entry *entry;
    struct nat_node *next;
};

struct nat_table {
    size_t size;
    struct nat_node **src_to_alloc_map;
    struct nat_node **alloc_to_src_map;
};

struct nat_table *nat_table_alloc(size_t size);

struct nat_entry *nat_table_insert(struct nat_table *table, struct nat_entry entry);

struct nat_entry *nat_table_get_by_src(struct nat_table *table, uint16_t src_port, uint32_t src_ip);

struct nat_entry *nat_table_get_by_alloc(struct nat_table *table, uint16_t alloc_port);

void nat_table_free(struct nat_table *table);

#endif
