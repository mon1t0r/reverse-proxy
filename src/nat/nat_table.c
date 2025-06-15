#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "nat/nat_table.h"
#include "nat/nat_map.h"

struct nat_table {
    nat_map *src_to_alloc_map;
    nat_map *alloc_to_src_map;
};

static bool cond_src_to_alloc(struct nat_entry entry, const void *data_ptr);
static bool cond_alloc_to_src(struct nat_entry entry, const void *data_ptr);

static size_t hash_src(uint16_t port_src, uint32_t addr_src, size_t size);
static size_t hash_alloc(uint16_t dst_port, size_t size);
static unsigned int hash_num(unsigned int x);

nat_table *nat_table_alloc(size_t size)
{
    nat_table *table;

    if(size == 0) {
        return NULL;
    }

    table = malloc(sizeof(nat_table));

    if(table == NULL) {
        return NULL;
    }

    table->src_to_alloc_map = nat_map_alloc(size);
    if(table->src_to_alloc_map == NULL) {
        goto err;
    }

    table->alloc_to_src_map = nat_map_alloc(size);
    if(table->alloc_to_src_map == NULL) {
        nat_map_free(table->src_to_alloc_map, NULL);
        goto err;
    }

    return table;

err:
    free(table);
    return NULL;
}

struct nat_entry *nat_table_insert(nat_table *table, struct nat_entry entry)
{
    struct nat_entry *entry_new;

    size_t src_hash;
    size_t alloc_hash;

    if(table == NULL) {
        return NULL;
    }

    entry_new = malloc(sizeof(struct nat_entry));
    if(entry_new == NULL) {
        return NULL;
    }
    memcpy(entry_new, &entry, sizeof(struct nat_entry));

    src_hash = hash_src(entry.port_src, entry.addr_src,
                        nat_map_get_size(table->src_to_alloc_map));
    alloc_hash = hash_alloc(entry.port_alloc,
                            nat_map_get_size(table->alloc_to_src_map));

    if(!nat_map_insert(table->src_to_alloc_map, entry_new, src_hash)) {
        goto err;
    }

    if(!nat_map_insert(table->alloc_to_src_map, entry_new, alloc_hash)) {
        goto err;
    }

    return entry_new;

err:
    free(entry_new);
    return NULL;
}

/* Do not change values of the returned reference except timestamp. */
struct nat_entry *nat_table_get_by_src(nat_table *table, uint16_t port_src,
                                       uint32_t addr_src)
{
    size_t index;
    uint64_t data;

    if(table == NULL) {
        return NULL;
    }

    index = hash_src(port_src, addr_src,
                     nat_map_get_size(table->src_to_alloc_map));

    data = port_src;
    data <<= 32;
    data |= addr_src;

    return nat_map_find(table->src_to_alloc_map, index, &data,
                        &cond_src_to_alloc);
}

/* Do not change values of the returned reference except timestamp. */
struct nat_entry *nat_table_get_by_alloc(nat_table *table,
                                         uint16_t port_alloc)
{
    size_t index;

    if(table == NULL) {
        return NULL;
    }

    index = hash_alloc(port_alloc, nat_map_get_size(table->alloc_to_src_map));

    return nat_map_find(table->alloc_to_src_map, index, &port_alloc,
                        &cond_alloc_to_src);
}

bool nat_table_remove_if(nat_table *table, const void *data_ptr,
                         nat_table_remove_condition condition)
{
    bool result;

    if(table == NULL || condition == NULL) {
        return false;
    }

    /* Two calls must return the same value,
     * otherwise the table data is damaged */
    result = nat_map_remove_if(table->src_to_alloc_map, data_ptr, condition,
                               NULL);
    result &= nat_map_remove_if(table->alloc_to_src_map, data_ptr, condition,
                                (nat_map_free_callback) &free);

    return result;
}

void nat_table_free(nat_table *table)
{
    if(table == NULL) {
        return;
    }

    nat_map_free(table->src_to_alloc_map, NULL);
    nat_map_free(table->alloc_to_src_map, (nat_map_free_callback) &free);

    free(table);
}

static bool cond_src_to_alloc(struct nat_entry entry, const void *data_ptr)
{
    const uint64_t *nat_data_ptr;
    uint32_t addr_src;
    uint16_t port_src;

    nat_data_ptr = data_ptr;

    addr_src = *nat_data_ptr & 0xFFFFFFFF;
    port_src = *nat_data_ptr >> 32;

    return entry.addr_src == addr_src && entry.port_src == port_src;
}

static bool cond_alloc_to_src(struct nat_entry entry, const void *data_ptr)
{
    return entry.port_alloc == *((uint16_t *) data_ptr);
}

static size_t hash_src(uint16_t port_src, uint32_t addr_src, size_t size)
{
    return hash_num(hash_num(port_src) + hash_num(addr_src)) % size;
}

static size_t hash_alloc(uint16_t dst_port, size_t size)
{
    return hash_num(dst_port) % size;
}

static unsigned int hash_num(unsigned int x)
{
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}
