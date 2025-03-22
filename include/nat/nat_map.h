#ifndef REV_PROXY_NAT_MAP_H
#define REV_PROXY_NAT_MAP_H

#include <stddef.h>
#include <stdbool.h>

#include "nat/nat_entry.h"

typedef struct nat_map nat_map;
typedef bool (*nat_map_find_condition)(struct nat_entry, uint64_t);
typedef void (*nat_map_free_callback)(struct nat_entry *);

nat_map *nat_map_alloc(size_t size);

size_t nat_map_get_size(nat_map *map);

bool nat_map_insert(nat_map *map, struct nat_entry *entry, size_t index);

struct nat_entry *nat_map_find(nat_map *map, size_t index, uint64_t data, nat_map_find_condition condition);

bool nat_map_remove_if(nat_map *map, uint64_t data, nat_map_find_condition condition, nat_map_free_callback free_callback);

void nat_map_free(nat_map *map, nat_map_free_callback free_callback);

#endif
