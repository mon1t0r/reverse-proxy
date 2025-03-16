#include <stdio.h>


#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "nat_table.h"

bool map_insert(struct nat_node **map, struct nat_entry *entry, size_t index);
void map_free(struct nat_node **map, size_t size);
void map_node_free(struct nat_node *node);

bool entries_equal(struct nat_entry *entry_1, struct nat_entry *entry_2);

size_t hash_src(uint16_t port_src, uint32_t addr_src, size_t size);
size_t hash_alloc(uint16_t dst_port, size_t size);
unsigned int hash_num(unsigned int x);

struct nat_table *nat_table_alloc(size_t size) {
    if(size == 0) {
        return NULL;
    }

    struct nat_table *table = malloc(sizeof(struct nat_table));

    if(table == NULL) {
        return NULL;
    }

    table->size = size;
    table->src_to_alloc_map = calloc(size, sizeof(struct nat_node *));
    table->alloc_to_src_map = calloc(size, sizeof(struct nat_node *));

    return table;
}

struct nat_entry *nat_table_insert(struct nat_table *table, struct nat_entry entry) {
    size_t src_hash;
    size_t alloc_hash;

    struct nat_entry *entry_creat;

    if(table == NULL) {
        return NULL;
    }

    src_hash = hash_src(entry.port_src, entry.addr_src, table->size);
    alloc_hash = hash_alloc(entry.port_alloc, table->size);

    entry_creat = malloc(sizeof(struct nat_entry));
    if(entry_creat == NULL) {
        return NULL;
    }
    memcpy(entry_creat, &entry, sizeof(struct nat_entry));

    if(!map_insert(table->src_to_alloc_map, entry_creat, src_hash)) {
        goto err;
    }

    if(!map_insert(table->alloc_to_src_map, entry_creat, alloc_hash)) {
        goto err;
    }

    return entry_creat;

err:
    free(entry_creat);
    return NULL;
}

/* Do not change files of the returned reference except timestamp. */
struct nat_entry *nat_table_get_by_src(struct nat_table *table, uint16_t port_src, uint32_t addr_src) {
    size_t index;
    struct nat_node *node;

    if(table == NULL) {
        return NULL;
    }

    index = hash_src(port_src, addr_src, table->size);

    node = table->src_to_alloc_map[index];
    while(node) {
        if(node->entry->port_src == port_src && node->entry->addr_src == addr_src) {
            return node->entry;
        }
        node = node->next;
    }

    return NULL;
}

/* Do not change files of the returned reference except timestamp. */
struct nat_entry *nat_table_get_by_alloc(struct nat_table *table, uint16_t port_alloc) {
    size_t index;
    struct nat_node *node;

    if(table == NULL) {
        return NULL;
    }

    index = hash_alloc(port_alloc, table->size);

    node = table->alloc_to_src_map[index];
    while(node) {
        if(node->entry->port_alloc == port_alloc) {
            return node->entry;
        }
        node = node->next;
    }

    return NULL;
}

void nat_table_free(struct nat_table *table) {
    if(table == NULL) {
        return;
    }

    map_free(table->src_to_alloc_map, table->size);
    map_free(table->alloc_to_src_map, table->size);

    free(table);
}

bool map_insert(struct nat_node **map, struct nat_entry *entry, size_t index) {
    struct nat_node *node_last;
    struct nat_node *node_new;

    if(map == NULL) {
        return false;
    }

    node_last = map[index];
    while(node_last) {
        if(entries_equal(node_last->entry, entry)) {
            return false;
        }

        if(node_last->next == NULL) {
            break;
        }

        node_last = node_last->next;
    }

    node_new = malloc(sizeof(struct nat_node));
    if(node_new == NULL) {
        return false;
    }

    node_new->entry = entry;
    node_new->next = NULL;

    if(node_last == NULL) {
        map[index] = node_new;
        return true;
    }

    node_last->next = node_new;
    return true;
}

void map_free(struct nat_node **map, size_t size) {
    for(size_t i = 0; i < size; i++) {
        map_node_free(map[i]);
    }
    free(map);
}

void map_node_free(struct nat_node *node) {
    struct nat_node *node_cur;
    struct nat_node *node_next;

    if(node == NULL) {
        return;
    }

    node_cur = node;

    while (node_cur) {
        node_next = node_cur->next;

        free(node_cur->entry);
        free(node_cur);

        node_cur = node_next;
    }
}

bool entries_equal(struct nat_entry *entry_1, struct nat_entry *entry_2) {
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

size_t hash_src(uint16_t port_src, uint32_t addr_src, size_t size) {
    return hash_num(hash_num(port_src) + hash_num(addr_src)) % size;
}

size_t hash_alloc(uint16_t dst_port, size_t size) {
    return hash_num(dst_port) % size;
}

unsigned int hash_num(unsigned int x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}
