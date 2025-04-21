#include <stdlib.h>

#include "nat/nat_map.h"

struct nat_node {
    struct nat_entry *entry;
    struct nat_node *next;
};

struct nat_map {
    size_t size;
    struct nat_node **node_arr;
};

void list_free(struct nat_node *node, nat_map_free_callback free_callback);

nat_map *nat_map_alloc(size_t size) {
    nat_map *nat_map;

    nat_map = malloc(sizeof(struct nat_map));

    if(!nat_map) {
        return NULL;
    }

    nat_map->size = size;
    nat_map->node_arr = calloc(size, sizeof(struct nat_node *));

    if(!nat_map->node_arr) {
        free(nat_map);
        return NULL;
    }

    return nat_map;
}

size_t nat_map_get_size(nat_map *map) {
    if(map == NULL) {
        return 0;
    }

    return map->size;
}

bool nat_map_insert(nat_map *map, struct nat_entry *entry, size_t index) {
    struct nat_node *node_last;
    struct nat_node *node_new;

    if(map == NULL || entry == NULL || index < 0 || index >= map->size) {
        return false;
    }

    node_last = map->node_arr[index];
    while(node_last != NULL) {
        if(nat_entries_equal(node_last->entry, entry)) {
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
        map->node_arr[index] = node_new;
        return true;
    }

    node_last->next = node_new;
    return true;
}

struct nat_entry *nat_map_find(nat_map *map, size_t index,
                               const void *data_ptr,
                               nat_map_find_condition condition) {
    struct nat_node *node;

    if(map == NULL || condition == NULL || index < 0 || index >= map->size) {
        return NULL;
    }

    node = map->node_arr[index];

    while(node != NULL) {
        if(condition(*node->entry, data_ptr)) {
            return node->entry;
        }

        node = node->next;
    }

    return NULL;
}

bool nat_map_remove_if(nat_map *map, const void *data_ptr,
                       nat_map_find_condition condition,
                       nat_map_free_callback free_callback) {
    size_t i;
    bool removed_any;

    struct nat_node *node;
    struct nat_node *node_prev;
    struct nat_node *node_temp;

    if(map == NULL || condition == NULL) {
        return false;
    }

    removed_any = 0;

    for(i = 0; i < map->size; i++) {
        node = map->node_arr[i];
        node_prev = NULL;

        while(node != NULL) {
            if(!condition(*node->entry, data_ptr)) {
                node_prev = node;
                node = node->next;
                continue;
            }

            if(node_prev != NULL) {
                node_prev->next = node->next;
            } else {
                map->node_arr[i] = node->next;
            }

            node_temp = node->next;

            if(free_callback != NULL) {
                free_callback(node->entry);
            }
            free(node);

            node = node_temp;

            removed_any = true;
        }
    }

    return removed_any;
}

void nat_map_free(nat_map *map, nat_map_free_callback free_callback) {
    size_t i;

    if(map == NULL) {
        return;
    }

    for(i = 0; i < map->size; i++) {
        list_free(map->node_arr[i], free_callback);
    }

    free(map->node_arr);
    free(map);
}

void list_free(struct nat_node *node, nat_map_free_callback free_callback) {
    struct nat_node *node_cur;
    struct nat_node *node_next;

    if(node == NULL) {
        return;
    }

    node_cur = node;

    while(node_cur != NULL) {
        node_next = node_cur->next;

        if(free_callback != NULL) {
            free_callback(node_cur->entry);
        }
        free(node_cur);

        node_cur = node_next;
    }
}
