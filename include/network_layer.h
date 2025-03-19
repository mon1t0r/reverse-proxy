#ifndef REV_PROXY_NETWORK_LAYER_H
#define REV_PROXY_NETWORK_LAYER_H

#include <stdint.h>

struct net_hdr_map {
    uint32_t *addr_src;
    uint32_t *addr_dst;
    uint8_t *next_proto;
    uint16_t *checksum;
};

uint8_t map_network_header(uint8_t *buf, struct net_hdr_map *net_hdr_map);

#endif
