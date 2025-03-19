#include <netinet/ip.h>

#include "include/network_layer.h"

uint8_t map_network_header(uint8_t *buf, struct net_hdr_map *net_hdr_map) {
    struct iphdr *iphdr;

    iphdr = (struct iphdr *) buf;

    net_hdr_map->addr_src = &iphdr->saddr;
    net_hdr_map->addr_dst = &iphdr->daddr;
    net_hdr_map->next_proto = &iphdr->protocol;
    net_hdr_map->checksum = &iphdr->check;

    return iphdr->ihl * 4;
}
