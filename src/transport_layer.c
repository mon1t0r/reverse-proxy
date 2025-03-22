#include <linux/tcp.h>
#include <linux/udp.h>

#include "transport_layer.h"

uint8_t map_transport_header(uint8_t *buf, uint8_t proto, struct trans_hdr_map *trans_hdr_map) {
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    /* TCP protocol */
    if(proto == 6) {
        tcphdr = (struct tcphdr *) buf;

        trans_hdr_map->port_src = &tcphdr->source;
        trans_hdr_map->port_dst = &tcphdr->dest;
        trans_hdr_map->checksum = &tcphdr->check;

        return tcphdr->doff;
    }

    /* UDP protocol */
    if(proto == 17) {
        udphdr = (struct udphdr *) buf;

        trans_hdr_map->port_src = &udphdr->source;
        trans_hdr_map->port_dst = &udphdr->dest;
        trans_hdr_map->checksum = &udphdr->check;

        return udphdr->len;
    }

    return 0;
}
