#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "transport_layer.h"

uint8_t
hdr_transport_map(uint8_t *buf, uint8_t protocol,
                  struct trans_hdr_map *trans_hdr_map)
{
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    if(protocol == IPPROTO_TCP) {
        tcphdr = (struct tcphdr *) buf;

        trans_hdr_map->port_src = &tcphdr->source;
        trans_hdr_map->port_dst = &tcphdr->dest;
        trans_hdr_map->checksum = &tcphdr->check;

        return tcphdr->doff;
    }

    if(protocol == IPPROTO_UDP) {
        udphdr = (struct udphdr *) buf;

        trans_hdr_map->port_src = &udphdr->source;
        trans_hdr_map->port_dst = &udphdr->dest;
        trans_hdr_map->checksum = &udphdr->check;

        return udphdr->len;
    }

    return 0;
}

