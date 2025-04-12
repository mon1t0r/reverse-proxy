#ifndef REV_PROXY_TRANSPORT_LAYER_H
#define REV_PROXY_TRANSPORT_LAYER_H

#include <stdint.h>

enum trans_proto {
    trans_proto_tcp = 6,
    trans_proto_udp = 17
};

struct trans_hdr_map {
    uint16_t *port_src;
    uint16_t *port_dst;
    uint16_t *checksum;
};

uint8_t map_transport_header(uint8_t *buf, uint8_t proto,
                             struct trans_hdr_map *trans_hdr_map);

#endif
