#ifndef REV_PROXY_TRANSPORT_LAYER_H
#define REV_PROXY_TRANSPORT_LAYER_H

#include <stdint.h>

struct trans_hdr_map {
    uint16_t *port_src;
    uint16_t *port_dst;
    uint16_t *checksum;
};

uint8_t
hdr_transport_map(uint8_t *buf, uint8_t protocol,
                  struct trans_hdr_map *trans_hdr_map);

#endif

