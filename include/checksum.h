#ifndef REV_PROXY_CHECKSUM_H
#define REV_PROXY_CHECKSUM_H

#include <stdint.h>

uint16_t recompute_checksum_16(uint16_t old_sum, uint16_t old_val,
                               uint16_t new_val);

uint16_t recompute_checksum_32(uint16_t old_sum, uint32_t old_val,
                               uint32_t new_val);

#endif
