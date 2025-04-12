#include "checksum.h"

uint16_t recompute_checksum_16(uint16_t old_sum, uint16_t old_val,
                               uint16_t new_val) {
    uint32_t sum;

    sum = ~old_sum - old_val;

    sum = (sum & 0xFFFF) + (sum >> 16);

    sum = sum + new_val;

    sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) ~sum;
}

uint16_t recompute_checksum_32(uint16_t old_sum, uint32_t old_val,
                               uint32_t new_val) {
    uint32_t sum;

    sum = ~old_sum - (old_val & 0xFFFF) - (old_val >> 16);

    sum = (sum & 0xFFFF) + (sum >> 16);

    sum = sum + (new_val & 0xFFFF) + (new_val >> 16);

    sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) ~sum;
}
