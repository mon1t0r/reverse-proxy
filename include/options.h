#ifndef REV_PROXY_OPTIONS_H
#define REV_PROXY_OPTIONS_H

#include <stdint.h>
#include <time.h>
#include <linux/if.h>

struct proxy_opts {
    char interface_name[IFNAMSIZ];
    uint16_t listen_port;
    uint32_t dest_addr;
    uint16_t dest_port;
    size_t nat_table_size;
    time_t nat_table_entry_min_lifetime;
    uint16_t nat_port_range_start;
    uint16_t nat_port_range_end;
};

struct proxy_opts options_parse(int argc, char * const *argv);

void options_print(const struct proxy_opts *options);

#endif
