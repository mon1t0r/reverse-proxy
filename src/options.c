#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "options.h"

static const char error_msg[] =
    "Usage: %s [OPTION]... [LISTEN_PORT] [DEST_ADDR] [DEST_PORT]\n(%s)\n";

static const struct option longopts[] = {
    { "interface",                    required_argument, NULL, 'I' },
    { "nat-table-size",               required_argument, NULL, 't' },
    { "nat-table-entry-min-lifetime", required_argument, NULL, 'l' },
    { "nat-port-range-start",         required_argument, NULL, 's' },
    { "nat-port-range-end",           required_argument, NULL, 'e' },
    { 0,                              0,                 0,    0   }
};

static const char optstring[] = "I:t:l:s:e:";

static void options_error(const char *exec_name, const char *reason) {
    fprintf(stderr, error_msg, exec_name, reason);
    exit(EXIT_FAILURE);
}

static bool options_parse_size(const char *arg, size_t *size) {
    return sscanf(arg, "%lu", size) == 1;
}

static bool options_parse_time(const char *arg, time_t *time) {
    return sscanf(arg, "%ld", time) == 1;
}

static bool options_parse_port(const char *arg, uint16_t *port) {
    return sscanf(arg, "%hu", port) == 1;
}

static bool options_parse_net_addr(const char *arg, uint32_t *addr) {
    if(inet_pton(AF_INET, arg, addr) != 1) {
        return false;
    }

    *addr = ntohl(*addr);

    return true;
}

static void options_set_default(struct proxy_opts *options) {
    memset(options, 0, sizeof(*options));

    options->interface_name[0]            = '\0';
    options->nat_table_size               = 50;
    options->nat_table_entry_min_lifetime = 5 * 60;
    options->nat_port_range_start         = 49160;
    options->nat_port_range_end           = 49190;
}

struct proxy_opts options_parse(int argc, char *argv[]) {
    extern int optind;
    extern char *optarg;

    struct proxy_opts options;
    char c;

    options_set_default(&options);

    if(argc <= 0) {
        options_error("reverse-proxy", "argc <= 0");
    }

    do {
        c = getopt_long(argc, argv, optstring, longopts, NULL);

        switch(c) {
            case -1:
                break;
            case 'I':
                strncpy(options.interface_name, optarg, IFNAMSIZ);
                options.interface_name[IFNAMSIZ - 1] = '\0';
                break;
            case 't':
                if(!options_parse_size(optarg, &options.nat_table_size)) {
                    options_error(argv[0], "nat-table-size - invalid value");
                }
                break;
            case 'l':
                if(!options_parse_time(optarg,
                                       &options.nat_table_entry_min_lifetime)
                ) {
                    options_error(argv[0],
                                  "nat-table-entry-min-lifetime -"
                                  " invalid value");
                }
                break;
            case 's':
                if(!options_parse_port(optarg,
                                       &options.nat_port_range_start)) {
                    options_error(argv[0],
                                  "nat-port-range-start - invalid value");
                }
                break;
            case 'e':
                if(!options_parse_port(optarg, &options.nat_port_range_end)) {
                    options_error(argv[0],
                                  "nat-port-range-end - invalid value");
                }
                break;
            default:
                options_error(argv[0], "unknown option");
        }
    } while(c != -1);

    if(optind + 3 != argc) {
        options_error(argv[0], "missing required parameters");
    }

    if(!options_parse_port(argv[optind], &options.listen_port)) {
        options_error(argv[0], "LISTEN_PORT - invalid value");
    }

    if(!options_parse_net_addr(argv[optind + 1], &options.dest_addr)) {
        options_error(argv[0], "DEST_ADDR - invalid value");
    }

    if(!options_parse_port(argv[optind + 2], &options.dest_port)) {
        options_error(argv[0], "DEST_PORT - invalid value");
    }

    return options;
}

void options_print(const struct proxy_opts *options) {
    struct in_addr addr;

    printf("Options\n");
    if(options->interface_name[0] != '\0') {
        printf("|-interface                     %s\n", options->interface_name);
    } else {
        printf("|-interface                     [not bound]\n");
    }
    printf("|-listen port                   %d\n", options->listen_port);

    addr.s_addr = htonl(options->dest_addr);
    printf("|-destination address           %s\n", inet_ntoa(addr));
    printf("|-nat table size                %lu\n", options->nat_table_size);
    printf("|-nat table entry min lifetime  %ld\n",
           options->nat_table_entry_min_lifetime);
    printf("|-nat port range                [%d - %d]\n",
           options->nat_port_range_start, options->nat_port_range_end);
}
