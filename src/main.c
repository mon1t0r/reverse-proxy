#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <asm-generic/socket.h>

#include "options.h"
#include "nat/nat_table.h"
#include "checksum.h"
#include "network_layer.h"
#include "transport_layer.h"
#include "if_utils.h"

enum {
    packet_buf_size = 65536
};

uint16_t get_free_port(nat_table *nat_table, const struct proxy_opts *options,
                       uint16_t *port_cntr) {
    uint16_t init_val;

    init_val = *port_cntr;

    (*port_cntr)++;

    if(*port_cntr < options->nat_port_range_start ||
        *port_cntr > options->nat_port_range_end) {
        *port_cntr = options->nat_port_range_start;
    }

    while(nat_table_get_by_alloc(nat_table, htons(*port_cntr))) {
        (*port_cntr)++;

        if(*port_cntr > options->nat_port_range_end) {
            *port_cntr = options->nat_port_range_start;
        }

        if(*port_cntr == init_val) {
            return 0;
        }
    }

    return htons(*port_cntr);
}

bool cond_time(struct nat_entry entry, const void *data_ptr) {
    const struct {
        time_t alloc_time;
        time_t min_lifetime;
    } *nat_data_ptr;

    nat_data_ptr = data_ptr;

    return nat_data_ptr->alloc_time - entry.alloc_time >=
        nat_data_ptr->min_lifetime;
}

void trans_hdr_tcp_update(struct trans_hdr_map *trans_hdr_map,
                          struct net_hdr_map *net_hdr_map,
                          uint32_t addr_src, uint32_t addr_dst) {

    if(*net_hdr_map->next_proto != trans_proto_tcp) {
        return;
    }

    *trans_hdr_map->checksum = recompute_checksum_32(
        *trans_hdr_map->checksum, *net_hdr_map->addr_src, addr_src);
    *trans_hdr_map->checksum = recompute_checksum_32(
        *trans_hdr_map->checksum, *net_hdr_map->addr_dst, addr_dst);
}

void net_hdr_update(struct net_hdr_map *map, uint32_t addr_src,
                    uint32_t addr_dst) {

    *map->checksum = recompute_checksum_32(
        *map->checksum, *map->addr_src, addr_src);
    *map->checksum = recompute_checksum_32(
        *map->checksum, *map->addr_dst, addr_dst);

    *map->addr_src = addr_src;
    *map->addr_dst = addr_dst;

}

void trans_hdr_update(struct trans_hdr_map *map,
                      uint16_t port_src, uint16_t port_dst) {
    *map->checksum = recompute_checksum_16(
        *map->checksum, *map->port_src, port_src);
    *map->checksum = recompute_checksum_16(
        *map->checksum, *map->port_dst, port_dst);

    *map->port_src = port_src;
    *map->port_dst = port_dst;
}

struct nat_entry *nat_open_new_con(nat_table *nat_table, uint16_t *port_cntr,
                                   const struct proxy_opts *options,
                                   uint32_t addr, uint16_t port) {
    struct nat_entry nat_entry_new;
    struct {
        time_t alloc_time;
        time_t min_lifetime;
    } nat_entry_data;

    nat_entry_new.addr_src = addr;
    nat_entry_new.port_src = port;
    nat_entry_new.alloc_time = time(NULL);
    nat_entry_new.port_alloc = get_free_port(nat_table, options, port_cntr);

    if(nat_entry_new.port_alloc == 0) {
        nat_entry_data.alloc_time = nat_entry_new.alloc_time;
        nat_entry_data.min_lifetime =
            options->nat_table_entry_min_lifetime;

        if(!nat_table_remove_if(nat_table, &nat_entry_data, &cond_time)) {
            return NULL;
        }

        nat_entry_new.port_alloc =
            get_free_port(nat_table, options, port_cntr);
        if(nat_entry_new.port_alloc == 0) {
            return NULL;
        }
    }

    return nat_table_insert(nat_table, nat_entry_new);
}

/* Client to server */
bool handle_packet_ctos(nat_table *nat_table,
                        uint16_t *port_cntr,
                        const struct proxy_opts *options,
                        uint32_t int_addr,
                        struct net_hdr_map *net_hdr_map,
                        struct trans_hdr_map *trans_hdr_map) {
    struct nat_entry *nat_entry_ptr;

    nat_entry_ptr = nat_table_get_by_src(nat_table, *trans_hdr_map->port_src,
                                     *net_hdr_map->addr_src);

    if(nat_entry_ptr == NULL) {
        nat_entry_ptr = nat_open_new_con(nat_table, port_cntr, options,
                                         *net_hdr_map->addr_src,
                                         *trans_hdr_map->port_src);
        if(nat_entry_ptr == NULL) {
            return false;
        }
    }

    trans_hdr_tcp_update(trans_hdr_map, net_hdr_map, int_addr,
                         htonl(options->dest_addr));
    net_hdr_update(net_hdr_map, int_addr,
                   htonl(options->dest_addr));
    trans_hdr_update(trans_hdr_map, nat_entry_ptr->port_alloc,
                     htons(options->dest_port));

    return true;
}

/* Server to client */
bool handle_packet_stoc(nat_table *nat_table,
                        uint16_t *port_cntr,
                        const struct proxy_opts *options,
                        uint32_t int_addr,
                        struct net_hdr_map *net_hdr_map,
                        struct trans_hdr_map *trans_hdr_map) {
    struct nat_entry *nat_entry_ptr;

    nat_entry_ptr = nat_table_get_by_alloc(nat_table,
                                           *trans_hdr_map->port_dst);
    if(nat_entry_ptr == NULL) {
        return false;
    }

    trans_hdr_tcp_update(trans_hdr_map, net_hdr_map, int_addr,
                         nat_entry_ptr->addr_src);
    net_hdr_update(net_hdr_map, int_addr,
                   nat_entry_ptr->addr_src);
    trans_hdr_update(trans_hdr_map, htons(options->listen_port),
                     nat_entry_ptr->port_src);

    return true;
}

bool handle_packet(uint8_t *buf, nat_table *nat_table,
                   uint16_t *port_cntr,
                   const struct proxy_opts *options,
                   uint32_t int_addr) {
    struct net_hdr_map net_hdr_map;
    uint8_t net_len;

    struct trans_hdr_map trans_hdr_map;
    uint8_t trans_len;

    net_len = map_network_header(buf, &net_hdr_map);
    if(net_len == 0) {
        return false;
    }

    trans_len = map_transport_header(buf + net_len, *net_hdr_map.next_proto,
                                     &trans_hdr_map);
    if(trans_len == 0) {
        return false;
    }

    if(*net_hdr_map.addr_dst != int_addr) {
        return false;
    }

    if(ntohs(*trans_hdr_map.port_dst) == options->listen_port) {
        return handle_packet_ctos(nat_table, port_cntr, options, int_addr,
                                  &net_hdr_map, &trans_hdr_map);
    }

    if(*trans_hdr_map.port_src == htons(options->dest_port) &&
              *net_hdr_map.addr_src == htonl(options->dest_addr)) {
        return handle_packet_stoc(nat_table, port_cntr, options, int_addr,
                                  &net_hdr_map, &trans_hdr_map);
    }

    return false;
}

void bind_socket_rx(int socket_fd, int if_index) {
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = if_index;

    /* Bind receive socket to interface */
    if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }
}

void bind_socket_tx(int socket_fd, int if_index) {
    struct ifreq ifreq;

    ifreq.ifr_ifindex = if_index;

    if(setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifreq,
                  sizeof(ifreq)) < 0) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }
}

void create_sockets(int *socket_rx_fd, int *socket_tx_fd) {
    int sockoptval;

    /* Create receive socket */
    /* TODO: AF_PACKET sockets do not reassamble IP fragments, implement 
     * AF_INET usage */
    if((*socket_rx_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    /* Create transmit socket */
    /* TODO: AF_INET sockets with IP_HDRINCL option set do not reassamble IP
     * fragments, implement without IP_HDRINCL */
    if((*socket_tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    /* Enable IP_HDRINCL on transmit socket */
    sockoptval = 1;
    if(setsockopt(*socket_tx_fd, IPPROTO_IP, IP_HDRINCL, &sockoptval,
                  sizeof(sockoptval)) < 0) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    struct proxy_opts options;

    uint8_t *buf;
    ssize_t buf_len;
    struct sockaddr_in dst_addr;
    struct net_hdr_map net_hdr_map;

    uint16_t port_cntr;
    nat_table *nat_table;

    int if_index;
    uint32_t if_net_addr;

    int socket_rx_fd;
    int socket_tx_fd;

    options = options_parse(argc, argv);

    options_print(&options);
    printf("\n");

    buf = malloc(packet_buf_size * sizeof(uint8_t));
    port_cntr = options.nat_port_range_start;

    nat_table = nat_table_alloc(options.nat_table_size);
    if(nat_table == NULL) {
        exit(EXIT_FAILURE);
    }

    create_sockets(&socket_rx_fd, &socket_tx_fd);
    if_index = get_interface_index(socket_rx_fd, options.interface_name);
    if_net_addr = get_interface_net_addr(socket_rx_fd, if_index);

    bind_socket_rx(socket_rx_fd, if_index);
    bind_socket_tx(socket_tx_fd, if_index);

    printf("Initialized successfully\n");
    printf("Listening on port %d...\n\n", options.listen_port);

    while((buf_len = recv(socket_rx_fd, buf,
                          packet_buf_size * sizeof(uint8_t), 0)) > 0) {
        if(!handle_packet(buf, nat_table, &port_cntr, &options, if_net_addr)) {
            continue;
        }

        if(map_network_header(buf, &net_hdr_map) == 0) {
            continue;
        }

        memset(&dst_addr, 0, sizeof(dst_addr));
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_addr.s_addr = *net_hdr_map.addr_dst;

        if(sendto(socket_tx_fd, buf, buf_len, 0, (struct sockaddr *) &dst_addr,
                  sizeof(dst_addr)) < 0) {
            perror("send()");
            continue;
        }
    }

    close(socket_rx_fd);
    free(buf);
    nat_table_free(nat_table);

    return EXIT_SUCCESS;
}
