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


/* Uncomment to enable packet logging */
/*#define ENABLE_LOG_INFO*/
/*#define ENABLE_LOG_DEBUG*/

#ifdef ENABLE_LOG_INFO
#define LOG_INFO(...) printf(__VA_ARGS__)
#else
#define LOG_INFO(...)
#endif

#ifdef ENABLE_LOG_DEBUG
#define LOG_DEBUG(...) printf(__VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

#define INTERFACE_NAME "eno1"

enum {
    packet_buf_size = 65536
};

struct int_info {
    int index;
    uint32_t addr_net;
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

    return nat_data_ptr->alloc_time - entry.alloc_time >= nat_data_ptr->min_lifetime;
}

bool handle_packet(uint8_t *buf, nat_table *nat_table, struct int_info *int_info,
                   const struct proxy_opts *options, uint16_t *port_cntr) {
    struct net_hdr_map net_hdr_map;
    uint8_t net_len;

    struct trans_hdr_map trans_hdr_map;
    uint8_t trans_len;

    struct nat_entry *nat_entry;
    struct nat_entry nat_entry_new;
    struct {
        time_t alloc_time;
        time_t min_lifetime;
    } nat_entry_data;

#ifdef ENABLE_LOG_INFO
    struct in_addr ip_addr;
#endif

    net_len = map_network_header(buf, &net_hdr_map);
    if(net_len == 0) {
        LOG_DEBUG("The network layer protocol is not recognized.\n\n");
        return false;
    }

    trans_len = map_transport_header(buf + net_len, *net_hdr_map.next_proto,
                                     &trans_hdr_map);

    if(trans_len == 0) {
        LOG_DEBUG("The transport layer protocol is not recognized.\n\n");
        return false;
    }

    if(*net_hdr_map.addr_dst != int_info->addr_net) {
        LOG_DEBUG("Destination IP is not equal to the interface IP.\n\n");
        return false;
    }

    /* Client to server packet */
    if(ntohs(*trans_hdr_map.port_dst) == options->listen_port) {
#ifndef ENABLE_LOG_DEBUG
        LOG_INFO("Packet\n");
#endif
        LOG_INFO("|-type: client to server\n");

        nat_entry = nat_table_get_by_src(nat_table, *trans_hdr_map.port_src,
                                         *net_hdr_map.addr_src);

        LOG_INFO("|-translation table entry: %s\n",
                 nat_entry ? "present" : "new one");

        if(!nat_entry) {
            nat_entry_new.port_src = *trans_hdr_map.port_src;
            nat_entry_new.addr_src = *net_hdr_map.addr_src;
            nat_entry_new.alloc_time = time(NULL);
            nat_entry_new.port_alloc = get_free_port(nat_table, options, port_cntr);

            if(nat_entry_new.port_alloc == 0) {
                LOG_INFO("No free ports left in NAT port range. \
                         NAT table cleanup attempt...\n");

                nat_entry_data.alloc_time = nat_entry_new.alloc_time;
                nat_entry_data.min_lifetime = options->nat_table_entry_min_lifetime;
                if(!nat_table_remove_if(nat_table, &nat_entry_data,
                                        &cond_time)) {
                    LOG_INFO("NAT table cleanup failed: No entries \
                             removed. Packet dropped.\n");
                    return false;
                }

                LOG_INFO("Nat table cleanup success. Retrying to \
                         allocate a port...\n");

                nat_entry_new.port_alloc = get_free_port(nat_table, options, port_cntr);

                if(nat_entry_new.port_alloc == 0) {
                    LOG_INFO("Port allocation failed again. Packet dropped.\n");
                    return false;
                }

                LOG_INFO("Port allocated successfully.\n");
            }

            nat_entry = nat_table_insert(nat_table, nat_entry_new);
            if(!nat_entry) {
                LOG_INFO("NAT table insert failed.\n\n");
                return false;
            }
        }

#ifdef ENABLE_LOG_INFO
        ip_addr.s_addr = *net_hdr_map.addr_src;
        LOG_INFO("|-client addr: %s\n", inet_ntoa(ip_addr));
        LOG_INFO("|-client port: %u\n", ntohs(*trans_hdr_map.port_src));
        LOG_INFO("|-alloc port: %u\n", ntohs(nat_entry->port_alloc));
#endif

        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum,
                                *net_hdr_map.addr_src, int_info->addr_net);
        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum,
                                *net_hdr_map.addr_dst, htonl(options->dest_addr));

        /* TCP pseudo header */
        if(*net_hdr_map.next_proto == trans_proto_tcp) {
            *trans_hdr_map.checksum = recompute_checksum_32(
                *trans_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr_net);
            *trans_hdr_map.checksum = recompute_checksum_32(
                *trans_hdr_map.checksum, *net_hdr_map.addr_dst, htonl(options->dest_addr));
        }

        *trans_hdr_map.checksum = recompute_checksum_16(
            *trans_hdr_map.checksum, *trans_hdr_map.port_src, nat_entry->port_alloc);
        *trans_hdr_map.checksum = recompute_checksum_16(*trans_hdr_map.checksum,
            *trans_hdr_map.port_dst, htons(options->dest_port));

        *net_hdr_map.addr_src = int_info->addr_net;
        *trans_hdr_map.port_src = nat_entry->port_alloc;
        *net_hdr_map.addr_dst = htonl(options->dest_addr);
        *trans_hdr_map.port_dst = htons(options->dest_port);

    /* Server to client packet */
    } else if(*trans_hdr_map.port_src == htons(options->dest_port) &&
              *net_hdr_map.addr_src == htonl(options->dest_addr)) {
#ifndef ENABLE_LOG_DEBUG
        LOG_INFO("Packet\n");
#endif
        LOG_INFO("|-type: server to client\n");

        nat_entry = nat_table_get_by_alloc(nat_table, *trans_hdr_map.port_dst);
        if(!nat_entry) {
            LOG_INFO("NAT entry not found.\n\n");
            return false;
        }

#ifdef ENABLE_LOG_INFO
        ip_addr.s_addr = nat_entry->addr_src;
        LOG_INFO("|-client addr: %s\n", inet_ntoa(ip_addr));
        LOG_INFO("|-client port: %u\n", ntohs(nat_entry->port_src));
        LOG_INFO("|-alloc port: %u\n", ntohs(nat_entry->port_alloc));
#endif

        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum,
                                *net_hdr_map.addr_src, int_info->addr_net);
        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum,
                                *net_hdr_map.addr_dst, nat_entry->addr_src);

        /* TCP pseudo header */
        if(*net_hdr_map.next_proto == trans_proto_tcp) {
            *trans_hdr_map.checksum = recompute_checksum_32(
                *trans_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr_net);
            *trans_hdr_map.checksum = recompute_checksum_32(
                *trans_hdr_map.checksum, *net_hdr_map.addr_dst, nat_entry->addr_src);
        }

        *trans_hdr_map.checksum = recompute_checksum_16(
            *trans_hdr_map.checksum, *trans_hdr_map.port_src, htons(options->listen_port));
        *trans_hdr_map.checksum = recompute_checksum_16(
            *trans_hdr_map.checksum, *trans_hdr_map.port_dst, nat_entry->port_src);

        *net_hdr_map.addr_src = int_info->addr_net;
        *trans_hdr_map.port_src = htons(options->listen_port);
        *net_hdr_map.addr_dst = nat_entry->addr_src;
        *trans_hdr_map.port_dst = nat_entry->port_src;
    } else {
        LOG_DEBUG("Packet is not intended for proxy.\n\n");
        return false;
    }

    return true;
}

void create_sockets(int *socket_rx_fd, int *socket_tx_fd, struct int_info *int_info) {
    int sockoptval;

    struct ifreq ifreq;
    struct sockaddr_ll addr;

    uint8_t addr_link[6];

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

    /* Get interface index */
    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if(ioctl(*socket_rx_fd, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }
    int_info->index = ifreq.ifr_ifindex;

    /* Get interface hardware address */
    if(ioctl(*socket_rx_fd, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        exit(EXIT_FAILURE);
    }
    memcpy(addr_link, &ifreq.ifr_hwaddr.sa_data, sizeof(addr_link));

    /* Get interface address */
    if(ioctl(*socket_rx_fd, SIOCGIFADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        exit(EXIT_FAILURE);
    }
    int_info->addr_net = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;

    /* Fill sockaddr_ll structure for receive socket */
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = int_info->index;

    /* Bind receive socket to interface */
    if(bind(*socket_rx_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind() - rx");
        exit(EXIT_FAILURE);
    }

    /* Bind transmit socket to interface */
    if(setsockopt(*socket_tx_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifreq,
                  sizeof(ifreq)) < 0) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }

    printf("Binded to interface\n");
    printf("|-name   %s\n", INTERFACE_NAME);
    printf("|-index  %d\n", int_info->index);
    printf("|-IPv4   %s\n", inet_ntoa(((struct sockaddr_in *)
                                     &ifreq.ifr_addr)->sin_addr));
    printf("|-MAC    %x:%x:%x:%x:%x:%x\n", addr_link[0], addr_link[1],
           addr_link[2], addr_link[3], addr_link[4], addr_link[5]);
    printf("Sockets initialized successfully\n\n");
}

int main(int argc, char *argv[]) {
    struct proxy_opts options;

    uint8_t *buf;
    ssize_t buf_len;
    struct sockaddr_in dst_addr;
    struct net_hdr_map net_hdr_map;

    uint16_t port_cntr;
    nat_table *nat_table;

    struct int_info int_info;
    int socket_rx_fd;
    int socket_tx_fd;

    options = options_parse(argc, argv);

    options_print(&options);
    printf("\n");

    buf = malloc(packet_buf_size * sizeof(uint8_t));
    port_cntr = options.nat_port_range_start;

    nat_table = nat_table_alloc(options.nat_table_size);
    if(nat_table == NULL) {
        LOG_INFO("Failed to create NAT table.");
        exit(EXIT_FAILURE);
    }

    create_sockets(&socket_rx_fd, &socket_tx_fd, &int_info);

    printf("The proxy is listening on port %d...\n\n", options.listen_port);

    while((buf_len = recv(socket_rx_fd, buf, packet_buf_size * sizeof(uint8_t), 0)) > 0) {
        LOG_DEBUG("Packet\n");
        LOG_DEBUG("|-length %ld\n", buf_len);

        if(!handle_packet(buf, nat_table, &int_info, &options, &port_cntr)) {
            continue;
        }

        LOG_INFO("Forwarding packet... ");

        if(map_network_header(buf, &net_hdr_map) == 0) {
            LOG_INFO("Failed.\n\n");
            continue;
        }

        memset(&dst_addr, 0, sizeof(dst_addr));
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_addr.s_addr = *net_hdr_map.addr_dst;

        if(sendto(socket_tx_fd, buf, buf_len, 0, (struct sockaddr *) &dst_addr,
                  sizeof(dst_addr)) < 0) {
            printf("msg len: %ld\n", buf_len);
            perror("send()");
            LOG_INFO("Failed.\n\n");
            continue;
        }

        LOG_INFO("Success.\n\n");
    }

    close(socket_rx_fd);
    free(buf);
    nat_table_free(nat_table);

    return EXIT_SUCCESS;
}
