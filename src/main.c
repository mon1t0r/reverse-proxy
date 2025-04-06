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
    /* Packet buffer size */
    packet_buf_size =              65536,
    /* NAT table array size (does not limit max NAT entries count) */
    nat_table_size =               50,
    /* Time, after last packet corresponding to a NAT entry,
     * after which the entry can be removed */
    nat_table_entry_min_lifetime = 5 * 60,
    /* Port range start, that can be used for NAT */
    nat_port_range_start =         49160,
    /* Port range end, that can be used for NAT */
    nat_port_range_end =           49190,
    /* Port, on which proxy is listening for incoming packets */
    listen_port =                  52880,

    /* Destination L2 address. Can be either address of the target host,
     * or address of the default gateway */
    dest_mac_1 = 0x74,
    dest_mac_2 = 0xFE,
    dest_mac_3 = 0xCE,
    dest_mac_4 = 0x8C,
    dest_mac_5 = 0x87,
    dest_mac_6 = 0x11,

    /* Destination L3 address */
    dest_ip_1 = 146,
    dest_ip_2 = 190,
    dest_ip_3 = 62,
    dest_ip_4 = 39,
    dest_port = 80
};

#define DEST_IP (dest_ip_1 | (dest_ip_2 << 8) | (dest_ip_3 << 16) | (dest_ip_4 << 24))

struct int_info {
    int index;
    uint32_t addr_net;
};

int create_socket(struct int_info *int_info);

bool handle_packet(uint8_t *buf, nat_table *nat_table, struct int_info *int_info, uint16_t *port_cntr);

bool cond_time(struct nat_entry entry, uint64_t data);
uint16_t get_free_port(nat_table *nat_table, uint16_t *port_cntr);

int main(void) {
    uint8_t *buf;
    uint16_t port_cntr;
    nat_table *nat_table;

    struct int_info int_info;
    int socket_fd;

    struct sockaddr_ll addr;

    ssize_t buf_len;

    buf = (uint8_t *) malloc(packet_buf_size * sizeof(uint8_t));
    port_cntr = nat_port_range_start;

    nat_table = nat_table_alloc(nat_table_size);
    if(nat_table == NULL) {
        LOG_INFO("Failed to create NAT table.");
        exit(EXIT_FAILURE);
    }

    socket_fd = create_socket(&int_info);

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = int_info.index;
    addr.sll_halen = 6;
    addr.sll_addr[0] = dest_mac_1;
    addr.sll_addr[1] = dest_mac_2;
    addr.sll_addr[2] = dest_mac_3;
    addr.sll_addr[3] = dest_mac_4;
    addr.sll_addr[4] = dest_mac_5;
    addr.sll_addr[5] = dest_mac_6;

    printf("The proxy is listening on port %d...\n\n", listen_port);

    while ((buf_len = recv(socket_fd, buf, packet_buf_size, 0)) > 0) {
        LOG_DEBUG("Packet\n");
        LOG_DEBUG("|-length %ld\n", buf_len);

        if(!handle_packet(buf, nat_table, &int_info, &port_cntr)) {
            continue;
        }

        LOG_INFO("Forwarding packet... ");

        if(sendto(socket_fd, buf, buf_len, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            LOG_INFO("Failed.\n\n");
            continue;
        }

        LOG_INFO("Success.\n\n");
    }

    close(socket_fd);
    free(buf);
    nat_table_free(nat_table);

    return EXIT_SUCCESS;
}

int create_socket(struct int_info *int_info) {
    int socket_fd;
    struct ifreq ifreq;
    struct sockaddr_ll addr;

    uint8_t addr_link[8];
    struct in_addr addr_net;

    if((socket_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);

    if(ioctl(socket_fd, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }

    int_info->index = ifreq.ifr_ifindex;

    if(ioctl(socket_fd, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        exit(EXIT_FAILURE);
    }

    memcpy(addr_link, &ifreq.ifr_hwaddr.sa_data, 8 * sizeof(uint8_t));

    if(ioctl(socket_fd, SIOCGIFADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        exit(EXIT_FAILURE);
    }

    int_info->addr_net = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = int_info->index;

    if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    addr_net.s_addr = int_info->addr_net;

    printf("Interface\n");
    printf("|-name %s\n", INTERFACE_NAME);
    printf("|-index %d\n", int_info->index);
    printf("|-mac %x:%x:%x:%x:%x:%x\n", addr_link[0], addr_link[1], addr_link[2], addr_link[3], addr_link[4], addr_link[5]);
    printf("|-ip %s\n", inet_ntoa(addr_net));
    printf("Socket initialized successfully\n\n");

    return socket_fd;
}

bool handle_packet(uint8_t *buf, nat_table *nat_table, struct int_info *int_info, uint16_t *port_cntr) {
    struct net_hdr_map net_hdr_map;
    uint8_t net_len;

    struct trans_hdr_map trans_hdr_map;
    uint8_t trans_len;

    struct nat_entry *nat_entry;
    struct nat_entry nat_entry_new;

#ifdef ENABLE_LOG_INFO
    struct in_addr ip_addr;
#endif

    net_len = map_network_header(buf, &net_hdr_map);
    if(net_len == 0) {
        LOG_DEBUG("The network layer protocol is not recognized.\n\n");
        return false;
    }

    trans_len = map_transport_header(buf + net_len, *net_hdr_map.next_proto, &trans_hdr_map);

    if(trans_len == 0) {
        LOG_DEBUG("The transport layer protocol is not recognized.\n\n");
        return false;
    }

    if(*net_hdr_map.addr_dst != int_info->addr_net) {
        LOG_DEBUG("Destination IP is not equal to the interface IP.\n\n");
        return false;
    }

    if(ntohs(*trans_hdr_map.port_dst) == listen_port) {
#ifndef ENABLE_DEBUG_LOG
        LOG_INFO("Packet\n");
#endif
        LOG_INFO("|-type: client to server\n");

        nat_entry = nat_table_get_by_src(nat_table, *trans_hdr_map.port_src, *net_hdr_map.addr_src);

        LOG_INFO("|-translation table entry: %s\n", nat_entry ? "present" : "new one");

        if(!nat_entry) {
            nat_entry_new.port_src = *trans_hdr_map.port_src;
            nat_entry_new.addr_src = *net_hdr_map.addr_src;
            nat_entry_new.alloc_time = time(NULL);
            nat_entry_new.port_alloc = get_free_port(nat_table, port_cntr);

            if(nat_entry_new.port_alloc == 0) {
                LOG_INFO("No free ports left in NAT port range. NAT table cleanup attempt...\n");

                if(!nat_table_remove_if(nat_table, nat_entry_new.alloc_time, &cond_time)) {
                    LOG_INFO("NAT table cleanup failed: No entries removed. Packet dropped.\n");
                    return false;
                }

                LOG_INFO("Nat table cleanup success. Retrying to allocate a port...\n");

                nat_entry_new.port_alloc = get_free_port(nat_table, port_cntr);

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

        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr_net);
        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum, *net_hdr_map.addr_dst, DEST_IP);

        /* TCP pseudo header */
        if(*net_hdr_map.next_proto == 6) {
            *trans_hdr_map.checksum = recompute_checksum_32(*trans_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr_net);
            *trans_hdr_map.checksum = recompute_checksum_32(*trans_hdr_map.checksum, *net_hdr_map.addr_dst, DEST_IP);
        }

        *trans_hdr_map.checksum = recompute_checksum_16(*trans_hdr_map.checksum, *trans_hdr_map.port_src, nat_entry->port_alloc);
        *trans_hdr_map.checksum = recompute_checksum_16(*trans_hdr_map.checksum, *trans_hdr_map.port_dst, htons(dest_port));

        *net_hdr_map.addr_src = int_info->addr_net;
        *trans_hdr_map.port_src = nat_entry->port_alloc;
        *net_hdr_map.addr_dst = DEST_IP;
        *trans_hdr_map.port_dst = htons(dest_port);
    } else if(*trans_hdr_map.port_src == htons(dest_port) && *net_hdr_map.addr_src == DEST_IP) {
#ifndef ENABLE_DEBUG_LOG
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

        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr_net);
        *net_hdr_map.checksum = recompute_checksum_32(*net_hdr_map.checksum, *net_hdr_map.addr_dst, nat_entry->addr_src);

        /* TCP pseudo header */
        if(*net_hdr_map.next_proto == 6) {
            *trans_hdr_map.checksum = recompute_checksum_32(*trans_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr_net);
            *trans_hdr_map.checksum = recompute_checksum_32(*trans_hdr_map.checksum, *net_hdr_map.addr_dst, nat_entry->addr_src);
        }

        *trans_hdr_map.checksum = recompute_checksum_16(*trans_hdr_map.checksum, *trans_hdr_map.port_src, htons(listen_port));
        *trans_hdr_map.checksum = recompute_checksum_16(*trans_hdr_map.checksum, *trans_hdr_map.port_dst, nat_entry->port_src);

        *net_hdr_map.addr_src = int_info->addr_net;
        *trans_hdr_map.port_src = htons(listen_port);
        *net_hdr_map.addr_dst = nat_entry->addr_src;
        *trans_hdr_map.port_dst = nat_entry->port_src;
    } else {
        LOG_DEBUG("Packet is not intended for proxy.\n\n");
        return false;
    }

    return true;
}

bool cond_time(struct nat_entry entry, uint64_t data) {
    return data - entry.alloc_time >= nat_table_entry_min_lifetime;
}

uint16_t get_free_port(nat_table *nat_table, uint16_t *port_cntr) {
    uint16_t init_val;

    init_val = *port_cntr;

    (*port_cntr)++;

    if(*port_cntr < nat_port_range_start || *port_cntr > nat_port_range_end) {
        *port_cntr = nat_port_range_start;
    }

    while(nat_table_get_by_alloc(nat_table, htons(*port_cntr))) {
        (*port_cntr)++;

        if(*port_cntr > nat_port_range_end) {
            *port_cntr = nat_port_range_start;
        }

        if(*port_cntr == init_val) {
            return 0;
        }
    }

    return htons(*port_cntr);
}
