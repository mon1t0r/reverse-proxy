#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "nat_table.h"

/* Max IP packet size is 65535 bytes */
#define BUF_SIZE 65536
#define NAT_TABLE_SIZE 200

#define NAT_PORT_RANGE_START 49160
#define NAT_PORT_RANGE_END 50160

#define INT_NAME "eno1"

#define LISTEN_PORT 52879

#define DEST_IP_1 142
#define DEST_IP_2 251
#define DEST_IP_3 40
#define DEST_IP_4 206
#define DEST_PORT 80

#define DEST_IP (DEST_IP_1 | (DEST_IP_2 << 8) | (DEST_IP_3 << 16) | (DEST_IP_4 << 24))

struct int_info {
    int index;
    uint32_t addr;
};

struct net_hdr_map {
    uint32_t *addr_src;
    uint32_t *addr_dst;
    uint8_t *next_proto;
    uint16_t *checksum;
};

struct trans_hdr_map {
    uint16_t *port_src;
    uint16_t *port_dst;
    uint16_t *checksum;
};

int create_socket(struct int_info *int_info);

bool handle_packet(uint8_t *buf, struct nat_table *nat_table, struct int_info *int_info, uint16_t *port_cntr);

uint8_t map_network_header(uint8_t *buf, struct net_hdr_map *net_hdr_map);
uint8_t map_transport_header(uint8_t *buf, uint8_t proto, struct trans_hdr_map *trans_hdr_map);
uint16_t get_free_port(struct nat_table *nat_table, uint16_t *port_cntr);
uint16_t recompute_checksum(uint16_t old_sum, uint32_t old_val, uint32_t new_val);

int main() {
    uint8_t *buf;
    struct nat_table *nat_table;
    uint16_t port_cntr;

    struct sockaddr addr;
    socklen_t len;

    struct int_info int_info;
    int socket_fd;

    size_t buf_len;

    buf = (uint8_t *) malloc(BUF_SIZE * sizeof(uint8_t));
    nat_table = nat_table_alloc(NAT_TABLE_SIZE);
    port_cntr = NAT_PORT_RANGE_START;

    len = sizeof(addr);

    socket_fd = create_socket(&int_info);

    printf("Listening on port %d...\n\n", LISTEN_PORT);

    while ((buf_len = recvfrom(socket_fd, buf, BUF_SIZE, 0, &addr, &len)) > 0) {
        printf("Received packet with length %lu\n", buf_len);

        if(!handle_packet(buf, nat_table, &int_info, &port_cntr)) {
            continue;
        }

        printf("Sending packet... ");

        if(sendto(socket_fd, buf, buf_len, 0, &addr, len) < 0) {
            printf("Failed\n\n");
            continue;
        }

        printf("Success\n\n");
    }

    close(socket_fd);
    free(buf);
    nat_table_free(nat_table);

    return EXIT_SUCCESS;
}

int create_socket(struct int_info *int_info) {
    int socket_fd;
    struct ifreq ifreq;

    uint8_t *ip_splitted;

    if((socket_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, INT_NAME, IFNAMSIZ - 1);

    if(ioctl(socket_fd, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }

    int_info->index = ifreq.ifr_ifindex;

    /*if(ioctl(socket_fd, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        exit(EXIT_FAILURE);
    }*/

    if(ioctl(socket_fd, SIOCGIFADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        exit(EXIT_FAILURE);
    }

    int_info->addr = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;

    ip_splitted = (uint8_t *) &int_info->addr;

    printf("Socket\n");
    printf("|-name %s\n", INT_NAME);
    printf("|-index %d\n", int_info->index);
    printf("|-ip %d.%d.%d.%d\n", ip_splitted[0], ip_splitted[1], ip_splitted[2], ip_splitted[3]);
    printf("Initialized successfully\n\n");

    return socket_fd;
}

bool handle_packet(uint8_t *buf, struct nat_table *nat_table, struct int_info *int_info, uint16_t *port_cntr) {
    struct net_hdr_map net_hdr_map;
    uint8_t net_len;

    struct trans_hdr_map trans_hdr_map;
    uint8_t trans_len;

    struct nat_entry *nat_entry;
    struct nat_entry nat_entry_new;

    net_len = map_network_header(buf, &net_hdr_map);
    if(net_len <= 0) {
        printf("Network header length is not positive. Ignoring packet\n\n");
        return false;
    }

    trans_len = map_transport_header(buf + net_len, *net_hdr_map.next_proto, &trans_hdr_map);
    if(trans_len == 0) {
        printf("Transport header length is not positive. Ignoring packet\n\n");
        return false;
    }

    if(*net_hdr_map.addr_dst != int_info->addr) {
        printf("Destination IP is not equal to interface IP. Ignoring packet\n\n");
        return false;
    }

    if(ntohs(*trans_hdr_map.port_dst) == LISTEN_PORT) {
        printf("This is a packet from the client\n");

        nat_entry = nat_table_get_by_src(nat_table, *trans_hdr_map.port_src, *net_hdr_map.addr_src);
        if(!nat_entry) {
            nat_entry_new.port_src = *trans_hdr_map.port_src;
            nat_entry_new.addr_src = *net_hdr_map.addr_src;
            nat_entry_new.port_alloc = get_free_port(nat_table, port_cntr);
            nat_entry_new.alloc_time = time(NULL);

            printf("NAT entry not found, creating a new one. Allocated port is %u\n", ntohs(nat_entry_new.port_alloc));

            nat_entry = nat_table_insert(nat_table, nat_entry_new);
            if(!nat_entry) {
                printf("NAT table inser failed. Ignoring packet\n\n");
                return false;
            }
        }

        *net_hdr_map.checksum = recompute_checksum(*net_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr);
        *net_hdr_map.checksum = recompute_checksum(*net_hdr_map.checksum, *net_hdr_map.addr_dst, DEST_IP);

        *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, int_info->addr, *net_hdr_map.addr_src);
        *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, DEST_IP, *net_hdr_map.addr_dst);

        /* Do not recompute TCP checksum due to checksum offload */
        /*
            *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, *trans_hdr_map.port_src, nat_entry->port_alloc);
            *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, *trans_hdr_map.port_dst, htons(DEST_PORT));
        */

        *net_hdr_map.addr_src = int_info->addr;
        *trans_hdr_map.port_src = nat_entry->port_alloc;
        *net_hdr_map.addr_dst = DEST_IP;
        *trans_hdr_map.port_dst = htons(DEST_PORT);
    } else if(ntohs(*trans_hdr_map.port_src) == DEST_PORT && ntohl(*net_hdr_map.addr_src) == DEST_IP) {
        printf("This is a packet from the server\n");

        nat_entry = nat_table_get_by_alloc(nat_table, *trans_hdr_map.port_dst);
        if(!nat_entry) {
            printf("NAT entry not found. Ignoring packet\n\n");
            return false;
        }

        *net_hdr_map.checksum = recompute_checksum(*net_hdr_map.checksum, *net_hdr_map.addr_src, int_info->addr);
        *net_hdr_map.checksum = recompute_checksum(*net_hdr_map.checksum, *net_hdr_map.addr_dst, nat_entry->addr_src);

        *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, int_info->addr, *net_hdr_map.addr_src);
        *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, nat_entry->addr_src, *net_hdr_map.addr_dst);

        /* Do not recompute TCP checksum due to checksum offload */
        /*
            *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, *trans_hdr_map.port_src, htons(LISTEN_PORT));
            *trans_hdr_map.checksum = recompute_checksum(*trans_hdr_map.checksum, *trans_hdr_map.port_dst, nat_entry->port_src);
        */

        *net_hdr_map.addr_src = int_info->addr;
        *trans_hdr_map.port_src = htons(LISTEN_PORT);
        *net_hdr_map.addr_dst = nat_entry->addr_src;
        *trans_hdr_map.port_dst = nat_entry->port_src;
    } else {
        printf("This packet is not intended for proxy. Ignoring packet\n\n");
        return false;
    }

    return true;
}

uint8_t map_network_header(uint8_t *buf, struct net_hdr_map *net_hdr_map) {
    struct iphdr *iphdr;

    iphdr = (struct iphdr *) buf;

    net_hdr_map->addr_src = &iphdr->saddr;
    net_hdr_map->addr_dst = &iphdr->daddr;
    net_hdr_map->next_proto = &iphdr->protocol;
    net_hdr_map->checksum = &iphdr->check;

    return iphdr->ihl * 4;
}

uint8_t map_transport_header(uint8_t *buf, uint8_t proto, struct trans_hdr_map *trans_hdr_map) {
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    /* TCP protocol */
    if(proto == 6) {
        tcphdr = (struct tcphdr *) buf;

        trans_hdr_map->port_src = &tcphdr->source;
        trans_hdr_map->port_dst = &tcphdr->dest;
        trans_hdr_map->checksum = &tcphdr->check;

        return tcphdr->doff;
    }

    /* UDP protocol */
    if(proto == 17) {
        udphdr = (struct udphdr *) buf;

        trans_hdr_map->port_src = &udphdr->source;
        trans_hdr_map->port_dst = &udphdr->dest;
        trans_hdr_map->checksum = &udphdr->check;

        return udphdr->len;
    }

    return 0;
}

uint16_t get_free_port(struct nat_table *nat_table, uint16_t *port_cntr) {
    (*port_cntr)++;

    if(*port_cntr < NAT_PORT_RANGE_START || *port_cntr > NAT_PORT_RANGE_END) {
        *port_cntr = NAT_PORT_RANGE_START;
    }

    while(nat_table_get_by_alloc(nat_table, *port_cntr)) {
        (*port_cntr)++;
        if(*port_cntr > NAT_PORT_RANGE_END) {
            *port_cntr = NAT_PORT_RANGE_START;
        }
    }

    return htons(*port_cntr);
}

uint16_t recompute_checksum(uint16_t old_sum, uint32_t old_val, uint32_t new_val) {
    uint32_t sum;

    sum = ~old_sum - (old_val & 0xFFFF) - (old_val >> 16);

    sum = (sum & 0xFFFF) + (sum >> 16);

    sum = sum + (new_val & 0xFFFF) + (new_val >> 16);

    sum = (sum & 0xFFFF) + (sum >> 16);

    return (u_int16_t) ~sum;
}
