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
    uint32_t ip;
};

int create_socket(struct int_info *int_info);

bool handle_packet(uint8_t *buf, struct nat_table *nat_table, struct int_info *int_info, uint16_t *port_cntr);

uint8_t map_network_header(uint8_t *buf, uint32_t **addr_src, uint32_t **addr_dst, uint8_t **next_proto);
uint8_t map_transport_header(uint8_t *buf, uint8_t proto, uint16_t **port_src, uint16_t **port_dst);
uint16_t get_free_port(struct nat_table *nat_table, uint16_t *port_cntr);

int main() {
    uint8_t *buf;
    struct nat_table *nat_table;
    uint16_t port_cntr;

    struct sockaddr addr;
    socklen_t len;

    struct int_info int_info;
    int socket_fd;

    size_t recv_size;

    buf = (uint8_t *) malloc(BUF_SIZE * sizeof(uint8_t));
    nat_table = nat_table_alloc(NAT_TABLE_SIZE);
    port_cntr = NAT_PORT_RANGE_START;

    len = sizeof(addr);

    socket_fd = create_socket(&int_info);

    printf("Listening on port %d...\n\n", LISTEN_PORT);

    while ((recv_size = recvfrom(socket_fd, buf, BUF_SIZE, 0, &addr, &len)) > 0) {
        printf("Received packet with length %u\n", len);

        if(!handle_packet(buf, nat_table, &int_info, &port_cntr)) {
            continue;
        }

        printf("Sending reply... ");

        if(sendto(socket_fd, buf, recv_size, 0, &addr, len) < 0) {
            printf("Failed\n");
            continue;
        }

        printf("Success\n");
    }

    close(socket_fd);
    free(buf);
    nat_table_free(nat_table);

    return EXIT_SUCCESS;
}

int create_socket(struct int_info *int_info) {
    int socket_fd;
    struct ifreq ifreq;

    uint32_t ip_h_order;
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

    ip_h_order = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;
    int_info->ip = htonl(ip_h_order);
    
    ip_splitted = (uint8_t *) &ip_h_order;

    printf("Socket\n");
    printf("|-name %s\n", INT_NAME);
    printf("|-index %d\n", int_info->index);
    printf("|-ip %d.%d.%d.%d\n", ip_splitted[0], ip_splitted[1], ip_splitted[2], ip_splitted[3]);
    printf("Initialized successfully\n\n");

    return socket_fd;
}

bool handle_packet(uint8_t *buf, struct nat_table *nat_table, struct int_info *int_info, uint16_t *port_cntr) {
    uint32_t *addr_src;
    uint32_t *addr_dst;
    uint8_t *trans_proto;
    uint8_t netw_len;

    uint16_t *port_src;
    uint16_t *port_dst;
    uint8_t trans_len;

    struct nat_entry *nat_entry;
    struct nat_entry nat_entry_new;

    netw_len = map_network_header(buf, &addr_src, &addr_dst, &trans_proto);
    trans_len = map_transport_header(buf + netw_len, *trans_proto, &port_src, &port_dst);

    if(trans_len == 0) {
        printf("Transport header length is 0. Ignoring packet\n");
        return false;
    }

    if(*addr_dst != int_info->ip) {
        printf("Destination IP is not equal to interface IP. Ignoring packet\n");
        return false;
    }

    if(ntohs(*port_dst) == LISTEN_PORT) {
        printf("This is a packet from the client\n");

        nat_entry = nat_table_get_by_src(nat_table, *port_src, *addr_src);
        if(!nat_entry) {
            nat_entry_new.src_port = *port_src;
            nat_entry_new.src_ip = *addr_src;
            nat_entry_new.alloc_port = get_free_port(nat_table, port_cntr);
            nat_entry_new.alloc_time = time(NULL);

            nat_entry = nat_table_insert(nat_table, nat_entry_new);
            if(!nat_entry) {
                return false;
            }
        }

        *addr_src = int_info->ip;
        *port_src = nat_entry->alloc_port;
        *addr_dst = htonl(DEST_IP);
        *port_dst = htons(DEST_PORT);
    } else if(ntohs(*port_src) == DEST_PORT && ntohl(*addr_src) == DEST_IP) {
        printf("This is a packet from the server\n");

        nat_entry = nat_table_get_by_alloc(nat_table, *port_dst);
        if(!nat_entry) {
            return false;
        }

        *addr_src = int_info->ip;
        *port_src = LISTEN_PORT;
        *addr_dst = nat_entry->src_ip;
        *port_dst = nat_entry->src_port;
    } else {
        printf("This packet is not intended for proxy. Ignoring packet\n");
        return false;
    }

    return true;

    /* TODO: Recalculate checksum*/
}

uint8_t map_network_header(uint8_t *buf, uint32_t **addr_src, uint32_t **addr_dst, uint8_t **next_proto) {
    struct iphdr *iphdr; 

    iphdr = (struct iphdr *) buf;

    *addr_src = &iphdr->saddr;
    *addr_dst = &iphdr->daddr;
    *next_proto = &iphdr->protocol;

    return iphdr->ihl * 4;
}

uint8_t map_transport_header(uint8_t *buf, uint8_t proto, uint16_t **port_src, uint16_t **port_dst) {
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    /* TCP protocol */
    if(proto == 6) {
        tcphdr = (struct tcphdr *) buf;

        *port_src = &tcphdr->source;
        *port_dst = &tcphdr->dest;

        return tcphdr->doff;
    }

    /* UDP protocol */
    if(proto == 17) {
        udphdr = (struct udphdr *) buf;

        *port_src = &udphdr->source;
        *port_dst = &udphdr->dest;

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

