#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "nat_table.h"

/* Max IP packet size is 65535 bytes */
#define BUF_SIZE 65536
#define NAT_TABLE_SIZE 200

#define NAT_PORT_RANGE_START 49160
#define NAT_PORT_RANGE_END 50160

#define LISTEN_PORT 52879

#define SEND_IP_1 142
#define SEND_IP_2 251
#define SEND_IP_3 40
#define SEND_IP_4 206
#define SEND_PORT 80

void handle_packet(uint8_t *buf, struct nat_table *nat_table);
uint8_t map_network_header(uint8_t *buf, uint32_t **addr_src, uint32_t **addr_dst, uint8_t **next_proto);
uint8_t map_transport_header(uint8_t *buf, uint8_t proto, uint16_t **port_src, uint16_t **port_dst);
uint16_t get_free_port(struct nat_table *nat_table);

uint16_t proxy_nat_last_port_used = 0;

int main() {
    int socket_fd;

    uint8_t *buf;
    struct sockaddr addr;
    socklen_t len;

    struct nat_table *nat_table;

    if((socket_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        return EXIT_FAILURE;
    }

    buf = (uint8_t *) malloc(BUF_SIZE * sizeof(uint8_t));
    len = sizeof(addr);

    nat_table = nat_table_alloc(NAT_TABLE_SIZE);

    while (recvfrom(socket_fd, buf, BUF_SIZE, 0, &addr, &len) > 0) {
        handle_packet(buf, nat_table);
    }

    nat_table_free(nat_table);
    free(buf);
    close(socket_fd);

    return EXIT_SUCCESS;
}

void handle_packet(uint8_t *buf, struct nat_table *nat_table) {
    uint32_t *addr_src;
    uint32_t *addr_dst;
    uint8_t *trans_proto;
    uint8_t netw_len;

    uint16_t port_src;
    uint16_t port_dst;
    uint8_t trans_len;

    struct nat_entry *nat_entry;
    struct nat_entry nat_entry_new;

    netw_len = map_network_header(buf, &addr_src, &addr_dst, &trans_proto);
    trans_len = map_transport_header(buf + netw_len, *trans_proto, &port_src, &port_dst);

    if(trans_len == 0) {
        return;
    }

    if(port_dst != LISTEN_PORT) {
        return;
    }

    nat_entry = nat_table_get_by_src(nat_table, port_src, *addr_src);
    if(!nat_entry) {
        nat_entry_new.src_port = port_src;
        nat_entry_new.src_ip = *addr_src;
        nat_entry_new.alloc_port = get_free_port(nat_table);

        nat_entry = nat_table_insert(nat_table, nat_entry_new);
        if(!nat_entry) {
            return;
        }
    }

    addr_src = 

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

uint16_t get_free_port(struct nat_table *nat_table) {
    proxy_nat_last_port_used++;

    if(proxy_nat_last_port_used < NAT_PORT_RANGE_START || proxy_nat_last_port_used > NAT_PORT_RANGE_END) {
        proxy_nat_last_port_used = NAT_PORT_RANGE_START;
    }

    while(nat_table_get_by_alloc(nat_table, proxy_nat_last_port_used)) {
        proxy_nat_last_port_used++;
        if(proxy_nat_last_port_used > NAT_PORT_RANGE_END) {
            proxy_nat_last_port_used = NAT_PORT_RANGE_START;
        }
    }

    return proxy_nat_last_port_used;
}

