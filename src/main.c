#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <asm-generic/socket.h>

#include "nat/nat_table.h"
#include "options.h"
#include "transport_layer.h"
#include "checksum.h"

enum {
    packet_buf_size = 65536
};

struct handle_context {
    struct proxy_opts  opts;
    uint16_t           port_cntr;
    nat_table          *nat_table;
};

uint16_t get_free_port(struct handle_context *ctx) {
    uint16_t init_val;

    init_val = ctx->port_cntr;

    ctx->port_cntr++;

    if(ctx->port_cntr < ctx->opts.nat_port_range_start ||
       ctx->port_cntr > ctx->opts.nat_port_range_end) {
        ctx->port_cntr = ctx->opts.nat_port_range_start;
    }

    /* Look for a free port, which is not currently used by NAT */
    while(nat_table_get_by_alloc(ctx->nat_table, ctx->port_cntr)) {
        ctx->port_cntr++;

        if(ctx->port_cntr > ctx->opts.nat_port_range_end) {
            ctx->port_cntr = ctx->opts.nat_port_range_start;
        }

        if(ctx->port_cntr == init_val) {
            return 0;
        }
    }

    return ctx->port_cntr;
}

bool nat_cond_func_time(struct nat_entry entry, const void *data_ptr) {
    const struct {
        time_t alloc_time;
        time_t min_lifetime;
    } *nat_data_ptr;

    nat_data_ptr = data_ptr;

    return nat_data_ptr->alloc_time - entry.alloc_time >=
           nat_data_ptr->min_lifetime;
}

struct nat_entry *nat_punch_hole(struct handle_context *ctx, uint16_t port_src,
                                 uint32_t addr_src) {
    struct nat_entry nat_entry_new;
    struct {
        time_t alloc_time;
        time_t min_lifetime;
    } nat_entry_data;

    nat_entry_new.port_src = port_src;
    nat_entry_new.addr_src = addr_src;
    nat_entry_new.alloc_time = time(NULL);
    nat_entry_new.port_alloc = get_free_port(ctx);

    /* If port successfully allocated, goto insert */
    if(nat_entry_new.port_alloc != 0) {
        goto ins;
    }

    /* Remove entries, that were inactive for too long */
    nat_entry_data.alloc_time = nat_entry_new.alloc_time;
    nat_entry_data.min_lifetime = ctx->opts.nat_table_entry_min_lifetime;

    /* If no entries were removed, NAT hole punch failed */
    if(!nat_table_remove_if(ctx->nat_table, &nat_entry_data,
                            &nat_cond_func_time)) {
        return NULL;
    }

    /* Try to get free port again */
    nat_entry_new.port_alloc = get_free_port(ctx);
    /* If port allocation failed again, NAT hole punch failed */
    if(nat_entry_new.port_alloc == 0) {
        return NULL;
    }

ins:
    return nat_table_insert(ctx->nat_table, nat_entry_new);
}

void hdr_update_pseudo(struct trans_hdr_map *hdr_map,
                       uint32_t addr_src_prev, uint32_t addr_dst_prev,
                       uint32_t addr_src, uint32_t addr_dst) {
    *hdr_map->checksum = recompute_checksum_32(
        *hdr_map->checksum, addr_src_prev, addr_src);
    *hdr_map->checksum = recompute_checksum_32(
        *hdr_map->checksum, addr_dst_prev, addr_dst);
}

void hdr_set_port(struct trans_hdr_map *hdr_map,
                  uint16_t port_src, uint16_t port_dst) {
    *hdr_map->checksum = recompute_checksum_16(
        *hdr_map->checksum, *hdr_map->port_src, port_src);
    *hdr_map->checksum = recompute_checksum_16(
        *hdr_map->checksum, *hdr_map->port_dst, port_dst);

    *hdr_map->port_src = port_src;
    *hdr_map->port_dst = port_dst;
}

/* Server to client */
bool packet_handle_stoc(struct handle_context *ctx,
                        struct trans_hdr_map *hdr_map,
                        struct sockaddr_in *addr, int protocol) {
    struct nat_entry *nat_entry_ptr;

    /* Look for existing NAT entry */
    nat_entry_ptr = nat_table_get_by_alloc(ctx->nat_table,
                                           ntohs(*hdr_map->port_dst));
    /* If NAT entry was not found, packet processing failed, as we do not know
     * to which client the packet should be sent */
    if(nat_entry_ptr == NULL) {
        return false;
    }

    /* TODO: Review if checksum recalculation is necessary */

    /* Recompute checksum only for TCP pseudo header, or if checksum is not
     * equal to 0 (UDP pseudo header, if UDP checksum is calculated) */
    if(protocol == IPPROTO_TCP || hdr_map->checksum != 0) {
        hdr_update_pseudo(hdr_map, addr->sin_addr.s_addr, 0, 0,
                          htonl(nat_entry_ptr->addr_src));
    }

    hdr_set_port(hdr_map, htons(ctx->opts.listen_port),
                 htons(nat_entry_ptr->port_src));

    addr->sin_addr.s_addr = htonl(nat_entry_ptr->addr_src);

    return true;
}

/* Client to server */
bool packet_handle_ctos(struct handle_context *ctx,
                        struct trans_hdr_map *hdr_map,
                        struct sockaddr_in *addr, int protocol) {
    struct nat_entry *nat_entry_ptr;

    /* Look for existing NAT entry */
    nat_entry_ptr = nat_table_get_by_src(ctx->nat_table,
                                         ntohs(*hdr_map->port_src),
                                         ntohl(addr->sin_addr.s_addr));

    /* If NAT entry was not found */
    if(nat_entry_ptr == NULL) {
        /* Create new NAT entry */
        nat_entry_ptr = nat_punch_hole(ctx, ntohs(*hdr_map->port_src),
                                       ntohl(addr->sin_addr.s_addr));
        /* If NAT entry creation failed, packet processing failed */
        if(nat_entry_ptr == NULL) {
            return false;
        }
    }

    /* TODO: Review if checksum recalculation is necessary */

    /* Recompute checksum only for TCP pseudo header, or if checksum is not
     * equal to 0 (UDP pseudo header, if UDP checksum is calculated) */
    if(protocol == IPPROTO_TCP || hdr_map->checksum != 0) {
        hdr_update_pseudo(hdr_map, addr->sin_addr.s_addr, 0, 0,
                          htonl(ctx->opts.dest_addr));
    }

    hdr_set_port(hdr_map, htons(nat_entry_ptr->port_alloc),
                 htons(ctx->opts.dest_port));

    addr->sin_addr.s_addr = htonl(ctx->opts.dest_addr);

    return true;
}

bool packet_handle(struct handle_context *ctx, uint8_t *buf,
                  struct sockaddr_in *addr, int protocol) {
    struct trans_hdr_map hdr_map;

    if(map_transport_header(buf, protocol, &hdr_map) == 0) {
        return false;
    }

    /* If packet dst port is listen port, this is a client to server packet */
    if(ntohs(*hdr_map.port_dst) == ctx->opts.listen_port) {
        return packet_handle_ctos(ctx, &hdr_map, addr, protocol);
    }

    /* If packet src address is dst address and packet src port is dst port,
     * this is a server to client packet*/
    if(ntohl(addr->sin_addr.s_addr) == ctx->opts.dest_addr &&
       ntohs(*hdr_map.port_src) == ctx->opts.dest_port) {
        return packet_handle_stoc(ctx, &hdr_map, addr, protocol);
    }

    return false;
}

void socket_init(int socket_fd, const char *int_name) {
    int sockoptval;
    int int_name_len;

    /* Disable path MTU discover on socket, so outgoing
     * packets can be fragmented */
    sockoptval = 0;
    if(setsockopt(socket_fd, IPPROTO_IP, IP_MTU_DISCOVER, &sockoptval,
                  sizeof(sockoptval)) < 0) {
        perror("setsockopt(IP_MTU_DISCOVER)");
        exit(EXIT_FAILURE);
    }

    int_name_len = strlen(int_name);
    if(int_name_len == 0) {
        return;
    }

    /* Bind socket to interface */
    if(setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, int_name,
                  int_name_len) < 0) {
        perror("setsockopt(SO_BINDTODEVICE)");
        exit(EXIT_FAILURE);
    }
}

int socket_create(int protocol) {
    int socket_fd;

    if((socket_fd = socket(AF_INET, SOCK_RAW, protocol)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    return socket_fd;
}

int main(int argc, char *argv[]) {
    struct handle_context ctx;

    int sock_tcp_fd, sock_udp_fd;

    fd_set sock_fd_set;
    int sock_max_fd1;
    int n_sock_ready;

    uint8_t *buf;
    ssize_t buf_len;
    int sock_recv_fd;

    struct sockaddr_in addr;
    socklen_t addr_len;

    struct iphdr *iphdr;

    /* Options */
    ctx.opts = options_parse(argc, argv);
    options_print(&ctx.opts);
    printf("\n");

    /* NAT table */
    ctx.nat_table = nat_table_alloc(ctx.opts.nat_table_size);

    /* Sockets */
    sock_tcp_fd = socket_create(IPPROTO_TCP);
    sock_udp_fd = socket_create(IPPROTO_UDP);
    socket_init(sock_tcp_fd, ctx.opts.interface_name);
    socket_init(sock_udp_fd, ctx.opts.interface_name);

    /* Port counter */
    ctx.port_cntr = ctx.opts.nat_port_range_start;

    /* Buffer */
    buf = malloc(packet_buf_size * sizeof(uint8_t));

    /* Preparation for select() */
    FD_ZERO(&sock_fd_set);
    sock_max_fd1 = (sock_tcp_fd > sock_udp_fd ? sock_tcp_fd : sock_udp_fd) + 1;

    printf("Initialized successfully\n");
    printf("Listening on port %d...\n\n", ctx.opts.listen_port);

    /* Main loop */
    for(;;) {
        FD_SET(sock_tcp_fd, &sock_fd_set);
        FD_SET(sock_udp_fd, &sock_fd_set);

        /* TODO: Rewrite with epoll() */
        n_sock_ready = select(sock_max_fd1, &sock_fd_set, NULL, NULL, NULL);
        if(n_sock_ready == 0) {
            continue;
        }
        if(n_sock_ready < 0) {
            perror("select()");
            exit(EXIT_FAILURE);
        }

        addr_len = sizeof(addr);

        if(FD_ISSET(sock_tcp_fd, &sock_fd_set)) {
            buf_len = recvfrom(sock_tcp_fd, buf,
                               packet_buf_size * sizeof(uint8_t),
                               0, (struct sockaddr *) &addr, &addr_len);
            sock_recv_fd = sock_tcp_fd;
        } else if(FD_ISSET(sock_udp_fd, &sock_fd_set)) {
            buf_len = recvfrom(sock_udp_fd, buf,
                               packet_buf_size * sizeof(uint8_t),
                               0, (struct sockaddr *) &addr, &addr_len);
            sock_recv_fd = sock_udp_fd;
        } else {
            continue;
        }

        if(buf_len < 0) {
            perror("recvfrom()");
            exit(EXIT_FAILURE);
        }

        iphdr = (struct iphdr *) buf;

        if(!packet_handle(&ctx, buf + (iphdr->ihl * 4), &addr,
                          iphdr->protocol)) {
            continue;
        }

        addr.sin_port = 0;
        if(sendto(sock_recv_fd, buf + (iphdr->ihl * 4),
                  buf_len - (iphdr->ihl * 4), 0, (struct sockaddr *) &addr,
                  sizeof(addr)) < 0) {
            perror("sendto()");
            exit(EXIT_FAILURE);
        }
    }

    /* Free resources */
    free(buf);
    close(sock_udp_fd);
    close(sock_tcp_fd);
    nat_table_free(ctx.nat_table);

    return EXIT_SUCCESS;
}
