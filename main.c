#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <asm/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* Max IP packet size is 65535 bytes */
#define BUF_SIZE 65536

int main() {
    int socket_fd;

    uint8_t *buf;
    struct sockaddr addr;
    socklen_t len;

    if((socket_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        perror("socket()");
        return EXIT_FAILURE;
    }

    buf = (uint8_t *) malloc(BUF_SIZE * sizeof(uint8_t));
    len = sizeof(addr);

    while (recvfrom(socket_fd, buf, BUF_SIZE, 0, &addr, &len) > 0) {
        struct iphdr *ip = (struct iphdr *) buf;

        uint8_t *source_addr = (uint8_t *) &ip->saddr;
        uint8_t *dest_addr = (uint8_t *) &ip->daddr;
        printf("IP packet received\n");
        printf("-src IP: %d.%d.%d.%d\n", source_addr[0], source_addr[1], source_addr[2], source_addr[3]);
        printf("-dst IP: %d.%d.%d.%d\n\n", dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
    }

    free(buf);
    close(socket_fd);

    return EXIT_SUCCESS;
}
