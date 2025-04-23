#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

int get_interface_index(int socket_fd, const char *interface_name) {
    struct ifreq ifreq;

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, interface_name, IFNAMSIZ - 1);
    if(ioctl(socket_fd, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }

    return ifreq.ifr_ifindex;
}

uint32_t get_interface_net_addr(int socket_fd, int interface_index) {
    struct ifreq ifreq;

    ifreq.ifr_ifindex = interface_index;

    if(ioctl(socket_fd, SIOCGIFADDR, &ifreq) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        exit(EXIT_FAILURE);
    }

    return ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr;
}
