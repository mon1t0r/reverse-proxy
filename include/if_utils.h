#ifndef REV_PROXY_IF_UTILS_H
#define REV_PROXY_IF_UTILS_H

#include <stdint.h>

int get_interface_index(int socket_fd, const char *interface_name);
uint32_t get_interface_net_addr(int socket_fd, int interface_index);

#endif
