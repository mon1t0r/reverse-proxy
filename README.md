## Overview
This project is an implementation of NAT / reverse proxy, that works
on Layer 3 and Layer 4 of the ISO/OSI model.

The application listens for incoming TCP and UDP packets on the configured
port, forwards them to the destination host, and then receives and forwards
response to the requesting client.

Therefore, the requesting client must send the data with the destination IP and
port of the proxy. Higher layer protocols, which check the destination address
(e.g. HTTPS) will not work correctly with the current implementation, as the
proxy operates only on L3/L4 and does not modify any TCP/UDP payload.

Work with multiple interfaces is currently unsupported (TCP/UDP checksum
recalculation will produce incorrect checksums). Please be sure that packets
come in and out on the same interface, or bind to the interface with `-I`
or `--interface` option.

## Build and run
### Requirements
```
gcc
make
cppcheck
```

### Build
```
git clone https://github.com/mon1t0r/reverse-proxy
cd reverse-proxy
make
```

### Run
```
sudo release/reverse-proxy [OPTION]... [LISTEN_PORT] [DEST_ADDR] [DEST_PORT]
```

### Options
```
LISTEN_PORT - port number, on which proxy will be listening for incoming packets
DEST_ADDR   - network address of the destination (where packets will be forwarded)
DEST_PORT   - port number of the destination (where packets will be forwarded)

-I --interface                      interface name
-t --nat-table-size                 size of the NAT hashtable (not related to the max number
                                    of NAT entries, as they will be added to linked lists
                                    in case the table cell is not empty)
-l --nat-table-entry-min-lifetime   time without a packet for a NAT entry, to be available
                                    for removal, in seconds
-s --nat-port-range-start           port range start number, which will be used for NAT
-e --nat-port-range-end             port range end number, which will be used for NAT
```

## Important info
Before using the proxy, make sure the correct port numbers are specified in the
script and run
```
sudo scripts/disable_tcp_reply.sh
```
The script disables kernel processing for TCP packets, so the client will not
receive `Connection refused` while establishing TCP handshake with the host.

Kernel processing can be enabled back by running
```
sudo scripts/enable_tcp_reply.sh
```

`iptables` needs to be installed in order to execute the script.

## TODO
 - perform extensive testing (including UDP packets);
 - fix TCP/UDP checksum recalculation when working with multiple interfaces.
