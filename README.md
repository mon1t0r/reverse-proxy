## Overview
This project is a NAT / reverse proxy, that works on Layer 3 and Layer 4 of the ISO/OSI model.

The application listens for TCP and UDP packets on the configured port, forwards them to the 
destination host and port, and then receives and forwards response to the requesting client.
Therefore, the requesting client must send the data with the destination ip and port of the proxy.
Higher level protocols, which check the destination address (e.g. HTTPS) will not work correctly
with the current implementation, as the proxy operates only on L3/L4 and does not modify any TCP/UDP
payload.

## Build from source
### Requirements
```
gcc
make
cppcheck
```

### Building
```
git clone https://github.com/mon1t0r/reverse-proxy
./reverse-proxy
make
```

## Important info
Before using the proxy, make sure the correct port number is specified in the script and run
```
sudo ./shell/disable_tcp_reply.sh
```
The script disables kernel processing for TCP packets, so the client will not
receive `Connection refused` while establishing TCP handshake with the host.

Kernel processing can be enabled back by running
```
sudo ./shell/enable_tcp_reply.sh
```

`iptables` needs to be installed to execute the script.
