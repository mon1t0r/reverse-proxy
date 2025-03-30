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
The script disables kernel processing for TCP packets, so the client will not recieve `Connection refused` while establishing TCP handshake with the host.

Kernel processing can be enabled back by running
```
sudo ./shell/enable_tcp_reply.sh
```
