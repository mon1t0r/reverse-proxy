#!/bin/bash

if [ "$#" -gt 3 ] || [ "$#" -lt 2 ]; then
    echo "Usage: $0 <action> <listen_port> [nat_port_range]"
    exit 1
fi

ACTION=$1
LISTEN_PORT=$2
NAT_PORT_RANGE=49160:49190
if [ "$#" -eq 3 ]; then
    NAT_PORT_RANGE=$3
fi

if [ "$ACTION" = "disable" ]; then
    set -x
    iptables -A OUTPUT -p tcp --source-port $LISTEN_PORT --tcp-flags RST \
        RST -j DROP
    iptables -A OUTPUT -p tcp --source-port $NAT_PORT_RANGE --tcp-flags RST \
        RST -j DROP
elif [ "$ACTION" = "enable" ]; then
    set -x
    iptables -D OUTPUT -p tcp --source-port $LISTEN_PORT --tcp-flags RST \
        RST -j DROP
    iptables -D OUTPUT -p tcp --source-port $NAT_PORT_RANGE --tcp-flags RST \
        RST -j DROP
else
    echo "Unknown action \"$ACTION\""
    exit 1
fi

