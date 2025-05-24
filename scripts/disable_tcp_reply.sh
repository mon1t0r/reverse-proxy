#!/bin/bash

LISTEN_PORT=52880
NAT_PORT_RANGE=49160:49192

set -x

iptables -A OUTPUT -p tcp --source-port $LISTEN_PORT --tcp-flags RST RST -j DROP
iptables -A OUTPUT -p tcp --source-port $NAT_PORT_RANGE --tcp-flags RST RST -j DROP

