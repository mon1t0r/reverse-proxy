#!/bin/sh

LISTEN_PORT=52880
NAT_PORT_RANGE=49160:49192

set -x

iptables -A INPUT -p tcp --destination-port $LISTEN_PORT -j DROP
iptables -A INPUT -p tcp --destination-port $NAT_PORT_RANGE -j DROP

