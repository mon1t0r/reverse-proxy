iptables -D INPUT -p tcp --destination-port 52880 -j DROP
iptables -D INPUT -p tcp --destination-port 49160:49192 -j DROP

