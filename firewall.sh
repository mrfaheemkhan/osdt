#!/bin/bash	

iptables -F
iptables -X
iptables -t nat -F

distro="DISTRO"

# allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# allow specific ICMP packets
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT # type 0
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT # type 8
iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT # type 3
iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT # type 3
iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT # type 11
iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT # type 11

# block common script kiddie attacks
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# allow SSH
iptables -A INPUT -p tcp -m tcp --dport 22 -m limit --limit 6/minute --limit-burst 15 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --sport 22 -j ACCEPT

# allow OpenVPN packets
iptables -A INPUT -p PROTO -m PROTO --dport VPNPORT -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p PROTO -m PROTO --sport VPNPORT -m state --state ESTABLISHED -j ACCEPT

# allow outbound DNS lookups
iptables -A OUTPUT -p udp -m udp --dport 53 -m state --state NEW -j ACCEPT

# allow outbound http and https connections for updates
iptables -A OUTPUT -p tcp -m tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT

# allow forwarding between external and tunnel interfaces
iptables -A FORWARD -i eth+ -o tun0 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i tun0 -o eth+ -m state --state NEW,ESTABLISHED -j ACCEPT

# perform NAT on outgoing packets
iptables -t nat -A POSTROUTING -s X.X.X.X/24 -o eth0 -j MASQUERADE

# allow incoming established connections
iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT

# drop everything else
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

if [ "$distro" == "Debian" ] || [ "$distro" == "Ubuntu" ]
then
	iptables-save > /etc/network/iptables
	cat > /etc/network/if-pre-up.d/iptables<<EOF
#!/bin/bash
/sbin/iptables-restore < /etc/network/iptables
EOF
	chmod +x /etc/network/if-pre-up.d/iptables
else
	service iptables save
fi
