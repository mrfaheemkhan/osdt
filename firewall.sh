#!/bin/bash	
# firewall rules

# Linux distribution set here
distro="DISTRO"

iptables -F
iptables -X
iptables -t nat -F

# drop everything else
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# allow established return traffic
iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED -j ACCEPT

# allow specific ICMP packets
icmp_types=(
"echo-request"
"echo-reply"
"destination-unreachable"
"time-exceeded"
)
for type in "${icmp_types[@]}"
do 
	iptables -A INPUT -p icmp --icmp-type $type -m limit --limit 1/s -j ACCEPT
	iptables -A OUTPUT -p icmp --icmp-type $type -j ACCEPT
done 

# allow SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate NEW -j ACCEPT

# allow OpenVPN packets
iptables -A INPUT -p PROTO --dport VPNPORT -m conntrack --ctstate NEW -j ACCEPT

# allow outbound DNS lookups
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# allow outbound http and https connections for updates
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT

# allow forwarding between tunnel and external interface
iptables -A FORWARD -i tun0 -o eth0 -m conntrack --ctstate NEW -j ACCEPT

# perform NAT on outgoing packets
iptables -t nat -A POSTROUTING -s X.X.X.X/24 -o eth0 -j MASQUERADE

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
