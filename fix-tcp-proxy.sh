# Save this as fix-tcp-proxy.sh
#!/bin/bash

# Allow MongoDB port
iptables -I INPUT 1 -p tcp --dport 27017 -j ACCEPT
iptables -I FORWARD 1 -p tcp --dport 27017 -j ACCEPT

# Allow overlay network traffic
iptables -I FORWARD 1 -i docker_gwbridge -o docker_gwbridge -j ACCEPT

# Allow traffic between overlay networks
iptables -I FORWARD 1 -i docker0 -o docker_gwbridge -j ACCEPT
iptables -I FORWARD 1 -i docker_gwbridge -o docker0 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
