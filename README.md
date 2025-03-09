## IP-Plan

# OpenWRT Subnet: 192.168.2.* / 255.255.255.0
- 192.168.2.20 (OpenWRT Hub to Radxa ethernet. Standard GW)
- 192.168.2.30 (OpenWRT Hub/Node)
- 192.168.2.31 (OpenWRT Node)

# Radxa Subnet: 192.168.1.* / 255.255.255.0

## sbc groundstation
- /config/scripts/stream.sh
- /config/scripts/autoload-wfb-nics.sh
- /etc/wifibroadcast.cfg

- systemctl stop wifibroadcast
- systemctl disable wifibroadcast
- systemctl enable wfb-cluster-node
- systemctl start wfb-cluster-node
- systemctl enable wfb-cluster-manager
- systemctl start wfb-cluster-manager

## Routing and forwarding:
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -d 192.168.1.20 -j DNAT --to-destination 10.5.0.10:80
sudo iptables -t nat -A POSTROUTING -p tcp -d 10.5.0.10 --dport 80 -j MASQUERADE

sudo iptables -t nat -A PREROUTING -p tcp --dport 2222 -d 192.168.1.20 -j DNAT --to-destination 10.5.0.10:20
sudo iptables -t nat -A POSTROUTING -p tcp -d 10.5.0.10 --dport 22 -j MASQUERADE

sudo apt-get install iptables-persistent
sudo netfilter-persistent save

sudo sysctl -w net.ipv4.ip_forward=1
sysctl net.ipv4.ip_forward
sudo sed -i '/^net.ipv4.ip_forward=/d' /etc/sysctl.conf && echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
