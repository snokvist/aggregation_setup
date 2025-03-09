### IP-Plan

## OpenWRT Subnet: 192.168.2.* / 255.255.255.0
- 192.168.2.20 (Google Wifi Gale to Radxa ethernet. Standard GW)
- 192.168.2.30 (Google Wifi Gale OpenWRT Hub/Node)
- 192.168.2.31 (CPE510v3 OpenWRT Node)
- Setup standard GW to 192.168.1.20

## Radxa Subnet: 192.168.1.* / 255.255.255.0
- 192.168.1.20 Radxa main Ethernet port
- 192.168.2.20 Radxa USB Ethernet port (Gateway to OpenWRT subnet)

## VTX Subnet (VPN)
10.5.0.1 Radxa gs-wfb vpn
10.5.0.10 VTX drone-wfb vpn
Setup default gateway to gain access to internet or similar:
route add default gw 10.5.0.1 wfb-tun

## Firewall rules for radxa to allow access to internet
sudo iptables -t nat -A POSTROUTING -s 10.5.0.10 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -s 10.5.0.10 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -d 10.5.0.10 -i eth0 -j ACCEPT


### OpenWRT
https://firmware-selector.openwrt.org/

## CPE510v3
https://firmware-selector.openwrt.org/?version=24.10.0&target=ath79%2Fgeneric&id=tplink_cpe510-v3
Install packages special:
base-files ca-bundle dnsmasq dropbear firewall4 fstools kmod-ath9k kmod-gpio-button-hotplug kmod-nft-offload libc libgcc libustream-mbedtls logd mtd netifd nftables odhcp6c odhcpd-ipv6only procd-ujail swconfig uboot-envtools uci uclient-fetch urandom-seed urngd wpad-basic-mbedtls rssileds bash wfb-ng

Special setup without luci:
/etc/config/wireless
config wifi-iface 'wifinet2'
        option device 'radio0'
        option mode 'monitor'
        option ssid 'monitor'
        option ifname 'phy1-wfb'
        option network 'lan'
 
/etc/config/network
config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        option ipaddr '192.168.2.31'
        option netmask '255.255.255.0'
        option ip6assign '60'
        option gateway '192.168.2.20'


### sbc groundstation
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
