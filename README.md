## sbc groundstation
- /config/scripts/stream.sh
- /config/scripts/autoload-wfb-nics.sh
- /etc/wifibroadcast.cfg

- 
- systemctl stop wifibroadcast
- systemctl disable wifibroadcast
- systemctl enable wfb-cluster-node
- systemctl start wfb-cluster-node
- systemctl enable wfb-cluster-manager
- systemctl start wfb-cluster-manager



