#!/bin/bash
set -emb

export LC_ALL=C

_cleanup()
{
  plist=$(jobs -p)
  if [ -n "$plist" ]
  then
      kill -TERM $plist || true
  fi
  exit 1
}

trap _cleanup EXIT

# Default values
DEFAULT_CHANNEL=165
DEFAULT_BANDWIDTH="HT20"
DEFAULT_REGION="US"
DEFAULT_SERVER_IP="192.168.1.20"

# If all three arguments are provided, override defaults
if [ $# -eq 4 ]; then
  CHANNEL=$1
  BANDWIDTH=$2
  REGION=$3
  SERVER_IP=$4
else
  CHANNEL=$DEFAULT_CHANNEL
  BANDWIDTH=$DEFAULT_BANDWIDTH
  REGION=$DEFAULT_REGION
  SERVER_IP=$DEFAULT_SERVER_IP
fi

echo "Using channel: $CHANNEL"
echo "Using bandwidth: $BANDWIDTH"
echo "Using region: $REGION"
echo "Using server ip: $SERVER_IP"

# Set wireless region
iw reg set "$REGION"

# Read available WLAN interfaces from config file
WFB_NICS=$(grep '^WFB_NICS=' /etc/default/wifibroadcast | cut -d'=' -f2 | tr -d '"')

# Check if there are any interfaces
if [ -z "$WFB_NICS" ]; then
  echo "No WLAN interfaces found in /etc/default/wifibroadcast."
  exit 1
fi

# Convert string to an array
read -r -a WLAN_INTERFACES <<< "$WFB_NICS"

for wlan in "${WLAN_INTERFACES[@]}"; do
  echo "Initializing $wlan"

  if which nmcli > /dev/null && ! nmcli device show "$wlan" | grep -q '(unmanaged)'; then
    nmcli device set "$wlan" managed no
    sleep 1
  fi

  ip link set "$wlan" down
  iw dev "$wlan" set monitor otherbss
  ip link set "$wlan" up
  iw dev "$wlan" set channel "$CHANNEL" "$BANDWIDTH"
done

# gs_video
wfb_rx -f -c $SERVER_IP -u 10000 -p 0 -i 7669206 -R 2097152 "${WLAN_INTERFACES[@]}" &

# gs_tunnel
wfb_rx -f -c $SERVER_IP -u 10001 -p 32 -i 7669206 -R 2097152 "${WLAN_INTERFACES[@]}" &
wfb_tx -I 11001 -R 2097152 "${WLAN_INTERFACES[@]}" &

echo "WFB-ng init done"
wait -n
