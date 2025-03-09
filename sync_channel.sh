#!/bin/sh
# Check for exactly 3 parameters
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <channel> <bandwidth> <region>" >&2
  exit 1
fi

CHANNEL="$1"
BANDWIDTH="$2"
# REGION is provided but will be silently ignored
REGION="$3"

# Get the current channel value from the YAML file
CURRENT_CHANNEL=$(yaml-cli -i /etc/wfb.yaml -g .wireless.channel 2>/dev/null)
if [ $? -ne 0 ]; then
  echo "Error: Failed to get current wireless channel from /etc/wfb.yaml" >&2
  exit 1
fi

# Set the new channel value using the provided <channel>
yaml-cli -i /etc/wfb.yaml -s .wireless.channel "$CHANNEL" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "Error: Failed to set new wireless channel in /etc/wfb.yaml" >&2
  exit 1
fi

# Get the current wifi_mode from the YAML file
CURRENT_WIFI_MODE=$(yaml-cli -i /etc/wfb.yaml -g .wireless.wifi_mode 2>/dev/null)
if [ $? -ne 0 ]; then
  echo "Error: Failed to get current wifi_mode from /etc/wfb.yaml" >&2
  exit 1
fi

# Set the new wifi_mode using the provided <bandwidth>
yaml-cli -i /etc/wfb.yaml -s .wireless.wifi_mode "$BANDWIDTH" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "Error: Failed to set new wifi_mode in /etc/wfb.yaml" >&2
  exit 1
fi

# Stop the wireless broadcast service
/etc/init.d/S98wifibroadcast stop 2>/dev/null
if [ $? -ne 0 ]; then
  echo "Error: Failed to stop S98wifibroadcast service" >&2
  exit 1
fi

# Start the wireless broadcast service with retry logic
/etc/init.d/S98wifibroadcast start 2>/dev/null
if [ $? -ne 0 ]; then
  sleep 2
  /etc/init.d/S98wifibroadcast start 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "Error: Failed to start S98wifibroadcast service after retry" >&2
    exit 1
  fi
fi

# Output success message with the new settings in one row
echo "Success: channel set to $CHANNEL, wifi_mode set to $BANDWIDTH"
exit 0
