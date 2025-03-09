#!/bin/sh
# Usage: killswitch.sh <original_channel> <original_bandwidth>

# Check for exactly 2 parameters
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <original_channel> <original_bandwidth>" >&2
  exit 1
fi

ORIGINAL_CHANNEL="$1"
ORIGINAL_BANDWIDTH="$2"

# Wait for 10 seconds before reverting (acts as the kill switch timeout)
sleep 10

# Restore the original channel value
yaml-cli -i /etc/wfb.yaml -s .wireless.channel "$ORIGINAL_CHANNEL" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "KillSwitch Error: Failed to restore original wireless channel" >&2
  exit 1
fi

# Restore the original wifi_mode value
yaml-cli -i /etc/wfb.yaml -s .wireless.wifi_mode "$ORIGINAL_BANDWIDTH" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "KillSwitch Error: Failed to restore original wifi_mode" >&2
  exit 1
fi

# Stop the wireless broadcast service
/etc/init.d/S98wifibroadcast stop 2>/dev/null
if [ $? -ne 0 ]; then
  echo "KillSwitch Error: Failed to stop S98wifibroadcast service" >&2
  #exit 1
fi

# Start the wireless broadcast service with retry logic:
# First attempt
/etc/init.d/S98wifibroadcast start 2>/dev/null
if [ $? -ne 0 ]; then
  sleep 2
  /etc/init.d/S98wifibroadcast start 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "KillSwitch Error: Failed to start S98wifibroadcast service after retry" >&2
    #exit 1
  fi
fi

echo "KillSwitch: Restored original settings: channel set to $ORIGINAL_CHANNEL, wifi_mode set to $ORIGINAL_BANDWIDTH"
exit 0
