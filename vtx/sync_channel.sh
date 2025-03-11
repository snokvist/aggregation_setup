#!/bin/sh
# Usage: sync_channel.sh <channel> <bandwidth> <region>
# Note: <region> is accepted but ignored.
set +e

# Launch the killswitch in the background.
# The killswitch will run for XX seconds, and if not killed before then,
# it will restore the predetermined channel 165, HT20 settings and restart the service.
killswitch.sh 165 HT20 &

# Check for exactly 3 parameters
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <channel> <bandwidth> <region>" >&2
  exit 1
fi

CHANNEL="$1"
BANDWIDTH="$2"
# REGION is provided but will be silently ignored
REGION="$3"

# Set the new channel value using the provided <channel>
yaml-cli -i /etc/wfb.yaml -s .wireless.channel "$CHANNEL" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "Error: Failed to set new wireless channel in /etc/wfb.yaml" >&2
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

# Start the wireless broadcast service with retry logic:
# First attempt
/etc/init.d/S98wifibroadcast start 2>/dev/null
if [ $? -ne 0 ]; then
  sleep 2
  /etc/init.d/S98wifibroadcast start 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "Error: Failed to start S98wifibroadcast service after retry" >&2
    # (Optional: you might add fallback logic here as well)
  fi
fi

# Restart the majestic service in case it died
/etc/init.d/S95majestic restart

# Output success message with the new settings in one row
echo "Success: channel set to $CHANNEL, wifi_mode set to $BANDWIDTH"
exit 0
