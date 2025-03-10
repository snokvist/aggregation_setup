#!/bin/bash
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# Ensure three arguments are provided: <channel> <bandwidth> <region>
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <channel> <bandwidth> <region>"
  exit 1
fi

CHANNEL=$1
BANDWIDTH=$2
REGION=$3

echo "Updating default values in /usr/sbin/wfb-ng.sh to:"
echo "  DEFAULT_CHANNEL=${CHANNEL}"
echo "  DEFAULT_BANDWIDTH=${BANDWIDTH}"
echo "  DEFAULT_REGION=${REGION}"

# Update the default values in /usr/sbin/wfb-ng.sh
sed -i "s/^DEFAULT_CHANNEL=.*/DEFAULT_CHANNEL=${CHANNEL}/" /usr/sbin/wfb-ng.sh
sed -i "s/^DEFAULT_BANDWIDTH=.*/DEFAULT_BANDWIDTH=\"${BANDWIDTH}\"/" /usr/sbin/wfb-ng.sh
sed -i "s/^DEFAULT_REGION=.*/DEFAULT_REGION=\"${REGION}\"/" /usr/sbin/wfb-ng.sh

echo "Defaults updated successfully."

# Restart the wfb-cluster-node service
echo "Restarting wfb-cluster-node service..."
if ! systemctl restart wfb-cluster-node; then
  echo "Failed to restart wfb-cluster-node service."
  exit 1
fi

echo "Service restarted successfully."
exit 0
