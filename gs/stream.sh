#!/bin/bash

#Make sure the current NICS are loaded before continuing.
sudo /config/scripts/autoload-wfb-nics.sh

AGGREGATOR_ENABLED=false  # Default value

DVR_PATH=/media
SCREEN_MODE=$(grep "^mode = " /config/scripts/screen-mode | cut -d'=' -f2 | tr -d ' ')
REC_FPS=$(grep "^fps = " /config/scripts/rec-fps | cut -d'=' -f2 | tr -d ' ')
OSD=$(grep "^render = " /config/scripts/osd | cut -d'=' -f2 | tr -d ' ')
PID=0
AP_MODE=0
LONG_PRESS_DURATION=4  # Duration in seconds for long press

# Button GPIO assignments
DVR_BUTTON=`gpiofind PIN_32`
UP_BUTTON=`gpiofind PIN_16`
DOWN_BUTTON=`gpiofind PIN_18`
LEFT_BUTTON=`gpiofind PIN_13`
RIGHT_BUTTON=`gpiofind PIN_11`
MHZ_BUTTON=`gpiofind PIN_38`

restart_service() {
    if [ "$AGGREGATOR_ENABLED" = true ]; then
        sudo systemctl restart wfb-cluster-node
    else
        sudo systemctl restart wifibroadcast
    fi
}

# Manage Aggregator Mode
if [ "$AGGREGATOR_ENABLED" = true ]; then
    sudo systemctl stop wifibroadcast
    sudo systemctl disable wifibroadcast
    sudo systemctl enable wfb-cluster-node
    sudo systemctl restart wfb-cluster-node
    sudo systemctl enable wfb-cluster-manager
    sudo systemctl restart wfb-cluster-manager
else
    sudo systemctl stop wfb-cluster-node
    sudo systemctl stop wfb-cluster-manager
    sudo systemctl disable wfb-cluster-node
    sudo systemctl disable wfb-cluster-manager
    sudo systemctl enable wifibroadcast@gs
    sudo systemctl restart wifibroadcast@gs
fi

# Function to start AP mode
start_ap_mode() {
    echo "Starting AP mode..." > /run/pixelpilot.msg
    nmcli con up Hostspot || nmcli con add type wifi ifname wlan0 con-name Hostspot autoconnect no ssid RadxaGroundstation && \
    nmcli con modify Hostspot 802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared && \
    nmcli con modify Hostspot wifi-sec.key-mgmt wpa-psk && \
    nmcli con modify Hostspot wifi-sec.psk "radxaopenipc" && \
    nmcli con modify Hostspot ipv4.addresses 192.168.4.1/24 && \
    nmcli con up Hostspot
    AP_MODE=1
}

stop_ap_mode() {
    nmcli con down Hostspot
    AP_MODE=0
}

i=0

full_freq_list=("5180" "5200" "5220" "5240" "5260" "5280" "5300" "5320" "5500" "5520" "5540" "5560" "5580" "5600" "5620" "5640" "5660" "5680" "5700" "5720" "5745" "5765" "5785" "5805" "5825")
full_chan_list=("36" "40" "44" "48" "52" "56" "60" "64" "100" "104" "108" "112" "116" "120" "124" "128" "132" "136" "140" "144" "149" "153" "157" "161" "165")
wide_freq_list=("5180" "5220" "5260" "5300" "5500" "5540" "5580" "5620" "5660" "5700" "5745" "5785" "5825")
wide_chan_list=("36" "44" "52" "60" "100" "108" "116" "124" "132" "140" "149" "157" "165")

FILE="/etc/default/wifibroadcast"
WFB_CFG="/etc/wifibroadcast.cfg"

if [[ -f "$FILE" ]]; then
    NIC_NAMES=$(grep -oP '^WFB_NICS="\K[^"]+' "$FILE")
    if [[ -n "$NIC_NAMES" ]]; then
        NICS=($NIC_NAMES)
    else
        exit 1
    fi
else
    exit 1
fi

pixelpilot --osd --osd-elements 0 --osd-custom-message --osd-refresh 100 --osd-config /config/scripts/osd.json --screen-mode $SCREEN_MODE --dvr-framerate $REC_FPS --dvr-fmp4 --dvr-template $DVR_PATH/record_%Y-%m-%d_%H-%M-%S.mp4 &
PID=$!

if [[ "$OSD" == "ground" ]]; then
    while ! ping -c 1 -W 1 10.5.0.1 >/dev/null 2>&1; do
        sleep 5
    done
    msposd_rockchip --osd --ahi 0 --matrix 11 -v -r 5 --master 10.5.0.1:5000 &
fi

echo "Monitoring buttons"

while true; do
    DVR_BUTTON_STATE=$(gpioget $DVR_BUTTON)
    MHZ_BUTTON_STATE=$(gpioget $MHZ_BUTTON)
    UP_BUTTON_STATE=$(gpioget $UP_BUTTON)
    DOWN_BUTTON_STATE=$(gpioget $DOWN_BUTTON)

    if [ "$MHZ_BUTTON_STATE" -eq 1 ]; then
        if [ "$mhz_press_start" -eq 0 ]; then
            mhz_press_start=$(date +%s)
        else
            elapsed=$(( $(date +%s) - mhz_press_start ))
            if [ "$elapsed" -ge "$LONG_PRESS_DURATION" ]; then
                if [ "$AP_MODE" -eq 0 ]; then
                    start_ap_mode
                else
                    stop_ap_mode
                fi
                mhz_press_start=0
                sleep 1
            fi
        fi
    else
        if [ "$mhz_press_start" -ne 0 ] && [ "$AP_MODE" -eq 0 ]; then
            bandwidth=$(grep '^bandwidth =' $WFB_CFG | cut -d'=' -f2 | sed 's/^ //')
            if [[ $bandwidth -eq 20 ]]; then
                sudo sed -i "/^bandwidth =/ s/=.*/= 40/" $WFB_CFG
                restart_service
            elif [[ $bandwidth -eq 40 ]]; then
                sudo sed -i "/^bandwidth =/ s/=.*/= 20/" $WFB_CFG
                restart_service
            fi
        fi
        mhz_press_start=0
    fi
    sleep 0.1
done
