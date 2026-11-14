#!/bin/bash

INTERFACE="tun0"

if ip link show "$INTERFACE" &> /dev/null; then
    TUN_IP=$(ip -o -4 addr show tun0 | awk '{print $4}' | cut -d '/' -f 1)
    TUN_IP=$TUN_IP docker-compose up -d vpn_certificate_api_dev
else
    echo "Interface $INTERFACE does not exist. Run this service on a machine with OpenVPN tunnel (tun0) interface."
fi