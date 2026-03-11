#!/bin/bash

# --- Configuration ---
# This IP must be in the 10.0.0.x range and unique in the private LAN
NEW_IP="10.0.0.5" # Change this IP for every added device (No duplicate IPs in LAN)
INTERFACE="ens33"
# This MUST match the Internal IP of your LANSec machine
GATEWAY="10.0.0.1" 

echo "-------------------------------------------"
echo "[*] Setting up Client Network Configuration..."
echo "-------------------------------------------"

# Clean up old IP addresses and routes to prevent conflicts
sudo ip addr flush dev $INTERFACE
sudo route del default 2>/dev/null

# Assign the new IP and bring the interface up
sudo ifconfig $INTERFACE $NEW_IP netmask 255.255.255.0 up

# Set the LANSec system as the Default Gateway
sudo route add default gw $GATEWAY

echo "-------------------------------------------"
echo "[+] Done! Client is now reachable at $NEW_IP"
echo "[+] All traffic is being routed through LANSec ($GATEWAY)"
echo "-------------------------------------------"