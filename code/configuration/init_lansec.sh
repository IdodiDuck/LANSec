#!/bin/bash

# --- Network Configuration ---
# External interface (Connected to the Internet/Router)
# HOW TO FIND THE RIGHT IP/GW:
# 1. On Windows (Host), run 'ipconfig'.
# 2. Look for your active connection (Wi-Fi or Ethernet).
# 3. Use that network range for EXT_IP (e.g., if Windows is 192.168.1.45, use 192.168.1.150).
# 4. Use the 'Default Gateway' from ipconfig for EXT_GW (usually 192.168.1.1).

EXT_IF="ens33"
EXT_IP="192.168.1.150/24" # Change this to match your current network range
EXT_GW="192.168.1.1" # Change this to match your current router/gateway IP

# Internal interface (Connected to the LAN itself)
INT_IF="ens37"
INT_IP_CIDR="10.0.0.1/24"
# Extracting only the IP (without /24) for the summary message
INT_IP=$(echo $INT_IP_CIDR | cut -d'/' -f1)

echo "-------------------------------------------"
echo "Initializing LANSec Inline Configuration..."
echo "-------------------------------------------"

# Cleaning up existing configurations to prevent conflicts
# This ensures the script can be re-run without "Address already assigned" errors
sudo ip addr flush dev $EXT_IF
sudo ip addr flush dev $INT_IF
sudo route del default 2>/dev/null

# Configure Interface Addresses:
# External
echo "Configuring External Interface ($EXT_IF)..."
sudo ip addr add $EXT_IP dev $EXT_IF
sudo ip link set $EXT_IF up

# Internal
echo "Configuring Internal Interface ($INT_IF)..."
sudo ip addr add $INT_IP_CIDR dev $INT_IF
sudo ip link set $INT_IF up

# Configure Routing
# Directing traffic through your physical router
sudo route add default gw $EXT_GW $EXT_IF 2>/dev/null

# Enable IP Forwarding
echo "Enabling IPv4 Forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Configure NAT (Network Address Translation)
echo "Configuring NAT on $EXT_IF..."
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -o $EXT_IF -j MASQUERADE

echo "-------------------------------------------"
echo "IDPS LAN is ready!"
echo "Internal Gateway (Protected): $INT_IP"
echo "External IP (Internet): $EXT_IP"
echo "Status: Connected via Bridged Mode"
echo "-------------------------------------------"