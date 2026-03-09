#!/bin/bash

# Setting up LANSec System InLine
sudo ip addr add 192.168.1.150/24 dev ens33 2>/dev/null
sudo ip link set ens33 up
sudo ip addr add 10.0.0.1/24 dev ens37 2>/dev/null
sudo ip link set ens37 up

sudo route add default gw 192.168.1.1 ens33 2>/dev/null

# Setting LANSec System to forward packets (As an inline component)
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE

echo "-------------------------------------------"
echo "IDPS Lab is READY!"
echo "Attacker (Internal): 10.0.0.1"
echo "Internet (External): 192.168.1.150"
echo "-------------------------------------------"
