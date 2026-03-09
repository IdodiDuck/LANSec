#!/bin/bash

# Setting gateway of LAN Machines to LANSec System
sudo ifconfig ens33 10.0.0.5 netmask 255.255.255.0 up
sudo route add default gw 10.0.0.1

echo "Connected to IDPS Gateway!"
