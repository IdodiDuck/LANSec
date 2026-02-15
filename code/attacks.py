import time
from colorama import Fore, init as color_init
import prevent.iptbls as iptbls
from utils.logger import alert 

color_init(autoreset=True)

from detect import (
    randomized_mac,
    syn_scan,
    dir_traversal,
    xss,
    sqli,
    arp_spoof,
    syn_flood,
    udp_flood,
    icmp_flood,
    ssh_bruteforce,
    arp_sweep,
    ping_sweep,
)

# Attacks Severities
NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
DANGEROUS = "DANGEROUS"
CRITICAL = "CRITICAL"

class Attack:
    def __init__(self, name, severity, inspect, logger, snf_fltr=""):
        self.name = name
        self.severity = severity
        self._inspect = inspect
        self.logger = logger
        self._snf_filter = snf_fltr
    def inspect(self, pkt):
        result = self._inspect(pkt)
        if not result: return

        alert_msg = f"{self.severity}: A possible {self.name} was detected!\n{result}\n"

        # commented out for debugging convenience
        # if self.severity in [CRITICAL, DANGEROUS]:
        if (ip := pkt["IP"].src if pkt.haslayer("IP") else pkt["ARP"].psrc if pkt.haslayer("ARP") else None):
            iptbls.block(ip)

        if self.logger: alert(alert_msg)


# 12345 for debugging
app_layer_fltr = "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345"
# SYN flag set
tcp_syn_fltr = "tcp and (tcp[13] & 2 != 0)" 
def load_attacks(logger):
    return [
        # Attack("Randomized MAC Address", NORMAL, randomized_mac.inspect, logger, "ALL"),
        Attack("XSS", SUSPICIOUS, xss.inspect, logger, snf_fltr=app_layer_fltr),
        Attack("SQLi", SUSPICIOUS, sqli.inspect, logger, snf_fltr=app_layer_fltr),
        Attack("Directory Traversal", SUSPICIOUS, dir_traversal.inspect, logger, snf_fltr=app_layer_fltr),
        Attack("Brute Force SSH", SUSPICIOUS, ssh_bruteforce.inspect, logger, snf_fltr="tcp port 22"),
        Attack("TCP SYN Scan", DANGEROUS, syn_scan.inspect, logger, snf_fltr=tcp_syn_fltr),
        Attack("Ping Sweep", DANGEROUS, ping_sweep.inspect, logger, snf_fltr="icmp"),
        Attack("ARP Sweep", DANGEROUS, arp_sweep.inspect, logger, snf_fltr="arp"),
        Attack("SYN Flood", CRITICAL, syn_flood.inspect, logger, snf_fltr=tcp_syn_fltr),
        Attack("ICMP Flood", CRITICAL, icmp_flood.inspect, logger, snf_fltr="icmp"),
        # Attack("UDP Flood", CRITICAL, udp_flood.inspect, logger, snf_filter="udp"),
        Attack("ARP Spoofing", CRITICAL, arp_spoof.inspect, logger, snf_fltr="arp")
    ]
