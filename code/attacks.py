import time
from colorama import Fore, init as color_init
import prevent.iptbls as iptbls

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
    def __init__(self, name, severity, inspect, logger):
        self.name = name
        self.severity = severity
        self._inspect = inspect
        self.logger = logger
    
    def inspect(self, pkt):
        result = self._inspect(pkt)
        
        if not result: 
            return

        technical_info = ""
        if isinstance(result, (tuple, list)):
            technical_info = " | ".join(map(str, result))

        elif isinstance(result, dict):
            technical_info = ", ".join([f"{k}: {v}" for k, v in result.items()])

        else:
            technical_info = str(result)

        attacker_ip = None
        if pkt.haslayer("IP"):
            attacker_ip = pkt["IP"].src
        elif pkt.haslayer("ARP"):
            attacker_ip = pkt["ARP"].psrc
        
        if attacker_ip:
            iptbls.block(attacker_ip)
            technical_info += f" | Status: IP {attacker_ip} Blocked"

        if self.logger: 
            self.logger.alert(
                severity=self.severity, 
                attack_type=self.name, 
                details=technical_info
            )


def load_attacks(logger):
    return [
        # Attack("Randomized MAC Address", NORMAL, randomized_mac.inspect, logger),
        Attack("XSS", SUSPICIOUS, xss.inspect, logger),
        Attack("SQLi", SUSPICIOUS, sqli.inspect, logger),
        Attack("Brute Force SSH", SUSPICIOUS, ssh_bruteforce.inspect, logger),
        Attack("Directory Traversal", SUSPICIOUS, dir_traversal.inspect, logger),
        Attack("TCP SYN Scan", DANGEROUS, syn_scan.inspect, logger),
        Attack("Ping Sweep", DANGEROUS, ping_sweep.inspect, logger),
        Attack("ARP Sweep", DANGEROUS, arp_sweep.inspect, logger),
        Attack("SYN Flood", CRITICAL, syn_flood.inspect, logger),
        Attack("ICMP Flood", CRITICAL, icmp_flood.inspect, logger),
        # Attack("UDP Flood", CRITICAL, udp_flood.inspect, logger),
        Attack("ARP Spoofing", CRITICAL, arp_spoof.inspect, logger)
    ]
