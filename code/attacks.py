import time
from colorama import Fore, init as color_init
color_init(autoreset=True)

from detect import (
    randomized_mac,
    syn_scan,
    dir_traversal,
    arp_spoof,
    syn_flood,
    ssh_bruteforce,
    tcp_connection_scan,
    xss
)

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
        
        if not result: # No detection
            return

        src, dst, details = result   # details = string, not tuple

        date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Construct a readable data to be logged
        attack_data = (
            f"\n{'='*70}\n"
            f"[{date}]  SEVERITY: {self.severity}\n"
            f"ATTACK TYPE: {self.name}\n"
            f"SOURCE: {src}\n"
            f"DESTINATION: {dst}\n"
            f"{'-'*70}\n"
            f"{details}\n"
            f"{'='*70}\n"
        )

        print(Fore.RED + attack_data + Fore.RESET)

        # Log a clean, plain-text version
        if self.logger:
            self.logger.info(attack_data)



def load_attacks(logger):
    attacks = [
        Attack("Randomized MAC Address", NORMAL, randomized_mac.inspect, logger),
        Attack("TCP SYN Scan", SUSPICIOUS, syn_scan.inspect, logger),
        Attack("Directory Traversal", DANGEROUS, dir_traversal.inspect, logger),
        Attack("XSS", CRITICAL, xss.inspect, logger),
        Attack("ARP Spoofing", CRITICAL, arp_spoof.inspect, logger),
        Attack("SYN Flood", CRITICAL, syn_flood.inspect, logger),
        Attack("Brute Force SSH", SUSPICIOUS, ssh_bruteforce.inspect, logger),
        Attack("TCP Connection Scan", SUSPICIOUS, tcp_connection_scan.inspect, logger)
    ]
    
    return attacks
