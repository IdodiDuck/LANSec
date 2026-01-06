import time
from colorama import Fore, init as color_init
color_init(autoreset=True)

from detect import (
    randomized_mac,
    syn_scan,
    dir_traversal,
    arp_spoof,
    syn_flood,
    udp_flood,
    icmp_flood,
    ssh_bruteforce,
    tcp_connection_scan,
    arp_sweep,
    ping_sweep
    
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
        if (data := self._inspect(pkt)):
            date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            print(
                f"{Fore.RED}{date}: {self.severity}: "
                f"A possible {self.name} was detected!\n{Fore.RESET}{data}\n"
            )

            if self.logger:
                self.logger.info(
                    f"{date}: {self.severity}: A possible {self.name} was detected!\n{data}\n"
                )


def load_attacks(logger):
    attacks = [
        Attack("Randomized MAC Address", NORMAL, randomized_mac.inspect, logger),
        Attack("TCP SYN Scan", SUSPICIOUS, syn_scan.inspect, logger),
        Attack("Directory Traversal", DANGEROUS, dir_traversal.inspect, logger),
        Attack("ARP Spoofing", CRITICAL, arp_spoof.inspect, logger),
        Attack("Ping Sweep", SUSPICIOUS, ping_sweep.inspect, logger),
        Attack("ARP Sweep", SUSPICIOUS, arp_sweep.inspect, logger),
        Attack("SYN Flood", CRITICAL, syn_flood.inspect, logger),
        Attack("UDP Flood", CRITICAL, udp_flood.inspect, logger),
        Attack("ICMP Flood", CRITICAL, icmp_flood.inspect, logger),
        Attack("Brute Force SSH", SUSPICIOUS, ssh_bruteforce.inspect, logger),
        Attack("TCP Connection Scan", SUSPICIOUS, tcp_connection_scan.inspect, logger)
    ]
    
    return attacks
