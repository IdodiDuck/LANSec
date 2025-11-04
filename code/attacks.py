import time
from colorama import Fore, init as color_init
color_init(autoreset=True)
print("Attacks Module Loaded")

from detect import randomized_mac, syn_scan, dir_traversal, arp_spoof


# TD: make this enum ?
NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
DANGEROUS = "DANGEROUS"
CRITICAL = "CRITICAL"


class Attack():
    def __init__(self, name, severity, inspect):
        self.name = name
        self.severity = severity
        self._inspect = inspect
    
    def inspect(self, pkt):
        if (data := self._inspect(pkt)):
            date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f'{Fore.RED}{date}: {self.severity}: A possible {self.name} was detected!\n{Fore.RESET}{data}')


attacks = [
    Attack("Randomized MAC Address", NORMAL, randomized_mac.inspect),
    Attack("TCP SYN Scan", SUSPICIOUS, syn_scan.inspect),
    Attack("Directory Traversal Attack", DANGEROUS, dir_traversal.inspect),
    Attack("ARP Spoofing Attack", CRITICAL, arp_spoof.inspect)
]