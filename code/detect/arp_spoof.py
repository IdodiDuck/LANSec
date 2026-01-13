# POC: Live Detection of an ARP spoofing attack
from scapy.all import *
from utils import logger

print("ARP Spoofing Detection Module Loaded")


arp_table = {}
def inspect(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if ip in arp_table:
            if arp_table[ip] != mac:
                return f"[!] Possible ARP Spoofing detected! IP: {ip} is now mapped to MAC: {mac} (was {arp_table[ip]})"
        else:
            arp_table[ip] = mac
            logger.info(f"[INFO] New mapping: IP {ip} is mapped to MAC {mac}")


if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system
    system('clear')
    print("Starting ARP Spoofing Detection...")

    sniff(prn=inspect, store=0, filter="arp")