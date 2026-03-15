# POC: Live Detection of an ARP spoofing attack
from scapy.all import ARP, sniff
from utils import logger

print("ARP Spoofing Detection Module Loaded")

# Internal cache to track established IP-to-MAC mappings
# Format: { "192.168.1.1": "00:11:22:33:44:55" }
arp_table = {}

def inspect(pkt):
    """
    Analyzes ARP packets to detect inconsistencies in the ARP cache.
    
    :param pkt: The captured Scapy packet.
    :return: A warning string if a mismatch is detected, otherwise None.
    """
    # op == 2 signifies an ARP Reply (Response)
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  
        ip = pkt[ARP].psrc   # Sender's IP
        mac = pkt[ARP].hwsrc # Sender's MAC

        if ip in arp_table:
            # If the MAC address has changed, it indicates a potential spoofing
            if arp_table[ip] != mac:
                return (
                    f"Conflict Detected! IP: {ip} is now claiming to be at MAC: {mac} "
                    f"(Previously verified at: {arp_table[ip]})"
                )
        else:
            # First time seeing this IP; record its MAC address as the legitimate baseline
            arp_table[ip] = mac
            logger.info(f"Establishing baseline: IP {ip} mapped to MAC {mac}")

    return None

if __name__ == "__main__":
    """
    Standalone testing mode for the ARP detection module.
    """
    from colorama import Fore, init as color_init
    from os import system
    
    color_init(autoreset=True)
    system('clear')
    
    print(f"{Fore.CYAN}Starting Real-Time ARP Spoofing Detection...")
    print(f"{Fore.YELLOW}Monitoring ARP traffic for cache poisoning attempts...")

    # Sniff only ARP traffic and pass it to the inspect function
    sniff(prn=lambda p: print(inspect(p)) if inspect(p) else None, store=0, filter="arp")