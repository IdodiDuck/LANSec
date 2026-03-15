from scapy.all import ICMP, IP, sniff
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector

print("ICMP Flood Module Loaded")

# Configuration - 
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=50, alert_cooldown=10)

# Specialized detector instance for ICMP Flood
detector = BaseDetector(counter, alerter, name="ICMP Flood")

def is_icmp_echo_request(pkt):
    """
    Checks if the packet is an ICMP Echo Request (Ping).
    """
    return pkt.haslayer(ICMP) and pkt[ICMP].type == 8 # Ping Opcode

def inspect(pkt):
    """
    Analyzes incoming traffic to detect ICMP flooding.
    Unlike ARP detection which often focuses on the source, ICMP flood
    detection focuses on the DESTINATION to identify victims of DoS.
    """
    # Ensure the packet has an IP layer and is a Ping request
    if not pkt.haslayer(IP) or not is_icmp_echo_request(pkt):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    # Record the event for the destination IP
    count = detector.count_event(dst_ip)

    if count:
        # If the detector returns a count, it means the threshold was breached
        return (f"icmp_count: {count}")

    return None

if __name__ == "__main__":
    """
    Standalone testing mode for the ICMP Flood detector.
    """
    from colorama import init as color_init
    from os import system

    color_init(autoreset=True)
    try:
        system("clear")
    except:
        pass

    print("Starting Real-Time ICMP Flood Detection Engine...")
    print("Monitoring ICMP Echo Requests (Filter: icmp)")
    
    # Sniff only ICMP traffic and process with the inspect function
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, 
          store=0, filter="icmp")