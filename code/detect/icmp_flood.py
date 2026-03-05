from scapy.all import ICMP, IP, sniff
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector

print("ICMP Flood Module Loaded")

# Sliding window for ICMP packets per destination IP
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
# Alert when ICMP rate to a specific target exceeds threshold
alerter = RateAlert(threshold=50, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="ICMP Flood")

def is_icmp(pkt):
    return pkt.haslayer(ICMP) and pkt[ICMP].type == 8  # Echo Request

def inspect(pkt):
    if not pkt.haslayer(IP) or not is_icmp(pkt):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    count = detector.count_event(dst_ip)

    if count:
        return (f"icmp_count: {count}")

if __name__ == "__main__":
    from colorama import init as color_init
    from os import system

    color_init(autoreset=True)

    try:
        system("cls")
        system("clear")
        
    except:
        pass

    print("Starting ICMP Flood Detection...")
    sniff(prn=inspect, store=0, filter="icmp")