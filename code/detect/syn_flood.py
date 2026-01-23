from scapy.all import *
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector

print("SYN Flood Module Loaded")

counter = SlidingWindowCounter(window_seconds=10, max_items=500)
alerter = RateAlert(threshold=20, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="SYN Flood")


def is_syn(pkt):
    return pkt.haslayer(TCP) and (pkt[TCP].flags & 0x12 == 0x02)


def inspect(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not is_syn(pkt):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst
    port = pkt[TCP].dport
    
    target_key = f"{dst}:{port}"
    count = detector.count_event(target_key)

    if count:
        return (
            f"[ALERT] SYN Flood Detected!\n"
            f"src_ip: {src}\n"
            f"target: {target_key}\n"
            f"syn_count: {count}\n"
        )

if __name__ == "__main__":
    from colorama import Fore, init as color_init
    from os import system
    color_init(autoreset=True)

    try:
        system('cls')
        system("clear")
    except:
        pass

    sniff(prn=inspect, store=0, filter="tcp and (tcp[13] & 2 != 0) and (tcp[13] & 16 == 0)")