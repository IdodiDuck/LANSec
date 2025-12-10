from scapy.all import *
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector
import time

print("ICMP Sweep Module Loaded")

# Sliding window: 10 seconds
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=20, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="ICMP Sweep")

unique_targets = {}
TARGET_WINDOW = 10
TARGET_THRESHOLD = 5
last_cleanup = time.time()

def clean_expired():
    global last_cleanup
    now = time.time()

    if now - last_cleanup < 5:
        return

    last_cleanup = now

    for attacker in list(unique_targets.keys()):
        if now - unique_targets[attacker]["last_seen"] > TARGET_WINDOW:
            del unique_targets[attacker]

def is_icmp_probe(pkt):
    return (pkt.haslayer(ICMP) and pkt[ICMP].type == 8)  # Echo request

def inspect(pkt):
    if not pkt.haslayer(IP) or not is_icmp_probe(pkt):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst
    now = time.time()

    # Track unique targets per attacker
    if src not in unique_targets:
        unique_targets[src] = {"targets": set(), "last_seen": now}

    unique_targets[src]["targets"].add(dst)
    unique_targets[src]["last_seen"] = now

    # Count rate events by Source IP
    count = detector.count_event(src)
    if count is None:
        return None

    clean_expired()

    unique_count = len(unique_targets[src]["targets"])

    # Threshold condition
    if unique_count >= TARGET_THRESHOLD:
        return (
            "[ALERT] Ping Sweep Detected!\n"
            f"attacker: {src}\n"
            f"unique_targets: {unique_count}\n"
            f"targets: {list(unique_targets[src]['targets'])[:15]}\n"
            f"events_in_window: {count}\n"
        )

if __name__ == "__main__":
    print("Starting Ping Sweep Detection...\n")

    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="icmp and icmp[icmptype] = icmp-echo")
