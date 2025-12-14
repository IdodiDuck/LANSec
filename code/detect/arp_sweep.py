from scapy.all import *
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector
import time

print("ARP Sweep Module Loaded")

# Rate-based detection (per attacker)
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=20, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="ARP Sweep")

# Unique-target detection
unique_targets = {}
TARGET_WINDOW = 10
TARGET_THRESHOLD = 5
last_cleanup = 0

UNIQUE_ALERT_COOLDOWN = 10
last_unique_alert = {}  # per-attacker cooldown


def clean_expired():
    """Remove attackers inactive for too long"""
    global last_cleanup
    now = time.time()

    if now - last_cleanup < 3:
        return

    last_cleanup = now

    for attacker in list(unique_targets.keys()):
        if now - unique_targets[attacker]["last_seen"] > TARGET_WINDOW:
            del unique_targets[attacker]


def is_arp_probe(pkt):
    return pkt.haslayer(ARP) and pkt[ARP].op == 1 # ARP Request (Who-Has)


def inspect(pkt):
    global last_unique_alert

    if not is_arp_probe(pkt):
        return None

    src = pkt[ARP].psrc
    dst = pkt[ARP].pdst
    now = time.time()

    # Track unique targets per attacker
    if src not in unique_targets:
        unique_targets[src] = {"targets": set(), "last_seen": now}

    unique_targets[src]["targets"].add(dst)
    unique_targets[src]["last_seen"] = now

    clean_expired()

    # Count total events for rate detection
    count = detector.count_event(src)

    if count is None:
        return None

    # Rate-Based Detection (20 events in 10s)
    if detector.alerter.should_alert(src, count):
        return (
            f"attacker: {src}\n"
            f"events_in_window: {count}\n"
        )

    # Unique Target Detection (5+ different IPs)
    uniq_count = len(unique_targets[src]["targets"])

    if uniq_count >= TARGET_THRESHOLD:

        # Cooldown check
        last = last_unique_alert.get(src, 0)
        if now - last < UNIQUE_ALERT_COOLDOWN:
            return None  # suppress duplicate alerts

        last_unique_alert[src] = now

        return (
            f"attacker: {src}\n"
            f"unique_targets: {uniq_count}\n"
            f"targets (partial): {list(unique_targets[src]['targets'])[:15]}\n"
            f"events_in_window: {count}\n"
        )


if __name__ == "__main__":
    print("Starting ARP Sweep Detection...\n")

    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="arp")