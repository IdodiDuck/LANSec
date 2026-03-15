from scapy.all import ARP, sniff
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector
import time

print("ARP Sweep Module Loaded")

# Configuration - 
# Rate-based detection: Tracks total volume of ARP requests from a single source
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=20, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="ARP Sweep")

# Target-based detection: Tracks how many different IP addresses an attacker probes
unique_targets = {}
TARGET_WINDOW = 10 
TARGET_THRESHOLD = 5
last_cleanup = 0

last_unique_alert = {}  # Per-attacker cooldown for unique target alerts
UNIQUE_ALERT_COOLDOWN = 10

def clean_expired():
    """
    Memory management: Removes attackers from the tracking dictionary 
    who haven't been active within the TARGET_WINDOW.
    """
    global last_cleanup
    now = time.time()

    if now - last_cleanup < 3: # Run cleanup every 3 seconds to save CPU
        return

    last_cleanup = now

    for attacker in list(unique_targets.keys()):
        if now - unique_targets[attacker]["last_seen"] > TARGET_WINDOW:
            del unique_targets[attacker]


def is_arp_probe(pkt):
    """ Validates if the packet is an ARP Request (Who-Has). """
    return pkt.haslayer(ARP) and pkt[ARP].op == 1 


def inspect(pkt):
    """
    Analyzes ARP requests to identify scanning patterns.
    Combines high-frequency detection with unique-destination tracking.
    """
    global last_unique_alert

    if not is_arp_probe(pkt):
        return None

    src = pkt[ARP].psrc # Potential Scanner
    dst = pkt[ARP].pdst # Potential Victim
    now = time.time()

    # Track Unique Targets per Attacker
    if src not in unique_targets:
        unique_targets[src] = {"targets": set(), "last_seen": now}

    unique_targets[src]["targets"].add(dst)
    unique_targets[src]["last_seen"] = now

    clean_expired()

    # Rate-Based Detection (Volume)
    count = detector.count_event(src)
    if count is not None:
        if detector.alerter.should_alert(src, count):
            return f"High rate detected: {count} ARP requests in window"

    # Unique Target Detection (Horizontal Scanning)
    uniq_count = len(unique_targets[src]["targets"])

    if uniq_count >= TARGET_THRESHOLD:
        # Check cooldown to prevent alert spamming for the same sweep
        last = last_unique_alert.get(src, 0)
        if now - last < UNIQUE_ALERT_COOLDOWN:
            return None 

        last_unique_alert[src] = now
        return f"Network Sweep Detected: {src} probed {uniq_count} unique IP addresses"

    return None


if __name__ == "__main__":
    """ Standalone CLI mode for testing ARP Sweep detection. """
    print("Starting ARP Sweep Detection Engine...\n")
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="arp")