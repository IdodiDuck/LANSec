from scapy.all import ICMP, IP, sniff
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector
import time

print("ICMP Sweep Module Loaded")

# Configuration -
# Rate-based detection: Tracks total volume of ICMP requests from a single source
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=20, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="ICMP Sweep")

# Target-based detection: Tracks how many different IP addresses an attacker probes
unique_targets = {}
TARGET_WINDOW = 10 
TARGET_THRESHOLD = 5 
last_cleanup = time.time()

last_unique_alert = {}  # Per-attacker cooldown for unique target alerts
UNIQUE_ALERT_COOLDOWN = 10

def clean_expired():
    """
    Memory Management: Periodically removes inactive scanners from the 
    tracking dictionary to prevent memory leaks.
    """
    global last_cleanup
    now = time.time()

    if now - last_cleanup < 5: # Run cleanup every 5 seconds
        return

    last_cleanup = now

    for attacker in list(unique_targets.keys()):
        if now - unique_targets[attacker]["last_seen"] > TARGET_WINDOW:
            del unique_targets[attacker]

def is_icmp_probe(pkt):
    """
    Identifies ICMP Echo Requests (Type 8). 
    These are the 'pings' sent by a scanner to elicit a response.
    """
    return pkt.haslayer(ICMP) and pkt[ICMP].type == 8

def inspect(pkt):
    """
    Analyzes ICMP traffic for scanning patterns. 
    Combines frequency analysis with unique-target counting.
    """
    if not pkt.haslayer(IP) or not is_icmp_probe(pkt):
        return None

    src = pkt[IP].src # Potential Scanner
    dst = pkt[IP].dst # Potential Victim
    now = time.time()

    # Track Unique Targets per Attacker
    if src not in unique_targets:
        unique_targets[src] = {"targets": set(), "last_seen": now}

    unique_targets[src]["targets"].add(dst)
    unique_targets[src]["last_seen"] = now

    # Rate-Based Detection (Volume)
    count = detector.count_event(src)
    if count is None:
        return None

    clean_expired()

    # Unique Target Detection (Horizontal Scanning)
    unique_count = len(unique_targets[src]["targets"])

    if unique_count >= TARGET_THRESHOLD:
        last = last_unique_alert.get(src, 0)
        if now - last < UNIQUE_ALERT_COOLDOWN:
            return None
        
        last_unique_alert[src] = now
        return f"Ping Sweep: {unique_count} hosts scanned"

    return None

if __name__ == "__main__":
    """
    Standalone testing mode for ICMP Sweep detection.
    Filters specifically for ICMP echo requests to optimize performance.
    """
    print("Starting ICMP Ping Sweep Detection Engine...\n")
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, 
          store=0, filter="icmp and icmp[icmptype] = icmp-echo")