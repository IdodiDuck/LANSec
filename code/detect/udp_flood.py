from scapy.all import *
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector
import time
from collections import deque

print("UDP Flood Module Loaded")

MINIMAL_SAMPLES = 5

class DynamicRateMonitor:
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.samples = deque()

    def add_sample(self, value):
        now = time.time()
        self.samples.append((now, value))

        # prune old samples
        cutoff = now - self.window
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def get_dynamic_threshold(self, factor=3):
        if len(self.samples) < MINIMAL_SAMPLES:
            return None  # Missing samples
        
        # Calculating threshold based on current traffic volume
        values = [v for (_, v) in self.samples]
        avg = sum(values) / len(values)
        stdev = (sum((x - avg)**2 for x in values) / (len(values)-1))**0.5 if len(values) > 1 else 0
        return avg + stdev * factor


counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=1000, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="UDP Flood Dynamic")

dynamic_monitor = DynamicRateMonitor(window_seconds=120)

def is_udp(pkt):
    return pkt.haslayer(UDP)

def inspect(pkt):
    now = time.time()

    if not pkt.haslayer(IP) or not is_udp(pkt):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dport = pkt[UDP].dport

    # Always get actual packet count
    count = counter.record(src_ip, now)

    # Calculate total rate (packets/sec)
    total_rate = sum(len(dq) for dq in counter.table.values()) / counter.window

    # Add dynamic sample once per second
    if not hasattr(inspect, "last_sample_time"):
        inspect.last_sample_time = 0

    if now - inspect.last_sample_time >= 1:
        dynamic_monitor.add_sample(total_rate)
        inspect.last_sample_time = now

    dynamic_threshold = dynamic_monitor.get_dynamic_threshold(factor=3)

    # Alert only if threshold is calculated
    if dynamic_threshold is not None and count > dynamic_threshold:
        print(
            f"[ALERT] Possible UDP Flood Detected!\n"
            f"src_ip: {src_ip}\n"
            f"dst_ip: {dst_ip}\n"
            f"dst_port: {dport}\n"
            f"packet_rate: {count}\n"
            f"dynamic_threshold: {dynamic_threshold:.2f}\n"
        )

if __name__ == "__main__":
    from colorama import init as color_init
    from os import system
    color_init(autoreset=True)

    try:
        system("cls")
        system("clear")
    except:
        pass

    print("Starting UDP Flood Detection...")
    sniff(prn=inspect, store=0, filter="udp")