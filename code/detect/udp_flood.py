from scapy.all import *
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector
import time
from collections import deque, defaultdict

print("UDP Flood Module Loaded")

MINIMAL_SAMPLES = 10     # Need more samples for a stable baseline
MIN_PPS_FLOOR = 100      # Never alert if rate is below 100 packets/sec
SUSTAIN_REQUIREMENT = 3  # Must exceed threshold for 3 consecutive checks
Z_SCORE_FACTOR = 4       # How many standard deviations above mean (4-5 is safer)
MIN_PORTS = 5            # Minimal amount of different ports to indicate flood

class DynamicRateMonitor:
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.samples = deque()

    def add_sample(self, value):
        now = time.time()
        self.samples.append((now, value))
        cutoff = now - self.window
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def get_dynamic_threshold(self, factor=Z_SCORE_FACTOR):
        if len(self.samples) < MINIMAL_SAMPLES:
            return None
        
        values = [v for (_, v) in self.samples]
        avg = sum(values) / len(values)
        
        # Calculate standard deviation
        variance = sum((x - avg)**2 for x in values) / len(values)
        stdev = variance**0.5
        
        # Calculate threshold and ensure it's at least the MIN_PPS_FLOOR
        calculated_threshold = avg + (stdev * factor)
        return max(calculated_threshold, MIN_PPS_FLOOR)

# Initialize components
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=1000, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="UDP Flood Dynamic")
dynamic_monitor = DynamicRateMonitor(window_seconds=120)

# Global trackers for stateful analysis
strike_counts = defaultdict(int) 
port_spread = defaultdict(set)

def inspect(pkt):
    now = time.time()

    if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dport = pkt[UDP].dport

    count = counter.record(src_ip, now)
    port_spread[src_ip].add(dport)

    if not hasattr(inspect, "last_sample_time"):
        inspect.last_sample_time = 0

    if now - inspect.last_sample_time >= 1:
        # Calculate total network-wide UDP rate for the baseline
        total_rate = sum(len(dq) for dq in counter.table.values()) / counter.window
        dynamic_monitor.add_sample(total_rate)
        inspect.last_sample_time = now
        
        # Periodically clear port spread to avoid memory leaks
        if int(now) % 30 == 0:
            port_spread.clear()

    dynamic_threshold = dynamic_monitor.get_dynamic_threshold()

    if dynamic_threshold is not None:
        # Only consider it a "strike" if it's above the baseline and the floor
        if count > dynamic_threshold:
            strike_counts[src_ip] += 1
            
            if strike_counts[src_ip] >= SUSTAIN_REQUIREMENT:                
                detection = (
                    f"src_ip: {src_ip} -> Destination: {dst_ip}\n"
                    f"rate: {count:.2f} pps\n"
                    f"threshold: {dynamic_threshold:.2f} pps\n"
                )

                # Reset strike count after alert to honor the cooldown
                strike_counts[src_ip] = 0

                return detection

        else:
            # Decay the strike count if traffic drops
            if strike_counts[src_ip] > 0:
                strike_counts[src_ip] -= 1
    

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