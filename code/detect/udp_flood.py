from scapy.all import UDP, IP, sniff
from .rate_limiter import SlidingWindowCounter, RateAlert
import time
from collections import deque, defaultdict

print("UDP Flood Module (Dynamic Baseline) Loaded")

# Constants - 
MINIMAL_SAMPLES = 10     # Minimum data points needed to establish a stable baseline
MIN_PPS_FLOOR = 100      # Safety floor: Never alert if rate is below 100 packets/sec
SUSTAIN_REQUIREMENT = 3  # Attack persistence: Must exceed threshold for 3 consecutive checks
Z_SCORE_FACTOR = 4       # Sensitivity: How many standard deviations above mean to trigger alert
MIN_PORTS = 5            # Minimum unique ports probed to distinguish flood from legitimate traffic

class DynamicRateMonitor:
    """
    Maintains a rolling history of network traffic to calculate statistical anomalies.
    """
    def __init__(self, window_seconds=60):
        """
        :param window_seconds: Duration of the historical memory for the baseline.
        """
        self.window = window_seconds
        self.samples = deque()

    def add_sample(self, value):
        """
        Adds a new traffic rate measurement to the baseline history.
        
        :param value: The measured packets-per-second (PPS).
        """
        now = time.time()
        self.samples.append((now, value))
        # Remove samples older than the rolling window
        cutoff = now - self.window
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def get_dynamic_threshold(self, factor=Z_SCORE_FACTOR):
        """
        Calculates a dynamic threshold based on the mean and standard deviation.
        
        :param factor: The multiplier for standard deviation (Z-score).
        :return: Calculated threshold or None if baseline is not yet ready.
        """
        if len(self.samples) < MINIMAL_SAMPLES:
            return None
        
        values = [v for (_, v) in self.samples]
        avg = sum(values) / len(values)
        
        # Calculate standard deviation to understand traffic volatility
        variance = sum((x - avg)**2 for x in values) / len(values)
        stdev = variance**0.5
        
        # Final threshold = Average + (Volatility * Sensitivity Factor)
        calculated_threshold = avg + (stdev * factor)
        return max(calculated_threshold, MIN_PPS_FLOOR)

# Global trackers for attack persistence and behavioral analysis
strike_counts = defaultdict(int) 
port_spread = defaultdict(set)
dynamic_monitor = DynamicRateMonitor(window_seconds=120)

# Detection components
counter = SlidingWindowCounter(window_seconds=10, max_items=2000)
alerter = RateAlert(threshold=1000, alert_cooldown=10) # Fallback alerter

def inspect(pkt):
    """
    Analyzes UDP traffic for volumetric flooding using statistical anomalies.

    :param pkt: The raw network packet.
    :return: An alert report if an anomaly is confirmed as a flood, else None.
    """
    now = time.time()

    if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dport = pkt[UDP].dport

    # Record activity and track port diversity
    count = counter.record(src_ip, now)
    port_spread[src_ip].add(dport)

    # Internal sampler: Records a network-wide baseline every 1 second
    if not hasattr(inspect, "last_sample_time"):
        inspect.last_sample_time = 0

    if now - inspect.last_sample_time >= 1:
        # Calculate current network-wide UDP rate
        total_rate = sum(len(dq) for dq in counter.table.values()) / counter.window
        dynamic_monitor.add_sample(total_rate)
        inspect.last_sample_time = now
        
        # Periodic memory cleanup for behavioral tracking
        if int(now) % 30 == 0:
            port_spread.clear()

    dynamic_threshold = dynamic_monitor.get_dynamic_threshold()

    if dynamic_threshold is not None:
        if count > dynamic_threshold:
            strike_counts[src_ip] += 1
            
            # Sustain requirement ensures we don't alert on brief traffic spikes
            if strike_counts[src_ip] >= SUSTAIN_REQUIREMENT:                
                detection = (
                    f"UDP Dynamic Flood Alert!\n"
                    f"Attacker: {src_ip} -> {dst_ip}\n"
                    f"Current Rate: {count:.2f} PPS | Baseline Threshold: {dynamic_threshold:.2f} PPS\n"
                    f"Strike Count: {strike_counts[src_ip]}"
                )
                strike_counts[src_ip] = 0 # Reset after alert
                return detection
        else:
            # Gradual decay of strikes if traffic returns to normal levels
            if strike_counts[src_ip] > 0:
                strike_counts[src_ip] -= 1
    
    return None

if __name__ == "__main__":
    """
    Standalone testing for Dynamic UDP Flood detection.
    """
    print("Starting Advanced UDP Flood Monitoring (Anomaly Detection)...")
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="udp")