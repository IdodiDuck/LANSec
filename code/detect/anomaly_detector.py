import numpy as np
from utils.address import Addr

class AnomalyDetector:
    """
    Statistical Anomaly Detection Engine.
    Monitors network traffic metrics and identifies deviations from established 
    baselines using an Exponential Moving Average (EMA) algorithm.
    """
    def __init__(self, logger):
        """
        :param logger: Logger instance for reporting suspicious activity.
        """
        self.stats = {}  # Nested dictionary storing baselines: {src_addr: {dst_addr: baseline_vector}}
        self.logger = logger
        
        # Sensitivity settings
        self.threshold = 10              # Alert if current value is 10x the baseline
        self.min_packets_to_alert = 50   # Ignore low-traffic flows to reduce False Positives
        
        # Metric labels corresponding to the input data vector
        self.labels = [
            "TCP Ports", "TCP SYN", "ARP Req", 
            "ARP Rep", "ICMP Req", "ICMP Rep", "UDP Ports"
        ]

    def inspect(self, src_addr: Addr, dst_addr: Addr, current_vals: list):
        """
        Analyzes a traffic burst and compares it against the historical baseline.
        If the current burst is significantly higher than the average, an alert is triggered.
        
        :param src_addr: Source Addr object.
        :param dst_addr: Destination Addr object.
        :param current_vals: List of metrics captured in the current time window.
        """
        val = np.array(current_vals)
        total_packets = np.sum(val)

        # Initialize data structures for new network nodes
        if src_addr not in self.stats:
            self.stats[src_addr] = {}

        if dst_addr not in self.stats[src_addr]:
            # Start with a zero baseline for new flows
            self.stats[src_addr][dst_addr] = np.zeros_like(val, dtype=float)

        baseline = self.stats[src_addr][dst_addr]

        # Analysis Phase: Only alert if there is enough traffic to be statistically significant
        if total_packets >= self.min_packets_to_alert:
            # Identify which specific metrics caused the anomaly
            anomalous_labels = [
                self.labels[i] for i in range(len(val)) 
                if val[i] >= (max(baseline[i], 0.5) * self.threshold)
            ]

            if anomalous_labels:
                self.logger.alert(
                    severity="SUSPICIOUS",
                    attack_type="Network Anomaly",
                    details=(
                        f"Anomalous Fields: {', '.join(anomalous_labels)}\n"
                        f"Baseline: {baseline.round(1).tolist()}\n"
                        f"Current Burst: {val.tolist()}\n"
                    ),
                    src_ip=src_addr.ip,
                    dst_ip=dst_addr.ip
                )

        # Learning Phase: Update the baseline using Exponential Moving Average (EMA)
        # This formula balances historical data (95%) with new observations (5%)
        self.stats[src_addr][dst_addr] = 0.95 * baseline + 0.05 * val