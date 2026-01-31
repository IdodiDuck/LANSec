import numpy as np
from utils.address import Addr

class AnomalyDetector:
    def __init__(self, logger):
        self.stats = {}
        self.logger = logger
        self.threshold = 10
        self.min_packets_to_alert = 50

    def inspect(self, src_addr: Addr, dst_addr: Addr, current_vals: list):
        val = np.array(current_vals)
        total_packets = np.sum(val)

        if src_addr not in self.stats:
            self.stats[src_addr] = {}

        if dst_addr not in self.stats[src_addr]:
            self.stats[src_addr][dst_addr] = np.zeros_like(val, dtype=float)

        baseline = self.stats[src_addr][dst_addr]

        if total_packets >= self.min_packets_to_alert:
            ratios = val / (baseline + 1.0)
            
            if any(r > self.threshold for r in ratios):
                self.logger.alert(
                    f"Anomaly detected from {src_addr} to {dst_addr}\n"
                    f"Average: {baseline.round(1)}\n"
                    f"New Data: {val}"
                )

        self.stats[src_addr][dst_addr] = 0.95 * baseline + 0.05 * val