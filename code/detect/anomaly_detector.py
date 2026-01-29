# detect/anomaly_detector.py
import numpy as np
from utils.address import Addr

class AnomalyDetector:
    def __init__(self, logger):
        self.stats = {}
        self.logger = logger
        self.threshold = 10

    def inspect(self, src_addr: Addr, dst_addr: Addr, current_vals: list):
        val = np.array(current_vals)
        
        if src_addr not in self.stats:
            self.stats[src_addr] = {dst_addr: val.astype(float)}
            return

        if dst_addr not in self.stats[src_addr]:
            self.stats[src_addr][dst_addr] = val.astype(float)
            return

        # Extracting norm
        baseline = self.stats[src_addr][dst_addr]

        ratios = val / (baseline + 0.0001)
        
        if any(r > self.threshold for r in ratios):
            self.logger.alert(
                f"Anomaly detected from {src_addr} to {dst_addr}\n"
                f"Average: {baseline.round(1)}\n"
                f"New Data: {val}"
            )

        # Updating norm
        self.stats[src_addr][dst_addr] = 0.99 * baseline + 0.01 * val