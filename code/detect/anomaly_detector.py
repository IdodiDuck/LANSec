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
            
            self.logger.alert(
                    severity="SUSPICIOUS",
                    attack_type="Network Anomaly",
                    details=(
                        f"Flow: {src_addr} -> {dst_addr} | "
                        f"Baseline: {baseline.round(1).tolist()} | "
                        f"Current Burst: {val.tolist()}"
                    )
                )

        self.stats[src_addr][dst_addr] = 0.95 * baseline + 0.05 * val