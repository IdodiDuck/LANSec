import threading
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from utils.address import Addr

class DataAggregator:
    """
    Aggregates network traffic data into statistical snapshots.
    It tracks specific metrics to build a behavioral profile of every active connection in the network.
    """
    def __init__(self, detector):
        """
        :param detector: The AnomalyDetector instance to send aggregated data to.
        """
        self.detector = detector
        # Initialize counters for new pairs
        self.window_data = defaultdict(lambda: {
            'tcp_ports': set(),   # Tracks unique destination ports
            'tcp_syn': 0,
            'arp_req': 0,     
            'arp_rep': 0,     
            'icmp_req': 0,  
            'icmp_rep': 0,
            'udp_ports': set()    # Tracks unique UDP ports
        })
        # Thread safety lock to prevent data corruption during aggregation/analysis cycles
        self.lock = threading.Lock()

    def add_packet(self, pkt):
        """
        Parses an individual packet and updates the relevant statistics in the current window.
        """
        try:
            # Handle IP-based traffic (TCP, UDP, ICMP)
            if IP in pkt:
                src_hex = Addr(pkt[IP].src, pkt.src).to_hex()
                dst_hex = Addr(pkt[IP].dst, pkt.dst).to_hex()
                pair = (src_hex, dst_hex)

                with self.lock:
                    if TCP in pkt:
                        self.window_data[pair]['tcp_ports'].add(pkt[TCP].dport)
                        if pkt[TCP].flags == "S": # SYN Flag detection
                            self.window_data[pair]['tcp_syn'] += 1

                    elif UDP in pkt:
                        self.window_data[pair]['udp_ports'].add(pkt[UDP].dport)

                    elif ICMP in pkt:
                        # ICMP Type 8: Echo Request, Type 0: Echo Reply
                        if pkt[ICMP].type == 8: self.window_data[pair]['icmp_req'] += 1
                        elif pkt[ICMP].type == 0: self.window_data[pair]['icmp_rep'] += 1
            
            # Handle Layer 2 traffic (ARP)
            elif ARP in pkt:
                src_addr = Addr(pkt[ARP].psrc, pkt[ARP].hwsrc)
                dst_addr = Addr(pkt[ARP].pdst, pkt[ARP].hwdst)
                pair = (src_addr.to_hex(), dst_addr.to_hex())

                with self.lock:
                    if pkt[ARP].op == 1: # ARP Request (Who-has)
                        self.window_data[pair]['arp_req'] += 1
                    elif pkt[ARP].op == 2: # ARP Reply (Is-at)
                        self.window_data[pair]['arp_rep'] += 1

        except Exception:
            # Ignore malformed packets
            pass

    def analyze_and_reset(self):
        """
        Extracts the current statistics, resets the window, and triggers the detection logic.
        This is typically called every X seconds by a background thread.
        """
        with self.lock:
            # Atomic swap: take the current data and clear the state for the next window
            current_copy = dict(self.window_data)
            self.window_data.clear()

        for (src_hex, dst_hex), stats in current_copy.items():
            # Convert aggregated stats into a numerical vector for the anomaly engine
            vals = [
                len(stats['tcp_ports']), # Count of unique ports (Vertical Scanning)
                stats['tcp_syn'], 
                stats['arp_req'],
                stats['arp_rep'], 
                stats['icmp_req'], 
                stats['icmp_rep'], 
                len(stats['udp_ports'])
            ]
            
            # Send the vector to the AnomalyDetector for baseline comparison
            self.detector.inspect(Addr.from_hex(src_hex), Addr.from_hex(dst_hex), vals)