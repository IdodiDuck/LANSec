import threading
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from utils.address import Addr

class DataAggregator:
    def __init__(self, detector):
        self.detector = detector
        self.window_data = defaultdict(lambda: {
            'tcp_ports': set(), 
            'tcp_syn': 0, 
            'arp_req': 0, 
            'arp_rep': 0, 
            'icmp_req': 0, 
            'icmp_rep': 0, 
            'udp_ports': set()
        })
        self.lock = threading.Lock()

    def add_packet(self, pkt):
        try:
            if IP in pkt:
                src_hex = Addr(pkt[IP].src, pkt.src).to_hex()
                dst_hex = Addr(pkt[IP].dst, pkt.dst).to_hex()
                pair = (src_hex, dst_hex)

                with self.lock:
                    if TCP in pkt:
                        self.window_data[pair]['tcp_ports'].add(pkt[TCP].dport)
                        if pkt[TCP].flags == "S":
                            self.window_data[pair]['tcp_syn'] += 1

                    elif UDP in pkt:
                        self.window_data[pair]['udp_ports'].add(pkt[UDP].dport)

                    elif ICMP in pkt:
                        if pkt[ICMP].type == 8: self.window_data[pair]['icmp_req'] += 1
                        elif pkt[ICMP].type == 0: self.window_data[pair]['icmp_rep'] += 1
            
            elif ARP in pkt:
                src_addr = Addr(pkt[ARP].psrc, pkt[ARP].hwsrc)
                dst_addr = Addr(pkt[ARP].pdst, pkt[ARP].hwdst)
                pair = (src_addr.to_hex(), dst_addr.to_hex())

                with self.lock:
                    if pkt[ARP].op == 1: # ARP Request
                        self.window_data[pair]['arp_req'] += 1

                    elif pkt[ARP].op == 2: # ARP Reply
                        self.window_data[pair]['arp_rep'] += 1

        except Exception:
            pass

    def analyze_and_reset(self):
        with self.lock:
            current_copy = dict(self.window_data)
            self.window_data.clear()

        for (src_hex, dst_hex), stats in current_copy.items():
            vals = [
                len(stats['tcp_ports']), stats['tcp_syn'], stats['arp_req'],
                stats['arp_rep'], stats['icmp_req'], stats['icmp_rep'], len(stats['udp_ports'])
            ]
            
            self.detector.inspect(Addr.from_hex(src_hex), Addr.from_hex(dst_hex), vals)