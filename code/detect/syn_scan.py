# Live Detection of an TCP SYN Scan
from scapy.all import *
from time import time
import general

print("TCP SYN Scan Detection Module Loaded")


RELEVANCE = 30 # seconds - half a minute
THRESHHOLD = 100 # number of ports
# If more than THRESHHOLD ports are scanned in RELEVANCE seconds, !ALERT!

class PortPkt:
    def __init__(self, pkt: Packet):
        self.port = pkt[TCP].dport
        self.ip_src = pkt[IP].src
        self.ip_dst = pkt[IP].dst
        self._time = time()

    def is_relevant(self):
        return time() - self._time < RELEVANCE
    
    def __eq__(self, other):
        if not isinstance(other, PortPkt):
            return False
        return self.port == other.port


class PortList:
    def __init__(self, ip_src, ip_dst):
        self._ip_src = ip_src
        self._ip_dst = ip_dst
        self.ports = []

    def add_port(self, port_pkt: PortPkt):
        if port_pkt.ip_src != self._ip_src or port_pkt.ip_dst != self._ip_dst:
            return False
        self.ports = [p for p in self.ports if p.is_relevant()]
        if port_pkt in self.ports:
            return True
        self.ports.append(port_pkt)
        if len(self.ports) > THRESHHOLD:
            raise Exception(f"[ALERT] Possible TCP SYN scan detected from {self._ip_src} to {self._ip_dst} \n{len(self.ports)} ports initiated in less than {RELEVANCE} seconds")
        return True

    def __repr__(self):
        return f"{self._ip_src} -> {self._ip_dst}: {len(self.ports)}"


port_lists = []
def inspect(pkt):
    # tcp[13] & 2 != 0) and (tcp[13] & 16 == 0)
    # Flages: SYN set and ACK not set
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags & 0x02 and not (flags & 0x10):
            general.log(port_lists)
            port_pkt = PortPkt(pkt)
            try:
                if not any(pl.add_port(port_pkt) for pl in port_lists):
                    port_lists.append(PortList(pkt[IP].src, pkt[IP].dst))
                    port_lists[-1].add_port(port_pkt)
            except Exception as e:
                return e


if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system
    system('clear')
    print("Starting TCP SYN scan Detection...")

    # Flages: SYN set and ACK not set
    sniff(prn=inspect, store=0, filter="tcp and (tcp[13] & 2 != 0) and (tcp[13] & 16 == 0)")