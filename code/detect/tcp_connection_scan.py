from scapy.all import IP, TCP, sniff
from time import time
from collections import defaultdict

print("TCP Connection Scan Module Loaded")


WINDOW = 12 # Sliding window in seconds
PORT_THRESHOLD = 10 # Minimum distinct ports to trigger alert
MAX_CONN_TIME = 0.8 # Short-lived connection threshold (seconds)

# Track active TCP connections
# key = (src, dst, sport, dport)
sessions = {}

# Track scanned ports inside sliding window
# scans[src][dst] = list of (port, timestamp)
scans = defaultdict(lambda: defaultdict(list))


def inspect(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None

    ip = pkt[IP]
    tcp = pkt[TCP]
    key = (ip.src, ip.dst, tcp.sport, tcp.dport)
    now = time()

    is_syn = tcp.flags & 0x02 != 0   # SYN bit
    # Track SYN (connection start)
    if is_syn:
        sessions[key] = {"start": now, "payload": False}
        return None

    has_payload = len(tcp.payload) > 0
    # Mark this session as real traffic if it has data
    if key in sessions and has_payload:
        sessions[key]["payload"] = True
        return None

    is_fin_or_rst = (tcp.flags & 0x01) or (tcp.flags & 0x04)
    # Connection ending (FIN or RST)
    if key in sessions and is_fin_or_rst:
        sess = sessions[key]
        duration = now - sess["start"]
        del sessions[key]

        # Ignore legitimate TCP sessions
        if sess["payload"]:
            return None

        # Short-lived is suspicious
        if duration <= MAX_CONN_TIME:

            scans[ip.src][ip.dst].append((tcp.dport, now))

            # Clean window
            scans[ip.src][ip.dst] = [
                (port, ts) for (port, ts) in scans[ip.src][ip.dst]
                if now - ts <= WINDOW
            ]

            # Count distinct destination ports
            distinct_ports = {port for (port, _) in scans[ip.src][ip.dst]}

            if len(distinct_ports) >= PORT_THRESHOLD:
                return (
                    "\n[ALERT] TCP Connection Scan Detected!\n"
                    f"source_ip: {ip.src}\n"
                    f"destination_ip: {ip.dst}\n"
                    f"distinct_ports_last_{WINDOW}s: {len(distinct_ports)}\n"
                    f"ports: {sorted(list(distinct_ports))}\n"
                )

    return None


if __name__ == "__main__":
    print("Starting TCP Connection Scan Detection...")
    sniff(prn=inspect, store=0, filter="tcp")
