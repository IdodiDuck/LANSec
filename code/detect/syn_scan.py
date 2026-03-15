from scapy.all import TCP, IP, sniff
from time import time

print("TCP SYN Scan Detection Module Loaded")

# Configuration -
RELEVANCE_WINDOW = 30  
THRESHOLD = 100
CLEANUP_INTERVAL = 60

# Global storage for tracking scanners:
# Structure: { (src_ip, dst_ip): { "ports": set(port1, port2...), "last_seen": timestamp } }
scanners = {}
last_cleanup = time()

def clean_expired_trackers():
    """
    Performs memory management by removing tracking entries that have 
    exceeded the relevance window.
    """
    global last_cleanup
    now = time()
    
    # Only run cleanup based on the defined interval to save CPU cycles
    if now - last_cleanup < CLEANUP_INTERVAL:
        return

    for key in list(scanners.keys()):
        if now - scanners[key]["last_seen"] > RELEVANCE_WINDOW:
            del scanners[key]
            
    last_cleanup = now

def inspect(pkt):
    """
    Analyzes TCP packets for 'Stealth' SYN scanning patterns.
    Detects attackers probing multiple ports without completing the handshake.

    :param pkt: The raw network packet captured by the sniffer.
    :return: A detailed alert string if a scan is confirmed, else None.
    """

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None

    # Identify SYN packets (0x02) that are NOT part of a SYN-ACK (0x12)
    flags = pkt[TCP].flags
    if not (flags & 0x02 and not (flags & 0x10)):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst
    port = pkt[TCP].dport
    now = time()

    # Track activity using a composite key (Source IP -> Destination IP)
    scan_key = (src, dst)

    if scan_key not in scanners:
        scanners[scan_key] = {"ports": set(), "last_seen": now}

    tracker = scanners[scan_key]
    
    # Add unique port to the set
    tracker["ports"].add(port)
    tracker["last_seen"] = now

    clean_expired_trackers()

    unique_ports = len(tracker["ports"])
    if unique_ports > THRESHOLD:
        # Clear tracker after alerting to prevent continuous spamming for the same event
        del scanners[scan_key]
        return (f"{unique_ports} unique ports probed within {RELEVANCE_WINDOW}s")

    return None

if __name__ == "__main__":
    """
    Standalone execution for real-time SYN scan monitoring.
    """
    print("Starting TCP Stealth Scan Detection Engine...")
    print(f"[*] Threshold: {THRESHOLD} ports | Window: {RELEVANCE_WINDOW}s")

    # Only capture TCP packets where SYN is set and ACK is clear
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="tcp and (tcp[13] & 2 != 0) and (tcp[13] & 16 == 0)")