from scapy.all import TCP, IP, sniff
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector

print("SYN Flood Module Loaded")

# Configuration - 
# Tracks the rate of SYN packets directed at a specific target (IP:Port)
counter = SlidingWindowCounter(window_seconds=10, max_items=500)
alerter = RateAlert(threshold=100, alert_cooldown=10)
detector = BaseDetector(counter, alerter, name="SYN Flood")


def is_syn(pkt) -> bool:
    """
    Checks if a packet is a 'pure' SYN request.
    It verifies that the SYN flag is set (0x02) and the ACK flag is NOT set.

    :param pkt: The captured network packet.
    :return: True if it's a SYN request, False otherwise.
    """
    # 0x12 represents both SYN (0x02) and ACK (0x10) flags.
    # Ensuring only the SYN bit is active.
    return pkt.haslayer(TCP) and (pkt[TCP].flags & 0x12 == 0x02)


def inspect(pkt):
    """
    Analyzes TCP traffic to detect potential SYN Flood DoS attacks.
    Focuses on the destination to identify if a specific service is being targeted.

    :param pkt: The raw packet to inspect.
    :return: A count report if the threshold for the target is breached, else None.
    """
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not is_syn(pkt):
        return None

    dst = pkt[IP].dst
    port = pkt[TCP].dport
    
    target_key = f"{dst}:{port}"
    count = detector.count_event(target_key)

    if count:
        return (f"syn_count: {count}")

    return None

if __name__ == "__main__":
    """
    Standalone test environment for SYN Flood detection.
    """
    from colorama import init as color_init
    from os import system
    color_init(autoreset=True)

    try:
        system("clear")
    except:
        pass

    print("Starting SYN Flood Detection Engine...")
    print("[*] Monitoring TCP handshake patterns.")

    # 'tcp[13] & 2 != 0' checks for SYN flag.
    # 'tcp[13] & 16 == 0' ensures ACK flag is NOT set.
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="tcp and (tcp[13] & 2 != 0) and (tcp[13] & 16 == 0)")