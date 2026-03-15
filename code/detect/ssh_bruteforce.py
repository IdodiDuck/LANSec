from scapy.all import TCP, IP, Raw, sniff
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector

print("SSH Brute Force Module Loaded")

# Configuration - 
SSH_PORT = 22
WINDOW_SECONDS = 20
THRESHOLD = 15
ALERT_COOLDOWN = 20 # Seconds to wait before re-alerting on the same source

# Rate-limiting infrastructure for tracking connection attempts
counter = SlidingWindowCounter(window_seconds=WINDOW_SECONDS, max_items=300)
alerter = RateAlert(threshold=THRESHOLD, alert_cooldown=ALERT_COOLDOWN)
detector = BaseDetector(counter, alerter, name="SSH BruteForce")


def is_ssh(pkt) -> bool:
    """
    Identifies potential SSH connection attempts or identification banners.

    :param pkt: The captured network packet.
    :return: True if the packet indicates an SSH connection attempt, False otherwise.
    """
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return False
    
    tcp = pkt[TCP]
    dport = tcp.dport

    # Detects the initial 'handshake' attempt to the SSH port
    if dport == SSH_PORT and (tcp.flags & 0x02 == 2):
        return True

    # Looks for the "SSH-" protocol identification string
    if pkt.haslayer(Raw) and dport == SSH_PORT:
        raw = pkt[Raw].load
        if raw.startswith(b"SSH-"):
            return True

    return False


def inspect(pkt):
    """
    Analyzes SSH traffic to detect Brute Force patterns using rate-limiting.

    :param pkt: The raw packet to inspect.
    :return: A detailed alert report if the threshold is breached, else None.
    """
    if not is_ssh(pkt):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst

    # Record the event for the source IP and check against rate thresholds
    count = detector.count_event(src)

    if count:
        # If detector returns a count, the threshold was exceeded
        return (
            f"SSH Brute Force Detected!\n"
            f"Attacker: {src} -> Target: {dst}\n"
            f"Attempts: {count} in {WINDOW_SECONDS}s (Threshold: {THRESHOLD})"
        )

    return None


if __name__ == "__main__":
    """
    Standalone testing entry point for SSH Brute Force detection.
    """
    from colorama import init as color_init
    color_init(autoreset=True)

    print("Starting SSH Brute Force Detection Engine...")
    print(f"Monitoring TCP Port {SSH_PORT} for excessive connection attempts.")

    # Only capture SYN packets heading to the SSH port
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="tcp and dst port 22 and tcp[tcpflags] & tcp-syn != 0")