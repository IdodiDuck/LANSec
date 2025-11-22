from scapy.all import *
from .rate_limiter import SlidingWindowCounter, RateAlert
from .base_detector import BaseDetector

print("SSH Brute Force Module Loaded")

# Configuration
SSH_PORT = 22
WINDOW_SECONDS = 20
THRESHOLD = 15
ALERT_COOLDOWN = 20

counter = SlidingWindowCounter(window_seconds=WINDOW_SECONDS, max_items=300)
alerter = RateAlert(threshold=THRESHOLD, alert_cooldown=ALERT_COOLDOWN)
detector = BaseDetector(counter, alerter, name="SSH BruteForce")


# Support Functions -
def is_ssh(pkt):
    """
    Detects possible SSH session attempts.
    
    Triggers when:
    1) A TCP SYN is sent TO an SSH port (default 22)
    2) SSH banner is observed ("SSH-" bytes)
    """

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return False
    
    tcp = pkt[TCP]
    dport = tcp.dport

    # TCP SYN to SSH
    if dport == SSH_PORT and (tcp.flags & 0x02 == 2):
        return True

    # Raw SSH identification string
    if pkt.haslayer(Raw) and dport == SSH_PORT:
        raw = pkt[Raw].load
        if raw.startswith(b"SSH-"):
            return True

    return False

def inspect(pkt):
    if not is_ssh(pkt):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst

    count = detector.count_event(src)

    if count:
        return (
            f"[ALERT] SSH Brute Force Detected!\n"
            f"src_ip: {src} -> {dst}\n"
            f"attempts_in_window: {count}\n"
            f"window_seconds: {WINDOW_SECONDS}\n"
            f"threshold: {THRESHOLD}\n"
        )

if __name__ == "__main__":
    from colorama import init as color_init
    from os import system
    color_init(autoreset=True)

    """try:
        system('cls')
        system("clear")

    except:
        pass"""

    sniff(
        prn=inspect,
        store=0,
        filter="tcp and dst port 22 and tcp[tcpflags] & tcp-syn != 0",
    )
