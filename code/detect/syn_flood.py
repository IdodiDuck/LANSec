from scapy.all import *
from collections import deque
import time

print("TCP SYN Flood Detection Module Loaded")

WINDOW_SECONDS = 10  # sliding window length (seconds)
SYN_THRESHOLD = 20
MAX_TIMESTAMPS_PER_IP = 200  # small cap to avoid unbounded growth per IP

INFO_INTERVAL = 1.0 # seconds: at most one INFO print per IP every INFO_INTERVAL
INFO_DELTA = 5 # print INFO only if count increased by at least this much
ALERT_DEBOUNCE = 10.0 # seconds: at most one ALERT per IP every ALERT_DEBOUNCE

syn_table = {}  # Each IP has deque of recorded SYN timestamps

_last_info_time = {}  # src_ip -> timestamp of last INFO print
_last_info_count = {}  # src_ip -> last printed count
_last_alert_time = {}  # src_ip -> last alert time (for debounce)

# Support Functions - 
def is_syn(pkt) -> bool:
    """Return True if packet is a TCP SYN (and not a SYN+ACK)"""

    if not pkt.haslayer(TCP):
        return False
    
    tcp = pkt[TCP]
    return (tcp.flags & 0x02 != 0) and (tcp.flags & 0x10 == 0)


def record_syn(src_ip: str, when: float):
    """Record SYN timestamp for src_ip and prune entries older than WINDOW_SECONDS"""

    dq = syn_table.get(src_ip)
    if dq is None:
        dq = deque()
        syn_table[src_ip] = dq

    dq.append(when)

    # prune older than WINDOW_SECONDS (sliding window)
    cutoff = when - WINDOW_SECONDS

    while dq and dq[0] < cutoff:
        dq.popleft()

    # cap deque length for safety
    while len(dq) > MAX_TIMESTAMPS_PER_IP:
        dq.popleft()

    return len(dq)

def should_alert(src_ip: str, count: int) -> bool:
    """Return True only if count >= threshold and we haven't alerted recently"""

    if count < SYN_THRESHOLD:
        return False

    last_time = _last_alert_time.get(src_ip, 0)
    now = time.time()

    if now - last_time >= ALERT_DEBOUNCE:
        _last_alert_time[src_ip] = now
        return True

    return False

# Inspection Logic - 
def inspect(pkt):
    """Called per packet by sniff. Returns alert string if detected"""

    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return None

        if not is_syn(pkt):
            return None

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        now = time.time()

        count = record_syn(src, now)

        last_info_t = _last_info_time.get(src, 0)
        last_info_c = _last_info_count.get(src, 0)

        # Rate-limited INFO printing
        if (now - last_info_t) >= INFO_INTERVAL or (count - last_info_c) >= INFO_DELTA:
            _last_info_time[src] = now
            _last_info_count[src] = count
            print(f"[INFO] {src} -> {dst} : {count} SYNs in last {WINDOW_SECONDS}s") # Debugging Printing

        if should_alert(src, count):
            alert = (
                f"[ALERT] Possible SYN Flood detected\n"
                f"src_ip: {src}, dst_ip: {dst}, src_port: {sport}, dst_port: {dport}\n"
                f"syn_count_in_{WINDOW_SECONDS}s: {count}\n"
                f"threshold: {SYN_THRESHOLD}\n"
            )

            return alert

        return None

    except Exception as e:
        err = f"SYN Flood Module: Inspection Error: {e}"
        return err


if __name__ == "__main__":
    from colorama import Fore, init as color_init
    from os import system
    color_init(autoreset=True)

    try:
        system('cls')
        system("clear")

    except:
        pass

    # Flags: SYN set and ACK not set
    sniff(prn=inspect, store=0, filter="tcp and (tcp[13] & 2 != 0) and (tcp[13] & 16 == 0)")
