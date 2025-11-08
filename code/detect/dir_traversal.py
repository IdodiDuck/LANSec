from scapy.all import *
import re
from urllib.parse import unquote
import posixpath

print("Directory Traversal Detection Module Loaded")

#  Number of "../" or "..\" sequences that trigger suspicion.
#  A higher value reduces false positives, while 1–2 is more sensitive.
SUSPICIOUS_TRAVERSAL_DEPTH = 3
SENSITIVE_TARGETS = ["/etc/passwd", "/etc/shadow", "/etc/hosts",
    "boot.ini", "windows/win.ini", "c:\\boot.ini",
    "web.config", "wp-config.php"]

# Support Functions - 
def multi_url_unquote(s: str, max_iters: int = 5) -> str:
    """
    Performs repeated URL-decoding (handles double/triple-encoded payloads)
    """
    prev = None
    cur = s
    for _ in range(max_iters):
        prev = cur
        cur = unquote(cur)
        if cur == prev:
            break

    return cur

def normalize_path(p: str) -> str:
    """
    Converts backslashes to slashes and normalizes the path
    """
    p = p.replace("\\", "/")
    normalized = posixpath.normpath(p)
    if p.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized

# Core Validation Logic - 
def is_valid(msg: str) -> bool:
    """
    Determines whether a given HTTP message or body is free of
    directory traversal patterns
    """
    if not msg:
        return True

    path = None

    try:
        header_part = msg.split("\r\n\r\n", 1)[0]
        first_line = header_part.splitlines()[0].strip()
        parts = first_line.split()
        if len(parts) >= 2:
            path = parts[1]

    except Exception:
        path = None

    if not path:
        path = msg # fallback: check full message or body

    decoded = multi_url_unquote(path, max_iters=6)
    lower_original = path.lower()
    lower_decoded = decoded.lower()

    # Literal traversal
    if re.search(r"\.\./", decoded) or re.search(r"\.\.\\", decoded):
        return False

    # Encoded traversal (%2e%2e%2f)
    if re.search(r"%2e%2e(?:%2f|/|%5c|\\)", lower_original):
        return False

    # Double-encoded traversal (%252e%252e%252f)
    if re.search(r"%252e%252e(?:%252f|%2f|/|%255c|%5c|\\)", lower_original):
        return False

    # Null-byte attempts
    if re.search(r"(?:%00|\x00)(?:%2f|/|%5c|\\)", lower_original):
        return False
    
    if re.search(r"\.\.(?:%00|\x00)(?:%2f|/|%5c|\\)", lower_original):
        return False

    # Traversal depth check
    depth = len(re.findall(r"\.\./", decoded)) + len(re.findall(r"\.\.\\", decoded))
    if depth >= SUSPICIOUS_TRAVERSAL_DEPTH:
        return False

    # Normalized path escaping
    normalized = normalize_path(decoded)
    if normalized.startswith("..") or "/../" in f"/{normalized}":
        return False

    # Sensitive file access
    for t in SENSITIVE_TARGETS:
        if t.lower() in lower_decoded or t.lower() in normalized.lower():
            return False

    return True

# Inspection Logic - 
def inspect(pkt):
    """
    Called by the Network Sniffer & Analyzer.
    Checks for Directory Traversal attempts within HTTP traffic
    """

    try:
        # Focus on HTTP-like TCP packets
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport in [80, 8080, 8000, 12345]:
            raw_bytes = bytes(pkt[Raw].load)

            try:
                payload_text = raw_bytes.decode("utf-8", errors="replace")

            except Exception:
                payload_text = raw_bytes.decode("latin-1", errors="replace")

            # Extract HTTP path (if exists)
            path = None
            try:

                header_part = payload_text.split("\r\n\r\n", 1)[0]
                lines = header_part.splitlines()
                if lines:
                    first = lines[0].strip()
                    parts = first.split()
                    if len(parts) >= 2:
                        path = parts[1]

            except Exception:
                path = None

            # No path -> check HTTP body
            if not path:
                payload_body = raw_bytes.split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
                if is_valid(payload_body):
                    return None
                
                alert = (f"[ALERT] Possible Directory Traversal detected!\n"
                         f"src_ip: {pkt[IP].src}, dst_ip: {pkt[IP].dst}, "
                         f"src_port: {pkt[TCP].sport}, dst_port: {pkt[TCP].dport}\n"
                         f"payload_body: {payload_body}\n")
                
                return alert

            # Path found -> validate it
            if is_valid(path):
                return None

            # Suspicious path found
            decoded_path = multi_url_unquote(path, max_iters=6)
            normalized = normalize_path(decoded_path)
            alert = (
                f"[ALERT] Possible Directory Traversal detected!\n"
                f"src_ip: {pkt[IP].src}, dst_ip: {pkt[IP].dst}, "
                f"src_port: {pkt[TCP].sport}, dst_port: {pkt[TCP].dport}\n"
                f"original_path: {path}\n"
                f"decoded_path: {decoded_path}\n"
                f"normalized_path: {normalized}\n"
            )
            
            return alert

        return None

    except Exception as e:
        err = f"Directory Traversal Module: Inspection Error: {e}"
        return err

if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system

    system('clear')
    print("Starting Directory Traversal Detection...\n\n")
    
    # filter for HTTP traffic (port 80, 8080, 8000) + 12345 for debugging
    sniff(prn=inspect, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")