from utils.http_normalizer import HTTPNormalizer
from urllib.parse import unquote
import re
import posixpath

SUSPICIOUS_TRAVERSAL_DEPTH = 3

SENSITIVE_TARGETS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "boot.ini", "windows/win.ini", "c:\\boot.ini",
    "web.config", "wp-config.php"
]


def multi_url_unquote(s: str, max_iters: int = 5) -> str:
    cur = s
    for _ in range(max_iters):
        new = unquote(cur)
        if new == cur:
            break
        cur = new
    return cur


def normalize_path(p: str) -> str:
    p = p.replace("\\", "/")
    normalized = posixpath.normpath(p)
    if p.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def is_valid_path(path: str) -> bool:
    decoded = multi_url_unquote(path, max_iters=6)
    lower_original = path.lower()
    lower_decoded = decoded.lower()

    if "../" in decoded or "..\\" in decoded:
        return False

    if re.search(r"%2e%2e(?:%2f|/|%5c|\\)", lower_original):
        return False

    if re.search(r"%252e%252e", lower_original):
        return False

    depth = decoded.count("../") + decoded.count("..\\")
    if depth >= SUSPICIOUS_TRAVERSAL_DEPTH:
        return False

    normalized = normalize_path(decoded)
    if normalized.startswith("..") or "/../" in f"/{normalized}":
        return False

    for t in SENSITIVE_TARGETS:
        if t.lower() in lower_decoded or t.lower() in normalized.lower():
            return False

    return True


def inspect(pkt):
    http = HTTPNormalizer.normalize(pkt)
    if not http:
        return None

    # Check path
    if not is_valid_path(http.path):
        decoded = multi_url_unquote(http.path)
        normalized = normalize_path(decoded)
        return (
            f"src={http.src} → dst={http.dst}\n"
            f"path={http.path}\n"
            f"decoded={decoded}\n"
            f"normalized={normalized}"
        )

    # Check body
    if http.body and not is_valid_path(http.body):
        return (
            f"src={http.src} → dst={http.dst}\n"
            f"body={http.body[:200]}"
        )

    return None

if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system

    system('clear')
    print("Starting Directory Traversal Detection...\n\n")
    
    # filter for HTTP traffic (port 80, 8080, 8000) + 12345 for debugging
    sniff(prn=inspect, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")