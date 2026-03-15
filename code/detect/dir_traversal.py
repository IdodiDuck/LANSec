from utils.http_normalizer import HTTPNormalizer
from urllib.parse import unquote
import re
import posixpath

# Threshold for excessive directory climbing
SUSPICIOUS_TRAVERSAL_DEPTH = 3

# High-value system files that should never be accessed via a web request
SENSITIVE_TARGETS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "boot.ini", "windows/win.ini", "c:\\boot.ini",
    "web.config", "wp-config.php"
]

def multi_url_unquote(s: str, max_iters: int = 5) -> str:
    """
    Handles 'Double Encoding' attacks by recursively decoding the string.
    Example: %252e%252e%252f -> %2e%2e%2f -> ../
    """
    cur = s
    for _ in range(max_iters):
        new = unquote(cur)
        if new == cur:
            break
        cur = new
    return cur

def normalize_path(p: str) -> str:
    """
    Converts Windows-style backslashes to forward slashes and resolves 
    relative path segments (e.g., /static/../etc/ -> /etc/).
    """
    p = p.replace("\\", "/")
    normalized = posixpath.normpath(p)
    # Ensure absolute paths remain absolute after normalization
    if p.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized

def is_valid_path(path: str) -> bool:
    """
    The core validation engine. Checks for traversal patterns and sensitive targets.
    Returns False if the path is deemed malicious.
    """
    decoded = multi_url_unquote(path, max_iters=6)
    lower_original = path.lower()
    lower_decoded = decoded.lower()

    # Direct Traversal Check
    if "../" in decoded or "..\\" in decoded:
        return False

    # Hex/URL Encoded Patterns (e.g., %2e%2e is '..')
    if re.search(r"%2e%2e(?:%2f|/|%5c|\\)", lower_original):
        return False

    # Double Encoding Check (%252e is a double-encoded '.')
    if re.search(r"%252e%252e", lower_original):
        return False

    # Multiple climbing steps are highly suspicious
    depth = decoded.count("../") + decoded.count("..\\")
    if depth >= SUSPICIOUS_TRAVERSAL_DEPTH:
        return False

    # Check if the path escapes the root after resolving '.' and '..'
    normalized = normalize_path(decoded)
    if normalized.startswith("..") or "/../" in f"/{normalized}":
        return False

    # Sensitive Target Check: Detect access to critical OS files
    for t in SENSITIVE_TARGETS:
        if t.lower() in lower_decoded or t.lower() in normalized.lower():
            return False

    return True

def inspect(pkt):
    """
    Integrates with the HTTPNormalizer to inspect request paths and bodies.
    """
    http = HTTPNormalizer.normalize(pkt)
    if not http:
        return None

    # Inspect the Request Path (URL)
    if not is_valid_path(http.path):
        decoded = multi_url_unquote(http.path)
        normalized = normalize_path(decoded)
        return (
            f"Directory Traversal Attempt Detected!\n"
            f"Original: {http.path}\n"
            f"Decoded:  {decoded}\n"
            f"Resolved: {normalized}"
        )

    # Inspect the Request Body (POST data)
    if http.body and not is_valid_path(http.body):
        return (
            f"Directory Traversal in Body"
        )

    return None

if __name__ == "__main__":
    from scapy.all import sniff

    print("Starting Directory Traversal Detection...")
    # Monitoring common web ports
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, 
          store=0, filter="tcp port 80 or tcp port 8080 or tcp port 12345")