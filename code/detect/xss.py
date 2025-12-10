from scapy.all import *
import re
from urllib.parse import unquote
from utils.http_normalizer import HTTPNormalizer

# XSS Basic Patterns
XSS_PATTERNS = [
    (re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE), "Inline <script> tag"),
    (re.compile(r"javascript:", re.IGNORECASE), "javascript: URI"),
    (re.compile(r"on\w+\s*=", re.IGNORECASE), "Event handler"),
    (re.compile(r"%3Cscript%3E", re.IGNORECASE), "URL-encoded <script>"),
    (re.compile(r"<.*?onerror\s*=", re.IGNORECASE), "onerror handler"),
    (re.compile(r"alert\s*\(", re.IGNORECASE), "alert() usage"),
]


def detect_xss(pkt):
    # Must have TCP payload
    if not pkt.haslayer(Raw):
        return None

    req = HTTPNormalizer.normalize(pkt)
    if req is None:
        return None

    findings = []

    # Locations to scan
    parts = {
        "path": req.path,
        "query": getattr(req, "query_string", ""),
        "body": req.body,
    }

    for part_name, text in parts.items():
        if not text:
            continue

        decoded = unquote(text).lower()

        for regex, label in XSS_PATTERNS:
            if regex.search(decoded):
                findings.append((part_name, label, decoded[:200]))

    if findings:
        return {
            "type": "XSS",
            "src": req.src,
            "dst": req.dst,
            "method": req.method,
            "path": req.path,
            "findings": findings
        }

    return None


def inspect(pkt):

    result = detect_xss(pkt)
    if not result:
        return None

    # Build readable description for logger
    desc_lines = [f"HTTP {result['method']} {result['path']}"]

    for location, label, snippet in result["findings"]:
        desc_lines.append(
            f"{location}: {label} | '{snippet}'"
        )

    desc = "\n".join(desc_lines)

    return (
        result["src"],
        result["dst"],
        desc
    )

if __name__ == "__main__":
    print("Starting XSS Detection...\n")

    sniff(prn=inspect,store=0,filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")
