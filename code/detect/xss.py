from scapy.all import TCP, sniff
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
    if not pkt.haslayer(TCP):
        return None

    req = HTTPNormalizer.normalize(pkt)
    if req is None:
        return None

    findings = []

    # GET / POST / URL / BODY
    parts = {
        "path": req.path or "",
        "query": getattr(req, "query_string", "") or "",
        "body": req.body or "",
    }

    for part_name, text in parts.items():
        if not text:
            continue

        # Decode twice (bypass tricks)
        decoded = unquote(unquote(text)).lower()

        for regex, label in XSS_PATTERNS:
            if regex.search(decoded):
                findings.append(
                    (part_name, label, decoded[:200])
                )

    if findings:
        return {
            "method": req.method,
            "path": req.path,
            "findings": findings
        }

    return None


def inspect(pkt):
    
    result = detect_xss(pkt)
    
    if not result:
        return None

    findings_list = [f"{loc} ({label})" for loc, label, snip in result["findings"]]
    findings_summary = " | ".join(findings_list)

    return (
        f"src_ip: {result["src"]}\n"
        f"target: {result["dst"]}\n"
        f"method: {result["method"]}\n"
        f"path: {result["path"]}\n"
        f"findings: {findings_summary}\n"
    )


if __name__ == "__main__":
    print("Starting XSS Detection...\n")

    sniff(prn=inspect, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")