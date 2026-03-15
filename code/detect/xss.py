from scapy.all import TCP, sniff
import re
import html
from urllib.parse import unquote
from utils.http_normalizer import HTTPNormalizer

print("XSS Detection Module Loaded")

# XSS Attack Patterns (Signatures)
XSS_PATTERNS = [
    (re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE), "Inline <script> tag"),
    (re.compile(r"javascript:", re.IGNORECASE), "javascript: URI"),
    (re.compile(r"on\w+\s*=", re.IGNORECASE), "Event handler (e.g., onclick, onload)"),
    (re.compile(r"%3Cscript%3E", re.IGNORECASE), "URL-encoded <script>"),
    (re.compile(r"<.*?onerror\s*=", re.IGNORECASE), "onerror handler bypass"),
    (re.compile(r"alert\s*\(", re.IGNORECASE), "alert() execution probe"),
]

def detect_xss(pkt):
    """
    Core detection logic for Cross-Site Scripting.
    Analyzes multiple parts of the HTTP request for malicious scripts.

    :param pkt: The captured network packet.
    :return: A dictionary containing findings and metadata if XSS is detected, else None.
    """
    if not pkt.haslayer(TCP):
        return None

    req = HTTPNormalizer.normalize(pkt)
    if req is None:
        return None

    findings = []

    # Segregating the request into inspectable segments
    parts = {
        "path": req.path or "",
        "query": getattr(req, "query_string", "") or "",
        "body": req.body or "",
    }

    for part_name, text in parts.items():
        if not text:
            continue

        # Double decoding
        decoded = unquote(unquote(text)).lower()

        for regex, label in XSS_PATTERNS:
            if regex.search(decoded):
                findings.append(
                    (part_name, label, decoded[:200]) # Capture location and type
                )
    
    if findings:
        return {
            "method": req.method,
            "path": req.path,
            "findings": findings
        }

    return None


def inspect(pkt):
    """
    High-level hook for the sniffer. Formats the raw findings into a readable alert.

    :param pkt: The raw packet to analyze.
    :return: A sanitized and formatted alert string if XSS is found, else None.
    """
    result = detect_xss(pkt)
    if not result:
        return None

    # Create a summary of all detected patterns in the packet
    findings_list = [f"{loc} ({label})" for loc, label, snip in result["findings"]]
    findings_summary = ", ".join(findings_list)
    
    # HTML escape the summary for safe UI displaying
    safe_summary = html.escape(findings_summary)

    return (
        f"Method: {result['method']}\n"
        f"Path:   {result['path']}\n"
        f"Findings:  {safe_summary}"
    )


if __name__ == "__main__":
    """
    Main entry point for standalone XSS monitoring.
    """
    print("Starting Real-Time XSS Detection Engine...")
    print("Filtering for HTTP ports: 80, 8080, 8000, 12345")

    # Process only relevant TCP/HTTP traffic
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")