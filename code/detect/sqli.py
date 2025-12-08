# from utils.http_normalizer import HTTPNormalizer
from scapy.all import *
import re


def is_valid(payload) -> bool:
    # Simple SQLi patterns
    sqli_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL operators
        r"\b(OR|AND)\b.+\=",  # Logical operators
        r"UNION(\s+ALL)?\s+SELECT",  # UNION SELECT
        r"SELECT\s+.*\s+FROM\s+",  # Basic SELECT statement
        r"INSERT\s+INTO\s+",  # Basic INSERT statement
        r"UPDATE\s+.*\s+SET\s+",  # Basic UPDATE statement
        r"DELETE\s+FROM\s+",  # Basic DELETE statement
        r"DROP\s+TABLE\s+",  # Basic DROP TABLE statement
    ]

    for pattern in sqli_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return False
    return True


def inspect(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore')
        if is_valid(payload) == False:
            return (
                f"{pkt[IP].src}:{pkt[TCP].sport} → {pkt[IP].dst}:{pkt[TCP].dport}\n"
                f"payload: {payload.split('\r\n\r\n')[-1]}"
            )


if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system

    system('clear')
    print("SQL Injection Detection")
    
    # filter for HTTP traffic (port 80, 8080, 8000) + 12345 for debugging
    sniff(prn=inspect, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")