from scapy.all import *

print("Directory Traversal Detection Module Loaded")


def is_valid(msg: string) -> bool:
    # TD: use regex to check extensively
    return not ".." in msg


def inspect(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport in [80, 8080, 8000, 12345]:
        payload = bytes(pkt[Raw].load).split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
        if is_valid(payload): return None
        return f'src_ip: {pkt[IP].src}, dst_ip: {pkt[IP].dst}, src_port: {pkt[TCP].sport}, dst_port: {pkt[TCP].dport}\npayload: {payload}'

        
if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system
    system('clear')
    print("Starting Directory Traversal Detection...\n\n")
    
    # filter for HTTP traffic (port 80, 8080, 8000) + 12345 for debugging
    sniff(prn=inspect, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")