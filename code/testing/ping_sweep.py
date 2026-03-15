from scapy.all import IP, ICMP, sr
from concurrent.futures import ThreadPoolExecutor
import sys

def icmp_ping(ip, active_hosts):
    """
    Sends an ICMP Echo Request and adds the IP to the list if a response is received.
    """
    try:
        packet = IP(dst=ip) / ICMP()
        # Fast timeout for local network scanning
        answered = sr(packet, timeout=1.5, verbose=0)[0]
        for _, res in answered:
            active_hosts.append(res.src)
    except:
        pass

def run_scanner(base_ip):
    """
    Orchestrates the multithreaded scan and prints a sorted list of active IPs.
    """
    active_hosts = []
    print(f"Scanning {base_ip}.0/24... Please wait.")

    with ThreadPoolExecutor(max_workers=100) as executor:
        ips = [f"{base_ip}.{i}" for i in range(1, 255)]
        executor.map(lambda ip: icmp_ping(ip, active_hosts), ips)

    if active_hosts:
        print("Active Hosts Found:")
        # Sort by the last octet (numeric sort)
        sorted_hosts = sorted(active_hosts, key=lambda ip: int(ip.split('.')[-1]))

        for host in sorted_hosts:
            print(host)

    else:
        print("No active hosts found.")

def main():
    """
    Main entry point for the scanner tool.
    """
    try:
        network = input("Enter network prefix (e.g., 192.168.1): ").strip() or "192.168.1"
        run_scanner(network)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()