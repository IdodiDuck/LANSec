from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor
import sys

def arp_ping(ip, active_hosts):
    """
    Sends an ARP request to a specific IP address and stores the result if the host is active.

    :param ip: The target IP address to probe.
    :param active_hosts: A shared list to store tuples of (IP, MAC) for active hosts.
    :return: None
    """
    try:
        # Create a Layer 2 broadcast frame with an ARP request
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, op=1)
        
        # Send the packet and wait for a response
        answered = srp(packet, timeout=1.5, verbose=0)[0]
        
        for _, res in answered:
            # res.psrc is the responding IP, res.hwsrc is the MAC address
            active_hosts.append((res.psrc, res.hwsrc))
    except:
        # Silent fail to ensure threads continue execution
        pass

def run_scanner(base_ip):
    """
    Orchestrates a multithreaded ARP sweep across a /24 subnet and prints sorted results.

    :param base_ip: The first three octets of the network (e.g., '192.168.1').
    :return: None
    """
    active_hosts = []
    print(f"Scanning {base_ip}.0/24... Please wait.")

    with ThreadPoolExecutor(max_workers=100) as executor:
        ips = [f"{base_ip}.{i}" for i in range(1, 255)]
        
        # Dispatch threads to probe each IP
        executor.map(lambda ip: arp_ping(ip, active_hosts), ips)

    if active_hosts:
        print("Active Hosts Found:")
        # Sort hosts numerically by the last octet of the IP address
        sorted_hosts = sorted(active_hosts, key=lambda x: int(x[0].split('.')[-1]))
        
        for ip, mac in sorted_hosts:
            print(ip, "is at", mac)
    else:
        print("No active hosts found.")
    

def main():
    """
    Entry point for the ARP Sweep Tester. Handles user input and execution.
    """
    try:
        network = input("Enter base IP (e.g., 192.168.1): ").strip() or "192.168.1"
        
        # Basic validation for the prefix format
        if network.count('.') != 2:
            print("[X] Error: Invalid format. Please use 'x.x.x'.")
            return

        run_scanner(network)
        
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()