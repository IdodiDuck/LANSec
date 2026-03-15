from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr, send
import sys

def check(ip, port, print_closed: bool):
    """
    Probes a specific TCP port to see if it is open, closed, or filtered.

    :param ip: The target IP address to scan.
    :param port: The port number (int).
    :param print_closed: Boolean to toggle visibility of non-open ports.
    :return: None
    """
    try:
        # Construct and send a SYN packet (Stealth Scan)
        ans, unans = sr(IP(dst=ip) / TCP(dport=port, flags='S'), timeout=1, verbose=False)
        
        for snd, rcv in ans:
            # If we get SYN-ACK (0x12), the port is open
            if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12:
                print(f"OPEN | Port: {port}")
                
                # Send RST to close the connection properly
                rst_pkt = IP(dst=ip) / TCP(dport=port, flags='R', seq=rcv.getlayer(TCP).ack)
                send(rst_pkt, verbose=False)
                
            elif print_closed:
                print(f"CLOSED | Port: {port}")
                
        # If no response was received, the port is likely filtered
        for snd in unans:
            if print_closed:
                print(f"GHOST  | Port: {port}")
                
    except Exception:
        pass

def run_range_scan(ip, start_p, end_p, print_closed):
    """
    Orchestrates a multithreaded scan over a sequential range of ports.

    :param ip: Target IP address.
    :param start_p: The starting port of the range.
    :param end_p: The ending port of the range.
    :param print_closed: Boolean to show non-open ports.
    :return: None
    """
    print(f"[*] Starting Range Scan on {ip} (Ports {start_p}-{end_p})...")
    
    
    ports = range(start_p, end_p + 1)
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda p: check(ip, p, print_closed), ports)

def main():
    """
    Main entry point for the Port Scanning Testing.
    """
    print("IDPS Test Suite: TCP SYN Port Scanning:")
    
    target_ip = input("Target IP [192.168.1.1]: ").strip() or "192.168.1.1"
    
    try:
        start_p = int(input("Start Port [1]: ") or 1)
        end_p = int(input("End Port [1024]: ") or 1024)
        show_all = input("Show closed ports? (y/n): ").lower() == 'y'
        
        run_range_scan(target_ip, start_p, end_p, show_all)
        print("\nTCP SYN Port Scanning completed.")
        
    except ValueError:
        print("[X] Error: Please enter valid numbers for ports.")
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        sys.exit(0)

if __name__ == '__main__':
    main()