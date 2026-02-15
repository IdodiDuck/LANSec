from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor

def arp_ping(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, op=1)
    answered = srp(packet, timeout=2, verbose=0)[0]
    for req, res in answered:
        print(f"{res.hwsrc}  ->  {res.psrc}")

print("Starting ARP sweep")
print("Assuming subnet mask /24")
baseip = input("Enter base IP (x.x.x): ") or "192.168.1"
with ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(lambda ip: arp_ping(f"{baseip}.{ip}"), (i for i in range(1, 256)))