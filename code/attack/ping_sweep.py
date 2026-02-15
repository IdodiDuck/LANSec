from scapy.all import IP, ICMP, sr
from concurrent.futures import ThreadPoolExecutor

output = []

def icmp_ping(ip):
    try:
        packet = IP(dst=ip)/ICMP()
        answered = sr(packet, timeout=2, verbose=0)[0]
        for req, res in answered:
            output.append(res.src)
            print(f"Host {res.src} is active")
    except Exception as e:
        print(f"Error pinging {ip}: {e}")


print("Starting ICMP ping sweep")
print("Assuming subnet mask /24")
baseip = input("Enter base IP (x.x.x): ") or "192.168.1"
with ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(lambda ip: icmp_ping(f"{baseip}.{ip}"), (i for i in range(1, 256)))


# you can clear above for pretty output
print("Ping sweep complete. Active hosts:")
for i in output:
    print(i)