from scapy.all import Ether, IP, sniff

print("Randomized MAC Detection Module Loaded")


def is_randomized(mac_addr: str) -> bool:
    first_byte = int(mac_addr.split(":")[0], 16)
    return (first_byte & 2) == 2  # Check the second least significant bit

# has layer Ether
def inspect(pkt):
    if pkt.haslayer(Ether):
        src_mac = pkt[Ether].src
        if is_randomized(src_mac):
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                return f"{src_mac} from IP: {src_ip}"
            
            else:
                return f"{src_mac} from IP: Unknown"


if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system
    system('clear')
    print("Starting Randomized Mac Detection...")

    sniff(prn=inspect, store=0)