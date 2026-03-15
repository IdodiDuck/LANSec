from scapy.all import Ether, IP, sniff

print("Randomized MAC Detection Module Loaded")

def is_randomized(mac_addr: str) -> bool:
    """
    Determines if a MAC address is randomized or locally administered.
    """
    try:
        # Convert the first octet from hex to integer
        first_byte = int(mac_addr.split(":")[0], 16)
        # Check the 'U/L' (Universal/Local) bit (Binary: 00000010)
        return (first_byte & 2) == 2
    except (ValueError, IndexError):
        return False

def inspect(pkt):
    """
    Analyzes Ethernet frames to check for randomized source MAC addresses.
    """
    if pkt.haslayer(Ether):
        src_mac = pkt[Ether].src
        
        # If the MAC is flagged as randomized/spoofable
        if is_randomized(src_mac):
            # Try to associate it with an IP for better context
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                return f"Randomized MAC Detected: {src_mac} (Associated IP: {src_ip})"
            
            else:
                return f"Randomized MAC Detected: {src_mac} (Layer 3: Unknown)"
    
    return None

if __name__ == "__main__":
    """
    Standalone testing for MAC Address analysis.
    """

    print("Starting Randomized MAC Detection Engine...")
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, store=0)