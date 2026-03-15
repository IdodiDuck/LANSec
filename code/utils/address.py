class Addr:
    """
    A utility class representing a network node's identity (IP and MAC addresses).
    """
    def __init__(self, ip: str, mac: str):
        """
        Initializes a network address object.
        :param ip: The IPv4 address string (e.g., "192.168.1.1").
        :param mac: The MAC address string (e.g., "AA:BB:CC:DD:EE:FF").
        """
        self.ip = ip
        self.mac = mac

    def __repr__(self):
        """ Returns a string representation, prioritizing IP over MAC. """
        return self.ip if self.ip else self.mac

    def to_hex(self) -> str:
        """
        Serializes the IP and MAC addresses into a single concatenated Hexadecimal string.
        This is useful for generating unique identifiers or database keys.
        :return: A 20-character Uppercase Hex string.
        """
        try:
            # Convert IP octets to 2-digit hex values
            ip_hex = ''.join(f"{int(octet):02x}" for octet in self.ip.split('.')).upper()
            
            # Remove separators from MAC and normalize to uppercase
            mac_hex = self.mac.replace(':', '').replace('-', '').upper()
            
            return f"{ip_hex}{mac_hex}"
        
        except Exception:
            # Fallback for invalid formats
            return "00000000000000000000"

    @staticmethod
    def from_hex(hex_str: str):
        """
        Deserializes a 20-character hex string back into an Addr object.
        :param hex_str: The hexadecimal representation of the addresses.
        :return: A new Addr instance.
        """
        try:
            ip_hex = hex_str[:8]    # First 8 chars represent the 4 IP octets
            mac_hex = hex_str[8:]   # Remaining 12 chars represent the MAC address
            
            # Reconstruct IPv4 format (x.x.x.x)
            ip = '.'.join(str(int(ip_hex[i:i+2], 16)) for i in range(0, 8, 2))
            
            # Reconstruct MAC format (XX:XX:XX:XX:XX:XX)
            mac = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2)).upper()
            
            return Addr(ip, mac)
        except Exception:
            # Return a default null address on failure
            return Addr("0.0.0.0", "00:00:00:00:00:00")

    def __eq__(self, other):
        """
        Defines equality logic for Addr objects.
        Ensures two objects are considered equal if their IP and MAC match.
        """
        if not isinstance(other, Addr):
            return False
        
        return (self.ip == other.ip) and (self.mac.upper() == other.mac.upper())

    def __hash__(self):
        """
        Generates a hash value for the object.
        Allows Addr instances to be used in Sets (e.g., for the Blacklist)
        or as keys in Dictionaries.
        """
        return hash((self.ip, self.mac.upper()))