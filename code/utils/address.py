class Addr:
    def __init__(self, ip: str, mac: str):
        self.ip = ip
        self.mac = mac

    def __repr__(self):
        return self.ip if self.ip else self.mac

    def to_hex(self) -> str:
        try:
            ip_hex = ''.join(f"{int(octet):02x}" for octet in self.ip.split('.')).upper()
            mac_hex = self.mac.replace(':', '').replace('-', '').upper()
            
            return f"{ip_hex}{mac_hex}"
        
        except Exception:
            return "00000000000000000000"

    @staticmethod
    def from_hex(hex_str: str):
        try:
            ip_hex = hex_str[:8]
            mac_hex = hex_str[8:]
            
            # Restoring IP
            ip = '.'.join(str(int(ip_hex[i:i+2], 16)) for i in range(0, 8, 2))
            
            # Restoring MAC
            mac = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2)).upper()
            
            return Addr(ip, mac)
        except Exception:
            return Addr("0.0.0.0", "00:00:00:00:00:00")

    def __eq__(self, other):
        if not isinstance(other, Addr):
            return False
        
        return (self.ip == other.ip) and (self.mac.upper() == other.mac.upper())

    def __hash__(self):
        return hash((self.ip, self.mac.upper()))