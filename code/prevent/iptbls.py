import subprocess

# In-memory set to track currently blocked IP addresses
blocked_ips = set()

def block(ip):
    """
    Blocks a specific IP address by inserting a DROP rule into iptables.
    The rule is applied to both INPUT (traffic to the host) and 
    FORWARD (traffic passing through the host).
    
    :param ip: The IPv4 address to be blocked.
    """
    if ip in blocked_ips:
        return # Already blocked, no need to add redundant rules
    
    # -I (Insert) adds the rule at the top of the chain (position 1)
    # to ensure it takes precedence over existing allow rules
    for chain in ["INPUT", "FORWARD"]:
        subprocess.run(["sudo", "iptables", "-I", chain, "-s", ip, "-j", "DROP"])

    blocked_ips.add(ip)

def _unblock(ip):
    """
    Internal helper to remove the iptables DROP rule for a specific IP.
    Does not modify the 'blocked_ips' set.
    """
    if ip not in blocked_ips:
        return
    
    # -D (Delete) removes the specific rule matching the signature.
    for chain in ["INPUT", "FORWARD"]:
        subprocess.run(["sudo", "iptables", "-D", chain, "-s", ip, "-j", "DROP"])

def unblock(ip):
    """
    Public method to unblock an IP and update the tracking set.
    Typically called from the Web UI 'Unblock' button.
    """
    _unblock(ip)
    blocked_ips.discard(ip)

def clear():
    """
    Cleanup method to remove all active blocks created by the system.
    Ensures the firewall is left in a clean state upon system shutdown.
    """
    for ip in blocked_ips:
        _unblock(ip)

    blocked_ips.clear()

    print("All dynamic blocks have been cleared.")

def status():
    """ Prints the list of currently blocked IP addresses to the terminal. """
    if not blocked_ips:
        print("No active blocks.")

    for ip in blocked_ips:
        print(ip)

if __name__ == "__main__":
    """
    Manual management mode. Allows administrators to block/unblock 
    IPs directly via a CLI during testing or maintenance.
    """
    try:
        print("LanSec Firewall Management CLI (Ctrl+C to exit)")
        while True:
            # Dangerous in production, but useful for development debugging
            eval(input(">>> "))
            
    except KeyboardInterrupt:
        clear()
        print("\nExiting and clearing firewall rules.")