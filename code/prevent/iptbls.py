import subprocess

blocked_ips = set()

def block(ip):
    if ip in blocked_ips:
        return
    
    for chain in ["INPUT", "FORWARD"]:
        subprocess.run(["sudo", "iptables", "-I", chain, "-s", ip, "-j", "DROP"])

    blocked_ips.add(ip)

def _unblock(ip):
    if ip not in blocked_ips:
        return
    
    for chain in ["INPUT", "FORWARD"]:
        subprocess.run(["sudo", "iptables", "-D", chain, "-s", ip, "-j", "DROP"])

def unblock(ip):
    _unblock(ip)
    blocked_ips.discard(ip)

def clear():
    for ip in blocked_ips:
        _unblock(ip)
    blocked_ips.clear()

    print("All blocks cleared")

def status():
    for ip in blocked_ips:
        print(ip)

if __name__ == "__main__":
    try:
        while True:
            eval(input(">>> "))
    except KeyboardInterrupt:
        clear()
        print("Exiting")