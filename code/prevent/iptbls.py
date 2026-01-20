import subprocess

blocked_ips = set()
def block(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    blocked_ips.add(ip)
    print(f"Blocked {ip}")

def unblock(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    blocked_ips.discard(ip)
    print(f"Unblocked {ip}")

def clear():
    for ip in blocked_ips:
        blocked_ips.discard(ip)
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