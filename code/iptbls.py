# Module name is negotiable: iptbls (iptables)
# iptbls.block("<IP_ADDRESS>")
import subprocess
import os
from utils.logger import get_logger

logger = get_logger()
CHAIN = "LanSec"
blocked_ips = set()

def _require_root():
    if os.geteuid() != 0:
        raise PermissionError("iptables requires root privileges")

def _run(cmd):
    subprocess.run(cmd, check=True)

def init():
    _require_root()

    # Initialize a dedicated iptables chain for dynamic IP blocking
    _run(["iptables", "-N", CHAIN])
    _run(["iptables", "-C", "INPUT", "-j", CHAIN])
    _run(["iptables", "-A", "INPUT", "-j", CHAIN])

def block(ip):
    if ip in blocked_ips:
        return

    _require_root()

    try:
        _run(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
        blocked_ips.add(ip)
        logger.info(f"Blocked IP: {ip}")

    except subprocess.CalledProcessError:
        logger.error(f"Failed to block IP: {ip}")

def unblock(ip):
    if ip not in blocked_ips:
        return

    try:
        _run(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
        blocked_ips.remove(ip)
        logger.info(f"Unblocked IP: {ip}")

    except subprocess.CalledProcessError:
        logger.error(f"Failed to unblock IP: {ip}")

def clear():
    try:
        _run(["iptables", "-F", CHAIN])
        blocked_ips.clear()
        logger.info("Cleared all LanSec blacklisted IPs")

    except subprocess.CalledProcessError:
        logger.error("Failed to clear LanSec iptables chain")

def status():
    return list(blocked_ips)

if __name__ == "__main__":
    try:
        while True:
            eval(input(">>> "))

    except KeyboardInterrupt:
        clear()
        print("Exiting")