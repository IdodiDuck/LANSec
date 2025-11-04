from scapy.all import *
from os import system
system('clear')

from attacks import attacks
import general
general.verbose = True


print(f"LanSec - Local Area Network Security\n{'-'*36}\n")


def snf(pkt):
    for attack in attacks:
        attack.inspect(pkt)

    
sniff(prn=snf, store=0)