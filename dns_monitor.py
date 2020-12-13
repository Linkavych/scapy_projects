#!/usr/bin/env python3
# A simple DNS monitoring program

from scapy.all import *
import signal, sys

# Allow for gracefule exit with C-c
def signal_handler(signal, frame):
    print("\n[+] Exiting program...")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# Function to find DNS packets and print them to screen
def find_dns(pkt):
    try:
        if pkt.haslayer(DNS):
            print(f"{pkt[IP].src}, {pkt[DNS].summary()}")
    except:
        pass

sniff(prn=find_dns)

