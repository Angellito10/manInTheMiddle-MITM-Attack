#!/usr/bin/env python
import scapy.all as scapy

def scan(ip):
    scapy.arping(ip) # to send arp ping that will discover the devices in the network
network = raw_input('Enter the IP of the network you want to scan with /24 /n: ')
scan(network)
