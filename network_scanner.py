#!/usr/bin/env python
import scapy.all as scapy
import argparse

# TAKES INPUT FROM USER
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="Give the private IPv4 address range to scan")
    options = parser.parse_args()
    if not options.ip:
        parser.error("Kindly give the appropriate private IPv4 address")
    return options

# SCANS NETWORK FOR AVAILABLE DEVICES ON NETWORK
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast/arp_request
    response = scapy.srp(combined_packet, timeout=1, verbose=False)[0]

    client_list = []
    for elements in response:
        client_dict = {"ip" : elements[1].psrc, "mac" : elements[1].hwsrc}
        client_list.append(client_dict)
    return client_list

# DISPLAYS FOUND DEVICES ON NETWORK
def display_result(results_list):
    print("IP\t\t\tMAC Address")
    print("-"*41)
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()

scan_result = scan(options.ip)
display_result(scan_result)