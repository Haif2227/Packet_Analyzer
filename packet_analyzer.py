#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import os
import signal
import sys
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse

# Global list to store captured packets
captured_packets = []

def get_next_pcap_filename():
    """Determine the next available filename in the 'capture' folder."""
    folder = "capture"
    os.makedirs(folder, exist_ok=True)  # Create the folder if it doesn't exist
    base_filename = os.path.join(folder, "capture")
    counter = 0

    while True:
        if counter == 0:
            filename = f"{base_filename}.pcap"
        else:
            filename = f"{base_filename}({counter}).pcap"
        if not os.path.exists(filename):
            return filename
        counter += 1

def analyze_packet(packet):
    """Analyze a single packet and extract details."""
    captured_packets.append(packet)  # Add packet to the global list
    print("\n" + "-" * 50)
    print(f"Packet Summary: {packet.summary()}")

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

    # Check if the packet has a TCP layer
    if packet.haslayer(TCP):
        print(f"TCP Source Port: {packet[TCP].sport}")
        print(f"TCP Destination Port: {packet[TCP].dport}")

    # Check if the packet has a UDP layer
    if packet.haslayer(UDP):
        print(f"UDP Source Port: {packet[UDP].sport}")
        print(f"UDP Destination Port: {packet[UDP].dport}")

    # Check if the packet has an HTTP layer (request or response)
    if packet.haslayer(HTTPRequest):
        print(f"HTTP Request Method: {packet[HTTPRequest].Method.decode()}")
        print(f"HTTP Host: {packet[HTTPRequest].Host.decode()}")
        print(f"HTTP Path: {packet[HTTPRequest].Path.decode()}")
    elif packet.haslayer(HTTPResponse):
        print(f"HTTP Response Status Code: {packet[HTTPResponse].Status_Code.decode()}")

    # Check for raw payload data
    if packet.haslayer(scapy.Raw):
        raw_data = packet[scapy.Raw].load
        print(f"Raw Payload: {raw_data[:50].decode('utf-8', errors='ignore')}...")

def save_pcap():
    """Save captured packets to a PCAP file."""
    if not captured_packets:
        print("[!] No packets captured. Nothing to save.")
        return

    filename = get_next_pcap_filename()
    scapy.wrpcap(filename, captured_packets)
    print(f"[+] Packets saved to {filename}")

def handle_exit(signal, frame):
    """Handle Ctrl+C and prompt to save packets."""
    print("\n[!] Live capture stopped.")
    choice = input("Do you want to save the captured packets? (y/n): ").strip().lower()
    if choice == 'y':
        save_pcap()
    else:
        print("[!] Packets not saved. Exiting...")
    sys.exit(0)

def read_pcap(file):
    """Read and analyze packets from a PCAP file."""
    print(f"[*] Reading packets from {file}...")
    try:
        packets = scapy.rdpcap(file)  # Read packets from PCAP file
        for packet in packets:
            analyze_packet(packet)
    except FileNotFoundError:
        print(f"[!] File {file} not found.")
    except Exception as e:
        print(f"[!] An error occurred while reading the PCAP file: {e}")

def live_capture(interface):
    """Capture and analyze packets in real-time."""
    print(f"[*] Starting live capture on interface: {interface}")
    try:
        scapy.sniff(iface=interface, store=False, prn=analyze_packet)
    except Exception as e:
        print(f"[!] An error occurred while sniffing packets: {e}")

def main():
    """Main function to handle arguments and run the analyzer."""
    signal.signal(signal.SIGINT, handle_exit)  # Capture Ctrl+C signal

    parser = argparse.ArgumentParser(description="Packet Analyzer Tool")
    parser.add_argument("-f", "--file", help="Specify a PCAP file to analyze")
    parser.add_argument("-i", "--interface", help="Specify a network interface for live capture")
    args = parser.parse_args()

    if args.file:
        read_pcap(args.file)
    elif args.interface:
        live_capture(args.interface)
    else:
        print("[!] Please specify a PCAP file (-f) or a network interface (-i) to analyze.")

if __name__ == "__main__":
    main()
