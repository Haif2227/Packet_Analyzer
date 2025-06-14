#!/bin/bash

echo "[*] Updating system..."
sudo apt update && sudo apt install -y python3 python3-pip

echo "[*] Installing Python requirements..."
pip3 install -r requirements.txt

echo "[+] Installation complete. Run your tool with: sudo python3 sniffer.py"
