#!/bin/bash

echo -e "\033[36m[+] Setting up the environment...\033[0m"

# Update package lists
sudo apt update

# Install required system packages
echo -e "\033[33m[+] Installing system dependencies...\033[0m"
sudo apt install -y python3 python3-pip nmap

# Install required Python libraries
echo -e "\033[33m[+] Installing Python dependencies...\033[0m"
pip3 install --upgrade pip
pip3 install python-nmap pyfiglet
pip install colorama --break-system-packages

# Verify installations
echo -e "\033[32m[+] Verifying installations...\033[0m"
if ! command -v nmap &> /dev/null; then
    echo -e "\033[31m[-] Nmap installation failed!\033[0m"
    exit 1
fi

if ! python3 -c "import nmap, pyfiglet" &> /dev/null; then
    echo -e "\033[31m[-] Python dependencies installation failed!\033[0m"
    exit 1
fi

echo -e "\033[32m[✔] Setup complete! You can now run your scan script.\033[0m"
