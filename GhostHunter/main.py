from ipaddress import ip_address
from colorama import Fore, Style
import nmap
import os
import sys
import time
import threading
import itertools
import pyfiglet

scan_dir = "scans"
os.makedirs(scan_dir, exist_ok=True)

os.system("clear")

banner = pyfiglet.figlet_format("GHost Hunter", font="slant")
print(banner.rstrip())
with open("ascii/haunter.txt", "r") as file:
    print(Fore.MAGENTA + file.read() + Style.RESET_ALL)

def loading_animation(stop_event):
    for frame in itertools.cycle(["|", "/", "-", "\\"]):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\033[36m\rScanning in progress... {frame} \033[0m")
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.write("\r" + " " * 30 + "\r")

def load_previous_scan(file_name):
    previous_devices = set()
    previous_hosts = []
    
    file_path = os.path.join(scan_dir, file_name)
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            for line in file.readlines()[2:]:
                parts = line.split()
                if len(parts) > 0:
                    previous_devices.add(parts[0])
                    previous_hosts.append(tuple(parts))
    return previous_devices, previous_hosts

def scan_network(target):
    print(f"\033[33mStarting scan on {target}...\033[0m")

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()

    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sn --script=targets-asn,targets-ip,targets-mac,targets-traceroute")

    stop_event.set()
    loader_thread.join()

    print(f"\n\033[32mScan completed!\033[0m\n")

    active_hosts = []
    for host in nm.all_hosts():
        full_hostname = nm[host].hostname() or "N/A"
        mac_address = nm[host]['addresses'].get('mac', "N/A")

        if "." in full_hostname:
            hostname, router = full_hostname.split(".", 1)
        else:
            hostname, router = full_hostname, "N/A"
        
        active_hosts.append((host, hostname, router, mac_address))

    active_hosts.sort(key=lambda x: ip_address(x[0]))

    scan_file = f"network_scan_{target.replace('/', '_')}.txt"
    
    previous_devices, previous_hosts = load_previous_scan(scan_file)
    current_devices = {host[0] for host in active_hosts}
    new_devices = current_devices - previous_devices

    if new_devices:
        print("\n\033[35mNew devices detected:\033[0m")
        for ip, hostname, router, mac in sorted(active_hosts, key=lambda x: ip_address(x[0])):
            if ip in new_devices:
                print(f"\033[32m[!] {ip} - {hostname} ({router}) - {mac}\033[0m")
        
        nm.scan(hosts=target, arguments="-sn")
        active_hosts = []
        for host in nm.all_hosts():
            full_hostname = nm[host].hostname() or "N/A"
            mac_address = nm[host]['addresses'].get('mac', "N/A")
            if "." in full_hostname:
                hostname, router = full_hostname.split(".", 1)
            else:
                hostname, router = full_hostname, "N/A"
            active_hosts.append((host, hostname, router, mac_address))
        active_hosts.sort(key=lambda x: ip_address(x[0]))
    
    all_hosts = previous_hosts + [host for host in active_hosts if host[0] in new_devices]
    all_hosts.sort(key=lambda x: ip_address(x[0]))
    
    column_widths = [18, 25, 15, 20]  
    scan_file_path = os.path.join(scan_dir, scan_file)
    
    with open(scan_file_path, "w") as file:
        header = f"{'IP Address'.ljust(column_widths[0])}{'Hostname'.ljust(column_widths[1])}{'Router'.ljust(column_widths[2])}{'MAC Address'.ljust(column_widths[3])}\n"
        file.write(header)
        file.write("=" * sum(column_widths) + "\n")

        for ip, hostname, router, mac in all_hosts:
            row = f"{ip.ljust(column_widths[0])}{hostname.ljust(column_widths[1])}{router.ljust(column_widths[2])}{mac.ljust(column_widths[3])}\n"
            file.write(row)
    
    print(f"\n\033[32mScan updated! Results saved in {scan_file_path}\033[0m")

network_target = input("\033[36mEnter the network to scan (default: 192.168.1.0/24): \033[0m").strip()
if not network_target:
    network_target = "192.168.1.0/24"

scan_network(network_target)
