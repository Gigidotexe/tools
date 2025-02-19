from ipaddress import ip_address
import nmap
import os
import sys
import time
import threading
import itertools
import pyfiglet
import signal

os.system("clear")

print("\033[36m" + pyfiglet.figlet_format("Host Discover") + "\033[0m")

def loading_animation(stop_event):
    for frame in itertools.cycle(["|", "/", "-", "\\"]):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\033[36m\rScanning... {frame} \033[0m")
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.write("\r" + " " * 30 + "\r")

def exit_animation(signal_received, frame):
    sys.stdout.write("\033[31m\rInterrupt detected, exiting...   \033[0m")
    sys.stdout.flush()
    time.sleep(1)
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()
    sys.exit(0)

signal.signal(signal.SIGINT, exit_animation)

def load_previous_scan(file_name):
    previous_devices, previous_hosts = set(), []
    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            for line in file.readlines()[2:]:
                parts = line.split()
                if parts:
                    previous_devices.add(parts[0])
                    previous_hosts.append(tuple(parts))
    return previous_devices, previous_hosts

def scan_network(target):
    print(f"\033[33mStarting scan on {target}...\033[0m")

    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()

    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sn")

    stop_event.set()
    loader_thread.join()

    print(f"\n\033[32mScan complete!\033[0m\n")

    active_hosts = [
        (host, nm[host].hostname() or "N/A", nm[host]['addresses'].get('mac', "N/A"))
        for host in nm.all_hosts()
    ]
    active_hosts.sort(key=lambda x: ip_address(x[0]))

    scan_file = f"network_scan_{target.replace('/', '_')}.txt"
    previous_devices, previous_hosts = load_previous_scan(scan_file)
    current_devices = {host[0] for host in active_hosts}
    new_devices = current_devices - previous_devices

    if new_devices:
        print("\n\033[35mNew devices detected:\033[0m")
        for ip, hostname, mac in sorted(active_hosts, key=lambda x: ip_address(x[0])):
            if ip in new_devices:
                print(f"\033[32m[!] {ip} - {hostname} - {mac}\033[0m")
        
        nm.scan(hosts=target, arguments="-sn")
        active_hosts = [
            (host, nm[host].hostname() or "N/A", nm[host]['addresses'].get('mac', "N/A"))
            for host in nm.all_hosts()
        ]
        active_hosts.sort(key=lambda x: ip_address(x[0]))
    
    all_hosts = previous_hosts + [host for host in active_hosts if host[0] in new_devices]
    all_hosts.sort(key=lambda x: ip_address(x[0]))
    
    column_widths = [18, 25, 20]
    with open(scan_file, "w") as file:
        file.write(f"{'IP Address'.ljust(column_widths[0])}{'Hostname'.ljust(column_widths[1])}{'MAC Address'.ljust(column_widths[2])}\n")
        file.write("=" * sum(column_widths) + "\n")
        for ip, hostname, mac in all_hosts:
            file.write(f"{ip.ljust(column_widths[0])}{hostname.ljust(column_widths[1])}{mac.ljust(column_widths[2])}\n")
    
    print(f"\n\033[32mScan updated! Results saved in {scan_file}\033[0m")

network_target = input("\033[36mEnter network to scan (default: 192.168.1.0/24): \033[0m").strip() or "192.168.1.0/24"
scan_network(network_target)
