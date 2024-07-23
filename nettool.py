import argparse
import socket
import subprocess
import platform
import requests
import speedtest
import whois
import traceroute
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from collections import Counter
import time
import nmap
import scapy.all as scapy
import netifaces
import random

def ping(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', host]
    return subprocess.call(command)

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return port, result == 0

def port_scan(host, ports):
    print(f"Scanning ports for {host}...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, host, port) for port in ports]
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    
    if open_ports:
        print("Open ports:")
        for port in sorted(open_ports):
            print(f"  {port}")
    else:
        print("No open ports found.")

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"The IP address of {domain} is {ip}")
    except socket.gaierror:
        print(f"Could not resolve {domain}")

def get_public_ip():
    response = requests.get('https://api.ipify.org')
    return response.text

def speed_test():
    st = speedtest.Speedtest()
    print("Testing download speed...")
    download_speed = st.download() / 1_000_000  # Convert to Mbps
    print("Testing upload speed...")
    upload_speed = st.upload() / 1_000_000  # Convert to Mbps
    print(f"Download speed: {download_speed:.2f} Mbps")
    print(f"Upload speed: {upload_speed:.2f} Mbps")

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(f"Domain Name: {w.domain_name}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
    except Exception as e:
        print(f"Error performing WHOIS lookup: {str(e)}")

def trace_route(host):
    try:
        results = traceroute.traceroute(host)
        for i, hop in enumerate(results, start=1):
            if hop[0] is not None:
                print(f"{i}: {hop[0]} ({hop[1]:.2f}ms)")
            else:
                print(f"{i}: *")
    except Exception as e:
        print(f"Error performing traceroute: {str(e)}")

def analyze_logs(log_file, threshold=100):
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ip_counts = Counter()
    
    print(f"Analyzing log file: {log_file}")
    print(f"DDOS detection threshold: {threshold} requests per minute")
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(ip_pattern, line)
            if match:
                ip = match.group()
                timestamp = time.strptime(line.split()[3][1:], "%d/%b/%Y:%H:%M:%S")
                ip_counts[(ip, timestamp.tm_year, timestamp.tm_mon, timestamp.tm_mday, timestamp.tm_hour, timestamp.tm_min)] += 1

    suspicious_ips = []
    for (ip, year, month, day, hour, minute), count in ip_counts.items():
        if count > threshold:
            suspicious_ips.append((ip, count, f"{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}"))

    if suspicious_ips:
        print("Potential DDOS attacks detected:")
        for ip, count, timestamp in suspicious_ips:
            print(f"IP: {ip}, Requests: {count}, Time: {timestamp}")
    else:
        print("No potential DDOS attacks detected.")

def network_discovery(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices_list = []
    for element in answered_list:
        device_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device_dict)
    
    print("Discovered devices on the network:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices_list:
        print(f"{device['ip']}\t\t{device['mac']}")

def os_detection(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-O")
    
    if target in nm.all_hosts():
        if 'osmatch' in nm[target]:
            print(f"OS Detection results for {target}:")
            for osmatch in nm[target]['osmatch']:
                print(f"OS: {osmatch['name']}, Accuracy: {osmatch['accuracy']}%")
        else:
            print(f"Unable to determine OS for {target}")
    else:
        print(f"Host {target} not found")

def list_interfaces():
    interfaces = netifaces.interfaces()
    print("Network Interfaces:")
    for interface in interfaces:
        print(f"\nInterface: {interface}")
        try:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                print(f"  IP Address: {addresses[netifaces.AF_INET][0]['addr']}")
                print(f"  Netmask: {addresses[netifaces.AF_INET][0]['netmask']}")
            if netifaces.AF_LINK in addresses:
                print(f"  MAC Address: {addresses[netifaces.AF_LINK][0]['addr']}")
        except ValueError:
            print("  Unable to retrieve address information")

def packet_capture(interface, count=10):
    print(f"Capturing {count} packets on interface {interface}...")
    packets = scapy.sniff(iface=interface, count=count)
    print("\nPacket Summary:")
    for packet in packets:
        print(packet.summary())

def main():
    parser = argparse.ArgumentParser(description="Network Tool CLI")
    parser.add_argument('action', choices=['ping', 'portscan', 'dnslookup', 'publicip', 'speedtest', 'whois', 'traceroute', 'ddos_detect', 'network_discovery', 'os_detection', 'list_interfaces', 'packet_capture'], help='Action to perform')
    parser.add_argument('target', nargs='?', help='Target host, domain, IP, or log file')
    parser.add_argument('-p', '--ports', type=int, nargs='+', help='Port number(s) for port scan')
    parser.add_argument('-t', '--threshold', type=int, default=100, help='Threshold for DDOS detection (requests per minute)')
    parser.add_argument('-i', '--interface', help='Network interface for packet capture')
    parser.add_argument('-c', '--count', type=int, default=10, help='Number of packets to capture')

    args = parser.parse_args()

    if args.action == 'ping':
        if args.target:
            ping(args.target)
        else:
            print("Target is required for ping")
    elif args.action == 'portscan':
        if args.target:
            if args.ports:
                port_scan(args.target, args.ports)
            else:
                common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
                port_scan(args.target, common_ports)
        else:
            print("Target is required for port scan")
    elif args.action == 'dnslookup':
        if args.target:
            dns_lookup(args.target)
        else:
            print("Target is required for DNS lookup")
    elif args.action == 'publicip':
        print(f"Your public IP address is: {get_public_ip()}")
    elif args.action == 'speedtest':
        speed_test()
    elif args.action == 'whois':
        if args.target:
            whois_lookup(args.target)
        else:
            print("Target domain is required for WHOIS lookup")
    elif args.action == 'traceroute':
        if args.target:
            trace_route(args.target)
        else:
            print("Target is required for traceroute")
    elif args.action == 'ddos_detect':
        if args.target:
            analyze_logs(args.target, args.threshold)
        else:
            print("Log file path is required for DDOS detection")
    elif args.action == 'network_discovery':
        if args.target:
            network_discovery(args.target)
        else:
            print("Target network (e.g., 192.168.1.0/24) is required for network discovery")
    elif args.action == 'os_detection':
        if args.target:
            os_detection(args.target)
        else:
            print("Target host is required for OS detection")
    elif args.action == 'list_interfaces':
        list_interfaces()
    elif args.action == 'packet_capture':
        if args.interface:
            packet_capture(args.interface, args.count)
        else:
            print("Network interface is required for packet capture")

def ddos_sim(target, port, duration, rate):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = random._urandom(1024)
    timeout = time.time() + duration
    sent = 0

    while time.time() < timeout:
        try:
            client.sendto(bytes, (target, port))
            sent += 1
            if sent % rate == 0:
                time.sleep(1)  # Adjust timing to maintain rate
        except Exception as e:
            print(f"Error: {e}")

    print(f"Sent {sent} packets to {target}:{port}")

# Usage example
# ddos_sim("192.168.1.1", 80, 10, 1000)  # 10 seconds at 1000 packets/sec

if __name__ == "__main__":
    main()
