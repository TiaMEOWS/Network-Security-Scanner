import os
import socket
import threading
import time
import ipaddress
import nmap
from datetime import datetime

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Scan active hosts in the network
def scan_active_hosts(network):
    print(f"{Colors.OKBLUE}[INFO] Starting network scan: {network}{Colors.ENDC}")
    active_hosts = []
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sn')
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(f"{Colors.OKGREEN}[+] Active host found: {host}{Colors.ENDC}")
                active_hosts.append(host)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
    return active_hosts

# Scan open ports on a specific IP address
def scan_open_ports(ip, ports):
    open_ports = []
    print(f"{Colors.OKBLUE}[INFO] Starting port scan: {ip}{Colors.ENDC}")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"{Colors.OKGREEN}[+] Open port found: {port}{Colors.ENDC}")
            open_ports.append(port)
        sock.close()
    return open_ports

# Identify services running on open ports
def identify_services(ip, ports):
    services = {}
    print(f"{Colors.OKBLUE}[INFO] Starting service identification: {ip}{Colors.ENDC}")
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments=f"-p {','.join(map(str, ports))} -sV")
        for port in ports:
            if port in nm[ip]['tcp']:
                service_info = nm[ip]['tcp'][port]
                service_name = service_info.get('name', 'Unknown')
                service_version = service_info.get('version', 'Unknown')
                services[port] = f"{service_name} ({service_version})"
                print(f"{Colors.OKCYAN}[+] Port {port}: {service_name} ({service_version}){Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
    return services

# Check for vulnerabilities
def check_vulnerabilities(ip, ports):
    vulnerabilities = []
    print(f"{Colors.WARNING}[INFO] Starting vulnerability scan: {ip}{Colors.ENDC}")
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments=f"-p {','.join(map(str, ports))} --script vuln")
        for port in ports:
            if 'script' in nm[ip]['tcp'][port]:
                for script, output in nm[ip]['tcp'][port]['script'].items():
                    vulnerabilities.append((port, script, output))
                    print(f"{Colors.FAIL}[!] Vulnerability found: Port {port}, Script: {script}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
    return vulnerabilities

# Generate a report
def generate_report(active_hosts, host_data):
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write("=== Cybersecurity Report ===\n\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for host in active_hosts:
            f.write(f"Active Host: {host}\n")
            f.write("----------------------------\n")
            data = host_data.get(host, {})
            open_ports = data.get('open_ports', [])
            services = data.get('services', {})
            vulnerabilities = data.get('vulnerabilities', [])
            
            f.write("Open Ports:\n")
            for port in open_ports:
                f.write(f"  - {port}\n")
            
            f.write("\nServices:\n")
            for port, service in services.items():
                f.write(f"  - Port {port}: {service}\n")
            
            f.write("\nVulnerabilities:\n")
            for port, script, output in vulnerabilities:
                f.write(f"  - Port {port}, Script: {script}\n")
                f.write(f"    Description: {output}\n")
            
            f.write("\n\n")
    print(f"{Colors.OKGREEN}[+] Report generated: {report_file}{Colors.ENDC}")

# Main function
def main():
    print(f"{Colors.HEADER}=== Cybersecurity Scanning Tool ==={Colors.ENDC}")
    network = input(f"{Colors.OKBLUE}[?] Enter the network range to scan (e.g., 192.168.1.0/24): {Colors.ENDC}")
    
    # Validate the network range
    try:
        ipaddress.ip_network(network)
    except ValueError:
        print(f"{Colors.FAIL}[!] Invalid network range.{Colors.ENDC}")
        return
    
    # Scan active hosts
    active_hosts = scan_active_hosts(network)
    if not active_hosts:
        print(f"{Colors.WARNING}[!] No active hosts found in the network.{Colors.ENDC}")
        return
    
    # Perform detailed scans for each host
    host_data = {}
    common_ports = range(1, 1025)  # First 1024 ports
    threads = []
    
    for host in active_hosts:
        thread = threading.Thread(target=lambda h=host: process_host(h, common_ports, host_data))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Generate the report
    generate_report(active_hosts, host_data)

# Process a single host
def process_host(host, ports, host_data):
    print(f"\n{Colors.BOLD}=== Starting scan for {host} ==={Colors.ENDC}")
    open_ports = scan_open_ports(host, ports)
    services = identify_services(host, open_ports)
    vulnerabilities = check_vulnerabilities(host, open_ports)
    host_data[host] = {
        'open_ports': open_ports,
        'services': services,
        'vulnerabilities': vulnerabilities
    }

if __name__ == "__main__":
    main()