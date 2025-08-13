import nmap
import re
import traceback

def is_valid_network(network):
    """Validate network range format (e.g., 192.168.1.0/24 or 192.168.1.1-100)."""
    cidr_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-2]?[0-9]|3[0-2])$"
    range_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(cidr_pattern, network) or re.match(range_pattern, network)

def scan_active_hosts(network):
    """Perform Nmap ping scan to find active hosts and scan for open ports with banners."""
    try:
        nm = nmap.PortScanner()
        print(f"\nStarting Nmap ping scan on {network}")
        nm.scan(hosts=network, arguments="-sn")
        
        if not nm.all_hosts():
            print("No active hosts found in the specified range.")
            return

        print("\nActive Hosts:")
        print("IP Address\tHostname\tState")
        print("-" * 40)
        active_hosts = sorted(nm.all_hosts(), key=lambda x: tuple(map(int, x.split("."))))
        
        for host in active_hosts:
            hostname = nm[host].hostname() if host in nm.all_hosts() else "unknown"
            state = nm[host].state()
            print(f"{host}\t{hostname}\t{state}")

            print(f"\nScanning ports for {host}...")
            nm_host = nmap.PortScanner()
            nm_host.scan(hosts=host, arguments="-sS --open -sV -p 1-1000")

            if host not in nm_host.all_hosts():
                print(f"Scan failed or no data returned for {host}")
                continue

            open_ports_found = False
            for proto in nm_host[host].all_protocols():
                ports = nm_host[host][proto].keys()
                if ports:
                    print(f"\nProtocol: {proto.upper()}")
                    print("Port\tState\tService\t\tBanner")
                    print("-" * 60)
                    for port in sorted(ports):
                        port_data = nm_host[host][proto][port]
                        state = port_data['state']
                        service = port_data.get('name', 'unknown')
                        banner = port_data.get('product', '') + ' ' + port_data.get('version', '')
                        banner = banner.strip() or 'N/A'
                        if state == 'open':
                            open_ports_found = True
                            print(f"{port}\t{state}\t{service:<15}\t{banner}")

            if not open_ports_found:
                print("No open ports found in the scanned range (1-1000).")

    except nmap.PortScannerError as e:
        print(f"Error: Nmap scan failed - {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()

def main():
    print("Nmap Active Host Scanner with Banner Grabbing")
    while True:
        network = input("Enter the network range to scan (e.g., 192.168.1.0/24 or 192.168.1.1-100, or 'q' to quit): ").strip()
        if network.lower() == "q":
            print("Exiting...")
            break
        if not is_valid_network(network):
            print("Invalid network range format. Use CIDR (e.g., 192.168.1.0/24) or range (e.g., 192.168.1.1-100).")
            continue
        scan_active_hosts(network)

if __name__ == "__main__":
    main()
