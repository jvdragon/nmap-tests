import nmap
import re

def is_valid_network(network):
    """Validate network range format (e.g., 192.168.1.0/24 or 192.168.1.1-100)."""
    # Basic check for CIDR or range format
    cidr_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-2]?[0-9]|3[0-2])$"
    range_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(cidr_pattern, network) or re.match(range_pattern, network)

def scan_active_hosts(network):
    """Perform Nmap ping scan to find active hosts."""
    try:
        nm = nmap.PortScanner()
        print(f"\nStarting Nmap ping scan on {network}")
        # Use -sn for ping scan (no port scan) to find active hosts
        nm.scan(hosts=network, arguments="-sn")
        
        if not nm.all_hosts():
            print("No active hosts found in the specified range.")
            return

        print("\nActive Hosts:")
        print("IP Address\tHostname\tState")
        print("-" * 40)
        for host in sorted(nm.all_hosts(), key=lambda x: tuple(map(int, x.split(".")))):
            hostname = nm[host].hostname() or "unknown"
            state = nm[host].state()
            print(f"{host}\t{hostname}\t{state}")

    except nmap.PortScannerError as e:
        print(f"Error: Nmap scan failed - {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def main():
    print("Nmap Active Host Scanner")
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