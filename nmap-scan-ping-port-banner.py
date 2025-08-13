import nmap
import re
import traceback

def is_valid_network(network):
    """Validate network range format (e.g., 192.168.1.0/24 or 192.168.1.1-100)."""
    cidr_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-2]?[0-9]|3[0-2])$"
    range_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(cidr_pattern, network) or re.match(range_pattern, network)

def scan_active_hosts(network):
    """Perform Nmap ping scan to find active hosts and scan for open ports with banners."""
    try:
        nm = nmap.PortScanner()
        print(f"\nStarting Nmap ping scan on {network}")
        nm.scan(hosts=network, arguments="-sn")
        
        active_hosts = sorted(nm.all_hosts(), key=lambda x: tuple(map(int, x.split("."))))
        if not active_hosts:
            print("No active hosts found in the specified range.")
            return

        print("\nActive Hosts Found:")
        print("IP Address\tHostname\tState")
        print("-" * 40)
        
        for host in active_hosts:
            hostname = nm[host].hostname() if host in nm.all_hosts() else "unknown"
            state = nm[host].state()
            print(f"{host}\t{hostname}\t{state}")

            # Now scan ports with banner info
            print(f"\n🔎 Scanning open ports on {host} (1–1000)...")
            nm_host = nmap.PortScanner()
            nm_host.scan(hosts=host, arguments="-sS --open -sV -p 1-1000")

            if host not in nm_host.all_hosts():
                print(f"⚠️  No scan data returned for {host}")
                continue

            open_ports = []
            for proto in nm_host[host].all_protocols():
                lport = nm_host[host][proto].keys()
                for port in sorted(lport):
                    port_data = nm_host[host][proto][port]
                    if port_data.get("state") == "open":
                        service = port_data.get('name', 'unknown')
                        product = port_data.get('product', '')
                        version = port_data.get('version', '')
                        banner = f"{product} {version}".strip() or "N/A"
                        open_ports.append((proto.upper(), port, service, banner))

            if open_ports:
                print("\nOpen Ports:")
                print("Proto\tPort\tService\t\tBanner")
                print("-" * 60)
                for proto, port, service, banner in open_ports:
                    print(f"{proto}\t{port}\t{service:<15}\t{banner}")
            else:
                print("❌ No open ports found in the range 1–1000.")

    except nmap.PortScannerError as e:
        print(f"❌ Nmap scan failed - {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        traceback.print_exc()

def main():
    print("🛡️ Nmap Active Host Scanner with Port and Banner Detection")
    while True:
        network = input("Enter network range to scan (CIDR or IP range, or 'q' to quit): ").strip()
        if network.lower() == "q":
            print("Goodbye!")
            break
        if not is_valid_network(network):
            print("❌ Invalid format. Use CIDR (e.g., 192.168.1.0/24) or range (e.g., 192.168.1.1-100).")
            continue
        scan_active_hosts(network)

if __name__ == "__main__":
    main()
