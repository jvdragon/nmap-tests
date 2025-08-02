import nmap
import re

def is_valid_ip(ip):
    """Validate IP address format."""
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, ip) is not None

def scan_ports(target):
    try:
        nm = nmap.PortScanner()
        print(f"\nStarting Nmap port scan on {target} with service version detection")
        # Perform TCP SYN scan (-sS) with service version detection (-sV) on ports 1-1000
        nm.scan(target, arguments="-sS --open -sV -p 1-1000")
        
        if not nm.all_hosts():
            print(f"No hosts found or {target} is not responding.")
            return

        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname() or 'unknown'})")
            print(f"State: {nm[host].state()}")
            
            open_ports_found = False
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                if ports:
                    print(f"\nProtocol: {proto.upper()}")
                    print("Port\tState\tService\t\tBanner")
                    print("-" * 60)
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name'] or 'unknown'
                        banner = nm[host][proto][port].get('product', '') + ' ' + nm[host][proto][port].get('version', '')
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

def main():
    print("Nmap Port Scanner with Banner Grabbing")
    while True:
        target = input("Enter the IP address to scan (or 'q' to quit): ").strip()
        if target.lower() == 'q':
            print("Exiting...")
            break
        if not is_valid_ip(target):
            print("Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.1).")
            continue
        scan_ports(target)

if __name__ == "__main__":
    main()