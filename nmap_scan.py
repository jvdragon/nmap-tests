import nmap
import sys

def scan_network(target, scan_type='-sS'):
    try:
        nm = nmap.PortScanner()
        print(f"Starting Nmap scan on {target} with scan type {scan_type}")
        nm.scan(target, arguments=scan_type)
        
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(f"Port: {port}\tState: {state}\tService: {service}")
    except nmap.PortScannerError as e:
        print(f"Error: Nmap scan failed - {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_scan.py <target> [scan_type]")
        print("Example: python nmap_scan.py 192.168.1.1 -sS")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else '-sS'
    scan_network(target, scan_type)