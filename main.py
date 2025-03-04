import nmap
import mysql.connector
import pswd
import ipaddress

conn = mysql.connector.connect(
    host=pswd.host,
    user=pswd.user,  # Replace with your MySQL username
    password=pswd.password,  # Replace with your MySQL password
    database=pswd.database  # The name of your database
)
cursor = conn.cursor()

if conn.is_connected:
    print("Success")
else:
    print("Failed")

# Run the Nmap scan
def run_nmap_scan(target):
    try:
        nm = nmap.PortScanner()
        print(f"Scanning {target} on all ports (1-1000)...")
        
        # Perform the scan
        nm.scan(target, '1-1000', "-Pn")
        # Print the scan info and stats
        print("Scan Info:", nm.scaninfo())
        print("Scan Stats:", nm.scanstats())

        # Print open ports and scan results
        for host in nm.all_hosts():
            ip_address = host
            # Get the protocol information
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()  # Get the list of ports scanned for the protocol
                for port in ports:
                    state = nm[host][protocol][port]['state']
                    if state == 'open':  # Only store open ports
                        # Insert the IP address and protocol into the scans table
                        insert_query = "INSERT INTO scans (ip, protocol) VALUES (%s, %s)"
                        cursor.execute(insert_query, (ip_address, protocol))
                        conn.commit()
                        print("Results saved to scanDB")

            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")

            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
    
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def iterate_ips(start_ip, end_ip):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    current = start
    while current <= end:
        print("Current scanning: " + current.compressed)
        run_nmap_scan(current.compressed)
        current += 1

# Main code
print("Enter start of IP range to scan")
start = input()
print("Enter end value og IP range to scan")
end = input()
iterate_ips(start, end)