import ssl
ssl.wrap_socket = ssl.SSLContext().wrap_socket
import nmap
import ipaddress
import socket
import mysql.connector
import pswd
import portList


conn = mysql.connector.connect(
    host=pswd.host,
    user=pswd.user,  # Replace with your MySQL username
    password=pswd.password,  # Replace with your MySQL password
    database=pswd.database,  # The name of your database
    ssl_disabled = True
)
cursor = conn.cursor()
#Use own list of ports to scan eg. 21, 22, 23, etc.
ports_str = ','.join(map(str, portList.portsToScan))

if conn.is_connected:
    print("Success")
else:
    print("Failed")


# Run the Nmap scan
def run_nmap_scan(target):
    try:
        nm = nmap.PortScanner()
        
        # Perform the scan
        nm.scan(target, ports_str, "-Pn")
        #Get the time of the scan
        scan_time = nm.scanstats().get('timestr')
        # Print the scan info and stats
        print("Scan Info:", nm.scaninfo())
        print("Scan Stats:", nm.scanstats())

        # Print open ports and scan results
        for host in nm.all_hosts():
            ip_address = host
            open_ports = []
            isp = None
            try:
                isp = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                isp = "Unknown ISP"

            # Get the protocol information
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()  # Get the list of ports scanned for the protocol
                for port in ports:
                    state = nm[host][protocol][port]['state']
                    if state == 'open':  # Only store open ports
                        open_ports.append(port)
                        open_ports_str = ','.join(map(str, open_ports))
                    # Insert the IP address and protocol into the scans table
                    else:
                        open_ports_str = "No ports open"
                    insert_query = """INSERT INTO scans (ip, protocol, open_ports, scan_time, isp) VALUES (%s, %s, %s, %s, %s)"""
                    cursor.execute(insert_query, (ip_address, protocol, open_ports_str, scan_time, isp))
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