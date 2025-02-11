import nmap
import mysql.connector

# Run the Nmap scan
def run_nmap_scan(target):
    try:
        nm = nmap.PortScanner()
        print(f"Scanning {target} on all ports (1-55)...")
        
        # Perform the scan
        nm.scan(target, '1-55')
        print("test")
        # Print the scan info and stats
        print("Scan Info:", nm.scaninfo())
        print("Scan Stats:", nm.scanstats())

        conn = mysql.connector.connect(
            host="localhost",
            user="",  # Replace with your MySQL username
            password="",  # Replace with your MySQL password
            database=""  # The name of your database
        )
        cursor = conn.cursor()


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

# Main code
print("Enter IP to scan")
target = input()
run_nmap_scan(target)
