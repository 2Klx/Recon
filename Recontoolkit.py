import socket
import subprocess
import sys
import ipinfo
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NEON_BLUE = '\033[38;2;0;149;255m'
RESET_COLOR = '\033[0m'


def dns_enum(target):
    try:
        print(f"{NEON_BLUE}Sublister Installation Verification{RESET_COLOR}")
        subprocess.run(['sudo', '-S', 'apt-get', 'install', 'sublist3r'], check=True)
        print(f"{NEON_BLUE}Sublister Installation Verification Complete{RESET_COLOR}")
        print(f"{NEON_BLUE}Sublist3r will now start{RESET_COLOR}")

        process = subprocess.Popen(['python', '/usr/lib/python3/dist-packages/sublist3r.py', '-d', target],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   text=True)

        #
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(f"{NEON_BLUE}{line}{RESET_COLOR}")
            sys.stdout.flush()

        process.wait()

    except FileNotFoundError:
        print(f"{NEON_BLUE}Tool Not Installed{RESET_COLOR}")


def port_scan(target):
    print(f"{NEON_BLUE}\nScanning ports on {target}...\n{RESET_COLOR}")
    port_list = {21: "FTP",
                 22: "SSH",
                 23: "Telnet",
                 25: "SMTP",
                 53: "DNS",
                 80: "HTTP",
                 443: "HTTPS",
                 3306: "MySQL",
                 1433: "Microsoft SQL Server",
                 3389: "RDP",
                 137: "NetBIOS",
                 138: "NetBIOS",
                 139: "NetBIOS",
                 445: "SMB",
                 389: "LDAP",
                 110: "POP3",
                 143: "IMAP",
                 1521: "Oracle",
                 2049: "NFS",
                 5900: "VNC",
                 161: "SNMP",
                 119: "NNTP",
                 5432: "PostgreSQL",
                 135: "Microsoft Remote Registry Service",
                 20: "FTP Data",
                 70: "Gopher Protocol",
                 88: "Kerberos",
                 6000: "X11",
                 123: "NTP",
                 548: "AFP", }
    for port in port_list.keys():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            service = port_list.get(port, "Unknown")
            print(f"{NEON_BLUE}Port {port} ({service}) is open{RESET_COLOR}")
        s.close()


def nslookup_info(target):
    print(f"{NEON_BLUE}Fetching DNS information for {target}...{RESET_COLOR}")
    try:
        result = subprocess.run(['nslookup', target], stdout=subprocess.PIPE, text=True)
        print(result.stdout)
    except FileNotFoundError:
        print(f"{NEON_BLUE}nslookup not found. Please install it.{RESET_COLOR}")


def geolocate(target):
    access_token = 'b3abfbb0ebe29c'
    handler = ipinfo.getHandler(access_token)

    ip_address = socket.gethostbyname(target)

    details = handler.getDetails(ip_address)

    print(f'IP Address: {details.ip}')
    print(f'Country: {details.country}')
    print(f'City: {details.city}')
    print(f'Latitude: {details.latitude}')
    print(f'Longitude: {details.longitude}')


def http_header_analysis(target):
    try:
        print(f"{NEON_BLUE}HTTP Header Analysis:{RESET_COLOR}")

        # Send a GET request to the target URL
        response = requests.get(f"https://{target}", timeout=10, verify=False)

        # Print the HTTP headers
        print(f"{NEON_BLUE}HTTP Headers:{RESET_COLOR}")
        for header, value in response.headers.items():
            print(f"{header}: {value}")

        # Analyze cookies
        cookies = response.cookies
        if cookies:
            print(f"{NEON_BLUE}\nCookies:{RESET_COLOR}")
            for cookie in cookies:
                print(f"{cookie.name}: {cookie.value}")

        # Extract server information from the 'Server' header
        server_header = response.headers.get('Server')
        if server_header:
            print(f"{NEON_BLUE}\nServer Information:{RESET_COLOR}")
            print(f"Server: {server_header}")

    except requests.RequestException as e:
        print(f"{NEON_BLUE}Error retrieving HTTP headers: {e}{RESET_COLOR}")
    except Exception as e:
        print(f"{NEON_BLUE}An error occurred: {e}{RESET_COLOR}")


def main():
    target = input(f"{NEON_BLUE}Enter the target domain name: {RESET_COLOR}")
    # nslookup_info(target)
    # geolocate(target)
    # port_scan(target)
    # dns_enum(target)
    http_header_analysis(target)


if __name__ == "__main__":
    main()
