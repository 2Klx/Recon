import socket
import subprocess
import sys
import warnings
import ipinfo
import urllib3
import requests
from Wappalyzer import Wappalyzer, WebPage

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

lightblue = '\033[38;2;0;149;255m'
reset = '\033[0m'
yellow = '\x1b[33m'
blue = '\033[94m'
red = '\u001b[31m'

choice = input("Is the target https or just http? (1/2) : ")
if choice == "1":
    security = "https://"
else:
    security = "http://"


def dns_recon(target):
    print(lightblue + "______________________________________________________________________________________" + reset)
    print(f"{blue}\nDNSRecon Installation/Verification{reset}")
    subprocess.run(['sudo', '-S', 'apt-get', 'install', 'dnsrecon'], check=True)
    print(f"{yellow}\nDNSRECON is running: \n ")
    try:

        result = subprocess.run(['dnsrecon', '-d', target], capture_output=True, text=True)

        if result.returncode == 0:

            print(result.stdout + reset)
        else:
            print(f"Error executing dnsrecon: {result.stderr}")

    except Exception as e:
        print(f"Error: {e}")


def osdetection(target):
    try:
        print(lightblue + "______________________________________________________________________________________" + reset)
        print(f"{blue}\nOS running on the Server is:\n ")
        response = requests.head(security + target)
        print(yellow + response.headers.get('Server') + reset)
    except Exception as e:
        print("An error occurred:", e)


def wappalyzer(target):
    print(lightblue + "______________________________________________________________________________________" + reset)
    print(f"{blue}\nWeb Technologies Used on the Site are:\n {reset}")
    warnings.filterwarnings("ignore", message="""Caught 'unbalanced parenthesis at position 119' compiling regex""", category=UserWarning)
    wapp = Wappalyzer.latest()
    webpage = WebPage.new_from_url(security + target)
    result = wapp.analyze(webpage)
    print(f"{yellow}{result}{reset}")


def dns_enum(target):
    print(lightblue + "______________________________________________________________________________________" + reset)
    try:
        print(f"{blue}\nSublister Installation Verification{reset}")
        subprocess.run(['sudo', '-S', 'apt-get', 'install', 'sublist3r'], check=True)
        print(f"{blue}Installation Verification Complete{reset}")
        print(f"{yellow}\nSublist3r will now start\n{reset}")

        process = subprocess.Popen(['python', '/usr/lib/python3/dist-packages/sublist3r.py', '-d', target],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   text=True)

        #
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(f"{blue}{line}{reset}")
            sys.stdout.flush()

        process.wait()

    except FileNotFoundError:
        print(f"{blue}Tool Not Installed{reset}")


def port_scan(target):
    print(lightblue + "______________________________________________________________________________________" + reset)
    print(blue + "\nPort Scanning will be done on " + target + "\n" + reset)
    scanchoice = input(f"{blue}What scan do you want? \n1. Custom port  \n2. Standard Preset? \n3. Exit\nChoose (1/2/3) \n{reset}")
    if scanchoice == "1":
        portnumber = int(input(blue + "Give Port- " + reset))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, portnumber))
        if result == 0:
            print(f"\n{yellow}Port {portnumber} is open{yellow}\n")
        s.close()
        port_scan(target)

    elif scanchoice == "2":
        print(f"{blue}Scanning ports on {target}...\n{reset}")
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
                print(f"\n{yellow}Port {port} ({service}) is open{reset}")
            s.close()
        port_scan(target)


def nslookup_info(target):
    print(lightblue + "______________________________________________________________________________________" + reset)
    print(f"{blue}\nFetching DNS information for {target}...{reset}\n")
    try:
        result = subprocess.run(['nslookup', target], stdout=subprocess.PIPE, text=True)
        print(yellow + result.stdout + reset)
    except FileNotFoundError:
        print(f"{blue}nslookup not found. Please install it.{reset}")


def geolocate(target):
    print(lightblue + "______________________________________________________________________________________" + reset)
    print(blue + "\nGeoLocating the Target - " + target + reset + "\n")
    access_token = 'b3abfbb0ebe29c'
    handler = ipinfo.getHandler(access_token)

    ip_address = socket.gethostbyname(target)

    details = handler.getDetails(ip_address)

    print(f'{yellow}IP Address: {details.ip}')
    print(f'Country: {details.country}')
    print(f'City: {details.city}')
    print(f'Latitude: {details.latitude}')
    print(f'Longitude: {details.longitude}{reset}')


def http_header_analysis(target):
    print(lightblue + "______________________________________________________________________________________" + reset)
    try:
        print(f"{blue}\nHTTP Header Analysis: \n{reset}")
        response = requests.get(f"{security}{target}", timeout=10, verify=False)

        print(f"{yellow}HTTP Headers:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")

        cookies = response.cookies
        if cookies:
            print(f"{yellow}\nCookies:{reset}")
            for cookie in cookies:
                print(f"{cookie.name}: {cookie.value}")

        server_header = response.headers.get('Server')
        if server_header:
            print(f"{yellow}\nServer Information: ")
            print(f"{yellow}Server: {server_header}")

    except requests.RequestException as e:
        print(f"Error retrieving HTTP headers: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    subprocess.run('clear')
    subprocess.run(['pip', 'install', '-r', 'requirements.txt'])
    print(red + """               ____  _____ ____ ___  _   _   _____ ___   ___  _     _  _____ _____ 
              |  _ \| ____/ ___/ _ \| \ | | |_   _/ _ \ / _ \| |   | |/ /_ _|_   _|
              | |_) |  _|| |  | | | |  \| |   | || | | | | | | |   | ' / | |  | |  
              |  _ <| |__| |__| |_| | |\  |   | || |_| | |_| | |___| . \ | |  | |  
              |_| \_\_____\____\___/|_| \_|   |_| \___/ \___/|_____|_|\_\___| |_|   by 2Klx""" + reset)
    print(red + "______________________________________________________________________________________" + reset)
    target = input(f"{blue}Enter the target domain name: \n{reset}")
    osdetection(target)
    wappalyzer(target)
    nslookup_info(target)
    geolocate(target)
    http_header_analysis(target)
    port_scan(target)
    dns_enum(target)
    dns_recon(target)

    print(red + "______________________________________________________________________________________" + reset)

    print(red + """\n                 _____ _   _ ____  
                | ____| \ | |  _ \ 
                |  _| |  \| | | | |
                | |___| |\  | |_| |
                |_____|_| \_|____/ """ + reset)


if __name__ == "__main__":
    main()
