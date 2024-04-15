Recon Toolkit
This Python script serves as a reconnaissance (recon) toolkit designed to gather information about a target domain. It utilizes various tools and libraries to perform tasks such as:

DNS Enumeration: Uses Sublist3r to enumerate subdomains of the target domain.
Port Scanning: Scans common ports to identify open services on the target server.
DNS Lookup: Retrieves DNS information for the target domain using the nslookup command.
Geolocation: Determines the geographical location of the target IP address.
HTTP Header Analysis: Analyzes HTTP headers to gather information about the web server, cookies, and other relevant details.
Features:
Subdomain Enumeration: Utilizes Sublist3r for subdomain enumeration.
Port Scanning: Scans a predefined list of ports to identify open services.
DNS Lookup: Fetches DNS information using the nslookup command.
Geolocation: Uses the ipinfo library to determine the geographical location of the target IP address.
HTTP Header Analysis: Analyzes HTTP headers to extract information about the web server, cookies, and server headers.
Dependencies:
sublist3r: For subdomain enumeration.
ipinfo: For geolocation.
requests: For HTTP requests and header analysis.
urllib3: For handling warnings and disabling insecure request warnings.
Usage:
Run the script.
Enter the target domain name when prompted.
The script will then perform various reconnaissance tasks and display the results.
