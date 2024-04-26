# Reconnaissance Toolkit (v1.0)

## Overview

This Python script serves as a comprehensive reconnaissance (recon) toolkit designed to gather valuable information about a target domain. It employs various tools and libraries to perform specific tasks, aiding in the analysis and understanding of the target's infrastructure.

## Features

- **Subdomain Enumeration**: Utilizes Sublist3r to enumerate subdomains of the target domain.
  
- **Port Scanning**: Scans a predefined list of common ports or a custom specified port to identify open services on the target server.
  
- **DNS Lookup**: Retrieves DNS information for the target domain using the `nslookup` command.
  
- **Geolocation**: Determines the geographical location of the target IP address using the ipinfo library.
  
- **HTTP Header Extraction**: Done to extract information about the web server, cookies, and server headers.

- **Serivce Detection**: Detects the OS of the web service being used.

- **Technology Detection**: Detects the technology being used by the web page.

- **Surface level DNS Details**: Uses the `dnsrecon` tool to give details about the DNS of the target.
## Dependencies
- `Wappalyzer`: Installed in the tool, used to gather information about the technologies being used.
- `DnsRecon` : Required for Dns Details, will install itself.
- `sublist3r`: Required for subdomain enumeration,will install itself.
  
- `ipinfo token`: Necessary for geolocation services.
  
- `requests`: Used for making HTTP requests and analyzing headers.
  
- `urllib3`: Required for handling warnings and disabling insecure request warnings.

## Usage
**Pre-Requisite**: Place the script and `requirements.txt` in the same directory.
1. **Run the Script**: Execute the script using Python.

    ```bash
    python Recontoolkit.py
    ```
   
2. **Enter Target Domain**: When prompted, enter the target domain name.

3. **View Results**: The script will execute various reconnaissance tasks and display the results in the terminal accordingly.

4. **Store Output**: To store the Output in a text file use the tee command as specified.
     ```bash
     python Recontoolkit.py | tee output.txt
     ```