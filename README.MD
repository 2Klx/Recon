# Reconnaissance Toolkit

## Overview

This Python script serves as a comprehensive reconnaissance (recon) toolkit designed to gather valuable information about a target domain. It employs various tools and libraries to perform specific tasks, aiding in the analysis and understanding of the target's infrastructure.

## Features

- **Subdomain Enumeration**: Utilizes Sublist3r to enumerate subdomains of the target domain.
  
- **Port Scanning**: Scans a predefined list of common ports to identify open services on the target server.
  
- **DNS Lookup**: Retrieves DNS information for the target domain using the `nslookup` command.
  
- **Geolocation**: Determines the geographical location of the target IP address using the ipinfo library.
  
- **HTTP Header Analysis**: Analyzes HTTP headers to extract information about the web server, cookies, and server headers.

## Dependencies

- `sublist3r`: Required for subdomain enumeration.
  
- `ipinfo token`: Necessary for geolocation services.
  
- `requests`: Used for making HTTP requests and analyzing headers.
  
- `urllib3`: Required for handling warnings and disabling insecure request warnings.

## Usage

1. **Run the Script**: Execute the script using Python.

    ```bash
    python Recontoolkit.py
    ```

2. **Enter Target Domain**: When prompted, enter the target domain name.

3. **View Results**: The script will execute various reconnaissance tasks and display the results accordingly.

