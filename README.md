# Advanced Subdomain Finder

A powerful Python tool for advanced subdomain enumeration, DNS resolution, port scanning, and IP geolocation. Designed for security researchers, penetration testers, and bug bounty hunters.

## Features

- **Subdomain Enumeration**: Finds subdomains using public sources (crt.sh, SecurityTrails API) and brute-force wordlists.
- **DNS Resolution**: Resolves discovered subdomains to IP addresses.
- **Port Scanning**: Scans for open ports using Python sockets or optionally nmap.
- **IP Geolocation**: Displays country, region, city, organization, and ASN for discovered IPs.
- **Multithreading**: Fast scanning with configurable thread pool.
- **Configurable**: Customize API keys, ports, and wordlists via files.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/loveyoubad/advanced-subdomain-finder.git
   cd advanced-subdomain-finder
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   > Requirements: `requests` (For nmap scanning, ensure `nmap` is installed on your system)

## Usage

```bash
python advanced_subdomain_scanner.py <domain> [--nmap] [--apikeys FILE] [--ports FILE] [--wordlist FILE]
```

**Arguments:**
- `<domain>`: The target domain (e.g., example.com)
- `--nmap`: Use nmap for port scanning (optional)
- `--apikeys FILE`: Specify your API keys file (default: apikeys.txt)
- `--ports FILE`: Specify your ports file (default: ports.txt)
- `--wordlist FILE`: Specify your wordlist file (default: wordlist.txt)

**Example:**
```bash
python advanced_subdomain_scanner.py example.com --nmap --apikeys mykeys.txt --ports myports.txt --wordlist mywords.txt
```

## Configuration Files

- **apikeys.txt**
  ```
  # Format: servicename=APIKEY
  securitytrails=YOUR_SECURITYTRAILS_API_KEY
  shodan=YOUR_SHODAN_API_KEY
  censys=YOUR_CENSYS_API_KEY
  ```
- **ports.txt**
  ```
  80
  443
  8080
  ...
  ```
- **wordlist.txt**
  ```
  www
  mail
  ftp
  ...
  ```

## Output

Results are printed as JSON to the console, including:
- Subdomain
- IP addresses
- Open ports and services
- Geolocation info

## Notes

- For best results, provide valid API keys in `apikeys.txt`.
- Ensure your wordlist and ports files are tailored to your target.
- Nmap scans require `nmap` to be installed and in your PATH.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Do not use against targets without explicit permission.

## License

MIT
