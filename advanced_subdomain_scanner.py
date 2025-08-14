import requests
import socket
import json
import threading
import subprocess
import re
import os

# ---- Load Configurations from Files ----
def load_api_keys(file_path="apikeys.txt"):
    # Format: service=key (one per line)
    keys = {}
    try:
        with open(file_path, "r") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    keys[k.strip()] = v.strip()
    except Exception as e:
        print(f"API key file error: {e}")
    return keys

def get_api_key(service, file_path="apikeys.txt"):
    """
    Fetch the API key for a given service from apikeys.txt.
    Usage: key = get_api_key("securitytrails")
    """
    keys = load_api_keys(file_path)
    return keys.get(service)

def load_ports(file_path="ports.txt"):
    ports = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.isdigit():
                    ports.append(int(line))
    except Exception as e:
        print(f"Ports file error: {e}")
    return ports if ports else [80, 443, 8080, 22, 21, 25, 8443, 3306, 5432, 8000, 8888]

def load_wordlist(file_path="wordlist.txt"):
    words = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                word = line.strip()
                if word:
                    words.append(word)
    except Exception as e:
        print(f"Wordlist file error: {e}")
    return words if words else [
        "www", "mail", "ftp", "test", "dev", "api", "staging", "portal", "blog", "admin", "shop", "dashboard"
    ]

# ---- Subdomain Enumeration ----
def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        if sub.endswith(domain):
                            subdomains.add(sub.strip())
            return list(subdomains)
    except Exception as e:
        print(f"crt.sh error: {e}")
    return []

def get_subdomains_securitytrails(domain, file_path="apikeys.txt"):
    api_key = get_api_key("securitytrails", file_path)
    if not api_key:
        print("SecurityTrails API key not found in apikeys.txt")
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {'APIKEY': api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subs = [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
            return subs
    except Exception as e:
        print(f"SecurityTrails error: {e}")
    return []

def brute_force_subdomains(domain, wordlist):
    return [f"{word}.{domain}" for word in wordlist]

# ---- DNS Resolution ----
def resolve_subdomain(subdomain):
    ips = []
    try:
        ip = socket.gethostbyname(subdomain)
        ips.append(ip)
    except Exception:
        pass
    return ips

# ---- Port Scanning ----
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()
    return open_ports

def scan_ports_nmap(ip, ports):
    port_str = ",".join(map(str, ports))
    try:
        result = subprocess.run(
            ["nmap", "-Pn", "-p", port_str, "-sV", ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30
        )
        output = result.stdout
        open_ports = []
        for line in output.splitlines():
            match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$", line)
            if match:
                port, service, banner = match.groups()
                open_ports.append({
                    "port": int(port),
                    "service": service,
                    "banner": banner
                })
        return open_ports
    except Exception as e:
        print(f"Nmap error: {e}")
    return []

# ---- IP Geolocation ----
def geolocate_ip(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "org": data.get("org"),
                "asn": data.get("as")
            }
    except Exception:
        pass
    return {}

# ---- Worker ----
def scan_subdomain(subdomain, ports, wordlist, use_nmap=False):
    result = {"subdomain": subdomain, "ips": []}
    ips = resolve_subdomain(subdomain)
    for ip in ips:
        if use_nmap:
            ports_info = scan_ports_nmap(ip, ports)
        else:
            open_ports = scan_ports(ip, ports)
            ports_info = [{"port": p} for p in open_ports]
        geo = geolocate_ip(ip)
        result["ips"].append({
            "ip": ip,
            "ports": ports_info,
            "geo": geo
        })
    return result

# ---- Main ----
def main(domain, apikey_file="apikeys.txt", ports_file="ports.txt", wordlist_file="wordlist.txt", use_nmap=False):
    ports = load_ports(ports_file)
    wordlist = load_wordlist(wordlist_file)

    print(f"[*] Enumerating subdomains for {domain}")
    subdomains = set(get_subdomains_crtsh(domain))
    subdomains.update(brute_force_subdomains(domain, wordlist))
    subdomains.update(get_subdomains_securitytrails(domain, apikey_file))
    print(f"[*] Found {len(subdomains)} subdomains")

    results = []
    threads = []
    lock = threading.Lock()
    THREADS = 20

    def worker(subdomain):
        res = scan_subdomain(subdomain, ports, wordlist, use_nmap=use_nmap)
        with lock:
            results.append(res)

    sema = threading.Semaphore(THREADS)
    for subdomain in subdomains:
        sema.acquire()
        t = threading.Thread(target=lambda s: [worker(s), sema.release()], args=(subdomain,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    import sys
    domain = None
    use_nmap = False
    apikey_file = "apikeys.txt"
    ports_file = "ports.txt"
    wordlist_file = "wordlist.txt"
    # Example: python advanced_subdomain_scanner.py example.com --nmap --apikeys mykeys.txt --ports myports.txt --wordlist mywords.txt
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <domain> [--nmap] [--apikeys FILE] [--ports FILE] [--wordlist FILE]")
        sys.exit(1)
    domain = sys.argv[1]
    if '--nmap' in sys.argv:
        use_nmap = True
    if '--apikeys' in sys.argv:
        i = sys.argv.index('--apikeys')
        apikey_file = sys.argv[i + 1]
    if '--ports' in sys.argv:
        i = sys.argv.index('--ports')
        ports_file = sys.argv[i + 1]
    if '--wordlist' in sys.argv:
        i = sys.argv.index('--wordlist')
        wordlist_file = sys.argv[i + 1]
    main(domain, apikey_file, ports_file, wordlist_file, use_nmap)
