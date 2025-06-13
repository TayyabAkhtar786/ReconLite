import socket
import argparse
import whois
import requests
import dns.resolver
import datetime
import re
import subprocess

# For logging
from datetime import datetime

def log(msg, verbose):
    if verbose:
        print(f"[+] {msg}")


def get_whois(domain, verbose=False):
    log("Performing WHOIS lookup...", verbose)
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Error: {e}"


def get_dns_records(domain, verbose=False):
    log("Fetching DNS records...", verbose)
    record_types = ['A', 'MX', 'TXT', 'NS']
    results = []
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                results.append(f"{rtype}: {rdata.to_text()}")
        except Exception as e:
            results.append(f"{rtype}: Error - {e}")
    return "\n".join(results)


def get_subdomains(domain, verbose=False):
    log("Enumerating subdomains using crt.sh...", verbose)
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=10)
        json_data = res.json()
        subdomains = set(entry['name_value'] for entry in json_data)
        return "\n".join(subdomains)
    except Exception as e:
        return f"Error: {e}"


def port_scan(domain, verbose=False):
    log("Scanning ports 1-100 on target...", verbose)
    open_ports = []
    ip = socket.gethostbyname(domain)
    for port in range(1, 101):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            continue
    return f"Open Ports: {open_ports}"


def banner_grab(domain, port=80, verbose=False):
    log(f"Grabbing banner from {domain}:{port}...", verbose)
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((domain, port))
        s.send(b"HEAD / HTTP/1.0\r\nHost: " + domain.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore')
        s.close()
        return banner
    except Exception as e:
        return f"Error: {e}"


def detect_technologies(domain, verbose=False):
    log("Detecting web technologies...", verbose)
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = res.headers
        html = res.text
        tech = []

        if 'wp-content' in html:
            tech.append("WordPress")
        if 'jquery' in html.lower():
            tech.append("jQuery")
        if 'x-powered-by' in headers:
            tech.append(f"X-Powered-By: {headers['x-powered-by']}")
        if 'server' in headers:
            tech.append(f"Server: {headers['server']}")

        return "\n".join(tech) if tech else "No technologies detected."
    except Exception as e:
        return f"Error: {e}"


def run_whatweb(domain, verbose=False):
    log("Running WhatWeb...", verbose)
    try:
        output = subprocess.check_output(["whatweb", domain], stderr=subprocess.STDOUT, timeout=10)
        return output.decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        return f"WhatWeb Error: {e.output.decode(errors='ignore')}"
    except FileNotFoundError:
        return "WhatWeb is not installed. Please install it using 'sudo apt install whatweb'"
    except Exception as e:
        return f"Error: {e}"


def write_report(domain, data):
    filename = f"recon_report_{domain}.txt"
    with open(filename, "w") as f:
        f.write(f"Recon Report for {domain}\n")
        f.write(f"Generated at: {datetime.now()}\n\n")
        f.write(data)
    return filename


def main():
    parser = argparse.ArgumentParser(
        description="ReconLite - Lightweight Recon Tool | Developed by: TAYYAB AKHTAR",
     epilog="Usage: python reconlite.py -t <target> [--dns --whois --subdomains --scan --banner --tech --whatweb --report --verbose]"
    )
    parser.add_argument("domain", help="Target website or IP address (Required)")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Fetch DNS records")
    parser.add_argument("--subdomains", action="store_true", help="Find subdomains")
    parser.add_argument("--scan", action="store_true", help="Scan ports")
    parser.add_argument("--banner", action="store_true", help="Grab HTTP banner")
    parser.add_argument("--tech", action="store_true", help="Detect website technologies")
    parser.add_argument("--whatweb", action="store_true", help="Run WhatWeb for detailed technology detection")
    parser.add_argument("--report", action="store_true", help="Generate report")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    results = ""

    if args.whois:
        results += "\n[WHOIS]\n" + get_whois(args.domain, args.verbose) + "\n"
    if args.dns:
        results += "\n[DNS Records]\n" + get_dns_records(args.domain, args.verbose) + "\n"
    if args.subdomains:
        results += "\n[Subdomains]\n" + get_subdomains(args.domain, args.verbose) + "\n"
    if args.scan:
        results += "\n[Port Scan]\n" + port_scan(args.domain, args.verbose) + "\n"
    if args.banner:
        results += "\n[Banner]\n" + banner_grab(args.domain, 80, args.verbose) + "\n"
    if args.tech:
        results += "\n[Technology Detection]\n" + detect_technologies(args.domain, args.verbose) + "\n"
    if args.whatweb:
        results += "\n[WhatWeb Detection]\n" + run_whatweb(args.domain, args.verbose) + "\n"

    if args.report:
        filename = write_report(args.domain, results)
        print(f"Report written to {filename}")
    else:
        print(results)

if __name__ == "__main__":
    main()
