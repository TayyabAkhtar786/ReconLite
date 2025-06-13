#  ReconLite - Lightweight Reconnaissance Tool

**Developed by:** Tayyab Akhtar  
**Purpose:** A beginner-friendly Python tool for automating information gathering and reconnaissance in cybersecurity assessments.

##  Features

- WHOIS Lookup
- DNS Records Enumeration (A, MX, TXT, NS)
- Subdomain Discovery via crt.sh
- Port Scanning (Ports 1–100)
- HTTP Banner Grabbing
- Basic Technology Fingerprinting
- WhatWeb Integration (Optional)
- Saves Results to a Report File
- Verbose Mode for Step-by-Step Feedback

##  Usage
python reconlite.py example.com [OPTIONS]

### Basic Syntax [Options]:
```bash
python reconlite.py <target> [options]
 Option             Description                                             
 ------------------------------------------------------------------------ 
 -t / <target>   : **(Required)** Target domain or IP address              
 --whois         : Perform WHOIS Lookup                                    
 --dns           : Retrieve A, MX, TXT, and NS records                     
 --subdomains    : Discover subdomains using certificate transparency logs 
 --scan          : Scan ports 1–100                                        
 --banner        : Grab HTTP banner (default: port 80)                     
 --tech          : Detect technologies using headers and page content      
 --whatweb       : Run WhatWeb (requires it to be installed separately)    
 --report        : Save all output to a `.txt` report file                
 --verbose       : Show process steps in console
 -h              : Show help and usage guide                               

