#!/usr/bin/env python3
"""
EthicalRecon - Comprehensive Information Gathering Tool
A modular reconnaissance tool for ethical hacking and penetration testing.

Author: Security Researcher
Version: 1.0
License: Educational/Research Use Only
"""

import asyncio
import aiohttp
import socket
import subprocess
import json
import csv
import re
import whois
import dns.resolver
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import argparse
from datetime import datetime
import os
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

class Colors:
    """Color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'

class Logger:
    """Simple logging utility"""
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.lock = threading.Lock()
    
    def info(self, message):
        with self.lock:
            print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    def success(self, message):
        with self.lock:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    def warning(self, message):
        with self.lock:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    def error(self, message):
        with self.lock:
            print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    def debug(self, message):
        if self.verbose:
            with self.lock:
                print(f"{Colors.PURPLE}[DEBUG]{Colors.END} {message}")

class DomainScanner:
    """Domain and IP scanning functionality"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def resolve_domain(self, domain):
        """Resolve domain to IP address"""
        try:
            ip = socket.gethostbyname(domain)
            self.logger.success(f"Resolved {domain} to {ip}")
            return ip
        except socket.gaierror as e:
            self.logger.error(f"Failed to resolve {domain}: {e}")
            return None
    
    def reverse_dns(self, ip):
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.logger.success(f"Reverse DNS for {ip}: {hostname}")
            return hostname
        except socket.herror:
            self.logger.debug(f"No reverse DNS record for {ip}")
            return None

class SubdomainEnumerator:
    """Subdomain enumeration using wordlists"""
    
    def __init__(self, logger):
        self.logger = logger
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'forum', 'support', 'help', 'docs', 'portal',
            'secure', 'vpn', 'remote', 'mx', 'ns1', 'ns2', 'dns', 'email',
            'webmail', 'pop', 'imap', 'smtp', 'news', 'app', 'mobile',
            'beta', 'alpha', 'demo', 'preview', 'old', 'new', 'backup'
        ]
    
    async def enumerate_subdomains(self, domain, wordlist=None, max_concurrent=50):
        """Asynchronously enumerate subdomains"""
        subdomains = wordlist if wordlist else self.common_subdomains
        found_subdomains = []
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_subdomain(subdomain):
            async with semaphore:
                target = f"{subdomain}.{domain}"
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, socket.gethostbyname, target
                    )
                    self.logger.success(f"Found subdomain: {target}")
                    return target
                except socket.gaierror:
                    return None
        
        tasks = [check_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        found_subdomains = [sub for sub in results if sub and not isinstance(sub, Exception)]
        return found_subdomains

class PortScanner:
    """Port scanning functionality"""
    
    def __init__(self, logger):
        self.logger = logger
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090
        ]
    
    def scan_port(self, host, port, timeout=3):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_name(port)
                self.logger.success(f"Port {port} is open on {host} ({service})")
                return {'port': port, 'status': 'open', 'service': service}
            return None
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
            return None
    
    def get_service_name(self, port):
        """Get common service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def scan_ports(self, host, ports=None, max_threads=100):
        """Scan multiple ports using threads"""
        ports_to_scan = ports if ports else self.common_ports
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port 
                      for port in ports_to_scan}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports

class WHOISGatherer:
    """WHOIS information gathering"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def get_whois_info(self, domain):
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)
            self.logger.success(f"WHOIS data retrieved for {domain}")
            
            whois_data = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'country': w.country,
                'org': w.org
            }
            return whois_data
        except Exception as e:
            self.logger.error(f"Failed to get WHOIS data for {domain}: {e}")
            return None

class DNSGatherer:
    """DNS records gathering"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def get_dns_records(self, domain):
        """Gather various DNS records"""
        dns_data = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = [str(rdata) for rdata in answers]
                dns_data[record_type] = records
                self.logger.success(f"Found {len(records)} {record_type} record(s) for {domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception) as e:
                self.logger.debug(f"No {record_type} records for {domain}: {e}")
                dns_data[record_type] = []
        
        return dns_data

class DirectoryBuster:
    """Directory and file enumeration"""
    
    def __init__(self, logger):
        self.logger = logger
        self.common_paths = [
            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/config.php',
            '/backup', '/test', '/dev', '/api', '/upload', '/uploads',
            '/images', '/css', '/js', '/assets', '/static', '/files',
            '/docs', '/documentation', '/help', '/support', '/contact',
            '/about', '/blog', '/news', '/forum', '/shop', '/store'
        ]
    
    async def bust_directories(self, base_url, paths=None, max_concurrent=20):
        """Asynchronously check for directories and files"""
        paths_to_check = paths if paths else self.common_paths
        found_paths = []
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_path(session, path):
            async with semaphore:
                url = urljoin(base_url, path)
                try:
                    async with session.get(url, timeout=10, allow_redirects=False) as response:
                        if response.status in [200, 301, 302, 403]:
                            self.logger.success(f"Found: {url} (Status: {response.status})")
                            return {'url': url, 'status': response.status, 'path': path}
                except Exception as e:
                    self.logger.debug(f"Error checking {url}: {e}")
                return None
        
        async with aiohttp.ClientSession() as session:
            tasks = [check_path(session, path) for path in paths_to_check]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        found_paths = [result for result in results if result and not isinstance(result, Exception)]
        return found_paths

class WebCrawler:
    """Web crawling for links and JavaScript files"""
    
    def __init__(self, logger):
        self.logger = logger
        self.visited_urls = set()
        self.js_files = set()
        self.links = set()
    
    def crawl_website(self, base_url, max_depth=2, max_pages=50):
        """Crawl website for links and JS files"""
        self.visited_urls.clear()
        self.js_files.clear()
        self.links.clear()
        
        def crawl_recursive(url, depth):
            if depth > max_depth or len(self.visited_urls) >= max_pages:
                return
            
            if url in self.visited_urls:
                return
            
            self.visited_urls.add(url)
            
            try:
                response = requests.get(url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract links
                    link_pattern = r'href=["\']([^"\']+)["\']'
                    links = re.findall(link_pattern, content, re.IGNORECASE)
                    
                    for link in links:
                        absolute_url = urljoin(url, link)
                        if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                            self.links.add(absolute_url)
                            if depth < max_depth:
                                crawl_recursive(absolute_url, depth + 1)
                    
                    # Extract JavaScript files
                    js_pattern = r'src=["\']([^"\']+\.js[^"\']*)["\']'
                    js_files = re.findall(js_pattern, content, re.IGNORECASE)
                    
                    for js_file in js_files:
                        absolute_js_url = urljoin(url, js_file)
                        self.js_files.add(absolute_js_url)
                    
                    self.logger.success(f"Crawled: {url}")
                
            except Exception as e:
                self.logger.debug(f"Error crawling {url}: {e}")
        
        crawl_recursive(base_url, 0)
        
        return {
            'links': list(self.links),
            'js_files': list(self.js_files),
            'pages_crawled': len(self.visited_urls)
        }

class DataExtractor:
    """Extract emails and phone numbers from content"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def extract_from_url(self, url):
        """Extract emails and phone numbers from a URL"""
        try:
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if response.status_code == 200:
                return self.extract_from_content(response.text)
        except Exception as e:
            self.logger.debug(f"Error extracting from {url}: {e}")
        
        return {'emails': [], 'phones': []}
    
    def extract_from_content(self, content):
        """Extract emails and phone numbers from content"""
        # Email regex pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = list(set(re.findall(email_pattern, content)))
        
        # Phone number regex patterns
        phone_patterns = [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # US format
            r'\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b',  # (123) 456-7890
            r'\b\+\d{1,3}[-.\s]?\d{1,14}\b'  # International format
        ]
        
        phones = set()
        for pattern in phone_patterns:
            phones.update(re.findall(pattern, content))
        
        return {
            'emails': emails,
            'phones': list(phones)
        }

class TechDetector:
    """Technology detection (similar to Wappalyzer)"""
    
    def __init__(self, logger):
        self.logger = logger
        self.tech_signatures = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
            'Drupal': [r'sites/default/files', r'misc/drupal.js'],
            'Joomla': [r'/media/system/js/', r'option=com_'],
            'Apache': [r'Apache/[\d.]+'],
            'Nginx': [r'nginx/[\d.]+'],
            'PHP': [r'X-Powered-By: PHP', r'\.php'],
            'ASP.NET': [r'X-AspNet-Version', r'ASP.NET'],
            'jQuery': [r'jquery[.-][\d.]+\.(?:min\.)?js'],
            'Bootstrap': [r'bootstrap[.-][\d.]+\.(?:min\.)?(?:css|js)'],
            'React': [r'react[.-][\d.]+\.(?:min\.)?js', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
            'Angular': [r'angular[.-][\d.]+\.(?:min\.)?js'],
            'Vue.js': [r'vue[.-][\d.]+\.(?:min\.)?js']
        }
    
    def detect_technologies(self, url):
        """Detect technologies used by the website"""
        detected_tech = []
        
        try:
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            headers = str(response.headers)
            content = response.text
            combined = headers + content
            
            for tech, patterns in self.tech_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        detected_tech.append(tech)
                        self.logger.success(f"Detected technology: {tech}")
                        break
            
        except Exception as e:
            self.logger.error(f"Error detecting technologies for {url}: {e}")
        
        return detected_tech

class ReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def generate_json_report(self, data, filename):
        """Generate JSON report"""
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            self.logger.success(f"JSON report saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
    
    def generate_csv_report(self, data, filename):
        """Generate CSV report (simplified)"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write basic information
                writer.writerow(['Category', 'Information'])
                writer.writerow(['Target', data.get('target', 'N/A')])
                writer.writerow(['Scan Date', data.get('scan_date', 'N/A')])
                
                # Write open ports
                if 'open_ports' in data:
                    writer.writerow([])
                    writer.writerow(['Open Ports'])
                    writer.writerow(['Port', 'Service', 'Status'])
                    for port_info in data['open_ports']:
                        writer.writerow([port_info['port'], port_info['service'], port_info['status']])
                
                # Write subdomains
                if 'subdomains' in data:
                    writer.writerow([])
                    writer.writerow(['Subdomains'])
                    for subdomain in data['subdomains']:
                        writer.writerow([subdomain])
            
            self.logger.success(f"CSV report saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {e}")
    
    def generate_html_report(self, data, filename):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>EthicalRecon Report - {data.get('target', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                .section {{ margin: 20px 0; padding: 10px; border-left: 3px solid #007acc; }}
                .success {{ color: #28a745; }}
                .warning {{ color: #ffc107; }}
                .error {{ color: #dc3545; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                pre {{ background: #f8f9fa; padding: 10px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <h1>EthicalRecon Security Assessment Report</h1>
            <div class="section">
                <h2>Target Information</h2>
                <p><strong>Target:</strong> {data.get('target', 'N/A')}</p>
                <p><strong>Scan Date:</strong> {data.get('scan_date', 'N/A')}</p>
                <p><strong>IP Address:</strong> {data.get('ip_address', 'N/A')}</p>
            </div>
        """
        
        # Add sections for different types of data
        sections = [
            ('open_ports', 'Open Ports'),
            ('subdomains', 'Discovered Subdomains'),
            ('dns_records', 'DNS Records'),
            ('directories', 'Found Directories'),
            ('technologies', 'Detected Technologies'),
            ('emails', 'Extracted Emails'),
            ('phones', 'Extracted Phone Numbers')
        ]
        
        for key, title in sections:
            if key in data and data[key]:
                html_content += f'<div class="section"><h2>{title}</h2>'
                
                if isinstance(data[key], list):
                    html_content += '<ul>'
                    for item in data[key]:
                        if isinstance(item, dict):
                            html_content += f'<li>{str(item)}</li>'
                        else:
                            html_content += f'<li>{item}</li>'
                    html_content += '</ul>'
                else:
                    html_content += f'<pre>{json.dumps(data[key], indent=2)}</pre>'
                
                html_content += '</div>'
        
        html_content += '</body></html>'
        
        try:
            with open(filename, 'w') as f:
                f.write(html_content)
            self.logger.success(f"HTML report saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")

class EthicalRecon:
    """Main reconnaissance tool class"""
    
    def __init__(self, verbose=False):
        self.logger = Logger(verbose)
        self.domain_scanner = DomainScanner(self.logger)
        self.subdomain_enum = SubdomainEnumerator(self.logger)
        self.port_scanner = PortScanner(self.logger)
        self.whois_gatherer = WHOISGatherer(self.logger)
        self.dns_gatherer = DNSGatherer(self.logger)
        self.dir_buster = DirectoryBuster(self.logger)
        self.web_crawler = WebCrawler(self.logger)
        self.data_extractor = DataExtractor(self.logger)
        self.tech_detector = TechDetector(self.logger)
        self.report_generator = ReportGenerator(self.logger)
    
    async def run_full_scan(self, target, output_format='json', output_file=None):
        """Run a comprehensive scan on the target"""
        self.logger.info(f"Starting comprehensive scan of {target}")
        start_time = time.time()
        
        # Initialize results
        results = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'ip_address': None,
            'reverse_dns': None,
            'subdomains': [],
            'open_ports': [],
            'whois_data': None,
            'dns_records': {},
            'directories': [],
            'crawl_data': {},
            'extracted_data': {'emails': [], 'phones': []},
            'technologies': [],
            'scan_duration': 0
        }
        
        # Resolve target to IP
        ip_address = self.domain_scanner.resolve_domain(target)
        if ip_address:
            results['ip_address'] = ip_address
            results['reverse_dns'] = self.domain_scanner.reverse_dns(ip_address)
        
        # Gather WHOIS information
        self.logger.info("Gathering WHOIS information...")
        results['whois_data'] = self.whois_gatherer.get_whois_info(target)
        
        # Gather DNS records
        self.logger.info("Gathering DNS records...")
        results['dns_records'] = self.dns_gatherer.get_dns_records(target)
        
        # Enumerate subdomains
        self.logger.info("Enumerating subdomains...")
        results['subdomains'] = await self.subdomain_enum.enumerate_subdomains(target)
        
        # Scan ports on main target
        if ip_address:
            self.logger.info("Scanning ports...")
            results['open_ports'] = self.port_scanner.scan_ports(ip_address)
        
        # Check if HTTP/HTTPS is available
        http_url = None
        for port_info in results['open_ports']:
            if port_info['port'] in [80, 8080]:
                http_url = f"http://{target}"
                break
            elif port_info['port'] in [443, 8443]:
                http_url = f"https://{target}"
                break
        
        if not http_url:
            # Try default HTTP/HTTPS even if ports weren't detected as open
            try:
                response = requests.get(f"https://{target}", timeout=5)
                if response.status_code < 400:
                    http_url = f"https://{target}"
            except:
                try:
                    response = requests.get(f"http://{target}", timeout=5)
                    if response.status_code < 400:
                        http_url = f"http://{target}"
                except:
                    pass
        
        if http_url:
            # Directory busting
            self.logger.info("Scanning for directories and files...")
            results['directories'] = await self.dir_buster.bust_directories(http_url)
            
            # Web crawling
            self.logger.info("Crawling website...")
            results['crawl_data'] = self.web_crawler.crawl_website(http_url)
            
            # Extract emails and phone numbers
            self.logger.info("Extracting contact information...")
            extracted = self.data_extractor.extract_from_url(http_url)
            results['extracted_data'] = extracted
            
            # Detect technologies
            self.logger.info("Detecting technologies...")
            results['technologies'] = self.tech_detector.detect_technologies(http_url)
        
        # Calculate scan duration
        results['scan_duration'] = round(time.time() - start_time, 2)
        
        # Generate report
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ethicalrecon_{target}_{timestamp}"
        
        if output_format.lower() == 'json':
            self.report_generator.generate_json_report(results, f"{output_file}.json")
        elif output_format.lower() == 'csv':
            self.report_generator.generate_csv_report(results, f"{output_file}.csv")
        elif output_format.lower() == 'html':
            self.report_generator.generate_html_report(results, f"{output_file}.html")
        else:
            self.logger.warning(f"Unknown output format: {output_format}. Defaulting to JSON.")
            self.report_generator.generate_json_report(results, f"{output_file}.json")
        
        self.logger.success(f"Scan completed in {results['scan_duration']} seconds")
        return results

def main():
    """Main function to run the tool"""
    parser = argparse.ArgumentParser(
        description="EthicalRecon - Comprehensive Information Gathering Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ethicalrecon.py -t example.com
  python3 ethicalrecon.py -t example.com -o html -f report
  python3 ethicalrecon.py -t example.com --verbose
        """
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target domain or IP address')
    parser.add_argument('-o', '--output', choices=['json', 'csv', 'html'], 
                       default='json', help='Output format (default: json)')
    parser.add_argument('-f', '--file', help='Output filename (without extension)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Print banner
    print(f"""{Colors.CYAN}
    ╔═══════════════════════════════════════════════════╗
    ║                 EthicalRecon v1.0                 ║
    ║        Comprehensive Information Gathering        ║
    ║              For Educational Use Only             ║
    ╚═══════════════════════════════════════════════════╝
    {Colors.END}""")
    
    # Initialize and run scanner
    scanner = EthicalRecon(verbose=args.verbose)
    
    try:
        # Run the scan
        asyncio.run(scanner.run_full_scan(
            target=args.target,
            output_format=args.output,
            output_file=args.file
        ))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] An error occurred: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()