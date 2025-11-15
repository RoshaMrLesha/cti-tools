#!/usr/bin/env python3
"""
Domain Scanner - Web Screenshot & DNS Resolution Tool
Usage: python script.py <file> <mode> [--uri <path>]

# Web mode with screenshots
python script.py domains.txt web

# Web mode with URI path
python script.py domains.txt web --uri /api/test

# IP mode for DNS resolution
python script.py domains.txt ip
"""

import argparse
import re
import socket
import sys
import csv
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from urllib.parse import urljoin, urlparse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException


def validate_domain(domain):
    """
    Validate domain format.
    Returns tuple: (is_valid, normalized_domain, has_protocol)
    """
    domain = domain.strip()
    
    # Check if it has protocol
    if domain.startswith('http://') or domain.startswith('https://'):
        has_protocol = True
        # Parse and validate
        parsed = urlparse(domain)
        if not parsed.netloc:
            return False, None, False
        normalized = domain
    else:
        has_protocol = False
        # Validate basic domain format
        # Pattern: optional subdomain(s), domain, tld
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            return False, None, False
        normalized = domain
    
    return True, normalized, has_protocol


def read_and_validate_file(filepath):
    """
    Read and validate domains from file.
    Supports both plain text (one domain per line) and CSV with 'Domain' column.
    Returns list of validated domains with protocol info.
    """
    try:
        with open(filepath, 'r') as f:
            # Try to detect if it's a CSV by reading first line
            first_line = f.readline().strip()
            f.seek(0)  # Reset to beginning
            
            # Check if it's a CSV with 'Domain' header
            is_csv = False
            if ',' in first_line or first_line.lower().startswith('domain'):
                # Try parsing as CSV
                try:
                    reader = csv.DictReader(f)
                    first_row = next(reader, None)
                    if first_row and 'Domain' in reader.fieldnames:
                        is_csv = True
                        f.seek(0)  # Reset again for actual processing
                except:
                    f.seek(0)  # Reset if CSV parsing failed
            
            if is_csv:
                # Process as CSV
                reader = csv.DictReader(f)
                if 'Domain' not in reader.fieldnames:
                    print("Error: CSV file must have 'Domain' as the first column header.")
                    sys.exit(1)
                
                domains = []
                invalid_lines = []
                
                for i, row in enumerate(reader, 2):  # Start at 2 (line 1 is header)
                    domain = row.get('Domain', '').strip()
                    if not domain:  # Skip empty cells
                        continue
                    
                    is_valid, normalized, has_protocol = validate_domain(domain)
                    if is_valid:
                        domains.append((normalized, has_protocol))
                    else:
                        invalid_lines.append((i, domain))
                
                print(f"✓ Detected CSV format with 'Domain' column")
            else:
                # Process as plain text
                lines = f.readlines()
                domains = []
                invalid_lines = []
                
                for i, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    
                    is_valid, normalized, has_protocol = validate_domain(line)
                    if is_valid:
                        domains.append((normalized, has_protocol))
                    else:
                        invalid_lines.append((i, line))
                
                print(f"✓ Detected plain text format")
            
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    if invalid_lines:
        print("Invalid domain format found on the following lines:")
        for line_num, content in invalid_lines:
            print(f"  Line {line_num}: {content}")
        sys.exit(1)
    
    if not domains:
        print("Error: No valid domains found in file.")
        sys.exit(1)
    
    return domains


def setup_driver():
    """Setup Selenium WebDriver with mobile user agent."""
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    
    # Mobile user agent (iPhone 12 Pro)
    mobile_ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1'
    options.add_argument(f'user-agent={mobile_ua}')
    
    # Set window size to mobile dimensions
    options.add_argument('--window-size=390,844')
    
    try:
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)
        return driver
    except Exception as e:
        print(f"Error setting up Chrome WebDriver: {e}")
        print("Make sure Chrome and ChromeDriver are installed.")
        sys.exit(1)


def take_screenshot(driver, url, output_path):
    """
    Navigate to URL and take screenshot.
    Returns True if successful, False otherwise.
    """
    try:
        driver.get(url)
        driver.save_screenshot(str(output_path))
        return True
    except TimeoutException:
        print(f"  Timeout loading {url}, taking screenshot anyway...")
        try:
            driver.save_screenshot(str(output_path))
            return True
        except Exception as e:
            print(f"  Failed to save screenshot: {e}")
            return False
    except WebDriverException as e:
        print(f"  WebDriver error for {url}: {e}")
        return False
    except Exception as e:
        print(f"  Unexpected error for {url}: {e}")
        return False


def web_mode(domains, uri, input_filename):
    """
    Web mode: Take screenshots of domains.
    """
    # Create output folder
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    folder_name = f"{Path(input_filename).stem}_screenshots_{timestamp}"
    output_dir = Path(folder_name)
    output_dir.mkdir(exist_ok=True)
    
    print(f"Screenshots will be saved to: {output_dir}/")
    print(f"Processing {len(domains)} domains...\n")
    
    driver = setup_driver()
    
    try:
        for domain, has_protocol in domains:
            # Build URL
            if has_protocol:
                base_url = domain
            else:
                base_url = f"http://{domain}"
            
            # Append URI if provided
            if uri:
                full_url = urljoin(base_url, uri)
            else:
                full_url = base_url
            
            # Extract domain name for filename
            parsed = urlparse(full_url)
            domain_name = parsed.netloc if parsed.netloc else domain.replace('http://', '').replace('https://', '')
            
            # Generate filename
            screenshot_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{domain_name}_{screenshot_timestamp}.jpg"
            output_path = output_dir / filename
            
            print(f"Processing: {full_url}")
            success = take_screenshot(driver, full_url, output_path)
            
            if success:
                print(f"  ✓ Screenshot saved: {filename}")
            else:
                print(f"  ✗ Failed to capture screenshot")
            print()
    
    finally:
        driver.quit()
    
    print(f"\nCompleted! Screenshots saved in: {output_dir}/")


def resolve_domain(domain):
    """
    Resolve domain to IP address.
    Returns IP address or None if resolution fails.
    """
    # Remove protocol if present
    clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        ip = socket.gethostbyname(clean_domain)
        return ip
    except socket.gaierror:
        return None


def ip_mode(domains):
    """
    IP mode: Resolve domains and group by IP.
    """
    print(f"Resolving {len(domains)} domains...\n")
    
    ip_to_domains = defaultdict(list)
    failed_resolutions = []
    
    for domain, _ in domains:
        # Remove protocol for display
        clean_domain = domain.replace('http://', '').replace('https://', '')
        
        print(f"Resolving: {clean_domain}")
        ip = resolve_domain(domain)
        
        if ip:
            ip_to_domains[ip].append(clean_domain)
            print(f"  → {ip}")
        else:
            failed_resolutions.append(clean_domain)
            print(f"  ✗ Failed to resolve")
        print()
    
    # Print report
    print("="*60)
    print("DNS RESOLUTION REPORT")
    print("="*60)
    print()
    
    if failed_resolutions:
        print("Failed Resolutions:")
        for domain in failed_resolutions:
            print(f"  ✗ {domain}")
        print()
    
    # Check if all domains are on different IPs
    resolved_domains = [d for ip_list in ip_to_domains.values() for d in ip_list]
    
    if len(ip_to_domains) == len(resolved_domains):
        print("All domains exist on different IP addresses.")
        print()
        for ip, domains_list in sorted(ip_to_domains.items()):
            print(f"IP: {ip}")
            print(f"  └─ {domains_list[0]}")
            print()
    else:
        print("Domains grouped by IP address:")
        print()
        
        for ip, domains_list in sorted(ip_to_domains.items()):
            print(f"IP: {ip}")
            print(f"  Domains ({len(domains_list)}):")
            for domain in sorted(domains_list):
                print(f"    • {domain}")
            print()
    
    print("="*60)
    print(f"Summary: {len(resolved_domains)} resolved, {len(failed_resolutions)} failed")
    print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Domain scanner for screenshots and DNS resolution'
    )
    parser.add_argument('file', help='Input file with domains (one per line)')
    parser.add_argument('mode', choices=['web', 'ip'], help='Operation mode')
    parser.add_argument('--uri', help='URI path to append to URLs (web mode only)')
    
    args = parser.parse_args()
    
    # Validate file exists
    if not Path(args.file).exists():
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)
    
    # Read and validate domains
    print(f"Reading domains from: {args.file}")
    domains = read_and_validate_file(args.file)
    print(f"✓ Validated {len(domains)} domains\n")
    
    # Execute mode
    if args.mode == 'web':
        web_mode(domains, args.uri, args.file)
    else:  # ip mode
        if args.uri:
            print("Warning: --uri argument is ignored in 'ip' mode\n")
        ip_mode(domains)


if __name__ == '__main__':
    main()
