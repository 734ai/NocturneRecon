"""
Utility functions for color printing, file I/O, and common operations
"""

import json
import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Back, Style
import validators

# Initialize colorama
init(autoreset=True)

class Colors:
    """Color constants for terminal output"""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM

def print_banner():
    """Print the NocturneRecon banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════════╗
    ║                     🦉 NocturneRecon                          ║
    ║           State-of-the-art API-free OSINT Framework          ║
    ║                                                               ║
    ║  Author: Muzan Sano                    Version: 1.0.0-dev    ║
    ║  License: MIT                          https://github.com/... ║
    ╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)

def print_success(message):
    """Print success message in green"""
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")

def print_error(message):
    """Print error message in red"""
    print(f"{Colors.RED}[!] {message}{Colors.RESET}")

def print_warning(message):
    """Print warning message in yellow"""
    print(f"{Colors.YELLOW}[*] {message}{Colors.RESET}")

def print_info(message):
    """Print info message in blue"""
    print(f"{Colors.BLUE}[i] {message}{Colors.RESET}")

def print_debug(message, verbose=False):
    """Print debug message in dim style if verbose mode"""
    if verbose:
        print(f"{Colors.DIM}[DEBUG] {message}{Colors.RESET}")

def print_result(message):
    """Print result in cyan"""
    print(f"{Colors.CYAN}    └─ {message}{Colors.RESET}")

def save_to_json(data, filepath):
    """Save data to JSON file with pretty formatting"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        return True
    except Exception as e:
        print_error(f"Failed to save JSON: {e}")
        return False

def save_to_csv(data, filepath, headers=None):
    """Save data to CSV file"""
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            if not data:
                return True
            
            # If data is a list of dictionaries
            if isinstance(data[0], dict):
                headers = headers or data[0].keys()
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(data)
            else:
                # If data is a simple list
                writer = csv.writer(f)
                if headers:
                    writer.writerow(headers)
                for item in data:
                    writer.writerow([item] if not isinstance(item, (list, tuple)) else item)
        return True
    except Exception as e:
        print_error(f"Failed to save CSV: {e}")
        return False

def save_to_txt(data, filepath):
    """Save data to plain text file"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            if isinstance(data, list):
                for item in data:
                    f.write(f"{item}\n")
            else:
                f.write(str(data))
        return True
    except Exception as e:
        print_error(f"Failed to save TXT: {e}")
        return False

def load_wordlist(filepath):
    """Load wordlist from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"Failed to load wordlist: {e}")
        return []

def is_valid_domain(domain):
    """Validate if string is a valid domain"""
    return validators.domain(domain) is True

def is_valid_email(email):
    """Validate if string is a valid email"""
    return validators.email(email) is True

def is_valid_url(url):
    """Validate if string is a valid URL"""
    return validators.url(url) is True

def clean_domain(domain):
    """Clean and normalize domain name"""
    domain = domain.lower().strip()
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://', 1)[1]
    # Remove path if present
    domain = domain.split('/')[0]
    # Remove port if present
    domain = domain.split(':')[0]
    return domain

def generate_timestamp():
    """Generate timestamp string for file naming"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def create_output_filename(target, module, format_type, timestamp=None):
    """Create standardized output filename"""
    if timestamp is None:
        timestamp = generate_timestamp()
    
    clean_target = clean_domain(target).replace('.', '_')
    return f"{clean_target}_{module}_{timestamp}.{format_type}"

def ensure_directory(path):
    """Ensure directory exists, create if not"""
    Path(path).mkdir(parents=True, exist_ok=True)

def deduplicate_list(input_list):
    """Remove duplicates while preserving order"""
    seen = set()
    result = []
    for item in input_list:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

def filter_subdomains(subdomains, target_domain):
    """Filter subdomains to only include those belonging to target domain"""
    target_domain = clean_domain(target_domain)
    filtered = []
    
    for subdomain in subdomains:
        clean_sub = clean_domain(subdomain)
        if clean_sub.endswith(f".{target_domain}") or clean_sub == target_domain:
            filtered.append(clean_sub)
    
    return deduplicate_list(filtered)

def read_file_lines(filepath):
    """Read file and return list of lines"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"Failed to read file {filepath}: {e}")
        return []

def write_file_lines(filepath, lines):
    """Write list of lines to file"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for line in lines:
                f.write(f"{line}\n")
        return True
    except Exception as e:
        print_error(f"Failed to write file {filepath}: {e}")
        return False

def get_file_size(filepath):
    """Get file size in bytes"""
    try:
        return os.path.getsize(filepath)
    except:
        return 0

def format_bytes(bytes_size):
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f}{unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f}TB"
