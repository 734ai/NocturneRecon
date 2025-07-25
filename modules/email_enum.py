"""
Email enumeration module for NocturneRecon
Supports Google/Bing dorking, GitHub search, and email permutation
"""

import requests
import re
import time
import threading
from urllib.parse import quote, urljoin
from bs4 import BeautifulSoup
from pathlib import Path
from core.utils import (
    print_success, print_error, print_info, print_result, print_debug,
    is_valid_email, clean_domain, deduplicate_list,
    save_to_json, save_to_csv, save_to_txt, create_output_filename,
    ensure_directory
)
from core.config import get_user_agent

class EmailEnumerator:
    """Email enumeration using search engines and permutation"""
    
    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.target = clean_domain(args.target)
        self.results = set()
        self.verbose = args.verbose
        self.timeout = args.timeout
        
        # Email regex pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        # Threading lock
        self.lock = threading.Lock()
    
    def run(self):
        """Main execution method"""
        print_info(f"Starting email enumeration for: {self.target}")
        
        # Search engine dorking
        search_engines = self.config.get('email_enum', {}).get('search_engines', ['google'])
        
        for engine in search_engines:
            print_info(f"Searching {engine.title()}...")
            if engine == 'google':
                results = self.search_google()
            elif engine == 'bing':
                results = self.search_bing()
            elif engine == 'duckduckgo':
                results = self.search_duckduckgo()
            else:
                continue
                
            self.add_results(results)
        
        # GitHub search
        if self.config.get('email_enum', {}).get('github_search', True):
            print_info("Searching GitHub...")
            github_results = self.search_github()
            self.add_results(github_results)
        
        # Email permutation
        print_info("Generating email permutations...")
        permutation_results = self.generate_permutations()
        self.add_results(permutation_results)
        
        # Convert to sorted list and filter
        final_results = self.filter_emails(sorted(list(self.results)))
        
        print_success(f"Found {len(final_results)} unique emails")
        
        # Print results if verbose
        if self.verbose:
            for email in final_results:
                print_result(email)
        
        return final_results
    
    def add_results(self, new_results):
        """Thread-safe method to add results"""
        with self.lock:
            if new_results:
                self.results.update(new_results)
                print_debug(f"Added {len(new_results)} new results", self.verbose)
    
    def search_google(self):
        """Search Google for emails using dorking"""
        results = set()
        
        # Google dorks for email finding
        dorks = [
            f'site:{self.target} "@{self.target}"',
            f'"{self.target}" email',
            f'"{self.target}" contact',
            f'intext:"@{self.target}"',
            f'site:{self.target} filetype:pdf',
            f'site:{self.target} "email" OR "mail" OR "contact"'
        ]
        
        headers = {
            'User-Agent': get_user_agent(self.config),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        for dork in dorks:
            try:
                url = f"https://www.google.com/search?q={quote(dork)}&num=100"
                
                response = requests.get(url, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                
                # Parse emails from response
                emails = self.extract_emails_from_text(response.text)
                results.update(emails)
                
                # Rate limiting
                time.sleep(self.args.delay)
                
            except requests.RequestException as e:
                print_error(f"Google search failed for dork '{dork}': {e}")
            except Exception as e:
                print_error(f"Error processing Google results: {e}")
        
        print_debug(f"Google search found {len(results)} emails", self.verbose)
        return results
    
    def search_bing(self):
        """Search Bing for emails using dorking"""
        results = set()
        
        # Bing dorks for email finding
        dorks = [
            f'site:{self.target} "@{self.target}"',
            f'"{self.target}" email',
            f'"{self.target}" contact',
            f'site:{self.target} filetype:pdf OR filetype:doc OR filetype:docx',
            f'site:{self.target} "email" OR "mail" OR "contact"'
        ]
        
        headers = {
            'User-Agent': get_user_agent(self.config),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        for dork in dorks:
            try:
                url = f"https://www.bing.com/search?q={quote(dork)}&count=50"
                
                response = requests.get(url, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                
                # Parse emails from response
                emails = self.extract_emails_from_text(response.text)
                results.update(emails)
                
                # Rate limiting
                time.sleep(self.args.delay)
                
            except requests.RequestException as e:
                print_error(f"Bing search failed for dork '{dork}': {e}")
            except Exception as e:
                print_error(f"Error processing Bing results: {e}")
        
        print_debug(f"Bing search found {len(results)} emails", self.verbose)
        return results
    
    def search_duckduckgo(self):
        """Search DuckDuckGo for emails"""
        results = set()
        
        queries = [
            f'site:{self.target} "@{self.target}"',
            f'"{self.target}" email contact',
            f'site:{self.target} "email" OR "mail"'
        ]
        
        headers = {
            'User-Agent': get_user_agent(self.config),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        for query in queries:
            try:
                url = f"https://duckduckgo.com/html/?q={quote(query)}"
                
                response = requests.get(url, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                
                # Parse emails from response
                emails = self.extract_emails_from_text(response.text)
                results.update(emails)
                
                # Rate limiting
                time.sleep(self.args.delay)
                
            except requests.RequestException as e:
                print_error(f"DuckDuckGo search failed for query '{query}': {e}")
            except Exception as e:
                print_error(f"Error processing DuckDuckGo results: {e}")
        
        print_debug(f"DuckDuckGo search found {len(results)} emails", self.verbose)
        return results
    
    def search_github(self):
        """Search GitHub for emails"""
        results = set()
        
        queries = [
            f'"{self.target}" email',
            f'"@{self.target}"',
            f'site:github.com "{self.target}" email',
            f'site:github.com "@{self.target}"'
        ]
        
        headers = {
            'User-Agent': get_user_agent(self.config),
            'Accept': 'application/vnd.github.v3+json',
        }
        
        # Use GitHub search via web interface (no API key required)
        for query in queries:
            try:
                url = f"https://github.com/search?q={quote(query)}&type=code"
                
                response = requests.get(url, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                
                # Parse emails from response
                emails = self.extract_emails_from_text(response.text)
                results.update(emails)
                
                # Rate limiting
                time.sleep(self.args.delay * 2)  # Be more conservative with GitHub
                
            except requests.RequestException as e:
                print_error(f"GitHub search failed for query '{query}': {e}")
            except Exception as e:
                print_error(f"Error processing GitHub results: {e}")
        
        print_debug(f"GitHub search found {len(results)} emails", self.verbose)
        return results
    
    def generate_permutations(self):
        """Generate email permutations based on common patterns"""
        results = set()
        
        # Common first/last name combinations for the domain
        patterns = self.config.get('email_enum', {}).get('permutation_patterns', [
            'admin@{domain}',
            'info@{domain}',
            'contact@{domain}',
            'support@{domain}',
            'sales@{domain}',
            'marketing@{domain}',
            'hr@{domain}',
            'it@{domain}',
            'help@{domain}',
            'service@{domain}',
            'office@{domain}',
            'mail@{domain}',
            'webmaster@{domain}',
            'no-reply@{domain}',
            'noreply@{domain}'
        ])
        
        for pattern in patterns:
            email = pattern.format(domain=self.target)
            if is_valid_email(email):
                results.add(email)
        
        print_debug(f"Generated {len(results)} email permutations", self.verbose)
        return results
    
    def extract_emails_from_text(self, text):
        """Extract emails from text using regex"""
        emails = set()
        
        # Find all email matches
        matches = self.email_pattern.findall(text)
        
        for match in matches:
            email = match.lower().strip()
            if is_valid_email(email):
                emails.add(email)
        
        return emails
    
    def filter_emails(self, emails):
        """Filter emails to only include target domain"""
        filtered = []
        
        for email in emails:
            if email.endswith(f"@{self.target}"):
                filtered.append(email)
        
        return deduplicate_list(filtered)
    
    def save_results(self, results):
        """Save results to file"""
        if not results:
            return
        
        # Ensure output directory exists
        ensure_directory(self.args.output_dir)
        
        # Create filename
        filename = create_output_filename(self.target, 'emails', self.args.output)
        filepath = Path(self.args.output_dir) / 'emails' / filename
        
        # Ensure subdirectory exists
        ensure_directory(filepath.parent)
        
        # Prepare data
        if self.args.output == 'json':
            data = {
                'target': self.target,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_found': len(results),
                'emails': results
            }
            success = save_to_json(data, filepath)
        elif self.args.output == 'csv':
            data = [{'email': email} for email in results]
            success = save_to_csv(data, filepath, ['email'])
        else:  # txt
            success = save_to_txt(results, filepath)
        
        if success:
            print_success(f"Results saved to: {filepath}")
        else:
            print_error("Failed to save results")
