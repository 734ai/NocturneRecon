#!/usr/bin/env python3
"""
NocturneRecon Dark Web Enumeration Module
Author: Muzan Sano
Version: 2.0.0-dev
License: MIT

This module provides dark web enumeration capabilities including:
- Tor hidden service discovery
- Dark web leak monitoring
- Onion domain analysis
- Deep web content discovery
"""

import os
import sys
import time
import requests
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socks
import socket

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import print_info, print_success, print_warning, print_error, save_to_json, save_to_csv, save_to_txt


class DarkWebEnumerator:
    """
    Dark Web Enumeration class for discovering hidden services and monitoring leaks
    """
    
    def __init__(self, target, config=None):
        """
        Initialize the Dark Web Enumerator
        
        Args:
            target (str): Target domain or organization to search for
            config (dict): Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'onion_domains': [],
            'leak_references': [],
            'dark_web_mentions': [],
            'hidden_services': []
        }
        
        # Tor configuration
        self.tor_proxy = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        
        # Hidden service directories and search engines
        self.onion_directories = [
            'http://3g2upl4pq6kufc4m.onion',  # DuckDuckGo onion
            'http://facebookcorewwwi.onion',  # Facebook onion
            'http://duckduckgogg42ts72.onion'  # DuckDuckGo onion (alternative)
        ]
        
        self.dark_search_engines = [
            'ahmia.fi',
            'onionland-search.com',
            'deeplink.onion.to'
        ]
        
        # Leak monitoring sources
        self.leak_sources = [
            'pastebin.com',
            'ghostbin.com',
            'hastebin.com',
            'justpaste.it',
            'rentry.co'
        ]
        
        self.threads = self.config.get('threads', 5)
        self.delay = self.config.get('delay', 2.0)
        self.timeout = self.config.get('timeout', 15)
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # User agents for stealth
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0'
        ]

    def check_tor_connection(self):
        """
        Check if Tor is running and accessible
        
        Returns:
            bool: True if Tor is accessible, False otherwise
        """
        try:
            print_info("Checking Tor connection...")
            
            # Test Tor proxy connection
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=self.tor_proxy,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('IsTor', False):
                    print_success(f"Tor connection successful. IP: {data.get('IP', 'Unknown')}")
                    return True
                else:
                    print_warning("Connected but not through Tor")
                    return False
            else:
                print_error(f"Tor check failed with status: {response.status_code}")
                return False
                
        except Exception as e:
            print_error(f"Tor connection failed: {str(e)}")
            print_info("Make sure Tor is running: sudo systemctl start tor")
            return False

    def search_onion_directories(self):
        """
        Search onion directories for references to the target
        """
        print_info(f"Searching onion directories for '{self.target}'...")
        
        search_queries = [
            self.target,
            self.target.replace('.', ' '),
            f'"{self.target}"',
            f'{self.target} leak',
            f'{self.target} database'
        ]
        
        for query in search_queries:
            for directory in self.onion_directories:
                try:
                    print_info(f"Searching {directory} for: {query}")
                    
                    # Search the onion directory
                    search_url = f"{directory}/search?q={query}"
                    
                    headers = {
                        'User-Agent': self.user_agents[0],
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive'
                    }
                    
                    response = self.session.get(
                        search_url,
                        headers=headers,
                        proxies=self.tor_proxy,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        onion_domains = self._extract_onion_links(response.text)
                        for domain in onion_domains:
                            if domain not in [r['domain'] for r in self.results['onion_domains']]:
                                self.results['onion_domains'].append({
                                    'domain': domain,
                                    'source': directory,
                                    'query': query,
                                    'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                                })
                                print_success(f"Found onion domain: {domain}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print_warning(f"Error searching {directory}: {str(e)}")
                    continue

    def search_dark_web_search_engines(self):
        """
        Search dark web search engines for target mentions
        """
        print_info(f"Searching dark web search engines for '{self.target}'...")
        
        search_queries = [
            f'{self.target} site:*.onion',
            f'"{self.target}" leak',
            f'{self.target} database dump',
            f'{self.target} credentials'
        ]
        
        for engine in self.dark_search_engines:
            for query in search_queries:
                try:
                    print_info(f"Searching {engine} for: {query}")
                    
                    # Use clearnet to search for dark web content
                    search_url = f"https://{engine}/search"
                    params = {'q': query}
                    
                    headers = {
                        'User-Agent': self.user_agents[0],
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                    
                    response = self.session.get(
                        search_url,
                        params=params,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        mentions = self._extract_dark_web_mentions(response.text, engine)
                        for mention in mentions:
                            self.results['dark_web_mentions'].append({
                                'title': mention.get('title', ''),
                                'url': mention.get('url', ''),
                                'snippet': mention.get('snippet', ''),
                                'source': engine,
                                'query': query,
                                'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                            })
                            print_success(f"Found mention: {mention.get('title', 'No title')}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print_warning(f"Error searching {engine}: {str(e)}")
                    continue

    def monitor_leak_sources(self):
        """
        Monitor paste sites and leak sources for target mentions
        """
        print_info(f"Monitoring leak sources for '{self.target}'...")
        
        search_terms = [
            self.target,
            self.target.replace('.com', ''),
            self.target.replace('.', ' '),
            f'{self.target} email',
            f'{self.target} password'
        ]
        
        for source in self.leak_sources:
            for term in search_terms:
                try:
                    print_info(f"Checking {source} for: {term}")
                    
                    # Different search approaches for different sources
                    if 'pastebin.com' in source:
                        search_url = f"https://pastebin.com/search?q={term}"
                    elif 'ghostbin.com' in source:
                        search_url = f"https://ghostbin.com/search/{term}"
                    else:
                        # Generic search approach
                        search_url = f"https://{source}/search?q={term}"
                    
                    headers = {
                        'User-Agent': self.user_agents[0],
                        'Accept': 'text/html,application/xhtml+xml'
                    }
                    
                    response = self.session.get(
                        search_url,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        leaks = self._extract_leak_references(response.text, source)
                        for leak in leaks:
                            self.results['leak_references'].append({
                                'title': leak.get('title', ''),
                                'url': leak.get('url', ''),
                                'source': source,
                                'search_term': term,
                                'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                            })
                            print_success(f"Found leak reference: {leak.get('title', 'No title')}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print_warning(f"Error checking {source}: {str(e)}")
                    continue

    def discover_hidden_services(self):
        """
        Discover hidden services related to the target
        """
        print_info(f"Discovering hidden services for '{self.target}'...")
        
        # Common hidden service patterns
        service_patterns = [
            f"{self.target.split('.')[0]}.onion",
            f"{self.target.replace('.', '')}.onion",
            f"{self.target.split('.')[0]}leak.onion",
            f"{self.target.split('.')[0]}dump.onion"
        ]
        
        for pattern in service_patterns:
            try:
                print_info(f"Checking hidden service pattern: {pattern}")
                
                # Try to resolve the onion domain
                test_url = f"http://{pattern}"
                
                headers = {
                    'User-Agent': self.user_agents[0],
                    'Accept': 'text/html,application/xhtml+xml'
                }
                
                response = self.session.get(
                    test_url,
                    headers=headers,
                    proxies=self.tor_proxy,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    self.results['hidden_services'].append({
                        'domain': pattern,
                        'status': 'active',
                        'title': self._extract_page_title(response.text),
                        'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                    })
                    print_success(f"Active hidden service found: {pattern}")
                
                time.sleep(self.delay)
                
            except Exception as e:
                print_warning(f"Hidden service {pattern} not accessible: {str(e)}")
                continue

    def _extract_onion_links(self, html_content):
        """
        Extract .onion links from HTML content
        
        Args:
            html_content (str): HTML content to parse
            
        Returns:
            list: List of onion domains
        """
        onion_domains = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all links
            links = soup.find_all('a', href=True)
            
            for link in links:
                href = link['href']
                if '.onion' in href:
                    # Extract domain from URL
                    if href.startswith('http'):
                        domain = urlparse(href).netloc
                    else:
                        domain = href.split('/')[0] if '/' in href else href
                    
                    if domain and domain.endswith('.onion'):
                        onion_domains.append(domain)
            
        except Exception as e:
            print_warning(f"Error extracting onion links: {str(e)}")
        
        return list(set(onion_domains))

    def _extract_dark_web_mentions(self, html_content, source):
        """
        Extract dark web mentions from search results
        
        Args:
            html_content (str): HTML content to parse
            source (str): Source search engine
            
        Returns:
            list: List of mention dictionaries
        """
        mentions = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Common search result patterns
            result_selectors = [
                'div.search-result',
                'div.result',
                'div.g',
                'div[class*="result"]'
            ]
            
            for selector in result_selectors:
                results = soup.select(selector)
                
                for result in results:
                    title_elem = result.find(['h3', 'h2', 'a'])
                    title = title_elem.get_text().strip() if title_elem else 'No title'
                    
                    link_elem = result.find('a', href=True)
                    url = link_elem['href'] if link_elem else ''
                    
                    snippet_elem = result.find(['p', 'div', 'span'])
                    snippet = snippet_elem.get_text().strip() if snippet_elem else ''
                    
                    if title and (self.target.lower() in title.lower() or 
                                 self.target.lower() in snippet.lower()):
                        mentions.append({
                            'title': title,
                            'url': url,
                            'snippet': snippet[:200] + '...' if len(snippet) > 200 else snippet
                        })
            
        except Exception as e:
            print_warning(f"Error extracting mentions from {source}: {str(e)}")
        
        return mentions

    def _extract_leak_references(self, html_content, source):
        """
        Extract leak references from paste sites
        
        Args:
            html_content (str): HTML content to parse
            source (str): Source website
            
        Returns:
            list: List of leak reference dictionaries
        """
        references = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Different patterns for different sources
            if 'pastebin.com' in source:
                # Pastebin specific parsing
                results = soup.find_all('div', class_='gsc-result')
            elif 'ghostbin.com' in source:
                # Ghostbin specific parsing
                results = soup.find_all('div', class_='paste-item')
            else:
                # Generic parsing
                results = soup.find_all(['div', 'li', 'tr'])
            
            for result in results:
                title_elem = result.find(['a', 'h3', 'h2'])
                title = title_elem.get_text().strip() if title_elem else 'No title'
                
                link_elem = result.find('a', href=True)
                url = link_elem['href'] if link_elem else ''
                
                if title and self.target.lower() in title.lower():
                    references.append({
                        'title': title,
                        'url': url if url.startswith('http') else f"https://{source}{url}"
                    })
            
        except Exception as e:
            print_warning(f"Error extracting leak references from {source}: {str(e)}")
        
        return references

    def _extract_page_title(self, html_content):
        """
        Extract page title from HTML content
        
        Args:
            html_content (str): HTML content to parse
            
        Returns:
            str: Page title or empty string
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_elem = soup.find('title')
            return title_elem.get_text().strip() if title_elem else ''
        except:
            return ''

    def run(self, output_format='json', output_dir='output'):
        """
        Run the dark web enumeration
        
        Args:
            output_format (str): Output format (json, csv, txt)
            output_dir (str): Output directory
            
        Returns:
            dict: Results dictionary
        """
        print_info(f"Starting dark web enumeration for: {self.target}")
        print_warning("DISCLAIMER: This module is for authorized security testing only!")
        
        # Check if Tor is available (optional for some functions)
        tor_available = self.check_tor_connection()
        
        try:
            # Search dark web search engines (clearnet accessible)
            self.search_dark_web_search_engines()
            
            # Monitor leak sources
            self.monitor_leak_sources()
            
            # Tor-dependent operations
            if tor_available:
                print_info("Tor connection available - running advanced enumeration...")
                self.search_onion_directories()
                self.discover_hidden_services()
            else:
                print_warning("Tor not available - skipping onion-specific searches")
                print_info("Install Tor: sudo apt-get install tor")
                print_info("Start Tor: sudo systemctl start tor")
            
            # Calculate statistics
            total_onion_domains = len(self.results['onion_domains'])
            total_mentions = len(self.results['dark_web_mentions'])
            total_leaks = len(self.results['leak_references'])
            total_services = len(self.results['hidden_services'])
            
            print_success(f"Dark web enumeration completed!")
            print_info(f"Found {total_onion_domains} onion domains")
            print_info(f"Found {total_mentions} dark web mentions")
            print_info(f"Found {total_leaks} leak references")
            print_info(f"Found {total_services} hidden services")
            
            # Save results
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"darkweb_{self.target}_{timestamp}"
            
            if 'json' in output_format:
                json_file = os.path.join(output_dir, f"{filename}.json")
                save_to_json(self.results, json_file)
                print_success(f"Results saved to: {json_file}")
            
            if 'csv' in output_format:
                csv_file = os.path.join(output_dir, f"{filename}.csv")
                self._save_to_csv(csv_file)
                print_success(f"Results saved to: {csv_file}")
            
            if 'txt' in output_format:
                txt_file = os.path.join(output_dir, f"{filename}.txt")
                self._save_to_txt(txt_file)
                print_success(f"Results saved to: {txt_file}")
            
            return self.results
            
        except KeyboardInterrupt:
            print_warning("Dark web enumeration interrupted by user")
            return self.results
        except Exception as e:
            print_error(f"Error during dark web enumeration: {str(e)}")
            return self.results

    def _save_to_csv(self, filename):
        """
        Save results to CSV format
        
        Args:
            filename (str): Output filename
        """
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Onion domains
            writer.writerow(['Onion Domains'])
            writer.writerow(['Domain', 'Source', 'Query', 'Discovered At'])
            for domain in self.results['onion_domains']:
                writer.writerow([
                    domain.get('domain', ''),
                    domain.get('source', ''),
                    domain.get('query', ''),
                    domain.get('discovered_at', '')
                ])
            
            writer.writerow([])  # Empty row
            
            # Dark web mentions
            writer.writerow(['Dark Web Mentions'])
            writer.writerow(['Title', 'URL', 'Source', 'Query', 'Discovered At'])
            for mention in self.results['dark_web_mentions']:
                writer.writerow([
                    mention.get('title', ''),
                    mention.get('url', ''),
                    mention.get('source', ''),
                    mention.get('query', ''),
                    mention.get('discovered_at', '')
                ])
            
            writer.writerow([])  # Empty row
            
            # Leak references
            writer.writerow(['Leak References'])
            writer.writerow(['Title', 'URL', 'Source', 'Search Term', 'Discovered At'])
            for leak in self.results['leak_references']:
                writer.writerow([
                    leak.get('title', ''),
                    leak.get('url', ''),
                    leak.get('source', ''),
                    leak.get('search_term', ''),
                    leak.get('discovered_at', '')
                ])

    def _save_to_txt(self, filename):
        """
        Save results to TXT format
        
        Args:
            filename (str): Output filename
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Dark Web Enumeration Results for: {self.target}\n")
            f.write(f"Generated: {self.results['timestamp']}\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("ONION DOMAINS:\n")
            f.write("-" * 20 + "\n")
            for domain in self.results['onion_domains']:
                f.write(f"Domain: {domain.get('domain', '')}\n")
                f.write(f"Source: {domain.get('source', '')}\n")
                f.write(f"Query: {domain.get('query', '')}\n")
                f.write(f"Discovered: {domain.get('discovered_at', '')}\n\n")
            
            f.write("DARK WEB MENTIONS:\n")
            f.write("-" * 20 + "\n")
            for mention in self.results['dark_web_mentions']:
                f.write(f"Title: {mention.get('title', '')}\n")
                f.write(f"URL: {mention.get('url', '')}\n")
                f.write(f"Source: {mention.get('source', '')}\n")
                f.write(f"Snippet: {mention.get('snippet', '')}\n\n")
            
            f.write("LEAK REFERENCES:\n")
            f.write("-" * 20 + "\n")
            for leak in self.results['leak_references']:
                f.write(f"Title: {leak.get('title', '')}\n")
                f.write(f"URL: {leak.get('url', '')}\n")
                f.write(f"Source: {leak.get('source', '')}\n\n")


def main():
    """
    Main function for testing the dark web enumeration module
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='NocturneRecon Dark Web Enumeration Module')
    parser.add_argument('--target', '-t', required=True, help='Target domain or organization')
    parser.add_argument('--output', '-o', default='json', help='Output format (json, csv, txt)')
    parser.add_argument('--output-dir', '-d', default='output', help='Output directory')
    parser.add_argument('--threads', default=5, type=int, help='Number of threads')
    parser.add_argument('--delay', default=2.0, type=float, help='Delay between requests')
    parser.add_argument('--timeout', default=15, type=int, help='Request timeout')
    
    args = parser.parse_args()
    
    config = {
        'threads': args.threads,
        'delay': args.delay,
        'timeout': args.timeout
    }
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Run dark web enumeration
    enumerator = DarkWebEnumerator(args.target, config)
    results = enumerator.run(args.output, args.output_dir)
    
    print(f"\nDark web enumeration completed for {args.target}")
    print(f"Results saved to {args.output_dir}/")


if __name__ == "__main__":
    main()
