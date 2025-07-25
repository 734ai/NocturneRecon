#!/usr/bin/env python3
"""
NocturneRecon Pastebin Monitor Module
Author: Muzan Sano
Version: 2.0.0-dev
License: MIT

This module provides pastebin monitoring capabilities including:
- Pastebin clone monitoring
- Real-time leak detection
- Historical paste analysis
- Multi-platform paste site support
"""

import os
import sys
import time
import requests
import threading
import re
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import print_info, print_success, print_warning, print_error, save_to_json, save_to_csv, save_to_txt


class PastebinMonitor:
    """
    Pastebin Monitor class for detecting leaks across paste sites
    """
    
    def __init__(self, target, config=None):
        """
        Initialize the Pastebin Monitor
        
        Args:
            target (str): Target domain or organization to monitor for
            config (dict): Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'paste_detections': [],
            'credential_leaks': [],
            'code_exposures': [],
            'historical_pastes': [],
            'monitored_sites': []
        }
        
        # Pastebin sites to monitor
        self.paste_sites = {
            'pastebin.com': {
                'search_url': 'https://pastebin.com/search?q={}',
                'recent_url': 'https://pastebin.com/archive',
                'api_url': 'https://scrape.pastebin.com/api_scraping.php',
                'requires_auth': False
            },
            'paste.ee': {
                'search_url': 'https://paste.ee/search?q={}',
                'recent_url': 'https://paste.ee/recent',
                'requires_auth': False
            },
            'hastebin.com': {
                'search_url': 'https://hastebin.com/search?q={}',
                'recent_url': 'https://hastebin.com/recent',
                'requires_auth': False
            },
            'ghostbin.co': {
                'search_url': 'https://ghostbin.co/search?q={}',
                'recent_url': 'https://ghostbin.co/browse',
                'requires_auth': False
            },
            'rentry.co': {
                'search_url': 'https://rentry.co/search?q={}',
                'recent_url': 'https://rentry.co/recent',
                'requires_auth': False
            },
            'justpaste.it': {
                'search_url': 'https://justpaste.it/search?q={}',
                'recent_url': 'https://justpaste.it/recent',
                'requires_auth': False
            },
            'dpaste.org': {
                'search_url': 'https://dpaste.org/search?q={}',
                'recent_url': 'https://dpaste.org/recent',
                'requires_auth': False
            }
        }
        
        # Search patterns for different types of leaks
        self.search_patterns = {
            'domain_mentions': [
                self.target,
                self.target.replace('.', ' '),
                f'"{self.target}"',
                self.target.split('.')[0] if '.' in self.target else self.target
            ],
            'credential_patterns': [
                f'{self.target} password',
                f'{self.target} login',
                f'{self.target} credentials',
                f'{self.target} database',
                f'{self.target} dump',
                f'{self.target} leak'
            ],
            'code_patterns': [
                f'{self.target} api',
                f'{self.target} token',
                f'{self.target} key',
                f'{self.target} config',
                f'{self.target} env'
            ]
        }
        
        # Regex patterns for sensitive information
        self.sensitive_patterns = {
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'passwords': r'(?i)(password|pass|pwd)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            'api_keys': r'(?i)(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?',
            'database_urls': r'(?i)(mongodb://|mysql://|postgresql://|redis://)[^\s]+',
            'aws_keys': r'(?i)(AKIA[0-9A-Z]{16}|aws_access_key_id)',
            'private_keys': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'jwt_tokens': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'credit_cards': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        }
        
        self.threads = self.config.get('threads', 3)  # Lower for paste sites
        self.delay = self.config.get('delay', 2.0)
        self.timeout = self.config.get('timeout', 15)
        self.monitor_duration = self.config.get('monitor_duration', 300)  # 5 minutes
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # User agents for stealth
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # Track seen pastes to avoid duplicates
        self.seen_pastes = set()

    def search_historical_pastes(self):
        """
        Search historical pastes across all monitored sites
        """
        print_info(f"Searching historical pastes for '{self.target}'...")
        
        all_patterns = []
        all_patterns.extend(self.search_patterns['domain_mentions'])
        all_patterns.extend(self.search_patterns['credential_patterns'])
        all_patterns.extend(self.search_patterns['code_patterns'])
        
        for site_name, site_config in self.paste_sites.items():
            if site_config.get('requires_auth', False):
                print_warning(f"Skipping {site_name} - requires authentication")
                continue
            
            print_info(f"Searching {site_name}...")
            
            for pattern in all_patterns:
                try:
                    search_url = site_config['search_url'].format(quote(pattern))
                    
                    headers = {
                        'User-Agent': self.user_agents[0],
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                    
                    response = self.session.get(
                        search_url,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        pastes = self._extract_paste_results(response.text, site_name, pattern)
                        
                        for paste in pastes:
                            paste_id = self._generate_paste_id(paste)
                            
                            if paste_id not in self.seen_pastes:
                                self.seen_pastes.add(paste_id)
                                
                                # Analyze paste content if available
                                content_analysis = self._analyze_paste_content(paste, site_name)
                                
                                paste_result = {
                                    'site': site_name,
                                    'title': paste.get('title', ''),
                                    'url': paste.get('url', ''),
                                    'author': paste.get('author', ''),
                                    'date': paste.get('date', ''),
                                    'search_pattern': pattern,
                                    'content_preview': paste.get('content_preview', ''),
                                    'sensitive_data': content_analysis.get('sensitive_data', []),
                                    'risk_score': content_analysis.get('risk_score', 0),
                                    'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                                }
                                
                                self.results['historical_pastes'].append(paste_result)
                                
                                # Categorize based on content
                                if content_analysis.get('has_credentials'):
                                    self.results['credential_leaks'].append(paste_result)
                                    print_warning(f"Credential leak found: {paste.get('title', 'Unknown')}")
                                elif content_analysis.get('has_code'):
                                    self.results['code_exposures'].append(paste_result)
                                    print_warning(f"Code exposure found: {paste.get('title', 'Unknown')}")
                                else:
                                    print_success(f"Paste found: {paste.get('title', 'Unknown')}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print_warning(f"Error searching {site_name} for '{pattern}': {str(e)}")
                    continue

    def monitor_recent_pastes(self):
        """
        Monitor recent pastes for real-time detection
        """
        print_info(f"Starting real-time monitoring for {self.monitor_duration} seconds...")
        
        start_time = time.time()
        monitoring_threads = []
        
        for site_name, site_config in self.paste_sites.items():
            if site_config.get('requires_auth', False):
                continue
            
            thread = threading.Thread(
                target=self._monitor_site_recent_pastes,
                args=(site_name, site_config, start_time)
            )
            thread.daemon = True
            monitoring_threads.append(thread)
            thread.start()
        
        # Wait for monitoring to complete
        time.sleep(self.monitor_duration)
        
        print_success("Real-time monitoring completed")

    def _monitor_site_recent_pastes(self, site_name, site_config, start_time):
        """
        Monitor recent pastes for a specific site
        
        Args:
            site_name (str): Name of the paste site
            site_config (dict): Site configuration
            start_time (float): Monitoring start time
        """
        print_info(f"Monitoring {site_name} for recent pastes...")
        
        while time.time() - start_time < self.monitor_duration:
            try:
                recent_url = site_config.get('recent_url')
                if not recent_url:
                    break
                
                headers = {
                    'User-Agent': self.user_agents[0],
                    'Accept': 'text/html,application/xhtml+xml'
                }
                
                response = self.session.get(
                    recent_url,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    recent_pastes = self._extract_recent_pastes(response.text, site_name)
                    
                    for paste in recent_pastes:
                        if self._contains_target_content(paste):
                            paste_id = self._generate_paste_id(paste)
                            
                            if paste_id not in self.seen_pastes:
                                self.seen_pastes.add(paste_id)
                                
                                # Get full paste content
                                content = self._get_paste_content(paste.get('url', ''), site_name)
                                
                                if content and self._contains_target_content({'content': content}):
                                    content_analysis = self._analyze_content_for_sensitive_data(content)
                                    
                                    detection = {
                                        'site': site_name,
                                        'title': paste.get('title', ''),
                                        'url': paste.get('url', ''),
                                        'author': paste.get('author', ''),
                                        'date': paste.get('date', ''),
                                        'content_preview': content[:500] + '...' if len(content) > 500 else content,
                                        'sensitive_data': content_analysis.get('sensitive_data', []),
                                        'risk_score': content_analysis.get('risk_score', 0),
                                        'detection_type': 'real_time',
                                        'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                                    }
                                    
                                    self.results['paste_detections'].append(detection)
                                    print_warning(f"REAL-TIME DETECTION: {paste.get('title', 'Unknown')} on {site_name}")
                
                time.sleep(self.delay * 2)  # Longer delay for real-time monitoring
                
            except Exception as e:
                print_warning(f"Error monitoring {site_name}: {str(e)}")
                break

    def analyze_paste_site_exposure(self):
        """
        Analyze overall exposure across paste sites
        """
        print_info(f"Analyzing paste site exposure for '{self.target}'...")
        
        exposure_summary = {
            'total_sites_checked': len(self.paste_sites),
            'sites_with_detections': 0,
            'total_pastes_found': len(self.results['historical_pastes']),
            'credential_leaks': len(self.results['credential_leaks']),
            'code_exposures': len(self.results['code_exposures']),
            'high_risk_pastes': 0,
            'medium_risk_pastes': 0,
            'low_risk_pastes': 0
        }
        
        sites_with_detections = set()
        
        for paste in self.results['historical_pastes']:
            sites_with_detections.add(paste['site'])
            
            risk_score = paste.get('risk_score', 0)
            if risk_score >= 8:
                exposure_summary['high_risk_pastes'] += 1
            elif risk_score >= 5:
                exposure_summary['medium_risk_pastes'] += 1
            else:
                exposure_summary['low_risk_pastes'] += 1
        
        exposure_summary['sites_with_detections'] = len(sites_with_detections)
        
        # Add monitored sites info
        for site in sites_with_detections:
            self.results['monitored_sites'].append({
                'site': site,
                'status': 'detections_found',
                'last_checked': time.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        self.results['exposure_summary'] = exposure_summary
        
        print_info(f"Exposure analysis complete:")
        print_info(f"- Sites with detections: {exposure_summary['sites_with_detections']}/{exposure_summary['total_sites_checked']}")
        print_info(f"- Total pastes found: {exposure_summary['total_pastes_found']}")
        print_info(f"- High risk pastes: {exposure_summary['high_risk_pastes']}")

    def _extract_paste_results(self, html_content, site_name, search_pattern):
        """
        Extract paste results from search pages
        
        Args:
            html_content (str): HTML content from search page
            site_name (str): Name of the paste site
            search_pattern (str): Search pattern used
            
        Returns:
            list: List of paste dictionaries
        """
        pastes = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Site-specific parsing
            if 'pastebin.com' in site_name:
                results = soup.find_all('div', class_='gsc-result')
                for result in results:
                    title_elem = result.find('a')
                    title = title_elem.get_text().strip() if title_elem else 'No title'
                    url = title_elem.get('href', '') if title_elem else ''
                    
                    pastes.append({
                        'title': title,
                        'url': url,
                        'author': '',
                        'date': '',
                        'content_preview': ''
                    })
            
            elif 'paste.ee' in site_name:
                results = soup.find_all('div', class_='paste-item')
                for result in results:
                    title_elem = result.find('h3')
                    title = title_elem.get_text().strip() if title_elem else 'No title'
                    
                    link_elem = result.find('a', href=True)
                    url = link_elem.get('href', '') if link_elem else ''
                    if url and not url.startswith('http'):
                        url = f"https://paste.ee{url}"
                    
                    pastes.append({
                        'title': title,
                        'url': url,
                        'author': '',
                        'date': '',
                        'content_preview': ''
                    })
            
            else:
                # Generic parsing for other sites
                results = soup.find_all(['div', 'li', 'tr'], class_=re.compile(r'paste|result|item'))
                for result in results:
                    title_elem = result.find(['a', 'h3', 'h2'])
                    title = title_elem.get_text().strip() if title_elem else 'No title'
                    
                    link_elem = result.find('a', href=True)
                    url = link_elem.get('href', '') if link_elem else ''
                    
                    if title and url:
                        pastes.append({
                            'title': title,
                            'url': url,
                            'author': '',
                            'date': '',
                            'content_preview': ''
                        })
            
        except Exception as e:
            print_warning(f"Error extracting paste results from {site_name}: {str(e)}")
        
        return pastes

    def _extract_recent_pastes(self, html_content, site_name):
        """
        Extract recent pastes from recent/archive pages
        
        Args:
            html_content (str): HTML content from recent page
            site_name (str): Name of the paste site
            
        Returns:
            list: List of recent paste dictionaries
        """
        return self._extract_paste_results(html_content, site_name, 'recent')

    def _contains_target_content(self, paste):
        """
        Check if paste contains target-related content
        
        Args:
            paste (dict): Paste information
            
        Returns:
            bool: True if contains target content
        """
        content_to_check = ' '.join([
            paste.get('title', ''),
            paste.get('content', ''),
            paste.get('content_preview', '')
        ]).lower()
        
        target_keywords = [
            self.target.lower(),
            self.target.split('.')[0].lower() if '.' in self.target else self.target.lower(),
            self.target.replace('.', '').lower()
        ]
        
        return any(keyword in content_to_check for keyword in target_keywords)

    def _get_paste_content(self, paste_url, site_name):
        """
        Get full content of a paste
        
        Args:
            paste_url (str): URL of the paste
            site_name (str): Name of the paste site
            
        Returns:
            str: Paste content or empty string
        """
        try:
            if not paste_url:
                return ''
            
            headers = {
                'User-Agent': self.user_agents[0],
                'Accept': 'text/html,application/xhtml+xml'
            }
            
            response = self.session.get(
                paste_url,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Site-specific content extraction
                if 'pastebin.com' in site_name:
                    content_elem = soup.find('textarea', id='paste_code')
                    if not content_elem:
                        content_elem = soup.find('div', id='paste_code')
                elif 'paste.ee' in site_name:
                    content_elem = soup.find('div', class_='paste-content')
                else:
                    # Generic extraction
                    content_elem = soup.find(['textarea', 'pre', 'code']) or soup.find('div', class_=re.compile(r'content|paste|code'))
                
                if content_elem:
                    return content_elem.get_text().strip()
            
        except Exception as e:
            print_warning(f"Error getting paste content from {paste_url}: {str(e)}")
        
        return ''

    def _analyze_paste_content(self, paste, site_name):
        """
        Analyze paste content for sensitive information
        
        Args:
            paste (dict): Paste information
            site_name (str): Name of the paste site
            
        Returns:
            dict: Analysis results
        """
        content = paste.get('content_preview', '')
        
        # Try to get full content if only preview available
        if len(content) < 100 and paste.get('url'):
            full_content = self._get_paste_content(paste.get('url'), site_name)
            if full_content:
                content = full_content
        
        return self._analyze_content_for_sensitive_data(content)

    def _analyze_content_for_sensitive_data(self, content):
        """
        Analyze content for sensitive data patterns
        
        Args:
            content (str): Content to analyze
            
        Returns:
            dict: Analysis results with sensitive data found
        """
        sensitive_data = []
        risk_score = 0
        has_credentials = False
        has_code = False
        
        for data_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, content)
            
            if matches:
                sensitive_data.append({
                    'type': data_type,
                    'count': len(matches),
                    'samples': matches[:3] if data_type != 'passwords' else ['***REDACTED***'] * min(3, len(matches))
                })
                
                # Calculate risk score
                if data_type in ['passwords', 'private_keys', 'aws_keys']:
                    risk_score += 10
                    has_credentials = True
                elif data_type in ['api_keys', 'jwt_tokens', 'database_urls']:
                    risk_score += 8
                    has_code = True
                elif data_type in ['emails', 'credit_cards']:
                    risk_score += 6
                    has_credentials = True
                else:
                    risk_score += 3
        
        # Check for target-specific mentions
        target_mentions = len(re.findall(re.escape(self.target), content, re.IGNORECASE))
        if target_mentions > 0:
            risk_score += min(target_mentions * 2, 5)
        
        return {
            'sensitive_data': sensitive_data,
            'risk_score': min(risk_score, 10),  # Cap at 10
            'has_credentials': has_credentials,
            'has_code': has_code,
            'target_mentions': target_mentions
        }

    def _generate_paste_id(self, paste):
        """
        Generate unique ID for a paste to avoid duplicates
        
        Args:
            paste (dict): Paste information
            
        Returns:
            str: Unique paste ID
        """
        unique_string = f"{paste.get('url', '')}{paste.get('title', '')}{paste.get('date', '')}"
        return hashlib.md5(unique_string.encode()).hexdigest()

    def run(self, output_format='json', output_dir='output'):
        """
        Run the pastebin monitoring
        
        Args:
            output_format (str): Output format (json, csv, txt)
            output_dir (str): Output directory
            
        Returns:
            dict: Results dictionary
        """
        print_info(f"Starting pastebin monitoring for: {self.target}")
        print_warning("DISCLAIMER: This module is for authorized security testing only!")
        
        try:
            # Search historical pastes
            self.search_historical_pastes()
            
            # Monitor recent pastes
            if self.monitor_duration > 0:
                self.monitor_recent_pastes()
            
            # Analyze exposure
            self.analyze_paste_site_exposure()
            
            # Calculate statistics
            total_pastes = len(self.results['historical_pastes'])
            total_detections = len(self.results['paste_detections'])
            total_credential_leaks = len(self.results['credential_leaks'])
            total_code_exposures = len(self.results['code_exposures'])
            
            print_success(f"Pastebin monitoring completed!")
            print_info(f"Found {total_pastes} historical pastes")
            print_info(f"Found {total_detections} real-time detections")
            print_info(f"Found {total_credential_leaks} credential leaks")
            print_info(f"Found {total_code_exposures} code exposures")
            
            # Save results
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"pastebin_monitor_{self.target}_{timestamp}"
            
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
            print_warning("Pastebin monitoring interrupted by user")
            return self.results
        except Exception as e:
            print_error(f"Error during pastebin monitoring: {str(e)}")
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
            
            # Historical pastes
            writer.writerow(['Historical Pastes'])
            writer.writerow(['Site', 'Title', 'URL', 'Risk Score', 'Sensitive Data Count', 'Discovered At'])
            for paste in self.results['historical_pastes']:
                sensitive_count = len(paste.get('sensitive_data', []))
                writer.writerow([
                    paste.get('site', ''),
                    paste.get('title', ''),
                    paste.get('url', ''),
                    paste.get('risk_score', 0),
                    sensitive_count,
                    paste.get('discovered_at', '')
                ])
            
            writer.writerow([])
            
            # Credential leaks
            writer.writerow(['Credential Leaks'])
            writer.writerow(['Site', 'Title', 'URL', 'Risk Score', 'Discovered At'])
            for leak in self.results['credential_leaks']:
                writer.writerow([
                    leak.get('site', ''),
                    leak.get('title', ''),
                    leak.get('url', ''),
                    leak.get('risk_score', 0),
                    leak.get('discovered_at', '')
                ])

    def _save_to_txt(self, filename):
        """
        Save results to TXT format
        
        Args:
            filename (str): Output filename
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Pastebin Monitoring Results for: {self.target}\n")
            f.write(f"Generated: {self.results['timestamp']}\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("EXPOSURE SUMMARY:\n")
            f.write("-" * 20 + "\n")
            if 'exposure_summary' in self.results:
                summary = self.results['exposure_summary']
                f.write(f"Total sites checked: {summary.get('total_sites_checked', 0)}\n")
                f.write(f"Sites with detections: {summary.get('sites_with_detections', 0)}\n")
                f.write(f"Total pastes found: {summary.get('total_pastes_found', 0)}\n")
                f.write(f"High risk pastes: {summary.get('high_risk_pastes', 0)}\n")
                f.write(f"Medium risk pastes: {summary.get('medium_risk_pastes', 0)}\n")
                f.write(f"Low risk pastes: {summary.get('low_risk_pastes', 0)}\n\n")
            
            f.write("CREDENTIAL LEAKS:\n")
            f.write("-" * 20 + "\n")
            for leak in self.results['credential_leaks']:
                f.write(f"Site: {leak.get('site', '')}\n")
                f.write(f"Title: {leak.get('title', '')}\n")
                f.write(f"URL: {leak.get('url', '')}\n")
                f.write(f"Risk Score: {leak.get('risk_score', 0)}/10\n")
                f.write(f"Discovered: {leak.get('discovered_at', '')}\n\n")
            
            f.write("CODE EXPOSURES:\n")
            f.write("-" * 20 + "\n")
            for exposure in self.results['code_exposures']:
                f.write(f"Site: {exposure.get('site', '')}\n")
                f.write(f"Title: {exposure.get('title', '')}\n")
                f.write(f"URL: {exposure.get('url', '')}\n")
                f.write(f"Risk Score: {exposure.get('risk_score', 0)}/10\n")
                f.write(f"Discovered: {exposure.get('discovered_at', '')}\n\n")


def main():
    """
    Main function for testing the pastebin monitor module
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='NocturneRecon Pastebin Monitor Module')
    parser.add_argument('--target', '-t', required=True, help='Target domain or organization')
    parser.add_argument('--output', '-o', default='json', help='Output format (json, csv, txt)')
    parser.add_argument('--output-dir', '-d', default='output', help='Output directory')
    parser.add_argument('--threads', default=3, type=int, help='Number of threads')
    parser.add_argument('--delay', default=2.0, type=float, help='Delay between requests')
    parser.add_argument('--timeout', default=15, type=int, help='Request timeout')
    parser.add_argument('--monitor-duration', default=300, type=int, help='Real-time monitoring duration (seconds)')
    
    args = parser.parse_args()
    
    config = {
        'threads': args.threads,
        'delay': args.delay,
        'timeout': args.timeout,
        'monitor_duration': args.monitor_duration
    }
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Run pastebin monitoring
    monitor = PastebinMonitor(args.target, config)
    results = monitor.run(args.output, args.output_dir)
    
    print(f"\nPastebin monitoring completed for {args.target}")
    print(f"Results saved to {args.output_dir}/")


if __name__ == "__main__":
    main()
