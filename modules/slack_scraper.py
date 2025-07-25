#!/usr/bin/env python3
"""
NocturneRecon Slack Intelligence Module
Author: Muzan Sano
Version: 2.0.0-dev
License: MIT

This module provides Slack workspace intelligence capabilities including:
- Slack workspace enumeration
- Exposed chat leak detection
- Public channel discovery
- Slack integration vulnerability scanning
"""

import os
import sys
import time
import requests
import threading
import re
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import print_info, print_success, print_warning, print_error, save_to_json, save_to_csv, save_to_txt


class SlackIntelligenceGatherer:
    """
    Slack Intelligence Gathering class for workspace enumeration and leak detection
    """
    
    def __init__(self, target, config=None):
        """
        Initialize the Slack Intelligence Gatherer
        
        Args:
            target (str): Target domain or organization to search for
            config (dict): Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'slack_workspaces': [],
            'public_channels': [],
            'exposed_messages': [],
            'slack_integrations': [],
            'archived_channels': [],
            'user_enumeration': []
        }
        
        # Slack workspace discovery patterns
        self.workspace_patterns = [
            f"{self.target.split('.')[0]}.slack.com",
            f"{self.target.replace('.', '')}.slack.com",
            f"{self.target.split('.')[0]}-team.slack.com",
            f"{self.target.split('.')[0]}hq.slack.com"
        ]
        
        # Common Slack subdomains
        self.slack_subdomains = [
            'team', 'corp', 'company', 'dev', 'eng', 'engineering',
            'sales', 'marketing', 'support', 'ops', 'security',
            'hr', 'finance', 'admin', 'main', 'general'
        ]
        
        # Search engines and sources for Slack content
        self.search_sources = [
            'google.com',
            'bing.com',
            'github.com',
            'pastebin.com',
            'archive.org'
        ]
        
        # Slack-specific search patterns
        self.slack_search_patterns = [
            f'site:slack.com "{self.target}"',
            f'site:slack.com intitle:"{self.target}"',
            f'"slack.com/{self.target}"',
            f'"{self.target}.slack.com"',
            f'slack webhook {self.target}',
            f'slack token {self.target}',
            f'slack api {self.target}'
        ]
        
        # Common exposed Slack content patterns
        self.exposure_patterns = [
            r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+',  # Webhooks
            r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+',  # Bot tokens
            r'xoxp-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+',  # User tokens
            r'xoxa-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+',  # App tokens
            r'xoxr-[0-9]+-[0-9]+-[a-zA-Z0-9]+',  # Refresh tokens
        ]
        
        self.threads = self.config.get('threads', 5)
        self.delay = self.config.get('delay', 1.5)
        self.timeout = self.config.get('timeout', 10)
        
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
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]

    def enumerate_slack_workspaces(self):
        """
        Enumerate potential Slack workspaces for the target organization
        """
        print_info(f"Enumerating Slack workspaces for '{self.target}'...")
        
        # Generate workspace patterns
        workspace_candidates = []
        
        # Add primary patterns
        workspace_candidates.extend(self.workspace_patterns)
        
        # Add subdomain variations
        base_name = self.target.split('.')[0]
        for subdomain in self.slack_subdomains:
            workspace_candidates.extend([
                f"{base_name}-{subdomain}.slack.com",
                f"{subdomain}-{base_name}.slack.com",
                f"{base_name}{subdomain}.slack.com"
            ])
        
        # Test each workspace candidate
        for workspace in workspace_candidates:
            try:
                print_info(f"Testing workspace: {workspace}")
                
                # Try to access the workspace
                workspace_url = f"https://{workspace}"
                
                headers = {
                    'User-Agent': self.user_agents[0],
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
                
                response = self.session.get(
                    workspace_url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                if response.status_code == 200 and 'slack' in response.text.lower():
                    workspace_info = self._analyze_slack_workspace(response.text, workspace)
                    
                    if workspace_info:
                        self.results['slack_workspaces'].append({
                            'workspace': workspace,
                            'status': 'active',
                            'title': workspace_info.get('title', ''),
                            'description': workspace_info.get('description', ''),
                            'public_signup': workspace_info.get('public_signup', False),
                            'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        print_success(f"Active Slack workspace found: {workspace}")
                        
                        # Try to discover public channels
                        self._discover_public_channels(workspace)
                
                time.sleep(self.delay)
                
            except Exception as e:
                print_warning(f"Error checking workspace {workspace}: {str(e)}")
                continue

    def search_for_slack_mentions(self):
        """
        Search for Slack-related mentions across various sources
        """
        print_info(f"Searching for Slack mentions related to '{self.target}'...")
        
        for pattern in self.slack_search_patterns:
            for source in self.search_sources:
                try:
                    print_info(f"Searching {source} for: {pattern}")
                    
                    if source == 'google.com':
                        search_url = f"https://www.google.com/search?q={quote(pattern)}"
                    elif source == 'bing.com':
                        search_url = f"https://www.bing.com/search?q={quote(pattern)}"
                    elif source == 'github.com':
                        search_url = f"https://github.com/search?q={quote(pattern)}&type=code"
                    else:
                        continue
                    
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
                        mentions = self._extract_slack_mentions(response.text, source, pattern)
                        for mention in mentions:
                            # Check for exposed tokens or webhooks
                            exposed_secrets = self._check_for_exposed_secrets(mention.get('content', ''))
                            
                            slack_mention = {
                                'title': mention.get('title', ''),
                                'url': mention.get('url', ''),
                                'source': source,
                                'search_pattern': pattern,
                                'exposed_secrets': exposed_secrets,
                                'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                            }
                            
                            self.results['exposed_messages'].append(slack_mention)
                            
                            if exposed_secrets:
                                print_warning(f"Exposed Slack secrets found in: {mention.get('title', 'Unknown')}")
                            else:
                                print_success(f"Slack mention found: {mention.get('title', 'Unknown')}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print_warning(f"Error searching {source}: {str(e)}")
                    continue

    def scan_slack_integrations(self):
        """
        Scan for exposed Slack integrations and webhooks
        """
        print_info(f"Scanning for Slack integrations related to '{self.target}'...")
        
        integration_search_terms = [
            f'{self.target} slack webhook',
            f'{self.target} slack bot',
            f'{self.target} slack app',
            f'{self.target} slack integration',
            f'slack token {self.target}',
            f'SLACK_TOKEN {self.target}',
            f'hooks.slack.com {self.target}'
        ]
        
        for term in integration_search_terms:
            try:
                print_info(f"Searching for integrations: {term}")
                
                # Search GitHub for exposed integrations
                github_url = f"https://github.com/search?q={quote(term)}&type=code"
                
                headers = {
                    'User-Agent': self.user_agents[0],
                    'Accept': 'text/html,application/xhtml+xml'
                }
                
                response = self.session.get(
                    github_url,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    integrations = self._extract_github_integrations(response.text)
                    
                    for integration in integrations:
                        # Analyze the integration for security issues
                        security_analysis = self._analyze_integration_security(integration)
                        
                        self.results['slack_integrations'].append({
                            'title': integration.get('title', ''),
                            'url': integration.get('url', ''),
                            'repository': integration.get('repository', ''),
                            'file_path': integration.get('file_path', ''),
                            'security_issues': security_analysis,
                            'search_term': term,
                            'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        
                        if security_analysis:
                            print_warning(f"Security issues found in integration: {integration.get('title', 'Unknown')}")
                        else:
                            print_success(f"Slack integration found: {integration.get('title', 'Unknown')}")
                
                time.sleep(self.delay)
                
            except Exception as e:
                print_warning(f"Error scanning integrations for '{term}': {str(e)}")
                continue

    def enumerate_slack_users(self):
        """
        Enumerate Slack users from discovered workspaces
        """
        print_info(f"Enumerating Slack users...")
        
        for workspace_data in self.results['slack_workspaces']:
            workspace = workspace_data['workspace']
            
            try:
                print_info(f"Enumerating users for workspace: {workspace}")
                
                # Try common user enumeration endpoints
                endpoints = [
                    f"https://{workspace}/api/users.list",
                    f"https://{workspace}/api/team.info",
                    f"https://{workspace}/customize/emoji"
                ]
                
                for endpoint in endpoints:
                    headers = {
                        'User-Agent': self.user_agents[0],
                        'Accept': 'application/json'
                    }
                    
                    response = self.session.get(
                        endpoint,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        users = self._extract_user_information(response.text, workspace)
                        
                        for user in users:
                            self.results['user_enumeration'].append({
                                'workspace': workspace,
                                'username': user.get('username', ''),
                                'display_name': user.get('display_name', ''),
                                'email': user.get('email', ''),
                                'profile_image': user.get('profile_image', ''),
                                'is_admin': user.get('is_admin', False),
                                'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                            })
                            print_success(f"User found: {user.get('username', 'Unknown')}")
                    
                    time.sleep(self.delay / 2)
                
            except Exception as e:
                print_warning(f"Error enumerating users for {workspace}: {str(e)}")
                continue

    def _analyze_slack_workspace(self, html_content, workspace):
        """
        Analyze Slack workspace HTML to extract information
        
        Args:
            html_content (str): HTML content of the workspace page
            workspace (str): Workspace domain
            
        Returns:
            dict: Workspace information
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract title
            title_elem = soup.find('title')
            title = title_elem.get_text().strip() if title_elem else ''
            
            # Extract description
            description_elem = soup.find('meta', attrs={'name': 'description'})
            description = description_elem.get('content', '') if description_elem else ''
            
            # Check for public signup
            public_signup = 'sign up' in html_content.lower() or 'join' in html_content.lower()
            
            return {
                'title': title,
                'description': description,
                'public_signup': public_signup
            }
            
        except Exception:
            return None

    def _discover_public_channels(self, workspace):
        """
        Discover public channels for a Slack workspace
        
        Args:
            workspace (str): Slack workspace domain
        """
        try:
            print_info(f"Discovering public channels for: {workspace}")
            
            # Try to access public channel listings
            channel_endpoints = [
                f"https://{workspace}/archives",
                f"https://{workspace}/channels",
                f"https://{workspace}/messages/general"
            ]
            
            for endpoint in channel_endpoints:
                headers = {
                    'User-Agent': self.user_agents[0],
                    'Accept': 'text/html,application/xhtml+xml'
                }
                
                response = self.session.get(
                    endpoint,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    channels = self._extract_channel_information(response.text, workspace)
                    
                    for channel in channels:
                        self.results['public_channels'].append({
                            'workspace': workspace,
                            'channel_name': channel.get('name', ''),
                            'channel_id': channel.get('id', ''),
                            'member_count': channel.get('member_count', 0),
                            'last_activity': channel.get('last_activity', ''),
                            'discovered_at': time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        print_success(f"Public channel found: {channel.get('name', 'Unknown')}")
                
                time.sleep(self.delay / 2)
                
        except Exception as e:
            print_warning(f"Error discovering channels for {workspace}: {str(e)}")

    def _extract_slack_mentions(self, html_content, source, pattern):
        """
        Extract Slack mentions from search results
        
        Args:
            html_content (str): HTML content to parse
            source (str): Source website
            pattern (str): Search pattern used
            
        Returns:
            list: List of mention dictionaries
        """
        mentions = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Different parsing for different sources
            if 'google.com' in source:
                results = soup.find_all('div', class_='g')
            elif 'bing.com' in source:
                results = soup.find_all('li', class_='b_algo')
            elif 'github.com' in source:
                results = soup.find_all('div', class_='f4')
            else:
                results = soup.find_all(['div', 'li', 'article'])
            
            for result in results:
                title_elem = result.find(['h3', 'h2', 'a'])
                title = title_elem.get_text().strip() if title_elem else 'No title'
                
                link_elem = result.find('a', href=True)
                url = link_elem['href'] if link_elem else ''
                
                content_elem = result.find(['p', 'div', 'span'])
                content = content_elem.get_text().strip() if content_elem else ''
                
                if title and (self.target.lower() in title.lower() or 
                             'slack' in title.lower() or
                             self.target.lower() in content.lower()):
                    mentions.append({
                        'title': title,
                        'url': url,
                        'content': content[:500] + '...' if len(content) > 500 else content
                    })
            
        except Exception as e:
            print_warning(f"Error extracting mentions from {source}: {str(e)}")
        
        return mentions

    def _check_for_exposed_secrets(self, content):
        """
        Check content for exposed Slack secrets
        
        Args:
            content (str): Content to analyze
            
        Returns:
            list: List of exposed secrets found
        """
        exposed_secrets = []
        
        for pattern in self.exposure_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                secret_type = 'unknown'
                if 'hooks.slack.com' in match:
                    secret_type = 'webhook_url'
                elif match.startswith('xoxb-'):
                    secret_type = 'bot_token'
                elif match.startswith('xoxp-'):
                    secret_type = 'user_token'
                elif match.startswith('xoxa-'):
                    secret_type = 'app_token'
                elif match.startswith('xoxr-'):
                    secret_type = 'refresh_token'
                
                exposed_secrets.append({
                    'type': secret_type,
                    'value': match[:20] + '...' if len(match) > 20 else match,
                    'full_match': match
                })
        
        return exposed_secrets

    def _extract_github_integrations(self, html_content):
        """
        Extract Slack integrations from GitHub search results
        
        Args:
            html_content (str): HTML content from GitHub search
            
        Returns:
            list: List of integration dictionaries
        """
        integrations = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # GitHub code search results
            results = soup.find_all('div', class_='f4')
            
            for result in results:
                title_elem = result.find('a')
                title = title_elem.get_text().strip() if title_elem else 'No title'
                
                url_elem = result.find('a', href=True)
                url = url_elem['href'] if url_elem else ''
                if url and not url.startswith('http'):
                    url = f"https://github.com{url}"
                
                # Extract repository and file path
                repo_match = re.search(r'github\.com/([^/]+/[^/]+)', url)
                repository = repo_match.group(1) if repo_match else ''
                
                file_match = re.search(r'/blob/[^/]+/(.+)$', url)
                file_path = file_match.group(1) if file_match else ''
                
                integrations.append({
                    'title': title,
                    'url': url,
                    'repository': repository,
                    'file_path': file_path
                })
            
        except Exception as e:
            print_warning(f"Error extracting GitHub integrations: {str(e)}")
        
        return integrations

    def _analyze_integration_security(self, integration):
        """
        Analyze integration for security issues
        
        Args:
            integration (dict): Integration information
            
        Returns:
            list: List of security issues found
        """
        security_issues = []
        
        # Check for common security issues in the file path
        file_path = integration.get('file_path', '').lower()
        title = integration.get('title', '').lower()
        
        if any(keyword in file_path for keyword in ['config', 'env', 'secret', 'key']):
            security_issues.append('Potential secrets in configuration file')
        
        if any(keyword in file_path for keyword in ['docker', 'dockerfile']):
            security_issues.append('Slack credentials in Docker configuration')
        
        if any(keyword in title for keyword in ['token', 'webhook', 'api_key']):
            security_issues.append('Exposed Slack credentials in filename')
        
        if 'public' in integration.get('repository', '').lower():
            security_issues.append('Credentials in public repository')
        
        return security_issues

    def _extract_channel_information(self, html_content, workspace):
        """
        Extract channel information from Slack workspace
        
        Args:
            html_content (str): HTML content from Slack workspace
            workspace (str): Workspace domain
            
        Returns:
            list: List of channel dictionaries
        """
        channels = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Look for channel listings
            channel_elements = soup.find_all(['div', 'li', 'span'], class_=re.compile(r'channel|room'))
            
            for elem in channel_elements:
                channel_name = elem.get_text().strip()
                
                if channel_name and len(channel_name) > 0 and len(channel_name) < 50:
                    # Clean channel name
                    channel_name = re.sub(r'[^a-zA-Z0-9-_]', '', channel_name)
                    
                    if channel_name:
                        channels.append({
                            'name': channel_name,
                            'id': '',  # Usually requires authentication
                            'member_count': 0,  # Usually requires authentication
                            'last_activity': ''  # Usually requires authentication
                        })
            
        except Exception as e:
            print_warning(f"Error extracting channel info from {workspace}: {str(e)}")
        
        return channels

    def _extract_user_information(self, content, workspace):
        """
        Extract user information from Slack API responses
        
        Args:
            content (str): Response content
            workspace (str): Workspace domain
            
        Returns:
            list: List of user dictionaries
        """
        users = []
        
        try:
            # Try to parse as JSON first
            import json
            data = json.loads(content)
            
            if isinstance(data, dict) and 'members' in data:
                for member in data['members']:
                    users.append({
                        'username': member.get('name', ''),
                        'display_name': member.get('real_name', ''),
                        'email': member.get('profile', {}).get('email', ''),
                        'profile_image': member.get('profile', {}).get('image_72', ''),
                        'is_admin': member.get('is_admin', False)
                    })
            
        except (json.JSONDecodeError, KeyError):
            # Fallback to HTML parsing
            soup = BeautifulSoup(content, 'html.parser')
            
            # Look for user mentions or listings
            user_elements = soup.find_all(['span', 'div'], class_=re.compile(r'user|member'))
            
            for elem in user_elements:
                username = elem.get_text().strip()
                if username and len(username) < 50:
                    users.append({
                        'username': username,
                        'display_name': '',
                        'email': '',
                        'profile_image': '',
                        'is_admin': False
                    })
        
        return users

    def run(self, output_format='json', output_dir='output'):
        """
        Run the Slack intelligence gathering
        
        Args:
            output_format (str): Output format (json, csv, txt)
            output_dir (str): Output directory
            
        Returns:
            dict: Results dictionary
        """
        print_info(f"Starting Slack intelligence gathering for: {self.target}")
        print_warning("DISCLAIMER: This module is for authorized security testing only!")
        
        try:
            # Enumerate Slack workspaces
            self.enumerate_slack_workspaces()
            
            # Search for Slack mentions
            self.search_for_slack_mentions()
            
            # Scan for Slack integrations
            self.scan_slack_integrations()
            
            # Enumerate users (if workspaces found)
            if self.results['slack_workspaces']:
                self.enumerate_slack_users()
            
            # Calculate statistics
            total_workspaces = len(self.results['slack_workspaces'])
            total_channels = len(self.results['public_channels'])
            total_exposures = len(self.results['exposed_messages'])
            total_integrations = len(self.results['slack_integrations'])
            total_users = len(self.results['user_enumeration'])
            
            print_success(f"Slack intelligence gathering completed!")
            print_info(f"Found {total_workspaces} Slack workspaces")
            print_info(f"Found {total_channels} public channels")
            print_info(f"Found {total_exposures} exposed messages/mentions")
            print_info(f"Found {total_integrations} Slack integrations")
            print_info(f"Found {total_users} users")
            
            # Save results
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"slack_intel_{self.target}_{timestamp}"
            
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
            print_warning("Slack intelligence gathering interrupted by user")
            return self.results
        except Exception as e:
            print_error(f"Error during Slack intelligence gathering: {str(e)}")
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
            
            # Slack workspaces
            writer.writerow(['Slack Workspaces'])
            writer.writerow(['Workspace', 'Status', 'Title', 'Public Signup', 'Discovered At'])
            for workspace in self.results['slack_workspaces']:
                writer.writerow([
                    workspace.get('workspace', ''),
                    workspace.get('status', ''),
                    workspace.get('title', ''),
                    workspace.get('public_signup', ''),
                    workspace.get('discovered_at', '')
                ])
            
            writer.writerow([])
            
            # Exposed messages
            writer.writerow(['Exposed Messages/Mentions'])
            writer.writerow(['Title', 'URL', 'Source', 'Has Secrets', 'Discovered At'])
            for message in self.results['exposed_messages']:
                has_secrets = len(message.get('exposed_secrets', [])) > 0
                writer.writerow([
                    message.get('title', ''),
                    message.get('url', ''),
                    message.get('source', ''),
                    has_secrets,
                    message.get('discovered_at', '')
                ])

    def _save_to_txt(self, filename):
        """
        Save results to TXT format
        
        Args:
            filename (str): Output filename
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Slack Intelligence Gathering Results for: {self.target}\n")
            f.write(f"Generated: {self.results['timestamp']}\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("SLACK WORKSPACES:\n")
            f.write("-" * 20 + "\n")
            for workspace in self.results['slack_workspaces']:
                f.write(f"Workspace: {workspace.get('workspace', '')}\n")
                f.write(f"Status: {workspace.get('status', '')}\n")
                f.write(f"Title: {workspace.get('title', '')}\n")
                f.write(f"Public Signup: {workspace.get('public_signup', '')}\n\n")
            
            f.write("EXPOSED MESSAGES:\n")
            f.write("-" * 20 + "\n")
            for message in self.results['exposed_messages']:
                f.write(f"Title: {message.get('title', '')}\n")
                f.write(f"URL: {message.get('url', '')}\n")
                f.write(f"Source: {message.get('source', '')}\n")
                if message.get('exposed_secrets'):
                    f.write(f"Exposed Secrets: {len(message.get('exposed_secrets', []))}\n")
                f.write("\n")


def main():
    """
    Main function for testing the Slack intelligence module
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='NocturneRecon Slack Intelligence Module')
    parser.add_argument('--target', '-t', required=True, help='Target domain or organization')
    parser.add_argument('--output', '-o', default='json', help='Output format (json, csv, txt)')
    parser.add_argument('--output-dir', '-d', default='output', help='Output directory')
    parser.add_argument('--threads', default=5, type=int, help='Number of threads')
    parser.add_argument('--delay', default=1.5, type=float, help='Delay between requests')
    parser.add_argument('--timeout', default=10, type=int, help='Request timeout')
    
    args = parser.parse_args()
    
    config = {
        'threads': args.threads,
        'delay': args.delay,
        'timeout': args.timeout
    }
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Run Slack intelligence gathering
    gatherer = SlackIntelligenceGatherer(args.target, config)
    results = gatherer.run(args.output, args.output_dir)
    
    print(f"\nSlack intelligence gathering completed for {args.target}")
    print(f"Results saved to {args.output_dir}/")


if __name__ == "__main__":
    main()
