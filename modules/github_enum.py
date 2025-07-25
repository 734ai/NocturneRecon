"""
GitHub enumeration module for NocturneRecon
Searches for code, commits, issues, and potential secrets related to target
"""

import requests
import re
import time
from urllib.parse import quote
from pathlib import Path
from core.utils import (
    print_success, print_error, print_info, print_result, print_debug,
    is_valid_email, clean_domain,
    save_to_json, save_to_csv, save_to_txt, create_output_filename,
    ensure_directory
)
from core.config import get_user_agent

class GitHubEnumerator:
    """GitHub dorking and intelligence gathering"""
    
    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.target = clean_domain(args.target)
        self.verbose = args.verbose
        self.timeout = args.timeout
        self.results = {
            'repositories': [],
            'code_matches': [],
            'commit_matches': [],
            'issue_matches': [],
            'users': [],
            'emails': set(),
            'secrets': []
        }
        
        # Patterns for secret detection
        self.secret_patterns = {
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})', re.MULTILINE),
            'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}', re.MULTILINE),
            'aws_secret_key': re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/]{40})', re.MULTILINE),
            'github_token': re.compile(r'ghp_[a-zA-Z0-9]{36}', re.MULTILINE),
            'slack_token': re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}', re.MULTILINE),
            'password': re.compile(r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{8,})', re.MULTILINE),
            'private_key': re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----', re.MULTILINE),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.MULTILINE)
        }
        
    def run(self):
        """Main execution method"""
        print_info(f"Starting GitHub enumeration for: {self.target}")
        
        config = self.config.get('github_enum', {})
        
        # Search repositories
        print_info("Searching repositories...")
        self.search_repositories()
        
        # Search code
        if config.get('search_code', True):
            print_info("Searching code...")
            self.search_code()
        
        # Search commits
        if config.get('search_commits', True):
            print_info("Searching commits...")
            self.search_commits()
        
        # Search issues
        if config.get('search_issues', True):
            print_info("Searching issues...")
            self.search_issues()
        
        # Convert sets to lists for JSON serialization
        self.results['emails'] = sorted(list(self.results['emails']))
        
        total_items = (len(self.results['repositories']) + 
                      len(self.results['code_matches']) + 
                      len(self.results['commit_matches']) + 
                      len(self.results['issue_matches']))
        
        print_success(f"Found {total_items} total items")
        
        # Print summary if verbose
        if self.verbose:
            self.print_summary()
        
        return self.results
    
    def search_repositories(self):
        """Search for repositories related to target"""
        queries = [
            f'"{self.target}"',
            f'{self.target.replace(".", " ")}',
            f'org:{self.target.split(".")[0]}' if '.' in self.target else None
        ]
        
        for query in queries:
            if not query:
                continue
                
            try:
                url = f"https://github.com/search?q={quote(query)}&type=repositories"
                repos = self.scrape_github_search(url, 'repository')
                self.results['repositories'].extend(repos)
                
                time.sleep(self.args.delay)
                
            except Exception as e:
                print_error(f"Repository search failed for '{query}': {e}")
        
        # Deduplicate repositories
        seen_repos = set()
        unique_repos = []
        for repo in self.results['repositories']:
            repo_id = repo.get('full_name', '')
            if repo_id not in seen_repos:
                seen_repos.add(repo_id)
                unique_repos.append(repo)
        
        self.results['repositories'] = unique_repos
        print_debug(f"Found {len(self.results['repositories'])} repositories", self.verbose)
    
    def search_code(self):
        """Search for code containing target domain"""
        queries = [
            f'"{self.target}"',
            f'"@{self.target}"',
            f'"{self.target}" AND (password OR secret OR key OR token)',
            f'"{self.target}" AND (config OR configuration)',
            f'"{self.target}" extension:env',
            f'"{self.target}" extension:config',
            f'"{self.target}" extension:yml',
            f'"{self.target}" extension:yaml'
        ]
        
        for query in queries:
            try:
                url = f"https://github.com/search?q={quote(query)}&type=code"
                code_results = self.scrape_github_search(url, 'code')
                
                # Analyze code for secrets
                for code_item in code_results:
                    content = code_item.get('content', '')
                    secrets = self.analyze_content_for_secrets(content)
                    code_item['detected_secrets'] = secrets
                    self.results['secrets'].extend(secrets)
                
                self.results['code_matches'].extend(code_results)
                
                time.sleep(self.args.delay)
                
            except Exception as e:
                print_error(f"Code search failed for '{query}': {e}")
        
        print_debug(f"Found {len(self.results['code_matches'])} code matches", self.verbose)
    
    def search_commits(self):
        """Search for commits containing target domain"""
        queries = [
            f'"{self.target}"',
            f'"@{self.target}"',
            f'"{self.target}" AND (fix OR bug OR security)',
            f'"{self.target}" AND (remove OR delete OR clean)'
        ]
        
        for query in queries:
            try:
                url = f"https://github.com/search?q={quote(query)}&type=commits"
                commits = self.scrape_github_search(url, 'commit')
                
                # Extract emails from commit authors
                for commit in commits:
                    author_email = commit.get('author_email', '')
                    if author_email and self.target in author_email:
                        self.results['emails'].add(author_email)
                
                self.results['commit_matches'].extend(commits)
                
                time.sleep(self.args.delay)
                
            except Exception as e:
                print_error(f"Commit search failed for '{query}': {e}")
        
        print_debug(f"Found {len(self.results['commit_matches'])} commit matches", self.verbose)
    
    def search_issues(self):
        """Search for issues containing target domain"""
        queries = [
            f'"{self.target}"',
            f'"@{self.target}"',
            f'"{self.target}" AND (bug OR error OR problem)',
            f'"{self.target}" AND (security OR vulnerability)'
        ]
        
        for query in queries:
            try:
                url = f"https://github.com/search?q={quote(query)}&type=issues"
                issues = self.scrape_github_search(url, 'issue')
                self.results['issue_matches'].extend(issues)
                
                time.sleep(self.args.delay)
                
            except Exception as e:
                print_error(f"Issue search failed for '{query}': {e}")
        
        print_debug(f"Found {len(self.results['issue_matches'])} issue matches", self.verbose)
    
    def scrape_github_search(self, url, search_type):
        """Scrape GitHub search results"""
        results = []
        
        try:
            headers = {
                'User-Agent': get_user_agent(self.config),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            if search_type == 'repository':
                results = self.parse_repository_results(soup)
            elif search_type == 'code':
                results = self.parse_code_results(soup)
            elif search_type == 'commit':
                results = self.parse_commit_results(soup)
            elif search_type == 'issue':
                results = self.parse_issue_results(soup)
            
        except requests.RequestException as e:
            print_error(f"GitHub search request failed: {e}")
        except Exception as e:
            print_error(f"Error parsing GitHub search results: {e}")
        
        return results
    
    def parse_repository_results(self, soup):
        """Parse repository search results from HTML"""
        results = []
        
        # GitHub search result structure may change
        repo_items = soup.find_all('div', class_='f4')
        
        for item in repo_items:
            try:
                link = item.find('a')
                if link:
                    repo_name = link.get_text(strip=True)
                    repo_url = f"https://github.com{link.get('href', '')}"
                    
                    # Get description
                    desc_elem = item.find_next('p')
                    description = desc_elem.get_text(strip=True) if desc_elem else ''
                    
                    results.append({
                        'name': repo_name,
                        'url': repo_url,
                        'description': description,
                        'full_name': repo_name
                    })
            except Exception as e:
                print_debug(f"Error parsing repository item: {e}", self.verbose)
        
        return results
    
    def parse_code_results(self, soup):
        """Parse code search results from HTML"""
        results = []
        
        # This is a simplified parser - GitHub's structure is complex
        # In production, you might want to use GitHub's API or more sophisticated scraping
        
        code_items = soup.find_all('div', class_='code-list-item')
        
        for item in code_items:
            try:
                # Extract file path and repository
                title_elem = item.find('div', class_='f4')
                if title_elem:
                    link = title_elem.find('a')
                    if link:
                        file_path = link.get_text(strip=True)
                        file_url = f"https://github.com{link.get('href', '')}"
                        
                        # Extract code snippet
                        code_elem = item.find('div', class_='code-list-item-code')
                        content = code_elem.get_text() if code_elem else ''
                        
                        results.append({
                            'file_path': file_path,
                            'url': file_url,
                            'content': content,
                            'repository': file_path.split('/')[0] if '/' in file_path else ''
                        })
            except Exception as e:
                print_debug(f"Error parsing code item: {e}", self.verbose)
        
        return results
    
    def parse_commit_results(self, soup):
        """Parse commit search results from HTML"""
        results = []
        
        commit_items = soup.find_all('div', class_='commit-group-item')
        
        for item in commit_items:
            try:
                # Extract commit message and details
                msg_elem = item.find('a', class_='commit-link')
                if msg_elem:
                    message = msg_elem.get_text(strip=True)
                    commit_url = f"https://github.com{msg_elem.get('href', '')}"
                    
                    # Extract author
                    author_elem = item.find('a', class_='commit-author')
                    author = author_elem.get_text(strip=True) if author_elem else ''
                    
                    results.append({
                        'message': message,
                        'url': commit_url,
                        'author': author,
                        'author_email': ''  # Would need more detailed parsing
                    })
            except Exception as e:
                print_debug(f"Error parsing commit item: {e}", self.verbose)
        
        return results
    
    def parse_issue_results(self, soup):
        """Parse issue search results from HTML"""
        results = []
        
        issue_items = soup.find_all('div', class_='issue-list-item')
        
        for item in issue_items:
            try:
                # Extract issue title and details
                title_elem = item.find('a', class_='h4')
                if title_elem:
                    title = title_elem.get_text(strip=True)
                    issue_url = f"https://github.com{title_elem.get('href', '')}"
                    
                    # Extract repository
                    repo_elem = item.find('a', class_='muted-link')
                    repository = repo_elem.get_text(strip=True) if repo_elem else ''
                    
                    results.append({
                        'title': title,
                        'url': issue_url,
                        'repository': repository
                    })
            except Exception as e:
                print_debug(f"Error parsing issue item: {e}", self.verbose)
        
        return results
    
    def analyze_content_for_secrets(self, content):
        """Analyze content for potential secrets"""
        secrets = []
        
        for secret_type, pattern in self.secret_patterns.items():
            matches = pattern.findall(content)
            for match in matches:
                if secret_type == 'email':
                    email = match
                    if self.target in email:
                        self.results['emails'].add(email)
                else:
                    secret_value = match[1] if isinstance(match, tuple) else match
                    secrets.append({
                        'type': secret_type,
                        'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                        'full_match': match[0] if isinstance(match, tuple) else match
                    })
        
        return secrets
    
    def print_summary(self):
        """Print summary of findings"""
        print_result(f"Repositories: {len(self.results['repositories'])}")
        print_result(f"Code matches: {len(self.results['code_matches'])}")
        print_result(f"Commit matches: {len(self.results['commit_matches'])}")
        print_result(f"Issue matches: {len(self.results['issue_matches'])}")
        print_result(f"Emails found: {len(self.results['emails'])}")
        print_result(f"Potential secrets: {len(self.results['secrets'])}")
        
        if self.results['emails']:
            print_info("Emails found:")
            for email in sorted(self.results['emails'])[:5]:  # Show first 5
                print_result(email)
    
    def save_results(self, results):
        """Save results to file"""
        if not results:
            return
        
        # Ensure output directory exists
        ensure_directory(self.args.output_dir)
        
        # Create filename
        filename = create_output_filename(self.target, 'github', self.args.output)
        filepath = Path(self.args.output_dir) / 'github' / filename
        
        # Ensure subdirectory exists
        ensure_directory(filepath.parent)
        
        # Prepare data
        if self.args.output == 'json':
            data = {
                'target': self.target,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'summary': {
                    'repositories': len(results['repositories']),
                    'code_matches': len(results['code_matches']),
                    'commit_matches': len(results['commit_matches']),
                    'issue_matches': len(results['issue_matches']),
                    'emails': len(results['emails']),
                    'secrets': len(results['secrets'])
                },
                'results': results
            }
            success = save_to_json(data, filepath)
        elif self.args.output == 'csv':
            # Flatten results for CSV
            csv_data = []
            
            # Add repositories
            for repo in results['repositories']:
                csv_data.append({
                    'type': 'repository',
                    'name': repo.get('name', ''),
                    'url': repo.get('url', ''),
                    'description': repo.get('description', ''),
                    'details': ''
                })
            
            # Add code matches
            for code in results['code_matches']:
                csv_data.append({
                    'type': 'code',
                    'name': code.get('file_path', ''),
                    'url': code.get('url', ''),
                    'description': code.get('repository', ''),
                    'details': code.get('content', '')[:200] + '...' if len(code.get('content', '')) > 200 else code.get('content', '')
                })
            
            headers = ['type', 'name', 'url', 'description', 'details']
            success = save_to_csv(csv_data, filepath, headers)
        else:  # txt
            # Simple text format
            text_lines = []
            text_lines.append(f"GitHub enumeration results for {self.target}")
            text_lines.append("=" * 50)
            
            if results['repositories']:
                text_lines.append("\nRepositories:")
                for repo in results['repositories']:
                    text_lines.append(f"  - {repo.get('name', '')} - {repo.get('url', '')}")
            
            if results['emails']:
                text_lines.append("\nEmails:")
                for email in results['emails']:
                    text_lines.append(f"  - {email}")
            
            success = save_to_txt(text_lines, filepath)
        
        if success:
            print_success(f"Results saved to: {filepath}")
        else:
            print_error("Failed to save results")
