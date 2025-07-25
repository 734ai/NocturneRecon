"""
Subdomain enumeration module for NocturneRecon
Supports multiple techniques: DNS brute-force, certificate transparency, scraping
"""

import requests
import dns.resolver
import threading
import time
import subprocess
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from pathlib import Path
from core.utils import (
    print_success, print_error, print_info, print_result, print_debug,
    is_valid_domain, clean_domain, deduplicate_list, filter_subdomains,
    save_to_json, save_to_csv, save_to_txt, create_output_filename,
    ensure_directory, load_wordlist
)
from core.config import get_dns_servers, get_user_agent, is_feature_enabled, get_wordlist_path

class SubdomainEnumerator:
    """Subdomain enumeration using multiple techniques"""
    
    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.target = clean_domain(args.target)
        self.results = set()
        self.threads = args.threads
        self.timeout = args.timeout
        self.verbose = args.verbose
        
        # Setup DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = get_dns_servers(config)
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        
        # Threading lock for results
        self.lock = threading.Lock()
        
    def run(self):
        """Main execution method"""
        print_info(f"Starting subdomain enumeration for: {self.target}")
        
        # Certificate Transparency
        if is_feature_enabled(self.config, 'subdomain_enum', 'use_crt_sh'):
            print_info("Searching certificate transparency logs...")
            crt_results = self.search_crt_sh()
            self.add_results(crt_results)
        
        # DNSDumpster scraping
        if is_feature_enabled(self.config, 'subdomain_enum', 'use_dnsdumpster'):
            print_info("Scraping DNSDumpster...")
            dns_dumpster_results = self.search_dnsdumpster()
            self.add_results(dns_dumpster_results)
        
        # DNS brute-force
        print_info("Starting DNS brute-force...")
        brute_results = self.dns_brute_force()
        self.add_results(brute_results)
        
        # External tools
        if is_feature_enabled(self.config, 'subdomain_enum', 'use_amass'):
            print_info("Running Amass...")
            amass_results = self.run_amass()
            self.add_results(amass_results)
        
        # Convert set to sorted list
        final_results = sorted(list(self.results))
        
        print_success(f"Found {len(final_results)} unique subdomains")
        
        # Print results if verbose
        if self.verbose:
            for subdomain in final_results:
                print_result(subdomain)
        
        return final_results
    
    def add_results(self, new_results):
        """Thread-safe method to add results"""
        with self.lock:
            if new_results:
                self.results.update(new_results)
                print_debug(f"Added {len(new_results)} new results", self.verbose)
    
    def search_crt_sh(self):
        """Search certificate transparency via crt.sh"""
        results = set()
        
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            headers = {'User-Agent': get_user_agent(self.config)}
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            for cert in data:
                name_value = cert.get('name_value', '')
                # Handle multiple SANs
                for name in name_value.split('\n'):
                    name = name.strip()
                    if name and is_valid_domain(name):
                        # Remove wildcard prefix
                        if name.startswith('*.'):
                            name = name[2:]
                        
                        # Filter for target domain
                        if name.endswith(f".{self.target}") or name == self.target:
                            results.add(name)
                            
        except requests.RequestException as e:
            print_error(f"crt.sh search failed: {e}")
        except Exception as e:
            print_error(f"Error parsing crt.sh response: {e}")
        
        print_debug(f"crt.sh found {len(results)} subdomains", self.verbose)
        return results
    
    def search_dnsdumpster(self):
        """Scrape DNSDumpster for subdomains"""
        results = set()
        
        try:
            session = requests.Session()
            headers = {'User-Agent': get_user_agent(self.config)}
            
            # Get CSRF token
            url = "https://dnsdumpster.com/"
            response = session.get(url, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            if not csrf_token:
                print_error("Could not find CSRF token for DNSDumpster")
                return results
            
            # Submit form
            data = {
                'csrfmiddlewaretoken': csrf_token['value'],
                'targetip': self.target,
                'user': 'free'
            }
            
            response = session.post(url, data=data, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse results
            for table in soup.find_all('table', {'class': 'table'}):
                for row in table.find_all('tr'):
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        subdomain = cells[0].text.strip()
                        if subdomain and is_valid_domain(subdomain):
                            if subdomain.endswith(f".{self.target}") or subdomain == self.target:
                                results.add(subdomain)
            
        except requests.RequestException as e:
            print_error(f"DNSDumpster search failed: {e}")
        except Exception as e:
            print_error(f"Error parsing DNSDumpster response: {e}")
        
        print_debug(f"DNSDumpster found {len(results)} subdomains", self.verbose)
        return results
    
    def dns_brute_force(self):
        """DNS brute-force using wordlists"""
        results = set()
        
        # Get wordlist
        wordlist_path = None
        if self.args.wordlist:
            wordlist_path = self.args.wordlist
        else:
            # Try default wordlists from config
            wordlists = self.config.get('subdomain_enum', {}).get('wordlists', [])
            for wl in wordlists:
                wordlist_path = get_wordlist_path(wl, self.config)
                if wordlist_path:
                    break
        
        if not wordlist_path:
            print_error("No wordlist found for DNS brute-force")
            return results
        
        # Load wordlist
        wordlist = load_wordlist(wordlist_path)
        if not wordlist:
            print_error(f"Failed to load wordlist: {wordlist_path}")
            return results
        
        print_info(f"Loaded {len(wordlist)} words from {Path(wordlist_path).name}")
        
        # Create thread pool for DNS queries
        def dns_worker(word):
            subdomain = f"{word}.{self.target}"
            if self.check_dns_record(subdomain):
                with self.lock:
                    results.add(subdomain)
                    if self.verbose:
                        print_result(f"Found: {subdomain}")
            
            # Rate limiting
            time.sleep(self.args.delay)
        
        # Start threads
        threads = []
        for word in wordlist:
            if len(threads) >= self.threads:
                # Wait for some threads to complete
                for t in threads[:]:
                    if not t.is_alive():
                        threads.remove(t)
                time.sleep(0.1)
            
            thread = threading.Thread(target=dns_worker, args=(word,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        print_debug(f"DNS brute-force found {len(results)} subdomains", self.verbose)
        return results
    
    def check_dns_record(self, domain):
        """Check if domain has DNS records"""
        try:
            # Try A record
            self.resolver.resolve(domain, 'A')
            return True
        except:
            try:
                # Try AAAA record
                self.resolver.resolve(domain, 'AAAA')
                return True
            except:
                try:
                    # Try CNAME record
                    self.resolver.resolve(domain, 'CNAME')
                    return True
                except:
                    return False
    
    def run_amass(self):
        """Run Amass tool for subdomain enumeration"""
        results = set()
        
        try:
            # Check if amass is installed
            subprocess.run(['amass', 'enum', '-version'], 
                         capture_output=True, check=True, timeout=5)
            
            # Run amass
            cmd = ['amass', 'enum', '-passive', '-d', self.target]
            
            print_debug(f"Running: {' '.join(cmd)}", self.verbose)
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=300)  # 5 minute timeout
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and is_valid_domain(line):
                        if line.endswith(f".{self.target}") or line == self.target:
                            results.add(line)
            else:
                print_error(f"Amass failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print_error("Amass timed out")
        except subprocess.CalledProcessError:
            print_error("Amass not found or failed to run")
        except Exception as e:
            print_error(f"Error running Amass: {e}")
        
        print_debug(f"Amass found {len(results)} subdomains", self.verbose)
        return results
    
    def save_results(self, results):
        """Save results to file"""
        if not results:
            return
        
        # Ensure output directory exists
        ensure_directory(self.args.output_dir)
        
        # Create filename
        filename = create_output_filename(self.target, 'subdomains', self.args.output)
        filepath = Path(self.args.output_dir) / 'subdomains' / filename
        
        # Ensure subdirectory exists
        ensure_directory(filepath.parent)
        
        # Prepare data
        if self.args.output == 'json':
            data = {
                'target': self.target,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_found': len(results),
                'subdomains': results
            }
            success = save_to_json(data, filepath)
        elif self.args.output == 'csv':
            data = [{'subdomain': sub} for sub in results]
            success = save_to_csv(data, filepath, ['subdomain'])
        else:  # txt
            success = save_to_txt(results, filepath)
        
        if success:
            print_success(f"Results saved to: {filepath}")
        else:
            print_error("Failed to save results")
