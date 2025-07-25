"""
Certificate transparency parser module for NocturneRecon
Extracts subdomains and information from SSL certificates
"""

import requests
import json
import time
from urllib.parse import quote
from pathlib import Path
from core.utils import (
    print_success, print_error, print_info, print_result, print_debug,
    is_valid_domain, clean_domain, deduplicate_list,
    save_to_json, save_to_csv, save_to_txt, create_output_filename,
    ensure_directory
)
from core.config import get_user_agent

class CertificateParser:
    """Certificate transparency log parser"""
    
    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.target = clean_domain(args.target)
        self.verbose = args.verbose
        self.timeout = args.timeout
        self.results = []
        
    def run(self):
        """Main execution method"""
        print_info(f"Starting certificate analysis for: {self.target}")
        
        # Sources to check
        sources = self.config.get('cert_parser', {}).get('sources', ['crt.sh'])
        
        for source in sources:
            print_info(f"Searching {source}...")
            if source == 'crt.sh':
                results = self.search_crt_sh()
            elif source == 'censys':
                results = self.search_censys()
            else:
                continue
            
            self.results.extend(results)
        
        # Deduplicate and sort
        self.results = self.deduplicate_certificates()
        
        print_success(f"Found {len(self.results)} certificates")
        
        # Print results if verbose
        if self.verbose:
            for cert in self.results[:10]:  # Show first 10
                print_result(f"{cert.get('common_name', 'N/A')} - {cert.get('issuer', 'N/A')}")
        
        return self.results
    
    def search_crt_sh(self):
        """Search certificates via crt.sh"""
        results = []
        
        try:
            # Search for certificates
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            headers = {'User-Agent': get_user_agent(self.config)}
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            max_certs = self.config.get('cert_parser', {}).get('max_certificates', 1000)
            include_expired = self.config.get('cert_parser', {}).get('include_expired', False)
            
            for cert_data in data[:max_certs]:
                try:
                    cert_info = self.parse_crt_sh_certificate(cert_data)
                    
                    # Filter expired certificates if not included
                    if not include_expired and cert_info.get('expired', False):
                        continue
                    
                    results.append(cert_info)
                    
                except Exception as e:
                    print_debug(f"Error parsing certificate: {e}", self.verbose)
                    continue
                    
        except requests.RequestException as e:
            print_error(f"crt.sh search failed: {e}")
        except json.JSONDecodeError as e:
            print_error(f"Invalid JSON response from crt.sh: {e}")
        except Exception as e:
            print_error(f"Error processing crt.sh response: {e}")
        
        print_debug(f"crt.sh found {len(results)} certificates", self.verbose)
        return results
    
    def parse_crt_sh_certificate(self, cert_data):
        """Parse certificate data from crt.sh response"""
        cert_info = {
            'id': cert_data.get('id'),
            'logged_at': cert_data.get('entry_timestamp'),
            'not_before': cert_data.get('not_before'),
            'not_after': cert_data.get('not_after'),
            'common_name': cert_data.get('common_name', ''),
            'issuer': cert_data.get('issuer_name', ''),
            'serial_number': cert_data.get('serial_number', ''),
            'source': 'crt.sh'
        }
        
        # Parse Subject Alternative Names
        name_value = cert_data.get('name_value', '')
        sans = []
        
        for name in name_value.split('\n'):
            name = name.strip()
            if name and is_valid_domain(name):
                # Remove wildcard prefix for processing
                clean_name = name[2:] if name.startswith('*.') else name
                sans.append(name)
        
        cert_info['subject_alt_names'] = sans
        cert_info['domains'] = list(set(sans + [cert_info['common_name']]))
        
        # Filter domains for target
        target_domains = []
        for domain in cert_info['domains']:
            clean_domain_name = domain[2:] if domain.startswith('*.') else domain
            if clean_domain_name.endswith(f".{self.target}") or clean_domain_name == self.target:
                target_domains.append(domain)
        
        cert_info['target_domains'] = target_domains
        
        # Check if expired
        try:
            from datetime import datetime
            not_after = cert_info['not_after']
            if not_after:
                expiry_date = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
                cert_info['expired'] = expiry_date < datetime.now()
            else:
                cert_info['expired'] = False
        except:
            cert_info['expired'] = False
        
        return cert_info
    
    def search_censys(self):
        """Search certificates via Censys (web scraping)"""
        results = []
        
        try:
            # Censys search without API key (limited)
            search_query = f"names: *.{self.target}"
            url = f"https://search.censys.io/certificates?q={quote(search_query)}"
            
            headers = {
                'User-Agent': get_user_agent(self.config),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            # Basic parsing - this would need more sophisticated scraping
            # for production use, potentially with Selenium
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # This is a simplified parser - Censys structure may change
            # In practice, you'd want to use their API or more robust scraping
            
            print_debug("Censys web scraping is limited without API", self.verbose)
            
        except requests.RequestException as e:
            print_error(f"Censys search failed: {e}")
        except Exception as e:
            print_error(f"Error processing Censys response: {e}")
        
        print_debug(f"Censys found {len(results)} certificates", self.verbose)
        return results
    
    def deduplicate_certificates(self):
        """Remove duplicate certificates based on serial number"""
        seen_serials = set()
        unique_certs = []
        
        for cert in self.results:
            serial = cert.get('serial_number')
            if serial and serial not in seen_serials:
                seen_serials.add(serial)
                unique_certs.append(cert)
            elif not serial:
                # Keep certificates without serial numbers
                unique_certs.append(cert)
        
        return sorted(unique_certs, key=lambda x: x.get('logged_at', ''), reverse=True)
    
    def extract_subdomains(self):
        """Extract unique subdomains from all certificates"""
        subdomains = set()
        
        for cert in self.results:
            target_domains = cert.get('target_domains', [])
            for domain in target_domains:
                # Remove wildcard prefix
                clean_domain_name = domain[2:] if domain.startswith('*.') else domain
                if is_valid_domain(clean_domain_name):
                    subdomains.add(clean_domain_name)
        
        return sorted(list(subdomains))
    
    def get_certificate_stats(self):
        """Get statistics about found certificates"""
        stats = {
            'total_certificates': len(self.results),
            'unique_issuers': len(set(cert.get('issuer', '') for cert in self.results)),
            'expired_certificates': len([cert for cert in self.results if cert.get('expired', False)]),
            'total_domains': len(self.extract_subdomains()),
        }
        
        # Issuer breakdown
        issuers = {}
        for cert in self.results:
            issuer = cert.get('issuer', 'Unknown')
            issuers[issuer] = issuers.get(issuer, 0) + 1
        
        stats['issuer_breakdown'] = issuers
        
        return stats
    
    def save_results(self, results):
        """Save results to file"""
        if not results:
            return
        
        # Ensure output directory exists
        ensure_directory(self.args.output_dir)
        
        # Create filename
        filename = create_output_filename(self.target, 'certificates', self.args.output)
        filepath = Path(self.args.output_dir) / 'certificates' / filename
        
        # Ensure subdirectory exists
        ensure_directory(filepath.parent)
        
        # Prepare data
        if self.args.output == 'json':
            data = {
                'target': self.target,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'statistics': self.get_certificate_stats(),
                'subdomains': self.extract_subdomains(),
                'certificates': results
            }
            success = save_to_json(data, filepath)
        elif self.args.output == 'csv':
            # Flatten certificate data for CSV
            csv_data = []
            for cert in results:
                row = {
                    'id': cert.get('id', ''),
                    'common_name': cert.get('common_name', ''),
                    'issuer': cert.get('issuer', ''),
                    'not_before': cert.get('not_before', ''),
                    'not_after': cert.get('not_after', ''),
                    'expired': cert.get('expired', False),
                    'domains': ', '.join(cert.get('target_domains', [])),
                    'source': cert.get('source', '')
                }
                csv_data.append(row)
            
            headers = ['id', 'common_name', 'issuer', 'not_before', 'not_after', 'expired', 'domains', 'source']
            success = save_to_csv(csv_data, filepath, headers)
        else:  # txt
            # Simple text format with subdomains
            subdomains = self.extract_subdomains()
            success = save_to_txt(subdomains, filepath)
        
        if success:
            print_success(f"Results saved to: {filepath}")
            
            # Also save subdomains separately
            if self.args.output != 'txt':
                subdomain_filename = create_output_filename(self.target, 'cert_subdomains', 'txt')
                subdomain_filepath = Path(self.args.output_dir) / 'subdomains' / subdomain_filename
                ensure_directory(subdomain_filepath.parent)
                
                subdomains = self.extract_subdomains()
                if save_to_txt(subdomains, subdomain_filepath):
                    print_info(f"Subdomains also saved to: {subdomain_filepath}")
        else:
            print_error("Failed to save results")
