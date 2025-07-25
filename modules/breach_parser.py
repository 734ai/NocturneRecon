"""
Breach parser module for NocturneRecon
Analyzes local breach data dumps for target domain emails and passwords
"""

import os
import gzip
import zipfile
import re
import time
from pathlib import Path
from core.utils import (
    print_success, print_error, print_info, print_result, print_debug,
    is_valid_email, clean_domain,
    save_to_json, save_to_csv, save_to_txt, create_output_filename,
    ensure_directory, get_file_size, format_bytes
)

class BreachParser:
    """Parse local breach data for target domain information"""
    
    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.target = clean_domain(args.target)
        self.verbose = args.verbose
        self.results = {
            'emails': [],
            'credentials': [],
            'statistics': {}
        }
        
        # Email pattern for target domain
        self.target_email_pattern = re.compile(
            rf'\b[A-Za-z0-9._%+-]+@{re.escape(self.target)}\b',
            re.IGNORECASE
        )
        
        # Common breach data patterns
        self.credential_patterns = [
            # email:password
            re.compile(r'([^:\s]+@[^:\s]+):([^:\s]+)', re.IGNORECASE),
            # email;password
            re.compile(r'([^;\s]+@[^;\s]+);([^;\s]+)', re.IGNORECASE),
            # email,password
            re.compile(r'([^,\s]+@[^,\s]+),([^,\s]+)', re.IGNORECASE),
            # email|password
            re.compile(r'([^|\s]+@[^|\s]+)\|([^|\s]+)', re.IGNORECASE),
            # email\tpassword
            re.compile(r'([^\t\s]+@[^\t\s]+)\t([^\t\s]+)', re.IGNORECASE),
        ]
        
    def run(self):
        """Main execution method"""
        print_info(f"Starting breach data analysis for: {self.target}")
        
        # Get breach directories from config
        breach_dirs = self.config.get('breach_parser', {}).get('breach_directories', [])
        
        if not breach_dirs:
            print_error("No breach directories configured")
            return self.results
        
        # Expand user paths
        expanded_dirs = []
        for dir_path in breach_dirs:
            expanded_path = Path(dir_path).expanduser()
            if expanded_path.exists():
                expanded_dirs.append(expanded_path)
            else:
                print_debug(f"Breach directory not found: {expanded_path}", self.verbose)
        
        if not expanded_dirs:
            print_error("No valid breach directories found")
            return self.results
        
        # Process each directory
        total_files = 0
        for breach_dir in expanded_dirs:
            print_info(f"Scanning directory: {breach_dir}")
            files_processed = self.process_breach_directory(breach_dir)
            total_files += files_processed
        
        # Generate statistics
        self.results['statistics'] = {
            'files_processed': total_files,
            'emails_found': len(self.results['emails']),
            'credentials_found': len(self.results['credentials']),
            'target_domain': self.target
        }
        
        print_success(f"Found {len(self.results['emails'])} emails and {len(self.results['credentials'])} credentials")
        
        # Print results if verbose
        if self.verbose:
            self.print_summary()
        
        return self.results
    
    def process_breach_directory(self, directory):
        """Process all breach files in a directory"""
        files_processed = 0
        supported_formats = self.config.get('breach_parser', {}).get('supported_formats', ['.txt', '.gz', '.zip'])
        max_file_size_str = self.config.get('breach_parser', {}).get('max_file_size', '500MB')
        max_file_size = self.parse_file_size(max_file_size_str)
        
        for file_path in directory.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Check file extension
            if not any(file_path.name.lower().endswith(ext) for ext in supported_formats):
                continue
            
            # Check file size
            file_size = get_file_size(file_path)
            if file_size > max_file_size:
                print_debug(f"Skipping large file: {file_path} ({format_bytes(file_size)})", self.verbose)
                continue
            
            print_debug(f"Processing: {file_path} ({format_bytes(file_size)})", self.verbose)
            
            try:
                self.process_breach_file(file_path)
                files_processed += 1
            except Exception as e:
                print_error(f"Error processing {file_path}: {e}")
        
        return files_processed
    
    def process_breach_file(self, file_path):
        """Process a single breach file"""
        file_extension = file_path.suffix.lower()
        
        if file_extension == '.gz':
            self.process_gzip_file(file_path)
        elif file_extension == '.zip':
            self.process_zip_file(file_path)
        elif file_extension in ['.txt', '.csv']:
            self.process_text_file(file_path)
        else:
            print_debug(f"Unsupported file format: {file_path}", self.verbose)
    
    def process_text_file(self, file_path):
        """Process plain text breach file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                for line in f:
                    line = line.strip()
                    if line:
                        self.analyze_line(line, str(file_path))
                        line_count += 1
                        
                        # Limit processing for very large files
                        if line_count > 1000000:  # 1 million lines max
                            print_debug(f"Reached line limit for {file_path}", self.verbose)
                            break
        except Exception as e:
            print_error(f"Error reading text file {file_path}: {e}")
    
    def process_gzip_file(self, file_path):
        """Process gzipped breach file"""
        try:
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                for line in f:
                    line = line.strip()
                    if line:
                        self.analyze_line(line, str(file_path))
                        line_count += 1
                        
                        # Limit processing for very large files
                        if line_count > 1000000:  # 1 million lines max
                            print_debug(f"Reached line limit for {file_path}", self.verbose)
                            break
        except Exception as e:
            print_error(f"Error reading gzip file {file_path}: {e}")
    
    def process_zip_file(self, file_path):
        """Process zip archive containing breach files"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    if file_info.is_dir():
                        continue
                    
                    # Skip large files within zip
                    if file_info.file_size > 100 * 1024 * 1024:  # 100MB limit for zip contents
                        print_debug(f"Skipping large file in zip: {file_info.filename}", self.verbose)
                        continue
                    
                    try:
                        with zip_ref.open(file_info.filename) as f:
                            line_count = 0
                            for line in f:
                                try:
                                    line = line.decode('utf-8', errors='ignore').strip()
                                    if line:
                                        self.analyze_line(line, f"{file_path}/{file_info.filename}")
                                        line_count += 1
                                        
                                        if line_count > 500000:  # 500k lines for zip contents
                                            break
                                except:
                                    continue
                    except Exception as e:
                        print_debug(f"Error processing {file_info.filename} in {file_path}: {e}", self.verbose)
        except Exception as e:
            print_error(f"Error reading zip file {file_path}: {e}")
    
    def analyze_line(self, line, source_file):
        """Analyze a single line for target domain data"""
        # Check for target domain emails
        email_matches = self.target_email_pattern.findall(line)
        for email in email_matches:
            if is_valid_email(email):
                email_data = {
                    'email': email.lower(),
                    'source_file': source_file,
                    'line_content': line[:200] + '...' if len(line) > 200 else line
                }
                
                # Check if email already found
                if not any(e['email'] == email.lower() for e in self.results['emails']):
                    self.results['emails'].append(email_data)
                    if self.verbose:
                        print_result(f"Found email: {email}")
        
        # Check for credentials (email:password patterns)
        for pattern in self.credential_patterns:
            matches = pattern.findall(line)
            for match in matches:
                if len(match) >= 2:
                    email, password = match[0], match[1]
                    
                    # Only include if email is from target domain
                    if self.target.lower() in email.lower() and is_valid_email(email):
                        credential_data = {
                            'email': email.lower(),
                            'password': password,
                            'source_file': source_file,
                            'password_length': len(password),
                            'password_hash': self.detect_hash_type(password)
                        }
                        
                        # Check if credential already found
                        if not any(c['email'] == email.lower() and c['password'] == password 
                                 for c in self.results['credentials']):
                            self.results['credentials'].append(credential_data)
                            if self.verbose:
                                print_result(f"Found credential: {email}:{password[:3]}***")
    
    def detect_hash_type(self, password):
        """Detect if password is a hash and what type"""
        if not password:
            return 'plaintext'
        
        # Common hash patterns
        hash_patterns = {
            'md5': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE),
            'sha1': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE),
            'sha256': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE),
            'bcrypt': re.compile(r'^\$2[abyxz]?\$[0-9]{2}\$.{53}$'),
            'ntlm': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE),
        }
        
        for hash_type, pattern in hash_patterns.items():
            if pattern.match(password):
                return hash_type
        
        # Check for other indicators
        if password.startswith('$'):
            return 'hashed'
        elif len(password) > 50:
            return 'likely_hash'
        else:
            return 'plaintext'
    
    def parse_file_size(self, size_str):
        """Parse file size string like '500MB' to bytes"""
        size_str = size_str.upper().strip()
        
        if size_str.endswith('B'):
            size_str = size_str[:-1]
        
        multipliers = {
            'K': 1024,
            'M': 1024 ** 2,
            'G': 1024 ** 3,
            'T': 1024 ** 4
        }
        
        for unit, multiplier in multipliers.items():
            if size_str.endswith(unit):
                try:
                    number = float(size_str[:-1])
                    return int(number * multiplier)
                except ValueError:
                    break
        
        try:
            return int(size_str)
        except ValueError:
            return 500 * 1024 * 1024  # Default 500MB
    
    def print_summary(self):
        """Print summary of findings"""
        stats = self.results['statistics']
        print_result(f"Files processed: {stats['files_processed']}")
        print_result(f"Emails found: {stats['emails_found']}")
        print_result(f"Credentials found: {stats['credentials_found']}")
        
        if self.results['emails']:
            print_info("Sample emails found:")
            for email_data in self.results['emails'][:5]:  # Show first 5
                print_result(email_data['email'])
        
        if self.results['credentials']:
            print_info("Password types found:")
            hash_types = {}
            for cred in self.results['credentials']:
                hash_type = cred.get('password_hash', 'unknown')
                hash_types[hash_type] = hash_types.get(hash_type, 0) + 1
            
            for hash_type, count in hash_types.items():
                print_result(f"{hash_type}: {count}")
    
    def save_results(self, results):
        """Save results to file"""
        if not results or (not results['emails'] and not results['credentials']):
            print_info("No breach data found for target domain")
            return
        
        # Ensure output directory exists
        ensure_directory(self.args.output_dir)
        
        # Create filename
        filename = create_output_filename(self.target, 'breach', self.args.output)
        filepath = Path(self.args.output_dir) / 'breach' / filename
        
        # Ensure subdirectory exists
        ensure_directory(filepath.parent)
        
        # Prepare data
        if self.args.output == 'json':
            data = {
                'target': self.target,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'statistics': results['statistics'],
                'emails': results['emails'],
                'credentials': [
                    {
                        'email': cred['email'],
                        'password_hash_type': cred['password_hash'],
                        'password_length': cred['password_length'],
                        'source_file': cred['source_file']
                        # Note: Not including actual passwords in JSON for security
                    }
                    for cred in results['credentials']
                ]
            }
            success = save_to_json(data, filepath)
        elif self.args.output == 'csv':
            # Create separate CSV for emails and credentials
            email_data = []
            for email_item in results['emails']:
                email_data.append({
                    'email': email_item['email'],
                    'source_file': email_item['source_file']
                })
            
            success = save_to_csv(email_data, filepath, ['email', 'source_file'])
            
            # Save credentials separately
            if results['credentials']:
                cred_filename = create_output_filename(self.target, 'breach_credentials', 'csv')
                cred_filepath = Path(self.args.output_dir) / 'breach' / cred_filename
                
                cred_data = []
                for cred in results['credentials']:
                    cred_data.append({
                        'email': cred['email'],
                        'password_type': cred['password_hash'],
                        'password_length': cred['password_length'],
                        'source_file': cred['source_file']
                    })
                
                save_to_csv(cred_data, cred_filepath, ['email', 'password_type', 'password_length', 'source_file'])
                print_info(f"Credentials metadata saved to: {cred_filepath}")
        else:  # txt
            # Simple text format with emails only
            emails = [item['email'] for item in results['emails']]
            success = save_to_txt(emails, filepath)
        
        if success:
            print_success(f"Results saved to: {filepath}")
            print_info("Note: Actual passwords are not saved in output files for security reasons")
        else:
            print_error("Failed to save results")
