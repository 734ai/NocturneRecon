"""
Configuration management for NocturneRecon
"""

import yaml
import os
from pathlib import Path
from core.utils import print_error, print_info

# Default configuration
DEFAULT_CONFIG = {
    'general': {
        'threads': 10,
        'timeout': 10,
        'delay': 1.0,
        'user_agents': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
    },
    'subdomain_enum': {
        'wordlists': [
            'wordlists/subdomains-top1million-5000.txt',
            'wordlists/dns-all.txt'
        ],
        'dns_servers': [
            '8.8.8.8',
            '1.1.1.1',
            '208.67.222.222'
        ],
        'use_amass': True,
        'use_massdns': True,
        'use_crt_sh': True,
        'use_dnsdumpster': True
    },
    'email_enum': {
        'search_engines': ['google', 'bing', 'duckduckgo'],
        'dorking_enabled': True,
        'github_search': True,
        'permutation_patterns': [
            '{first}.{last}@{domain}',
            '{first}{last}@{domain}',
            '{first}_{last}@{domain}',
            '{first}@{domain}',
            '{last}@{domain}',
            '{first}{l}@{domain}',
            '{f}{last}@{domain}'
        ]
    },
    'cert_parser': {
        'sources': ['crt.sh', 'censys'],
        'include_expired': False,
        'max_certificates': 1000
    },
    'github_enum': {
        'search_code': True,
        'search_commits': True,
        'search_issues': True,
        'max_results': 100,
        'include_forks': False
    },
    'breach_parser': {
        'breach_directories': [
            '/opt/breach-parse',
            '~/breach-data'
        ],
        'supported_formats': ['.txt', '.gz', '.zip'],
        'max_file_size': '500MB'
    },
    'output': {
        'formats': ['json', 'csv', 'txt'],
        'timestamp_files': True,
        'deduplicate': True,
        'sort_results': True
    },
    'proxy': {
        'enabled': False,
        'proxy_list': [],
        'rotation_enabled': False,
        'tor_enabled': False
    },
    'opsec': {
        'random_delays': True,
        'randomize_user_agents': True,
        'respect_robots_txt': False,
        'max_requests_per_host': 100
    }
}

def load_config(config_path=None):
    """Load configuration from YAML file or return default config"""
    config = DEFAULT_CONFIG.copy()
    
    # Default config locations
    default_paths = [
        'config.yaml',
        'config.yml',
        '~/.nocturnerecon/config.yaml',
        '/etc/nocturnerecon/config.yaml'
    ]
    
    # Use provided path or search defaults
    paths_to_check = [config_path] if config_path else default_paths
    
    for path in paths_to_check:
        if not path:
            continue
            
        expanded_path = Path(path).expanduser()
        
        if expanded_path.exists():
            try:
                with open(expanded_path, 'r', encoding='utf-8') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        config = merge_configs(config, user_config)
                        print_info(f"Loaded configuration from: {expanded_path}")
                        break
            except Exception as e:
                print_error(f"Failed to load config from {expanded_path}: {e}")
                continue
    
    return config

def merge_configs(default_config, user_config):
    """Recursively merge user config with default config"""
    merged = default_config.copy()
    
    for key, value in user_config.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_configs(merged[key], value)
        else:
            merged[key] = value
    
    return merged

def save_default_config(config_path='config.yaml'):
    """Save default configuration to file"""
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, indent=2)
        print_info(f"Default configuration saved to: {config_path}")
        return True
    except Exception as e:
        print_error(f"Failed to save default config: {e}")
        return False

def validate_config(config):
    """Validate configuration values"""
    errors = []
    
    # Validate general settings
    if config.get('general', {}).get('threads', 0) <= 0:
        errors.append("threads must be greater than 0")
    
    if config.get('general', {}).get('timeout', 0) <= 0:
        errors.append("timeout must be greater than 0")
    
    if config.get('general', {}).get('delay', 0) < 0:
        errors.append("delay cannot be negative")
    
    # Validate subdomain enum settings
    dns_servers = config.get('subdomain_enum', {}).get('dns_servers', [])
    if not dns_servers:
        errors.append("At least one DNS server must be configured")
    
    # Print validation errors
    if errors:
        for error in errors:
            print_error(f"Config validation error: {error}")
        return False
    
    return True

def get_wordlist_path(wordlist_name, config):
    """Get full path to wordlist file"""
    # Check if it's already a full path
    if os.path.isabs(wordlist_name):
        return wordlist_name if Path(wordlist_name).exists() else None
    
    # Search in common locations
    search_paths = [
        Path.cwd() / wordlist_name,
        Path.cwd() / 'wordlists' / wordlist_name,
        Path.home() / '.nocturnerecon' / 'wordlists' / wordlist_name,
        Path('/usr/share/wordlists') / wordlist_name,
        Path('/opt/wordlists') / wordlist_name
    ]
    
    for path in search_paths:
        if path.exists():
            return str(path)
    
    return None

def get_user_agent(config):
    """Get random user agent from config"""
    import random
    user_agents = config.get('general', {}).get('user_agents', [])
    return random.choice(user_agents) if user_agents else None

def get_dns_servers(config):
    """Get DNS servers from config"""
    return config.get('subdomain_enum', {}).get('dns_servers', ['8.8.8.8'])

def is_feature_enabled(config, module, feature):
    """Check if a specific feature is enabled in config"""
    return config.get(module, {}).get(feature, False)
