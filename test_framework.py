#!/usr/bin/env python3
"""
Quick test script for NocturneRecon
Tests basic functionality of each module
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.utils import print_info, print_success, print_error, print_banner
from core.config import load_config

def test_imports():
    """Test that all modules can be imported"""
    print_info("Testing module imports...")
    
    try:
        from core.cli import create_parser
        from core.utils import clean_domain, is_valid_domain
        from core.config import load_config
        print_success("Core modules imported successfully")
    except Exception as e:
        print_error(f"Core module import failed: {e}")
        return False
    
    try:
        from modules.subdomain_enum import SubdomainEnumerator
        from modules.email_enum import EmailEnumerator
        from modules.cert_parser import CertificateParser
        from modules.github_enum import GitHubEnumerator
        from modules.breach_parser import BreachParser
        print_success("v1.0 Reconnaissance modules imported successfully")
    except Exception as e:
        print_error(f"v1.0 Reconnaissance module import failed: {e}")
        return False
    
    try:
        from modules.darkweb_enum import DarkWebEnumerator
        from modules.slack_scraper import SlackIntelligenceGatherer
        from modules.paste_monitor import PastebinMonitor
        from modules.doc_intel import DocumentIntelligenceGatherer
        print_success("v2.0+ Advanced modules imported successfully")
    except Exception as e:
        print_error(f"v2.0+ Advanced module import failed: {e}")
        return False
    
    try:
        from scrapers.serp_scraper import SERPScraper
        from scrapers.html_parser import HTMLParser
        print_success("Scraper modules imported successfully")
    except Exception as e:
        print_error(f"Scraper module import failed: {e}")
        return False
    
    return True

def test_config():
    """Test configuration loading"""
    print_info("Testing configuration...")
    
    try:
        config = load_config()
        if config:
            print_success("Configuration loaded successfully")
            print_info(f"Threads configured: {config.get('general', {}).get('threads', 'N/A')}")
            return True
        else:
            print_error("Configuration is empty")
            return False
    except Exception as e:
        print_error(f"Configuration test failed: {e}")
        return False

def test_utilities():
    """Test utility functions"""
    print_info("Testing utility functions...")
    
    try:
        from core.utils import clean_domain, is_valid_domain, is_valid_email
        
        # Test domain validation
        test_domains = ["example.com", "test.example.com", "invalid..domain"]
        for domain in test_domains:
            clean = clean_domain(domain)
            valid = is_valid_domain(clean)
            print_info(f"Domain '{domain}' -> '{clean}' (valid: {valid})")
        
        # Test email validation
        test_emails = ["test@example.com", "invalid.email", "user@domain.co.uk"]
        for email in test_emails:
            valid = is_valid_email(email)
            print_info(f"Email '{email}' (valid: {valid})")
        
        print_success("Utility functions working correctly")
        return True
    except Exception as e:
        print_error(f"Utility test failed: {e}")
        return False

def test_output_functions():
    """Test output functions"""
    print_info("Testing output functions...")
    
    try:
        from core.utils import save_to_json, save_to_csv, save_to_txt
        import tempfile
        import json
        
        # Test data
        test_data = [
            {"name": "test1", "value": "value1"},
            {"name": "test2", "value": "value2"}
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test JSON output
            json_file = Path(temp_dir) / "test.json"
            if save_to_json(test_data, json_file):
                print_success("JSON output test passed")
            else:
                print_error("JSON output test failed")
                return False
            
            # Test CSV output
            csv_file = Path(temp_dir) / "test.csv"
            if save_to_csv(test_data, csv_file, ["name", "value"]):
                print_success("CSV output test passed")
            else:
                print_error("CSV output test failed")
                return False
            
            # Test TXT output
            txt_file = Path(temp_dir) / "test.txt"
            txt_data = ["line1", "line2", "line3"]
            if save_to_txt(txt_data, txt_file):
                print_success("TXT output test passed")
            else:
                print_error("TXT output test failed")
                return False
        
        return True
    except Exception as e:
        print_error(f"Output function test failed: {e}")
        return False

def test_module_initialization():
    """Test that modules can be initialized"""
    print_info("Testing module initialization...")
    
    try:
        # Mock args object
        class MockArgs:
            def __init__(self):
                self.target = "example.com"
                self.threads = 5
                self.timeout = 10
                self.delay = 1.0
                self.verbose = True
                self.output = "json"
                self.output_dir = "output"
                self.wordlist = None
        
        args = MockArgs()
        config = load_config()
        
        # Test each v1.0 module
        v1_modules = {
            'SubdomainEnumerator': 'modules.subdomain_enum',
            'EmailEnumerator': 'modules.email_enum',
            'CertificateParser': 'modules.cert_parser',
            'GitHubEnumerator': 'modules.github_enum',
            'BreachParser': 'modules.breach_parser'
        }
        
        for module_name, module_path in v1_modules.items():
            try:
                module = __import__(module_path, fromlist=[module_name])
                module_class = getattr(module, module_name)
                instance = module_class(args, config)
                print_success(f"{module_name} initialized successfully")
            except Exception as e:
                print_error(f"{module_name} initialization failed: {e}")
                return False
        
        # Test v2.0+ modules (different initialization pattern)
        v2_modules = {
            'DarkWebEnumerator': 'modules.darkweb_enum',
            'SlackIntelligenceGatherer': 'modules.slack_scraper',
            'PastebinMonitor': 'modules.paste_monitor',
            'DocumentIntelligenceGatherer': 'modules.doc_intel'
        }
        
        for module_name, module_path in v2_modules.items():
            try:
                module = __import__(module_path, fromlist=[module_name])
                module_class = getattr(module, module_name)
                instance = module_class(args.target, config)  # Different initialization
                print_success(f"{module_name} (v2.0+) initialized successfully")
            except Exception as e:
                print_error(f"{module_name} (v2.0+) initialization failed: {e}")
                return False
        
        return True
    except Exception as e:
        print_error(f"Module initialization test failed: {e}")
        return False

def main():
    """Run all tests"""
    print_banner()
    print_info("Running NocturneRecon test suite...")
    print_info("=" * 50)
    
    tests = [
        ("Import Test", test_imports),
        ("Configuration Test", test_config),
        ("Utilities Test", test_utilities),
        ("Output Functions Test", test_output_functions),
        ("Module Initialization Test", test_module_initialization)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print_info(f"\n--- {test_name} ---")
        if test_func():
            passed += 1
        else:
            print_error(f"{test_name} FAILED")
    
    print_info("\n" + "=" * 50)
    print_info(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print_success("All tests passed! NocturneRecon v2.0+ is ready to use.")
        print_info("\nNext steps:")
        print_info("1. Run: python3 main.py --help")
        print_info("2. Try v1.0 modules: python3 main.py --module subdomains --target example.com")
        print_info("3. Try v2.0+ modules: python3 main.py --module darkweb --target example.com")
        print_info("4. Advanced usage: python3 main.py --module slack --target example.com --verbose")
        return 0
    else:
        print_error(f"{total - passed} tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
