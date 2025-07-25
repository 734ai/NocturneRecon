"""
CLI argument parsing and main entry point for NocturneRecon
"""

import argparse
import sys
from pathlib import Path
from core.utils import print_banner, print_success, print_error, print_info
from core.config import load_config

def create_parser():
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description='NocturneRecon - State-of-the-art API-free OSINT & Passive Recon Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --module subdomains --target example.com
  python3 main.py --module emails --target example.com --output json
  python3 main.py --module certs --target example.com --verbose
  python3 main.py --module github --target example.com --output-dir /tmp/results
        """
    )
    
    # Required arguments
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target domain or organization'
    )
    
    parser.add_argument(
        '--module', '-m',
        required=True,
        choices=['subdomains', 'emails', 'certs', 'github', 'breach', 'all'],
        help='Reconnaissance module to run'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        choices=['json', 'csv', 'txt'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--output-dir', '-d',
        default='output',
        help='Output directory (default: output/)'
    )
    
    # Behavior options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress banner and minimize output'
    )
    
    parser.add_argument(
        '--threads', '-th',
        type=int,
        default=10,
        help='Number of threads (default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Delay between requests in seconds (default: 1.0)'
    )
    
    # Module-specific options
    parser.add_argument(
        '--wordlist',
        help='Custom wordlist file for subdomain brute-force'
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Configuration file path'
    )
    
    return parser

def validate_args(args):
    """Validate command line arguments"""
    # Check if target is valid
    if not args.target:
        print_error("Target cannot be empty")
        return False
    
    # Check output directory
    output_path = Path(args.output_dir)
    if not output_path.exists():
        try:
            output_path.mkdir(parents=True, exist_ok=True)
            print_info(f"Created output directory: {output_path}")
        except Exception as e:
            print_error(f"Cannot create output directory: {e}")
            return False
    
    # Check wordlist file if provided
    if args.wordlist and not Path(args.wordlist).exists():
        print_error(f"Wordlist file not found: {args.wordlist}")
        return False
    
    # Check config file if provided
    if args.config and not Path(args.config).exists():
        print_error(f"Config file not found: {args.config}")
        return False
    
    return True

def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Show banner unless quiet mode
    if not args.quiet:
        print_banner()
    
    # Validate arguments
    if not validate_args(args):
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    print_info(f"Target: {args.target}")
    print_info(f"Module: {args.module}")
    print_info(f"Output: {args.output}")
    
    try:
        # Import and run the appropriate module
        if args.module == 'subdomains':
            from modules.subdomain_enum import SubdomainEnumerator
            module = SubdomainEnumerator(args, config)
        elif args.module == 'emails':
            from modules.email_enum import EmailEnumerator
            module = EmailEnumerator(args, config)
        elif args.module == 'certs':
            from modules.cert_parser import CertificateParser
            module = CertificateParser(args, config)
        elif args.module == 'github':
            from modules.github_enum import GitHubEnumerator
            module = GitHubEnumerator(args, config)
        elif args.module == 'breach':
            from modules.breach_parser import BreachParser
            module = BreachParser(args, config)
        elif args.module == 'all':
            print_info("Running all modules...")
            # TODO: Implement all modules runner
            print_error("All modules runner not yet implemented")
            sys.exit(1)
        
        # Run the module
        results = module.run()
        
        if results:
            print_success(f"Found {len(results)} results")
            module.save_results(results)
        else:
            print_info("No results found")
            
    except ImportError as e:
        print_error(f"Module not implemented yet: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error running module: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
