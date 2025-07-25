# 🚀 Quick Start Guide

## Installation

1. **Clone and setup**:
```bash
cd /home/o1/Documents/portfolio.github/NocturneRecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Install external tools** (optional but recommended):
```bash
bash scripts/install_tools.sh
```

3. **Test the framework**:
```bash
python3 test_framework.py
```

## Basic Usage

### 🔍 Subdomain Enumeration
```bash
python3 main.py --module subdomains --target example.com
```

### 📧 Email Harvesting
```bash
python3 main.py --module emails --target example.com --verbose
```

### 🔐 Certificate Analysis
```bash
python3 main.py --module certs --target example.com --output csv
```

### 🕵️ GitHub Intelligence
```bash
python3 main.py --module github --target example.com
```

### 💾 Custom Output
```bash
python3 main.py --module subdomains --target example.com --output-dir ./my-results --output json
```

## Output Formats

- **JSON**: Structured data with metadata
- **CSV**: Spreadsheet-compatible format  
- **TXT**: Simple text lists

## Configuration

Edit `config.yaml` to customize:
- Thread counts
- Request delays
- User agents
- Module-specific settings

## Advanced Usage

### Multiple modules with custom settings:
```bash
python3 main.py --module subdomains --target example.com --threads 20 --delay 0.5 --verbose
```

### Using custom wordlists:
```bash
python3 main.py --module subdomains --target example.com --wordlist ./my-wordlist.txt
```

### Custom configuration:
```bash
python3 main.py --module emails --target example.com --config ./my-config.yaml
```

---

**Need help?** Run `python3 main.py --help` for full usage information.
