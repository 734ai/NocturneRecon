# 📋 Requirements

## System Requirements

- **Python 3.8+** (Recommended: Python 3.9 or 3.10)
- **Linux/MacOS** (Windows support via WSL)
- **4GB RAM minimum** (8GB+ recommended for large operations)
- **Internet connection** (for passive reconnaissance)

## Python Dependencies

All Python dependencies are listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

### Core Dependencies:
- `requests` - HTTP client for web scraping
- `beautifulsoup4` - HTML/XML parsing
- `lxml` - Fast XML/HTML parser
- `dnspython` - DNS toolkit
- `colorama` - Cross-platform colored terminal text
- `tqdm` - Progress bars
- `pyyaml` - YAML parsing for configuration
- `selenium` - Web automation (optional, for JavaScript-heavy sites)
- `fake-useragent` - Random user agent generation
- `validators` - URL/email validation

## External Tools (Optional)

These tools enhance functionality but are not required for basic operation:

### DNS/Subdomain Tools:
- `amass` - Advanced subdomain enumeration
- `massdns` - Fast DNS resolution
- `subfinder` - Fast passive subdomain discovery

### Screenshot Tools:
- `gowitness` - Web screenshot utility
- `aquatone` - Visual inspection of websites

### Additional Tools:
- `git` - For GitHub enumeration
- `curl` - HTTP client
- `proxychains` - Proxy chaining for OPSEC

## Installation Script

Run the automated installation script:

```bash
bash scripts/install_tools.sh
```

This will install compatible external tools for your system.

## Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv nocturnerecon-env

# Activate (Linux/Mac)
source nocturnerecon-env/bin/activate

# Activate (Windows)
nocturnerecon-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Docker Support (Future)

Docker containerization is planned for v2.0 to ensure consistent environments across all platforms.