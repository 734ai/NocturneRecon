# 🦉 NocturneRecon

> **State-of-the-art API-free OSINT & Passive Recon Framework**

NocturneRecon is a stealth-oriented, fully modular reconnaissance toolkit for red teamers, penetration testers, and cyber threat analysts. Designed to **outperform theHarvester**, it operates **entirely without APIs** by using advanced scraping, certificate parsing, DNS brute-force, GitHub dorking, and breach data analysis — making it highly OPSEC-resilient and airgap-compatible.

---

## 🎯 Core Features

| Capability               | Description                                                                   |
| ------------------------ | ----------------------------------------------------------------------------- |
| 🔎 Subdomain Enumeration | Amass, DNS brute-force, crt.sh scraping, massdns, DNSDumpster                 |
| 📧 Email Harvesting      | Google/Bing dork-based scraping, permutator, GitHub exposure scanning         |
| 🔐 Breach Intel          | Local parsing of breach dumps (`breach-parse`, `leakcheck`, custom regex)     |
| 🧬 Cert Transparency     | Passive cert scraping from crt.sh & Censys HTML feeds                         |
| 🕵️ GitHub Intel         | GitHub dork scanning (regex, secret leaks, emails via scraping)               |
| 🖼 Screenshot Engine     | Full webpage rendering of resolved subdomains using `gowitness` or `aquatone` |
| 🔍 Search Engine Scraper | Headless search engine scraping via `serp_scraper.py`                         |
| 💾 Output Management     | Structured output in JSON/CSV, auto-saved per module with timestamping        |

---

## 🧰 Project Structure

```
nocturnerecon/
├── main.py                      # CLI entrypoint
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── LICENSE                      # MIT License
├── core/
│   ├── cli.py                   # Argument parsing
│   ├── utils.py                 # Color printing, file I/O
│   └── config.py                # Future YAML-based config loader
├── modules/
│   ├── subdomain_enum.py        # Subdomain recon module
│   ├── email_enum.py            # Email recon module
│   ├── breach_parser.py         # Breach intelligence
│   ├── cert_parser.py           # Certificate search
│   └── github_enum.py           # GitHub dorking/search
├── scrapers/
│   ├── serp_scraper.py          # Search engine HTML parser
│   └── html_parser.py           # Generic site scrapers
├── output/
│   ├── screenshots/
│   ├── emails/
│   └── subdomains/
└── scripts/
    └── install_tools.sh         # Installs CLI binaries like amass, gowitness, etc.
```

---

## 💻 Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/nocturnerecon
cd nocturnerecon

# Create virtual environment (optional)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install required system tools
bash scripts/install_tools.sh
```

---

## 🚀 Usage

```bash
python3 main.py --module subdomains --target example.com
python3 main.py --module emails --target example.com
python3 main.py --module certs --target example.com
python3 main.py --module github --target example.com
```

Supports output in JSON, CSV, and TXT.

---

## 🧪 Module Highlights

### 🔹 Subdomain Enumeration

* Passive: `crt.sh`, `DNSDumpster`, `rapiddns`, `certstream`
* Brute: `amass`, `massdns`, custom wordlist DNS fuzz

### 🔹 Email Harvesting

* Google dork-based search (scraped)
* GitHub secrets & regex matchers
* Email permutation generator

### 🔹 Breach Parser

* Uses local `.gz`, `.txt` dumps or `breach-parse`
* Matches emails/domains

### 🔹 GitHub Recon

* Dorking & HTML scraping via search
* Optional local clone scanner

---

## 🛡️ OPSEC Friendly

* ❌ No APIs
* 🧊 Works in airgapped/offline labs
* 🌐 Compatible with `proxychains`, `TOR`, `Tails`, `Whonix`
* 🤖 Adjustable scraping delays, user-agent randomization, header spoofing

---

## 🧠 Future Modules (Planned)

* `darkweb_enum`: Tor hidden services parsing
* `slack_scraper`: Slack misconfigs and exposed chat leaks
* `paste_monitor`: Monitor pastebin clones for leaks
* `PDF/Doc Intel`: Harvest and extract metadata from public files

---

## 📜 License

MIT © 2025 Muzan Sano
