# 🤝 Copilot Instructions for NocturneRecon

## Project Context

You are working on **NocturneRecon**, a state-of-the-art OSINT and passive reconnaissance framework designed for cybersecurity professionals. The framework focuses on API-free reconnaissance techniques to maintain operational security (OPSEC) and work in air-gapped environments.

## Development Environment

### Project Structure
```
nocturnerecon/
├── main.py                 # CLI entry point
├── core/                   # Core framework
│   ├── cli.py             # Argument parsing
│   ├── utils.py           # Utilities and color printing
│   └── config.py          # Configuration management
├── modules/               # Reconnaissance modules
│   ├── subdomain_enum.py  # Subdomain enumeration
│   ├── email_enum.py      # Email harvesting
│   ├── cert_parser.py     # Certificate transparency
│   ├── github_enum.py     # GitHub intelligence
│   └── breach_parser.py   # Breach data analysis
├── scrapers/              # Web scraping utilities
├── output/                # Output directories
└── scripts/               # Installation and utility scripts
```

### Technology Stack
- **Python 3.8+**: Core language
- **requests**: HTTP client
- **beautifulsoup4**: HTML parsing
- **dnspython**: DNS operations
- **colorama**: Terminal colors
- **pyyaml**: Configuration files

## Coding Guidelines

### When Suggesting Code Changes

1. **Follow Project Patterns**: Use existing utility functions from `core/utils.py`
2. **Error Handling**: Always include proper try-catch blocks
3. **OPSEC Awareness**: Include rate limiting and user agent rotation
4. **Logging**: Use the color-coded print functions (`print_info`, `print_success`, etc.)
5. **Configuration**: Read settings from the config system
6. **Output**: Support all three output formats (JSON, CSV, TXT)

### Code Examples

#### Basic Module Structure
```python
from core.utils import print_info, print_success, print_error
from core.config import get_user_agent

class NewModule:
    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.target = clean_domain(args.target)
        
    def run(self):
        print_info(f"Starting {self.__class__.__name__} for: {self.target}")
        # Implementation here
        return results
```

#### Making HTTP Requests
```python
headers = {'User-Agent': get_user_agent(self.config)}
response = requests.get(url, headers=headers, timeout=self.timeout)
time.sleep(self.args.delay)  # Rate limiting
```

#### Error Handling Pattern
```python
try:
    result = risky_operation()
    print_success(f"Operation completed: {result}")
except requests.RequestException as e:
    print_error(f"Network error: {e}")
except Exception as e:
    print_error(f"Unexpected error: {e}")
    if self.verbose:
        import traceback
        traceback.print_exc()
```

## Common Tasks

### Adding New Reconnaissance Modules

1. **Create Module File**: Add to `modules/` directory
2. **Implement Required Methods**: `__init__`, `run`, `save_results`
3. **Update CLI**: Add new module option to `core/cli.py`
4. **Add Configuration**: Update default config in `core/config.py`
5. **Test Thoroughly**: Verify with known targets

### Enhancing Existing Modules

1. **Check Current Implementation**: Understand existing patterns
2. **Maintain Compatibility**: Don't break existing functionality
3. **Add Configuration Options**: Make features configurable
4. **Update Documentation**: Modify relevant docstrings
5. **Test Edge Cases**: Verify error handling

### Working with Output

#### JSON Output Pattern
```python
data = {
    'target': self.target,
    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    'total_found': len(results),
    'results': results
}
save_to_json(data, filepath)
```

#### CSV Output Pattern
```python
csv_data = [{'field': item.field} for item in results]
save_to_csv(csv_data, filepath, ['field'])
```

## Debugging and Testing

### Debugging Tips
- Use `--verbose` flag for detailed output
- Check network connectivity with simple requests first
- Validate target domain format
- Test with known working targets

### Testing Checklist
- [ ] Module works with valid target
- [ ] Handles invalid targets gracefully
- [ ] Rate limiting is respected
- [ ] All output formats work
- [ ] Configuration options are honored
- [ ] Error messages are helpful

## Security and OPSEC

### Always Consider
- **Rate Limiting**: Don't hammer services
- **User Agent Rotation**: Randomize request headers
- **Proxy Support**: Design with proxy chains in mind
- **Data Sanitization**: Clean output data
- **Error Disclosure**: Don't leak internal details

### Never Do
- Store sensitive data in logs
- Use hardcoded credentials
- Ignore rate limiting
- Skip input validation
- Expose debug information to users

## Module-Specific Guidelines

### Subdomain Enumeration
- Focus on passive techniques first
- Validate all discovered subdomains
- Filter results to target domain only
- Support multiple wordlists

### Email Enumeration
- Use search engine dorking
- Validate email format
- Filter to target domain only
- Implement permutation patterns

### Certificate Analysis
- Parse certificate transparency logs
- Extract SANs and CNs
- Handle expired certificates appropriately
- Deduplicate results

### GitHub Intelligence
- Search across different GitHub content types
- Detect potential secrets in code
- Extract emails from commits
- Respect GitHub's rate limits

### Breach Analysis
- Handle large files efficiently
- Support multiple file formats
- Never store plaintext passwords
- Provide metadata only

## Configuration Best Practices

### Adding New Config Options
```python
# In core/config.py DEFAULT_CONFIG
'new_module': {
    'option1': 'default_value',
    'option2': True,
    'option_list': ['item1', 'item2']
}

# In module code
config = self.config.get('new_module', {})
option1 = config.get('option1', 'fallback')
```

### Using Existing Config
```python
# Get user agent
user_agent = get_user_agent(self.config)

# Get DNS servers
dns_servers = get_dns_servers(self.config)

# Check if feature is enabled
if is_feature_enabled(self.config, 'module_name', 'feature_name'):
    # Feature implementation
```

## Common Patterns

### Threading Pattern
```python
import threading

def worker(item):
    # Process item
    with self.lock:
        self.results.add(processed_item)

threads = []
for item in items:
    thread = threading.Thread(target=worker, args=(item,))
    thread.daemon = True
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()
```

### File Processing Pattern
```python
def process_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f):
                line = line.strip()
                if line:
                    yield line
    except Exception as e:
        print_error(f"Error reading {filepath}: {e}")
```

## Questions to Ask When Reviewing Code

1. Does this follow the project's error handling patterns?
2. Is rate limiting implemented appropriately?
3. Are configuration options being used correctly?
4. Will this work with all supported output formats?
5. Is the code OPSEC-aware?
6. Are there any hardcoded values that should be configurable?
7. Is input validation sufficient?
8. Are results being filtered and deduplicated properly?

## Getting Help

### Resources
- Check existing modules for patterns
- Review `core/utils.py` for available utilities
- Look at `core/config.py` for configuration options
- Test with verbose mode for debugging

### Common Issues
- **Import Errors**: Check module paths and dependencies
- **Network Issues**: Verify connectivity and DNS resolution
- **Config Issues**: Validate YAML syntax and option names
- **Output Issues**: Check file permissions and directory existence

---

**Remember**: NocturneRecon prioritizes stealth and OPSEC. Always consider the operational impact of code changes.