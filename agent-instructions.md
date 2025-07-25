# 🤖 Agent Instructions for NocturneRecon Development

## Project Overview

NocturneRecon is a state-of-the-art, API-free OSINT (Open Source Intelligence) and passive reconnaissance framework designed for red teamers, penetration testers, and cyber threat analysts. The framework operates entirely without APIs by using advanced scraping, certificate parsing, DNS brute-force, GitHub dorking, and breach data analysis.

## Development Guidelines

### Code Structure
- **Modular Design**: Each reconnaissance technique is implemented as a separate module
- **Core Framework**: Common utilities, configuration, and CLI handling in the `core/` directory
- **Clean Separation**: Scrapers, modules, and output handlers are in separate directories
- **Error Handling**: Comprehensive error handling and graceful degradation

### Coding Standards
- **Python 3.8+**: Use modern Python features and type hints where appropriate
- **PEP 8**: Follow Python style guidelines
- **Documentation**: Include docstrings for all classes and functions
- **Error Handling**: Use try-except blocks and proper logging
- **Security**: Never expose sensitive data in logs or output files

### Module Development
When creating new modules, follow this pattern:

```python
class ModuleName:
    def __init__(self, args, config):
        # Initialize with CLI args and config
        
    def run(self):
        # Main execution method
        # Returns list/dict of results
        
    def save_results(self, results):
        # Save results in requested format
```

### OPSEC Considerations
- **Rate Limiting**: Always implement delays between requests
- **User Agent Rotation**: Use random user agents from config
- **Proxy Support**: Design with proxy support in mind
- **Minimal Footprint**: Avoid unnecessary requests
- **Error Handling**: Don't expose internal details in errors

### Testing Guidelines
- Test modules individually with known targets
- Verify output formats (JSON, CSV, TXT)
- Test error conditions and edge cases
- Validate data sanitization and filtering

## Module Specifications

### Subdomain Enumeration (`modules/subdomain_enum.py`)
- **Passive Methods**: Certificate transparency, DNS records, search engines
- **Active Methods**: DNS brute-force with wordlists
- **External Tools**: Amass, massdns integration
- **Output**: Deduplicated list of valid subdomains

### Email Enumeration (`modules/email_enum.py`)
- **Search Engines**: Google, Bing, DuckDuckGo dorking
- **GitHub Search**: Code and commit analysis
- **Permutation**: Generate common email patterns
- **Output**: Valid emails for target domain

### Certificate Parser (`modules/cert_parser.py`)
- **Sources**: crt.sh, Censys (web scraping)
- **Analysis**: Extract subdomains, issuer info, validity dates
- **Filtering**: Target domain specific results
- **Output**: Certificate data and extracted subdomains

### GitHub Enumeration (`modules/github_enum.py`)
- **Search Types**: Repositories, code, commits, issues
- **Secret Detection**: API keys, tokens, passwords
- **Data Extraction**: Emails, usernames, sensitive info
- **Output**: Comprehensive GitHub intelligence

### Breach Parser (`modules/breach_parser.py`)
- **File Support**: .txt, .gz, .zip formats
- **Pattern Matching**: Various credential formats
- **Security**: Never store plaintext passwords
- **Output**: Emails and credential metadata only

## Configuration Management

### Config Structure
The configuration system uses YAML with these sections:
- `general`: Global settings (threads, timeout, user agents)
- `module_name`: Module-specific settings
- `output`: Output format preferences
- `proxy`: Proxy configuration
- `opsec`: Operational security settings

### Adding New Config Options
1. Add default values to `DEFAULT_CONFIG` in `core/config.py`
2. Update validation in `validate_config()`
3. Use `config.get('section', {}).get('option', default)` in modules

## Output Management

### Supported Formats
- **JSON**: Structured data with metadata
- **CSV**: Tabular format for spreadsheet analysis
- **TXT**: Simple text lists

### File Naming Convention
`{target}_{module}_{timestamp}.{format}`

Example: `example_com_subdomains_20250725_143022.json`

## Error Handling

### Guidelines
- Always use try-except blocks for external requests
- Provide meaningful error messages
- Use `print_error()` for user-facing errors
- Use `print_debug()` for detailed debugging info
- Gracefully handle rate limiting and timeouts

### Common Error Scenarios
- Network connectivity issues
- Invalid target domains
- Missing external tools
- File permission problems
- Rate limiting from services

## Performance Optimization

### Threading
- Use thread pools for I/O-bound operations
- Implement proper locking for shared resources
- Respect rate limiting even with multiple threads

### Memory Management
- Process large files in chunks
- Use generators for large datasets
- Clean up temporary files

### Caching
- Implement result caching where appropriate
- Avoid redundant DNS queries
- Cache configuration data

## Security Considerations

### Data Handling
- Never log sensitive information
- Sanitize output data
- Validate all user inputs
- Use secure file permissions

### Network Security
- Support proxy chains
- Implement SSL verification
- Handle certificates properly
- Rotate user agents and headers

## Future Development

### Planned Modules
- Dark web enumeration
- Slack intelligence
- Pastebin monitoring
- Document intelligence

### Infrastructure Improvements
- Docker containerization
- REST API interface
- Database integration
- CI/CD pipeline

## Troubleshooting

### Common Issues
1. **Module Import Errors**: Check Python path and dependencies
2. **Network Timeouts**: Increase timeout values in config
3. **Rate Limiting**: Increase delay between requests
4. **Missing Tools**: Run `scripts/install_tools.sh`
5. **Permission Errors**: Check file/directory permissions

### Debug Mode
Enable verbose mode with `--verbose` flag for detailed output.

## Contributing

### Pull Request Guidelines
1. Test all changes thoroughly
2. Update documentation as needed
3. Follow coding standards
4. Include error handling
5. Add appropriate logging

### Code Review Checklist
- [ ] Follows project structure
- [ ] Includes error handling
- [ ] Respects OPSEC guidelines
- [ ] Has appropriate documentation
- [ ] Tested with multiple targets
- [ ] Output formats work correctly

---

**Last Updated**: July 25, 2025  
**Version**: 1.0.0-dev