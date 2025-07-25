"""
Generic HTML parser for NocturneRecon
Provides utilities for parsing websites and extracting data
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.utils import print_error, print_debug, is_valid_email, is_valid_url
from core.config import get_user_agent

class HTMLParser:
    """Generic HTML parser for web scraping"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        
        # Common patterns
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.phone_pattern = re.compile(r'(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})')
        self.social_patterns = {
            'twitter': re.compile(r'(?:https?://)?(?:www\.)?twitter\.com/([A-Za-z0-9_]+)', re.IGNORECASE),
            'linkedin': re.compile(r'(?:https?://)?(?:www\.)?linkedin\.com/(?:in|company)/([A-Za-z0-9_-]+)', re.IGNORECASE),
            'facebook': re.compile(r'(?:https?://)?(?:www\.)?facebook\.com/([A-Za-z0-9_.]+)', re.IGNORECASE),
            'github': re.compile(r'(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_-]+)', re.IGNORECASE),
        }
        
    def fetch_page(self, url, timeout=10):
        """Fetch a webpage and return BeautifulSoup object"""
        try:
            headers = {
                'User-Agent': get_user_agent(self.config),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            response = self.session.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup
            
        except requests.RequestException as e:
            print_error(f"Failed to fetch {url}: {e}")
            return None
        except Exception as e:
            print_error(f"Error parsing {url}: {e}")
            return None
    
    def extract_emails(self, soup_or_text):
        """Extract email addresses from HTML or text"""
        emails = set()
        
        if isinstance(soup_or_text, BeautifulSoup):
            text = soup_or_text.get_text()
        else:
            text = str(soup_or_text)
        
        # Find all email matches
        matches = self.email_pattern.findall(text)
        for match in matches:
            email = match.lower().strip()
            if is_valid_email(email):
                emails.add(email)
        
        return list(emails)
    
    def extract_links(self, soup, base_url=None):
        """Extract all links from HTML"""
        links = set()
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Convert relative URLs to absolute
            if base_url:
                href = urljoin(base_url, href)
            
            if is_valid_url(href):
                links.add(href)
        
        return list(links)
    
    def extract_external_links(self, soup, base_url, target_domain):
        """Extract links that point to external domains"""
        external_links = []
        internal_links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Convert relative URLs to absolute
            full_url = urljoin(base_url, href)
            
            if is_valid_url(full_url):
                parsed = urlparse(full_url)
                domain = parsed.netloc.lower()
                
                if target_domain.lower() in domain or domain in target_domain.lower():
                    internal_links.append(full_url)
                else:
                    external_links.append(full_url)
        
        return external_links, internal_links
    
    def extract_phone_numbers(self, soup_or_text):
        """Extract phone numbers from HTML or text"""
        phones = set()
        
        if isinstance(soup_or_text, BeautifulSoup):
            text = soup_or_text.get_text()
        else:
            text = str(soup_or_text)
        
        matches = self.phone_pattern.findall(text)
        for match in matches:
            if isinstance(match, tuple):
                phone = f"({match[0]}) {match[1]}-{match[2]}"
            else:
                phone = match
            phones.add(phone)
        
        return list(phones)
    
    def extract_social_media(self, soup_or_text):
        """Extract social media profiles from HTML or text"""
        social_profiles = {}
        
        if isinstance(soup_or_text, BeautifulSoup):
            text = soup_or_text.get_text()
            html = str(soup_or_text)
        else:
            text = html = str(soup_or_text)
        
        for platform, pattern in self.social_patterns.items():
            profiles = set()
            
            # Search in both text and HTML
            for content in [text, html]:
                matches = pattern.findall(content)
                for match in matches:
                    if match and match.lower() not in ['home', 'login', 'signin', 'signup']:
                        profiles.add(match)
            
            if profiles:
                social_profiles[platform] = list(profiles)
        
        return social_profiles
    
    def extract_metadata(self, soup):
        """Extract metadata from HTML head"""
        metadata = {}
        
        # Title
        title = soup.find('title')
        if title:
            metadata['title'] = title.get_text(strip=True)
        
        # Meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content = meta.get('content', '')
            
            if name and content:
                metadata[f'meta_{name}'] = content
            
            # Open Graph tags
            property_attr = meta.get('property', '').lower()
            if property_attr.startswith('og:'):
                metadata[property_attr] = content
        
        return metadata
    
    def extract_contact_info(self, soup):
        """Extract contact information from a webpage"""
        contact_info = {
            'emails': self.extract_emails(soup),
            'phones': self.extract_phone_numbers(soup),
            'social_media': self.extract_social_media(soup),
            'addresses': []
        }
        
        # Look for address patterns
        text = soup.get_text()
        
        # Simple address pattern (can be improved)
        address_pattern = re.compile(
            r'\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b[^,]*(?:,\s*[A-Za-z\s]+){0,2}(?:,\s*\d{5})?',
            re.IGNORECASE
        )
        
        addresses = address_pattern.findall(text)
        contact_info['addresses'] = list(set(addresses))
        
        return contact_info
    
    def extract_forms(self, soup):
        """Extract forms and their fields"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'fields': []
            }
            
            # Extract input fields
            for input_field in form.find_all(['input', 'textarea', 'select']):
                field_data = {
                    'tag': input_field.name,
                    'type': input_field.get('type', ''),
                    'name': input_field.get('name', ''),
                    'id': input_field.get('id', ''),
                    'placeholder': input_field.get('placeholder', ''),
                    'required': input_field.has_attr('required')
                }
                form_data['fields'].append(field_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_javascript_urls(self, soup):
        """Extract URLs from JavaScript code"""
        js_urls = set()
        
        # Pattern to find URLs in JavaScript
        url_pattern = re.compile(
            r'(?:https?://|//)[A-Za-z0-9._~:/?#[\]@!$&\'()*+,;=-]+',
            re.IGNORECASE
        )
        
        # Check script tags
        for script in soup.find_all('script'):
            script_content = script.string
            if script_content:
                matches = url_pattern.findall(script_content)
                for match in matches:
                    if is_valid_url(match):
                        js_urls.add(match)
        
        return list(js_urls)
    
    def extract_comments(self, soup):
        """Extract HTML comments"""
        comments = []
        
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
            comments.append(comment.strip())
        
        return comments
    
    def crawl_site(self, start_url, max_pages=10, target_domain=None):
        """Basic site crawler"""
        visited = set()
        to_visit = [start_url]
        results = []
        
        if not target_domain:
            target_domain = urlparse(start_url).netloc
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            print_debug(f"Crawling: {url}", True)
            
            soup = self.fetch_page(url)
            if not soup:
                continue
            
            # Extract data from this page
            page_data = {
                'url': url,
                'title': soup.find('title').get_text(strip=True) if soup.find('title') else '',
                'emails': self.extract_emails(soup),
                'links': self.extract_links(soup, url),
                'contact_info': self.extract_contact_info(soup),
                'metadata': self.extract_metadata(soup)
            }
            
            results.append(page_data)
            
            # Find more internal links to crawl
            external_links, internal_links = self.extract_external_links(soup, url, target_domain)
            
            for link in internal_links:
                if link not in visited and link not in to_visit:
                    to_visit.append(link)
        
        return results
    
    def analyze_page_structure(self, soup):
        """Analyze the structure of a webpage"""
        structure = {
            'headings': {},
            'images': 0,
            'links': 0,
            'forms': 0,
            'scripts': 0,
            'stylesheets': 0
        }
        
        # Count headings
        for i in range(1, 7):
            headings = soup.find_all(f'h{i}')
            if headings:
                structure['headings'][f'h{i}'] = len(headings)
        
        # Count other elements
        structure['images'] = len(soup.find_all('img'))
        structure['links'] = len(soup.find_all('a'))
        structure['forms'] = len(soup.find_all('form'))
        structure['scripts'] = len(soup.find_all('script'))
        structure['stylesheets'] = len(soup.find_all('link', {'rel': 'stylesheet'}))
        
        return structure
