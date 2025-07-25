"""
Search Engine Results Page (SERP) scraper for NocturneRecon
Handles scraping of Google, Bing, DuckDuckGo and other search engines
"""

import requests
import time
import random
from urllib.parse import quote, urljoin
from bs4 import BeautifulSoup
from core.utils import print_error, print_debug, print_warning
from core.config import get_user_agent

class SERPScraper:
    """Search Engine Results Page scraper"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        
        # Default headers
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
    def search_google(self, query, num_results=100, delay=2.0):
        """Search Google and return results"""
        results = []
        
        try:
            # Update headers with random user agent
            headers = self.headers.copy()
            headers['User-Agent'] = get_user_agent(self.config)
            
            # Google search URL
            url = f"https://www.google.com/search?q={quote(query)}&num={num_results}"
            
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse search results
            for result_div in soup.find_all('div', class_='g'):
                try:
                    # Get title and URL
                    title_elem = result_div.find('h3')
                    link_elem = result_div.find('a')
                    
                    if title_elem and link_elem:
                        title = title_elem.get_text(strip=True)
                        url = link_elem.get('href', '')
                        
                        # Get snippet
                        snippet_elem = result_div.find('span', class_='st')
                        if not snippet_elem:
                            snippet_elem = result_div.find('div', class_='s')
                        snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                        
                        results.append({
                            'title': title,
                            'url': url,
                            'snippet': snippet,
                            'engine': 'google'
                        })
                        
                except Exception as e:
                    print_debug(f"Error parsing Google result: {e}", True)
                    continue
            
            # Rate limiting
            time.sleep(delay + random.uniform(0, 1))
            
        except requests.RequestException as e:
            print_error(f"Google search failed: {e}")
        except Exception as e:
            print_error(f"Error processing Google results: {e}")
        
        return results
    
    def search_bing(self, query, num_results=50, delay=2.0):
        """Search Bing and return results"""
        results = []
        
        try:
            headers = self.headers.copy()
            headers['User-Agent'] = get_user_agent(self.config)
            
            # Bing search URL
            url = f"https://www.bing.com/search?q={quote(query)}&count={num_results}"
            
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse search results
            for result_li in soup.find_all('li', class_='b_algo'):
                try:
                    # Get title and URL
                    title_elem = result_li.find('h2')
                    if title_elem:
                        link_elem = title_elem.find('a')
                        if link_elem:
                            title = link_elem.get_text(strip=True)
                            url = link_elem.get('href', '')
                            
                            # Get snippet
                            snippet_elem = result_li.find('p')
                            snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                            
                            results.append({
                                'title': title,
                                'url': url,
                                'snippet': snippet,
                                'engine': 'bing'
                            })
                            
                except Exception as e:
                    print_debug(f"Error parsing Bing result: {e}", True)
                    continue
            
            # Rate limiting
            time.sleep(delay + random.uniform(0, 1))
            
        except requests.RequestException as e:
            print_error(f"Bing search failed: {e}")
        except Exception as e:
            print_error(f"Error processing Bing results: {e}")
        
        return results
    
    def search_duckduckgo(self, query, delay=2.0):
        """Search DuckDuckGo and return results"""
        results = []
        
        try:
            headers = self.headers.copy()
            headers['User-Agent'] = get_user_agent(self.config)
            
            # DuckDuckGo search URL (HTML version)
            url = f"https://duckduckgo.com/html/?q={quote(query)}"
            
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse search results
            for result_div in soup.find_all('div', class_='result'):
                try:
                    # Get title and URL
                    title_elem = result_div.find('a', class_='result__a')
                    if title_elem:
                        title = title_elem.get_text(strip=True)
                        url = title_elem.get('href', '')
                        
                        # Get snippet
                        snippet_elem = result_div.find('a', class_='result__snippet')
                        snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                        
                        results.append({
                            'title': title,
                            'url': url,
                            'snippet': snippet,
                            'engine': 'duckduckgo'
                        })
                        
                except Exception as e:
                    print_debug(f"Error parsing DuckDuckGo result: {e}", True)
                    continue
            
            # Rate limiting
            time.sleep(delay + random.uniform(0, 1))
            
        except requests.RequestException as e:
            print_error(f"DuckDuckGo search failed: {e}")
        except Exception as e:
            print_error(f"Error processing DuckDuckGo results: {e}")
        
        return results
    
    def search_all_engines(self, query, delay=2.0):
        """Search all engines and combine results"""
        all_results = []
        
        # Search each engine
        print_debug("Searching Google...", True)
        google_results = self.search_google(query, delay=delay)
        all_results.extend(google_results)
        
        print_debug("Searching Bing...", True)
        bing_results = self.search_bing(query, delay=delay)
        all_results.extend(bing_results)
        
        print_debug("Searching DuckDuckGo...", True)
        ddg_results = self.search_duckduckgo(query, delay=delay)
        all_results.extend(ddg_results)
        
        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for result in all_results:
            url = result.get('url', '')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(result)
        
        return unique_results
    
    def extract_content_from_results(self, results, delay=1.0):
        """Extract full content from search result URLs"""
        enriched_results = []
        
        for result in results:
            try:
                url = result.get('url', '')
                if not url or url.startswith('#'):
                    continue
                
                # Skip certain URL types
                skip_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
                if any(url.lower().endswith(ext) for ext in skip_extensions):
                    print_debug(f"Skipping document URL: {url}", True)
                    continue
                
                headers = self.headers.copy()
                headers['User-Agent'] = get_user_agent(self.config)
                
                response = self.session.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                
                # Parse content
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Remove script and style elements
                for script in soup(["script", "style"]):
                    script.decompose()
                
                # Get text content
                text_content = soup.get_text()
                
                # Clean up text
                lines = (line.strip() for line in text_content.splitlines())
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                clean_text = ' '.join(chunk for chunk in chunks if chunk)
                
                # Add content to result
                result['content'] = clean_text[:5000]  # Limit content size
                result['content_length'] = len(clean_text)
                
                enriched_results.append(result)
                
                # Rate limiting
                time.sleep(delay + random.uniform(0, 0.5))
                
            except requests.RequestException as e:
                print_debug(f"Failed to fetch content from {url}: {e}", True)
                # Add result without content
                enriched_results.append(result)
            except Exception as e:
                print_debug(f"Error processing content from {url}: {e}", True)
                enriched_results.append(result)
        
        return enriched_results
    
    def search_with_dorking(self, base_query, dork_patterns, delay=2.0):
        """Perform dorking with multiple patterns"""
        all_results = []
        
        for pattern in dork_patterns:
            query = pattern.format(query=base_query)
            print_debug(f"Searching with dork: {query}", True)
            
            # Search all engines with this dork
            results = self.search_all_engines(query, delay=delay)
            
            # Mark results with the dork pattern used
            for result in results:
                result['dork_pattern'] = pattern
                result['full_query'] = query
            
            all_results.extend(results)
        
        return all_results
