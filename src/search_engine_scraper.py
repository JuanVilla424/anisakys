"""
Professional Search Engine Scraper for Phishing Detection
Extracts URLs from Google, Bing, DuckDuckGo results including ads
"""
import requests
import re
import logging
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
import time

logger = logging.getLogger(__name__)


class SearchEngineScraper:
    """Professional search engine scraper for phishing detection."""

    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def extract_domain(self, url: str) -> str:
        """Extract clean domain from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            # Remove www
            domain = domain.replace('www.', '')
            return domain.lower()
        except:
            return ""

    def is_valid_url(self, url: str, exclude_domain: str) -> bool:
        """Check if URL is valid and not the original domain."""
        if not url or not url.startswith('http'):
            return False

        domain = self.extract_domain(url)
        exclude_clean = exclude_domain.replace('www.', '').lower()

        # Exclude original domain and search engines
        excluded = [exclude_clean, 'google.', 'bing.', 'duckduckgo.', 'yahoo.',
                   'search.', 'wikipedia.', 'youtube.']

        return not any(exc in domain for exc in excluded)

    def search_google(self, query: str, exclude_domain: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """
        Search Google and extract URLs from organic results and ads.

        Args:
            query: Search query
            exclude_domain: Domain to exclude from results
            max_results: Maximum results to extract

        Returns:
            List of dicts with url, title, snippet, is_ad
        """
        results = []

        try:
            # Google search URL
            search_url = f"https://www.google.com/search?q={requests.utils.quote(query)}&num=50"

            logger.info(f"🔍 Searching Google: {query[:50]}...")

            response = self.session.get(search_url, timeout=10)

            if response.status_code != 200:
                logger.warning(f"⚠️ Google returned status {response.status_code}")
                return results

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract organic results
            for g in soup.find_all('div', class_='g'):
                try:
                    # Find link
                    link_tag = g.find('a')
                    if not link_tag or not link_tag.get('href'):
                        continue

                    url = link_tag['href']

                    # Clean Google redirect URLs
                    if '/url?q=' in url:
                        url = parse_qs(urlparse(url).query).get('q', [''])[0]

                    if not self.is_valid_url(url, exclude_domain):
                        continue

                    # Extract title
                    title_tag = g.find('h3')
                    title = title_tag.get_text() if title_tag else ''

                    # Extract snippet
                    snippet_tag = g.find('div', class_=['VwiC3b', 'lyLwlc'])
                    snippet = snippet_tag.get_text() if snippet_tag else ''

                    results.append({
                        'url': url,
                        'title': title,
                        'snippet': snippet,
                        'is_ad': False,
                        'source': 'google_organic'
                    })

                    if len(results) >= max_results:
                        break

                except Exception as e:
                    logger.debug(f"Error parsing Google result: {e}")
                    continue

            # Extract ads (top and bottom)
            for ad in soup.find_all('div', {'data-text-ad': '1'}):
                try:
                    link_tag = ad.find('a')
                    if not link_tag or not link_tag.get('href'):
                        continue

                    url = link_tag['href']

                    # Clean URL
                    if '/aclk?' in url or '/url?' in url:
                        parsed = parse_qs(urlparse(url).query)
                        url = parsed.get('q', parsed.get('adurl', ['']))[0]

                    if not self.is_valid_url(url, exclude_domain):
                        continue

                    title_tag = ad.find('div', role='heading')
                    title = title_tag.get_text() if title_tag else ''

                    results.append({
                        'url': url,
                        'title': title,
                        'snippet': 'Advertisement',
                        'is_ad': True,
                        'source': 'google_ad'
                    })

                    if len(results) >= max_results:
                        break

                except Exception as e:
                    logger.debug(f"Error parsing Google ad: {e}")
                    continue

            logger.info(f"✅ Google: Found {len(results)} URLs")

        except Exception as e:
            logger.error(f"❌ Google search error: {e}")

        return results

    def search_bing(self, query: str, exclude_domain: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """Search Bing and extract URLs."""
        results = []

        try:
            search_url = f"https://www.bing.com/search?q={requests.utils.quote(query)}&count=50"

            logger.info(f"🔍 Searching Bing: {query[:50]}...")

            response = self.session.get(search_url, timeout=10)

            if response.status_code != 200:
                logger.warning(f"⚠️ Bing returned status {response.status_code}")
                return results

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract organic results
            for result in soup.find_all('li', class_='b_algo'):
                try:
                    link_tag = result.find('a')
                    if not link_tag or not link_tag.get('href'):
                        continue

                    url = link_tag['href']

                    if not self.is_valid_url(url, exclude_domain):
                        continue

                    title = link_tag.get_text()

                    snippet_tag = result.find('p')
                    snippet = snippet_tag.get_text() if snippet_tag else ''

                    results.append({
                        'url': url,
                        'title': title,
                        'snippet': snippet,
                        'is_ad': False,
                        'source': 'bing_organic'
                    })

                    if len(results) >= max_results:
                        break

                except Exception as e:
                    logger.debug(f"Error parsing Bing result: {e}")
                    continue

            # Extract ads
            for ad in soup.find_all('li', class_='b_ad'):
                try:
                    link_tag = ad.find('a')
                    if not link_tag or not link_tag.get('href'):
                        continue

                    url = link_tag['href']

                    if not self.is_valid_url(url, exclude_domain):
                        continue

                    title = link_tag.get_text()

                    results.append({
                        'url': url,
                        'title': title,
                        'snippet': 'Advertisement',
                        'is_ad': True,
                        'source': 'bing_ad'
                    })

                    if len(results) >= max_results:
                        break

                except Exception as e:
                    logger.debug(f"Error parsing Bing ad: {e}")
                    continue

            logger.info(f"✅ Bing: Found {len(results)} URLs")

        except Exception as e:
            logger.error(f"❌ Bing search error: {e}")

        return results

    def search_duckduckgo(self, query: str, exclude_domain: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """Search DuckDuckGo and extract URLs."""
        results = []

        try:
            # DuckDuckGo HTML search
            search_url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"

            logger.info(f"🔍 Searching DuckDuckGo: {query[:50]}...")

            response = self.session.get(search_url, timeout=10)

            if response.status_code != 200:
                logger.warning(f"⚠️ DuckDuckGo returned status {response.status_code}")
                return results

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract results
            for result in soup.find_all('div', class_='result'):
                try:
                    link_tag = result.find('a', class_='result__a')
                    if not link_tag or not link_tag.get('href'):
                        continue

                    # DuckDuckGo uses redirect
                    url = link_tag['href']
                    if 'uddg=' in url:
                        url = unquote(parse_qs(urlparse(url).query).get('uddg', [''])[0])

                    if not self.is_valid_url(url, exclude_domain):
                        continue

                    title = link_tag.get_text()

                    snippet_tag = result.find('a', class_='result__snippet')
                    snippet = snippet_tag.get_text() if snippet_tag else ''

                    results.append({
                        'url': url,
                        'title': title,
                        'snippet': snippet,
                        'is_ad': False,
                        'source': 'duckduckgo_organic'
                    })

                    if len(results) >= max_results:
                        break

                except Exception as e:
                    logger.debug(f"Error parsing DuckDuckGo result: {e}")
                    continue

            logger.info(f"✅ DuckDuckGo: Found {len(results)} URLs")

        except Exception as e:
            logger.error(f"❌ DuckDuckGo search error: {e}")

        return results

    def comprehensive_search(self, dorks: List[str], exclude_domain: str,
                            max_results_per_dork: int = 10) -> List[Dict[str, Any]]:
        """
        Execute comprehensive search across multiple engines with dorks.

        Args:
            dorks: List of search queries/dorks
            exclude_domain: Domain to exclude
            max_results_per_dork: Max results per dork per engine

        Returns:
            Deduplicated list of URLs found
        """
        all_results = []
        seen_urls: Set[str] = set()

        logger.info(f"🌐 Starting comprehensive search with {len(dorks)} dorks")

        for idx, dork in enumerate(dorks, 1):
            logger.info(f"📊 Processing dork {idx}/{len(dorks)}")

            # Search Google
            google_results = self.search_google(dork, exclude_domain, max_results_per_dork)

            # Search Bing
            time.sleep(1)  # Rate limiting
            bing_results = self.search_bing(dork, exclude_domain, max_results_per_dork)

            # Search DuckDuckGo
            time.sleep(1)  # Rate limiting
            ddg_results = self.search_duckduckgo(dork, exclude_domain, max_results_per_dork)

            # Combine and deduplicate
            for result in google_results + bing_results + ddg_results:
                url = result['url']
                if url not in seen_urls:
                    seen_urls.add(url)
                    result['search_query'] = dork
                    all_results.append(result)

            # Rate limiting between dorks
            if idx < len(dorks):
                time.sleep(2)

        logger.info(f"✅ Comprehensive search complete: {len(all_results)} unique URLs found")

        return all_results
