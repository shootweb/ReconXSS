import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, quote
import re
import logging
from queue import Queue
import time
import signal
import sys
from fake_useragent import UserAgent

# Configure logging with DEBUG level
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def signal_handler(sig, frame):
    logging.info("Sitemap crawling interrupted, results saved so far.")
    sys.exit(0)

def get_domain(url):
    """Normalize URL to include scheme and handle missing 'www'."""
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    parsed_url = urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}"

def is_valid_sitemap_url(url):
    """Validate that a URL is a valid sitemap (ends with .xml and uses http/https)."""
    return url.lower().endswith('.xml') and url.startswith(('http://', 'https://'))

def get_urls_from_source(url, session, bypass_bot=False, custom_headers=None):
    """Fetch and parse URLs from a given sitemap URL."""
    try:
        headers = {
            "User-Agent": UserAgent().random if bypass_bot else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Referer": "https://www.google.com/" if bypass_bot else url,
        }
        if custom_headers:
            headers.update(custom_headers)

        time.sleep(0.5)  # Rate limiting
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        logging.debug(f"Fetched sitemap {url}: {response.text[:500]}...")
        urls = re.findall(r'<loc>(.*?)</loc>', response.text, re.DOTALL)
        valid_urls = []
        for u in urls:
            u = u.strip()
            if u:
                try:
                    # Encode URL to handle non-ASCII characters
                    sanitized_url = quote(u, safe=':/?=&%#')
                    valid_urls.append(sanitized_url)
                except Exception as e:
                    logging.warning(f"Skipping invalid URL {u}: {e}")
        logging.debug(f"Found {len(valid_urls)} URLs in {url}: {valid_urls[:5]}...")
        return valid_urls

    except requests.RequestException as e:
        logging.error(f"Error fetching URLs from {url}: {e} (Status: {getattr(e.response, 'status_code', 'N/A')})")
        return []

def extract_sitemaps_from_index(sitemap_index_url, session, bypass_bot=False, custom_headers=None):
    """Extract individual sitemap URLs from a sitemap index using XML parser."""
    try:
        headers = {
            "User-Agent": UserAgent().random if bypass_bot else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        }
        if custom_headers:
            headers.update(custom_headers)

        time.sleep(0.5)  # Rate limiting
        response = session.get(sitemap_index_url, headers=headers, timeout=10)
        response.raise_for_status()

        logging.debug(f"Sitemap index content for {sitemap_index_url}: {response.text[:500]}...")
        root = ET.fromstring(response.text)
        namespace = {'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
        sitemap_urls = [elem.text for elem in root.findall('.//sitemap:loc', namespace) if elem.text and is_valid_sitemap_url(elem.text)]
        
        logging.info(f"Found {len(sitemap_urls)} nested sitemaps in {sitemap_index_url}: {sitemap_urls}")
        return sitemap_urls

    except Exception as e:
        logging.error(f"Error parsing sitemap index {sitemap_index_url}: {e}")
        return []

def filter_urls_by_domain(domain, urls):
    """Filter URLs to keep only those that match the specified domain (ignoring www)."""
    parsed_domain = urlparse(domain).netloc
    base_domain = parsed_domain.replace('www.', '')
    filtered = []
    for url in urls:
        url_netloc = urlparse(url).netloc
        if url_netloc == parsed_domain or url_netloc.replace('www.', '') == base_domain:
            filtered.append(url)
    logging.debug(f"Filtered {len(urls)} URLs to {len(filtered)} for domain {domain}: {filtered[:5]}...")
    return filtered

def filter_in_files(urls):
    """Filter URLs to include those with allowed extensions or no extension."""
    filtered = [url for url in urls if not urlparse(url).path.endswith(('.xml', '.pdf', '.jpg', '.png', '.gif'))]
    logging.debug(f"Filtered {len(urls)} URLs to {len(filtered)} based on file extensions: {filtered[:5]}...")
    return filtered

def write_to_file(unique_urls, filename):
    """Write the list of URLs to a file."""
    try:
        with open(filename, "a", encoding="utf-8") as file:
            for url in unique_urls:
                file.write(url + "\n")
            file.flush()  # Ensure immediate write
        logging.debug(f"Wrote {len(unique_urls)} URLs to {filename}")
    except Exception as e:
        logging.error(f"Failed to write to {filename}: {e}")

def search_for_sitemap_in_robots(domain, session, bypass_bot=False, custom_headers=None):
    """Search for the sitemap URL in the robots.txt file."""
    robots_url = get_domain(domain) + '/robots.txt'
    try:
        headers = {
            "User-Agent": UserAgent().random if bypass_bot else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        }
        if custom_headers:
            headers.update(custom_headers)

        response = session.get(robots_url, headers=headers, timeout=10)
        response.raise_for_status()

        sitemap_urls = re.findall(r'Sitemap:\s*(https?://\S+)', response.text, re.IGNORECASE)
        if sitemap_urls and is_valid_sitemap_url(sitemap_urls[0]):
            logging.info(f"Sitemap found in robots.txt: {sitemap_urls[0]}")
            return sitemap_urls[0]
    except requests.RequestException as e:
        logging.warning(f"Failed to fetch robots.txt {robots_url}: {e} (Status: {getattr(e.response, 'status_code', 'N/A')})")
    
    return None

def search_for_sitemap(domain, session, bypass_bot=False, custom_headers=None):
    """Search for a sitemap by checking default locations or robots.txt."""
    base_url = get_domain(domain)
    
    # Try main sitemap
    initial_sitemap_url = f"{base_url}/sitemap.xml"
    try:
        headers = {
            "User-Agent": UserAgent().random if bypass_bot else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        }
        if custom_headers:
            headers.update(custom_headers)

        response = session.get(initial_sitemap_url, headers=headers, timeout=10)
        response.raise_for_status()
        logging.info(f"Sitemap found at: {initial_sitemap_url}")
        return initial_sitemap_url
    except requests.RequestException as e:
        logging.info(f"Main sitemap not found at {initial_sitemap_url}: {e} (Status: {getattr(e.response, 'status_code', 'N/A')})")

    # Try with www prefix
    if not base_url.startswith(('http://www.', 'https://www.')):
        www_url = base_url.replace('://', '://www.')
        www_sitemap_url = f"{www_url}/sitemap.xml"
        try:
            response = session.get(www_sitemap_url, headers=headers, timeout=10)
            response.raise_for_status()
            logging.info(f"Sitemap found at: {www_sitemap_url}")
            return www_sitemap_url
        except requests.RequestException as e:
            logging.info(f"WWW sitemap not found at {www_sitemap_url}: {e} (Status: {getattr(e.response, 'status_code', 'N/A')})")

    # Fallback to robots.txt
    logging.info("Checking robots.txt...")
    return search_for_sitemap_in_robots(domain, session, bypass_bot, custom_headers)

def process_sitemaps_iteratively(starting_sitemap, session, output_file, bypass_bot=False, custom_headers=None):
    """Iteratively process sitemaps to handle nested sitemaps."""
    all_urls = set()
    processed_sitemaps = set()
    sitemap_queue = Queue()

    # Start with the initial sitemap
    if is_valid_sitemap_url(starting_sitemap):
        sitemap_queue.put(starting_sitemap)
    else:
        logging.warning(f"Invalid sitemap URL: {starting_sitemap}")
        return

    while not sitemap_queue.empty():
        current_sitemap = sitemap_queue.get()

        if current_sitemap in processed_sitemaps:
            continue  # Avoid reprocessing the same sitemap

        logging.info(f"Processing sitemap: {current_sitemap}")
        processed_sitemaps.add(current_sitemap)

        # Get URLs from the current sitemap
        urls = get_urls_from_source(current_sitemap, session, bypass_bot, custom_headers)
        all_urls.update(urls)

        # Check if there are nested sitemaps within the current sitemap
        nested_sitemaps = extract_sitemaps_from_index(current_sitemap, session, bypass_bot, custom_headers)
        for nested_sitemap_url in nested_sitemaps:
            if nested_sitemap_url not in processed_sitemaps and is_valid_sitemap_url(nested_sitemap_url):
                sitemap_queue.put(nested_sitemap_url)

        # Periodically write to file to avoid memory overflow
        if len(all_urls) > 1000:
            filtered_urls = filter_in_files(filter_urls_by_domain(get_domain(starting_sitemap), all_urls))
            write_to_file(filtered_urls, output_file)
            all_urls.clear()  # Clear memory after writing

    # Write any remaining URLs to file
    if all_urls:
        filtered_urls = filter_in_files(filter_urls_by_domain(get_domain(starting_sitemap), all_urls))
        write_to_file(filtered_urls, output_file)

def crawl_sitemap(input_url, output_file, session=None, bypass_bot=False, custom_headers=None):
    """Main function to crawl sitemap and save URLs to output file."""
    if session is None:
        session = requests.Session()

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Ensure output file is empty
    try:
        open(output_file, "w", encoding="utf-8").close()
    except Exception as e:
        logging.error(f"Failed to initialize output file {output_file}: {e}")
        return None

    # Determine whether the input is a sitemap or a domain
    if input_url.endswith(".xml"):
        sitemap_url = input_url
    else:
        sitemap_url = search_for_sitemap(input_url, session, bypass_bot, custom_headers)

    if sitemap_url:
        # Iteratively process the sitemaps
        process_sitemaps_iteratively(sitemap_url, session, output_file, bypass_bot, custom_headers)
        logging.info(f"Mapped sites written to {output_file}")
        return output_file
    else:
        logging.error("Sitemap URL could not be determined.")
        return None