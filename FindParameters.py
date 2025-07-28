import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, quote
import re
import logging
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_page_content(url, headers=None, session=None, custom_headers=None):
    if session is None:
        session = requests.Session()
    try:
        # Merge custom headers with defaults
        final_headers = headers or {}
        if custom_headers:
            final_headers.update(custom_headers)
        response = session.get(url, headers=final_headers, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            logging.warning(f"Failed to fetch {url}: Status {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
    except UnicodeEncodeError as e:
        logging.error(f"UnicodeEncodeError fetching {url}: {e}")
    return None

def extract_parameters(html_content, base_url):
    parameters = set()
    soup = BeautifulSoup(html_content, "html.parser")

    # Find form-related input tags and other types of input fields
    form_tags = soup.find_all(["input", "textarea", "select", "form"])
    for tag in form_tags:
        param_name = tag.get("name")
        if param_name:
            parameters.add(param_name)

    # Include hidden input fields
    hidden_fields = soup.find_all("input", type="hidden")
    for hidden in hidden_fields:
        param_name = hidden.get("name")
        if param_name:
            parameters.add(param_name)

    # Extract parameters from query strings in anchor tags
    for link in soup.find_all("a", href=True):
        parsed_url = urlparse(link["href"])
        query_params = parse_qs(parsed_url.query)
        for param_name in query_params:
            parameters.add(param_name)

    # Look for parameters in script tags or inline event handlers
    for script in soup.find_all("script"):
        matches = re.findall(r'[?&](\w+)=', script.text)
        parameters.update(matches)

    return parameters

def is_valid_parameter(param_name):
    """Filter out array-like parameters."""
    return not re.match(r'.*\[.*\]', param_name)

def read_target_urls(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            urls = file.read().splitlines()
        # Log URLs for debugging
        logging.debug(f"Read {len(urls)} URLs from {file_path}: {urls[:5]}...")
        # Sanitize URLs to ensure they are valid
        sanitized_urls = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            try:
                # Encode URL to handle non-ASCII characters
                sanitized_url = quote(url, safe=':/?=&%#')
                sanitized_urls.append(sanitized_url)
            except Exception as e:
                logging.warning(f"Skipping invalid URL {url}: {e}")
        return sanitized_urls
    except Exception as e:
        logging.error(f"Failed to read {file_path}: {e}")
        return []

def process_url(target_url, session, custom_headers=None):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Referer": "https://www.google.com/"
    }

    html_content = fetch_page_content(target_url, headers, session, custom_headers)
    if not html_content:
        return {}

    parameters = extract_parameters(html_content, target_url)
    filtered_parameters = {param: f"{target_url}?{param}=" for param in parameters if is_valid_parameter(param)}
    return filtered_parameters

def find_parameters(input_file, output_file, session=None, custom_headers=None):
    """Main function to find parameters in URLs and save to output file."""
    if session is None:
        session = requests.Session()

    # Ensure output file is empty
    try:
        open(output_file, "w", encoding="utf-8").close()
    except Exception as e:
        logging.error(f"Failed to initialize output file {output_file}: {e}")
        return None

    target_urls = read_target_urls(input_file)
    all_parameters = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda url: process_url(url, session, custom_headers), target_urls))

    for result in results:
        all_parameters.update(result)

    try:
        with open(output_file, "w", encoding="utf-8") as output_file_handle:
            for param, url in all_parameters.items():
                output_file_handle.write(f"{url}\n")
            output_file_handle.flush()
        logging.info(f"Parameters written to {output_file}")
        return output_file
    except Exception as e:
        logging.error(f"Failed to write to {output_file}: {e}")
        return None