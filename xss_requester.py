import requests
import concurrent.futures
import urllib.parse
import time
import sys
import os
import logging
from fake_useragent import UserAgent
import random
from bs4 import BeautifulSoup
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default configuration
THREADS = 10
RETRY_COUNT = 3
REQUEST_TIMEOUT = 10
DELAY_RANGE = (0.5, 2.0)  # Random delay range for bot bypass (seconds)

def load_file(filepath):
    if not os.path.exists(filepath):
        logger.error(f"File not found: {filepath}")
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            logger.error(f"No valid entries found in {filepath}")
        return lines
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
        return []

def get_headers(bypass_bot, custom_headers=None):
    """Generate headers, with bot bypass if enabled."""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    }
    if bypass_bot:
        ua = UserAgent()
        headers["User-Agent"] = ua.random
        headers["Referer"] = "https://www.google.com/"
    if custom_headers:
        headers.update(custom_headers)
    return headers

def write_result(output_file, result):
    """Write a single result to the output file immediately."""
    try:
        with open(output_file, "a", encoding="utf-8") as out_file:
            out_file.write(result + "\n")
            out_file.flush()  # Ensure immediate write to disk
    except Exception as e:
        logger.error(f"Failed to write to {output_file}: {e}")

def is_html_response(response):
    """Check if the response is HTML based on Content-Type."""
    content_type = response.headers.get('Content-Type', '').lower()
    return 'text/html' in content_type or 'application/xhtml+xml' in content_type

def check_reflection_context(response_text, payload):
    """Analyze where the payload is reflected in the response."""
    try:
        soup = BeautifulSoup(response_text, 'html.parser')
        contexts = []

        # Check HTML content
        for tag in soup.find_all(text=re.compile(re.escape(payload), re.IGNORECASE)):
            parent = tag.parent
            if parent.name in ['script', 'style']:
                contexts.append(f"{parent.name.upper()} context")
            else:
                contexts.append("HTML content")

        # Check attributes
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    contexts.append(f"Attribute: {tag.name}[{attr}]")

        # Check for sanitization
        sanitized_patterns = [
            re.escape(payload.replace('<', '&lt;').replace('>', '&gt;')),
            re.escape(payload.replace('"', '&quot;')),
            re.escape(payload.replace('<', '\\u003C').replace('>', '\\u003E'))
        ]
        for pattern in sanitized_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                contexts.append("Sanitized reflection")

        return contexts if contexts else ["No exploitable context"]
    except Exception as e:
        logging.warning(f"Error parsing HTML for context: {e}")
        return ["Parse error"]

def test_payload(url, payload, param, session, output_file, bypass_bot=False, proxies=None, custom_headers=None):
    """Test a single payload against a URL parameter for XSS reflection."""
    try:
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        headers = get_headers(bypass_bot, custom_headers)

        # Retry logic for transient failures
        for attempt in range(RETRY_COUNT):
            try:
                # GET request
                get_query = urllib.parse.urlencode({param: payload})
                get_url = f"{base}?{get_query}"
                get_resp = session.get(get_url, headers=headers, timeout=REQUEST_TIMEOUT, proxies=proxies)

                if get_resp.status_code in [200, 301, 302] and is_html_response(get_resp):
                    contexts = check_reflection_context(get_resp.text, payload)
                    if payload in get_resp.text and "Sanitized reflection" not in contexts:
                        result = f"[REFLECTED:GET] {get_url} [Status: {get_resp.status_code}] [Context: {', '.join(contexts)}]"
                        logger.info(result)
                        write_result(output_file, result)
                        return result
                    elif "Sanitized reflection" in contexts:
                        result = f"[SANITIZED:GET] {get_url} [Status: {get_resp.status_code}] [Context: {', '.join(contexts)}]"
                        logger.info(result)
                        write_result(output_file, result)
                        return result

                # POST request
                post_data = {param: payload}
                post_resp = session.post(base, data=post_data, headers=headers, timeout=REQUEST_TIMEOUT, proxies=proxies)

                if post_resp.status_code in [200, 201, 301, 302] and is_html_response(post_resp):
                    contexts = check_reflection_context(post_resp.text, payload)
                    if payload in post_resp.text and "Sanitized reflection" not in contexts:
                        result = f"[REFLECTED:POST] {base} DATA={post_data} [Status: {post_resp.status_code}] [Context: {', '.join(contexts)}]"
                        logger.info(result)
                        write_result(output_file, result)
                        return result
                    elif "Sanitized reflection" in contexts:
                        result = f"[SANITIZED:POST] {base} DATA={post_data} [Status: {post_resp.status_code}] [Context: {', '.join(contexts)}]"
                        logger.info(result)
                        write_result(output_file, result)
                        return result

                break  # Exit retry loop if successful

            except requests.exceptions.RequestException as e:
                if attempt == RETRY_COUNT - 1:
                    error = f"[ERROR] {url} with {payload} on param {param} -> {e}"
                    logger.error(error)
                    write_result(output_file, error)
                    return error
                time.sleep(random.uniform(*DELAY_RANGE))  # Random delay for retries

        return None

    except Exception as e:
        error = f"[ERROR] {url} with {payload} on param {param} -> {e}"
        logger.error(error)
        write_result(output_file, error)
        return error

def test_xss(urls_file, payloads_file, output_file, threads=THREADS, bypass_bot=False, proxies_file=None, session=None, custom_headers=None):
    """Main function to test XSS payloads on URLs."""
    if session is None:
        session = requests.Session()

    # Ensure output file is empty
    try:
        open(output_file, "w", encoding="utf-8").close()
    except Exception as e:
        logger.error(f"Failed to initialize output file {output_file}: {e}")
        return None

    # Load URLs and payloads
    urls = load_file(urls_file)
    payloads = load_file(payloads_file)
    if not payloads:
        logger.error("No payloads provided in payloads_file. Exiting.")
        return None
    proxy_list = load_file(proxies_file) if proxies_file else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            params = list(qs.keys()) if qs else []
            if parsed.query and not qs:
                params = [parsed.query.split('=')[0]]  # Handle query= case

            if not params:
                logger.warning(f"No query parameters found in {url}")
                continue

            # Test each parameter with each payload
            for param in params:
                for payload in payloads:
                    proxies = {"http": random.choice(proxy_list), "https": random.choice(proxy_list)} if proxy_list else None
                    futures.append(executor.submit(test_payload, url, payload, param, session, output_file, bypass_bot, proxies, custom_headers))
                    if bypass_bot:
                        time.sleep(random.uniform(*DELAY_RANGE))

        for future in concurrent.futures.as_completed(futures):
            future.result()

    logging.info(f"XSS testing results written to {output_file}")
    return output_file