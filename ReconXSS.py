import argparse
import logging
import os
import requests
import sys
import signal
from sitemapper import crawl_sitemap
from FindParameters import find_parameters
from xss_requester import test_xss

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def signal_handler(sig, frame):
    logger.info("Pipeline interrupted, results saved so far.")
    sys.exit(0)

def parse_headers(header_strings):
    """Parse header strings into a dictionary."""
    headers = {}
    if not header_strings:
        return headers
    for header in header_strings:
        if ':' not in header:
            logger.error(f"Invalid header format: {header}. Must be 'key:value'.")
            sys.exit(1)
        key, value = header.split(':', 1)
        headers[key.strip()] = value.strip()
    return headers

def validate_inputs(domains_file, payloads_file, run_sitemapper, run_findparams, run_xss, headers):
    """Validate input files and headers based on selected steps."""
    if not os.path.exists(domains_file):
        logger.error(f"Domains file not found: {domains_file}")
        sys.exit(1)
    if run_xss and not payloads_file:
        logger.error("Payloads file is required when --run-xss is specified.")
        sys.exit(1)
    if run_xss and payloads_file and not os.path.exists(payloads_file):
        logger.error(f"Payloads file not found: {payloads_file}")
        sys.exit(1)
    if not run_sitemapper and not run_findparams and run_xss:
        logger.info("Using domains_file directly for XSS testing since --run-sitemapper and --run-findparams are not specified.")

def orchestrate_pipeline(domains_file, payloads_file, output_dir, threads=10, bypass_bot=False, proxies_file=None, headers=None, run_sitemapper=True, run_findparams=True, run_xss=True):
    """Orchestrate the selected pipeline steps."""
    # Create output directory if it doesn't exist
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create output directory {output_dir}: {e}")
        sys.exit(1)

    # Initialize requests session for connection reuse
    with requests.Session() as session:
        input_file = domains_file
        mappedsites_file = os.path.join(output_dir, "mappedsites.txt")
        parameters_file = os.path.join(output_dir, "parameters.txt")
        xss_results_file = os.path.join(output_dir, "xss_results.txt")

        # Step 1: Crawl sitemaps
        if run_sitemapper:
            logger.info(f"Crawling sitemaps from {domains_file}")
            try:
                with open(domains_file, "r", encoding="utf-8") as f:
                    domains = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"Failed to read domains file {domains_file}: {e}")
                sys.exit(1)

            for domain in domains:
                logger.info(f"Crawling sitemap for {domain}")
                result = crawl_sitemap(domain, mappedsites_file, session, bypass_bot, headers)
                if not result:
                    # Retry with www prefix
                    if not domain.startswith(('http://www.', 'https://www.')):
                        www_domain = domain.replace('://', '://www.') if '://' in domain else f"https://www.{domain}"
                        logger.info(f"Retrying with {www_domain}")
                        result = crawl_sitemap(www_domain, mappedsites_file, session, bypass_bot, headers)
                    if not result:
                        logger.warning(f"No sitemap found for {domain}, continuing to next domain")

            # Check if mappedsites.txt is empty
            if not os.path.exists(mappedsites_file) or os.path.getsize(mappedsites_file) == 0:
                logger.error("No URLs found by sitemapper. Exiting.")
                sys.exit(1)
            input_file = mappedsites_file
        else:
            logger.info("Skipping sitemapper step.")

        # Step 2: Find parameters
        if run_findparams:
            logger.info(f"Finding parameters in {input_file}")
            result = find_parameters(input_file, parameters_file, session, headers)
            if not result or not os.path.exists(parameters_file) or os.path.getsize(parameters_file) == 0:
                logger.error("No parameters found by FindParameters. Exiting.")
                sys.exit(1)
            input_file = parameters_file
        else:
            logger.info("Skipping find parameters step.")

        # Step 3: Test XSS
        if run_xss:
            logger.info(f"Testing XSS on {input_file} with payloads from {payloads_file}")
            result = test_xss(input_file, payloads_file, xss_results_file, threads, bypass_bot, proxies_file, session, headers)
            if not result:
                logger.error("XSS testing failed.")
                sys.exit(1)
        else:
            logger.info("Skipping XSS testing step.")

    logger.info(f"Pipeline completed. Results saved in {output_dir}")

def main():
    # Set up signal handler for graceful interruption
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="XSS Testing Pipeline", add_help=False)
    parser.add_argument("domains_file", help="File containing domains, sitemap URLs, or URLs with parameters")
    parser.add_argument("payloads_file", nargs="?", help="File containing XSS payloads (required if --run-xss)")
    parser.add_argument("output_dir", help="Directory to save output files")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--bypass-bot", action="store_true", help="Enable bot detection bypass (random User-Agent, delays)")
    parser.add_argument("--proxies", help="File containing proxy list (one per line, format: http://ip:port)")
    parser.add_argument("--header", action="append", help="Custom header in format 'key:value' (e.g., 'Authorization:Bearer token')")
    parser.add_argument("--run-sitemapper", action="store_true", help="Run sitemapper to crawl URLs")
    parser.add_argument("--run-findparams", action="store_true", help="Run FindParameters to extract parameters")
    parser.add_argument("--run-xss", action="store_true", help="Run xss_requester to test XSS")

    # Check for minimum required arguments
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <domains.txt> [payloads.txt] <output_dir> [--threads THREADS] [--bypass-bot] [--proxies PROXIES] [--header HEADER] [--run-sitemapper] [--run-findparams] [--run-xss]")
        sys.exit(1)

    args = parser.parse_args()

    # Parse custom headers
    headers = parse_headers(args.header)

    # Default to running all steps if no specific steps are selected
    run_sitemapper = args.run_sitemapper or (not args.run_sitemapper and not args.run_findparams and not args.run_xss)
    run_findparams = args.run_findparams or (not args.run_sitemapper and not args.run_findparams and not args.run_xss)
    run_xss = args.run_xss or (not args.run_sitemapper and not args.run_findparams and not args.run_xss)

    # Validate inputs
    validate_inputs(args.domains_file, args.payloads_file, run_sitemapper, run_findparams, run_xss, headers)

    orchestrate_pipeline(
        args.domains_file,
        args.payloads_file,
        args.output_dir,
        args.threads,
        args.bypass_bot,
        args.proxies,
        headers,
        run_sitemapper,
        run_findparams,
        run_xss
    )

if __name__ == "__main__":
    main()