# ReconXSS

**ReconXSS** is a modular pipeline that automates sitemap crawling, parameter discovery, and XSS vulnerability testing. It is designed to streamline reconnaissance and client-side security testing by chaining together three distinct steps.

---

## Features

- Sitemap discovery and crawling from domains or sitemap URLs
- Parameter extraction from HTML forms, links, and scripts
- Automated XSS reflection testing via GET and POST (I highly recommend to use XSS Hunter -xsshunter.trufflesecurity.com)
- Bot detection evasion using random User-Agents and delays
- Proxy support and header injection
- Multi-threaded performance for scalability

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ReconXSS.git
cd ReconXSS
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

Required packages include:
- `requests`
- `beautifulsoup4`
- `fake-useragent`
- `lxml`

---

## Usage

By default ReconXSS.py will run sitemapper, findparams and XSS testing.
```bash
python ReconXSS.py <domains.txt> [payloads.txt] <output_dir> [--threads 10] [--bypass-bot] [--proxies proxylist.txt] [--header "Key:Value"] [--run-sitemapper] [--run-findparams] [--run-xss]
```

### Example

```bash
python ReconXSS.py domains.txt payloads.txt results/ --run-sitemapper --run-findparams --run-xss --bypass-bot
```

---

## Arguments

- `domains.txt`: A file containing a list of domains or sitemap URLs
- `payloads.txt`: A file with XSS payloads (required for `--run-xss`)
- `output_dir`: Directory to save the output files
- `--threads`: Number of concurrent threads (default: 10)
- `--bypass-bot`: Use fake user-agents and randomized delays
- `--proxies`: File containing proxy list in `http://ip:port` format
- `--header`: Custom header (e.g., `Authorization:Bearer token`)
- `--run-sitemapper`: Crawl sitemaps from the domain list
- `--run-findparams`: Discover query/form parameters from URLs
- `--run-xss`: Execute XSS reflection testing

---

## Output Files

- `mappedsites.txt`: Discovered URLs from sitemaps
- `parameters.txt`: URLs with parameters ready for testing
- `xss_results.txt`: Reflection and sanitization results from payload tests

---

## Example Domain Input

**domains.txt**
```
example.com
https://testsite.org/sitemap.xml
```

---

## License

MIT License

---

## Disclaimer

This tool is intended for **authorized security testing** only. Do not use it on systems you do not own or have explicit permission to test.
