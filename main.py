import argparse
import requests
import logging
import sys
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    parser = argparse.ArgumentParser(description="Analyzes HTTP response sizes to detect anomalies.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-t", "--threshold", type=int, default=100000, help="Threshold size (in bytes) for flagging large responses. Default: 100000")
    parser.add_argument("-w", "--wordlist", type=str, help="Path to a wordlist for directory brute-forcing.")
    parser.add_argument("-d", "--detect_tech", action="store_true", help="Attempt to detect the technology stack used by the website.")
    return parser.parse_args()


def get_response_size(url):
    """Fetch a URL and return (size, status), or (None, None) on a network error.

    Error status responses are data for this analyzer, so the status is
    read first and the body size is measured for 4xx and 5xx responses
    as well instead of raising them away.
    """
    try:
        response = requests.get(url, timeout=10)
        return len(response.content), response.status_code
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return None, None


def analyze_response_size(url, threshold):
    """Analyze the primary URL. Returns True when a response was received."""
    size, status = get_response_size(url)
    if size is None:
        return False

    logging.info(f"Response size for {url}: {size} bytes (status {status})")

    if size > threshold:
        logging.warning(f"Large response size detected for {url}. Size: {size} bytes, Threshold: {threshold} bytes. Potential data exfiltration or DoS vulnerability.")
    return True


def directory_bruteforce(url, wordlist_path):
    """Brute-force paths from a wordlist.

    Returns (recorded, failed): recorded counts every response received,
    including error statuses with their status and size; failed counts
    network errors. Returns None when the wordlist cannot be opened.
    """
    try:
        with open(wordlist_path, 'r') as f:
            directories = [line.strip() for line in f]
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
        return None
    except OSError as e:
        logging.error(f"Could not open wordlist {wordlist_path}: {e}")
        return None

    logging.info(f"Starting directory brute-force on {url} using {wordlist_path}")
    recorded = 0
    failed = 0
    for directory in directories:
        if not directory:
            continue
        target_url = f"{url.rstrip('/')}/{directory}"
        size, status = get_response_size(target_url)
        if size is None:
            failed += 1
            continue
        recorded += 1
        logging.info(f"{target_url}: Status {status}, Response size {size} bytes")
    logging.info(f"Directory brute-force summary: {recorded} responses recorded, {failed} fetches failed.")
    return recorded, failed

def detect_technology(url):
    """Attempt technology detection. Error responses are still analyzed,
    because their headers and body are the data this check reports."""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        if "WordPress" in response.text:
            logging.info("Technology Detection: WordPress detected (based on HTML content).")
        if response.headers.get("X-Powered-By"):
            logging.info(f"Technology Detection: X-Powered-By header: {response.headers.get('X-Powered-By')}")

        for meta in soup.find_all('meta'):
            if meta.get('name') == 'generator':
                logging.info(f"Technology Detection: Generator meta tag: {meta.get('content')}")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error detecting technology for {url}: {e}")
        return False



def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def main():
    args = setup_argparse()

    if not validate_url(args.url):
        logging.error("Invalid URL provided.  Please ensure the URL starts with http:// or https://")
        sys.exit(1)

    failures = []

    if not analyze_response_size(args.url, args.threshold):
        failures.append(f"primary URL {args.url} could not be fetched")

    if args.wordlist:
        result = directory_bruteforce(args.url, args.wordlist)
        if result is None:
            failures.append(f"wordlist {args.wordlist} could not be opened")
        else:
            recorded, failed = result
            if recorded == 0 and failed > 0:
                failures.append("directory brute-force received no responses")

    if args.detect_tech:
        detect_technology(args.url)

    if failures:
        logging.error("Scan failed: " + "; ".join(failures))
        sys.exit(1)



if __name__ == "__main__":
    main()

# Example Usage:
# python vscan-http-response-size-analyzer.py https://www.example.com
# python vscan-http-response-size-analyzer.py https://www.example.com -t 50000
# python vscan-http-response-size-analyzer.py https://www.example.com -w wordlist.txt
# python vscan-http-response-size-analyzer.py https://www.example.com -d
# python vscan-http-response-size-analyzer.py https://www.example.com -w wordlist.txt -d
