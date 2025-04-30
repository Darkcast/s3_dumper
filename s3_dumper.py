#!/usr/bin/env python3

import argparse
import base64
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlparse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Base64-encoded ASCII art Banner
encoded_art = """
CiAgICAgX19fICAgICAgICAgXwogX19ffF8gIHwgICAgICBffCB8XyBfIF9fX19fIF9fXyBfX18gX19fCnxfIC18XyAgfCAgICAgfCAuIHwgfCB8ICAgICB8IC4gfCAtX3wgIF98CnxfX198X19ffF9fX19ffF9fX3xfX198X3xffF98ICBffF9fX3xffAogICAgICAgIHxfX19fX3wgICAgICAgICAgICAgfF98CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJ5IERhcmtjYXN0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFZlcnNpb24gMC40Cg==
""".strip()

def print_ascii_art(b64_string):
    if b64_string:
        try:
            decoded = base64.b64decode(b64_string).decode('utf-8')
            print(decoded)
        except Exception as e:
            print(f"[!] Failed to decode banner: {e}")

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_args():
    parser = argparse.ArgumentParser(description="Download all files from an open S3 bucket listing.")

    # URL input options - mutually exclusive
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="URL to the S3 bucket XML listing")
    group.add_argument("-l", "--list", help="File containing list of S3 bucket URLs (one per line)")

    parser.add_argument("-t", "--threads", type=int, default=8, help="Number of concurrent download threads (default: 8)")
    return parser.parse_args()

def fetch_xml(url):
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()
        return ET.fromstring(response.text)
    except Exception as e:
        print(f"[!] Failed to fetch or parse XML from {url}: {e}")
        return None

def download_file(base_url, key, destination_folder):
    file_url = urljoin(base_url + "/", key)
    local_path = destination_folder / key

    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with requests.get(file_url, stream=True, verify=False) as r:
            r.raise_for_status()
            with open(local_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"[+] Downloaded: {key}")
    except Exception as e:
        print(f"[!] Failed to download {key}: {e}")

def get_clean_domain(url):
    domain = urlparse(url).netloc
    return domain[4:] if domain.startswith("www.") else domain

def process_url(url, threads):
    print(f"\n[*] Processing bucket: {url}")
    root = fetch_xml(url)

    if root is None:
        print(f"[!] Skipping {url} due to error")
        return 0

    ns = {'s3': 'http://doc.s3.amazonaws.com/2006-03-01'}
    keys = [elem.text for elem in root.findall("s3:Contents/s3:Key", ns)]

    if not keys:
        print(f"[!] No files found in the bucket listing for {url}")
        return 0

    domain = get_clean_domain(url)
    destination = Path.cwd() / "dump" / domain

    print(f"[*] Downloading {len(keys)} files using {threads} threads...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(download_file, url, key, destination) for key in keys]
        for future in as_completed(futures):
            future.result()

    print(f"[✓] All files from {url} downloaded to: {destination}")
    return len(keys)

def read_url_list(list_file):
    try:
        with open(list_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        return urls
    except Exception as e:
        print(f"[!] Failed to read URL list from {list_file}: {e}")
        sys.exit(1)

def main():
    # Print banner
    print_ascii_art(encoded_art)

    args = parse_args()
    total_files = 0

    if args.url:
        # Process single URL
        total_files = process_url(args.url, args.threads)
    elif args.list:
        # Process multiple URLs from file
        urls = read_url_list(args.list)
        print(f"[*] Found {len(urls)} URLs in list file")

        for i, url in enumerate(urls, 1):
            print(f"\n[*] Processing URL {i}/{len(urls)}")
            file_count = process_url(url, args.threads)
            total_files += file_count

    print(f"\n[✓] Total operation complete: {total_files} files downloaded")

if __name__ == "__main__":
    main()
