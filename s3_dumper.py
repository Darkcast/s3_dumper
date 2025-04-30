#!/usr/bin/env python3

import argparse
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlparse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_args():
    parser = argparse.ArgumentParser(description="Download all files from an open S3 bucket listing.")
    parser.add_argument("-u", "--url", required=True, help="URL to the S3 bucket XML listing")
    parser.add_argument("-t", "--threads", type=int, default=8, help="Number of concurrent download threads (default: 8)")
    return parser.parse_args()

def fetch_xml(url):
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()
        return ET.fromstring(response.text)
    except Exception as e:
        print(f"[!] Failed to fetch or parse XML: {e}")
        exit(1)

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

def main():
    args = parse_args()
    base_url = args.url
    root = fetch_xml(base_url)

    ns = {'s3': 'http://doc.s3.amazonaws.com/2006-03-01'}
    keys = [elem.text for elem in root.findall("s3:Contents/s3:Key", ns)]

    if not keys:
        print("[!] No files found in the bucket listing.")
        return

    domain = get_clean_domain(base_url)
    destination = Path.cwd() / "site" / domain

    print(f"[*] Downloading {len(keys)} files using {args.threads} threads...")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(download_file, base_url, key, destination) for key in keys]
        for future in as_completed(futures):
            future.result()

    print(f"\n[✓] All files downloaded to: {destination}")

if __name__ == "__main__":
    main()
