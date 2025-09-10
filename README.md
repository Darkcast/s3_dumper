```
     ___         _
 ___|_  |      _| |_ _ _____ ___ ___ ___
|_ -|_  |     | . | | |     | . | -_|  _|
|___|___|_____|___|___|_|_|_|  _|___|_|
        |_____|             |_|
                                 by Darkcast

```

# s3dumper

S3Dumper is an advanced Python tool designed to download all files from misconfigured S3 buckets with directory listing enabled. It features adaptive threading, sensitive file detection, secret scanning, and stealth capabilities for security research and penetration testing.

## Features

- **Adaptive Threading**: Automatically adjusts thread count based on performance metrics
- **Sensitive File Detection**: Identifies potentially sensitive files (configs, keys, databases, etc.)
- **Secret Scanning**: Integrated TruffleHog support for detecting hardcoded secrets
- **Stealth Mode**: Random bot user-agents to avoid detection
- **Real-time Progress**: Live download progress and performance statistics
- **File Categorization**: Automatic classification of downloaded files
- **Multi-Platform**: Works on Windows, macOS, and Linux
- **Retry Logic**: Robust error handling with exponential backoff
- **Detailed Reporting**: Comprehensive security warnings and summaries

## Requirements

- Python 3.6+
- Required Python packages:
```bash
requests[socks]
urllib3
psutil
colorama
lxml
```

## Install TruffleHog (Optional)

macOS:
```bash
brew install trufflehog
```
Linux:

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

Windows: 
Download from TruffleHog [Releases](https://github.com/trufflesecurity/trufflehog/releases)

or 

With Chocolatey:
```bash
choco install trufflehog
```
With Scoop:
```bash 
scoop install trufflehog
```

With Winget:
```bash
winget install TruffleHog
```

## Install S3Dumper
Clone or download the repository
Install dependencies:

```bash
pip3 install requirement.txt
or
pdm install

```

## Usage
Basic Usage

```bash
python3 s3_dumper.py -u https://bucket.s3.amazonaws.com/
```

Advanced Usage
```bash

# rotating UA mode with secret scanning
python3 s3_dumper.py -u https://bucket.s3.amazonaws.com/ -rua -s

# Fixed threading with 20 threads
python3 s3_dumper.py -u https://bucket.s3.amazonaws.com/ -t 20 --no-adaptive

# Process multiple buckets from a file
python3 s3_dumper.py -l bucket_urls.txt -s

```
## Command Line Options
Option	Description
```bash
-u,     --url                   URL to the S3 bucket XML listing
-l,     --list	                File containing list of S3 bucket URLs (one per line)
-t,     --threads	            Number of threads (default: 10, adaptive unless --no-adaptive)
-na,    --no-adaptive	        Use fixed thread count instead of adaptive
-ai,    --adjustment-interval	Seconds between thread adjustments (default: 2)
-rua,   --random-user-agent	    Use random bot user agents for stealth
-s,     --secrets	            Run TruffleHog secret scan on downloaded files
--version	                    Show version information
--tor                           Route traffic through Tor for anonymity
--debug                         Enable debug output for troubleshooting

```

## ⚠️ Security Warnings
This tool will highlight potentially sensitive files:


━━━ SECURITY WARNINGS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[!] 3 sensitive files found:

  - config/database.json          (Configuration file)
      💾 Saved as: dump/bucket.com/config/database.json

  - backup.sql                    (Database file)
      💾 Saved as: dump/bucket.com/backup.sql


## 🔐 Secret Detection
With TruffleHog integration (-s flag):

━━━ SECRETS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[!] 2 secrets found:

  - config/app.js                 (API key) [VERIFIED]
      💾 Saved as: dump/bucket.com/config/app.js
      🔍 Detector: Stripe
      📍 Line: 15
      🔑 Secret: sk_test_1234567890abcdef1234567890abcdef

  - .env                          (Database credential) [VERIFIED]
      💾 Saved as: dump/bucket.com/.env
      🔍 Detector: MySQL
      📍 Line: 3
      🔑 Secret: mysql://user:password123@localhost:3306/db



## Legal Notice
This tool is intended for authorized security testing and research purposes only. Always ensure you have proper permission before scanning any infrastructure. The authors are not responsible for any misuse or damage caused by this tool


## License
This project is intended solely for educational use and authorized security testing. Commercial use is prohibited unless explicitly permitted by the original tool developer.

## Need support ?
here's a hug, 🤗 there, there, buddy, there, there.
