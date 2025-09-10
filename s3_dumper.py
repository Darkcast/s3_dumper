#!/usr/bin/env python3

import argparse
import base64
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlparse
import urllib3
import time
import threading
import random
import os
from collections import deque, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import sys
import platform
import subprocess
import json
import shutil
import signal
import psutil
import logging
import socket
import re

# Add colorama for colored output
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Global debug flag
DEBUG = False

# Thread-safe printing
print_lock = threading.Lock()

def thread_safe_print(*args, **kwargs):
    """Thread-safe print function to prevent interleaved output"""
    with print_lock:
        print(*args, **kwargs)

def debug_print(*args, **kwargs):
    """Print debug information only if debug mode is enabled"""
    if DEBUG:
        with print_lock:
            print(f"{Fore.LIGHTBLACK_EX}[DEBUG]", *args, **kwargs)

# Version constant
VERSION = "1.10"

# Bot user agents for stealth mode (only used with -rua flag)
bot_user_agents = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "Slurp/3.0 (Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "Baiduspider/2.0; (+http://www.baidu.com/search/spider.html)",
    "YandexBot/3.0; (+http://yandex.com/bots)",
    "Sogou web spider/4.0 (+http://www.sogou.com/docs/help/webmasters.htm#07)",
    "Exabot/3.0 (+http://www.exabot.com/go/robot)",
    "ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)",
    "SemrushBot/7~bl (+http://www.semrush.com/bot.html)",
    "DotBot/1.1 (+http://www.opensiteexplorer.org/dotbot)",
    "AhrefsBot/7.0 (+http://ahrefs.com/robot/)",
    "MJ12bot/v1.4.8 (http://mj12bot.com/)",
    "BLEXBot/2.0 (+http://webmeup-crawler.com/)",
    "rogerbot/1.0 (http://www.rogerswebsite.com/)",
    "SeznamBot/3.2 (+http://fulltext.sblog.cz/)",
    "BitlyBot/1.0 (+http://bitly.com/)",
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "UptimeRobot/2.0 (+http://www.uptimerobot.com/)",
    "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)",
    "Baidu Imagespider (+http://www.baidu.com/search/spider.htm)",
    "Archive.org_bot",
    "SiteLockSpider/1.0",
    "NaverBot/1.0 (+http://help.naver.com/robots/)",
    "MegaIndex.ru/2.0 (http://www.megaindex.ru/crawler)",
    "OpenLinkProfiler.org bot",
    "OpenBot/1.0 (+http://www.openlinkprofiler.org/bot)"
]

# Sensitive / security-relevant files to watch for
SENSITIVE_FILES = [
    # Databases
    ".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf", ".frm", ".myd", ".myi",
    
    # Backup / dump files  
    ".bak", ".backup", ".dump", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", 
    ".tar.xz", ".txz", ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz",
    
    # Config / environment
    ".env", ".config", ".ini", ".cfg", ".conf", ".cnf", ".properties", ".toml", 
    ".yml", ".yaml", ".xml", ".json", ".plist",
    
    # Credentials / secrets
    ".key", ".pem", ".ppk", ".csr", ".pfx", ".p12", ".jks", ".keystore", ".truststore",
    ".asc", ".gpg", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    
    # Certificates & signing
    ".crt", ".cer", ".cert", ".ca-bundle", ".p7b", ".p7c", ".p7s", ".der", ".sig",
    
    # Logs that may contain sensitive info
    ".log", ".logs", ".old", ".history", ".audit", ".access", ".error", ".out",
    
    # System files
    "passwd", "shadow", "hosts", "fstab", "sudoers", ".htpasswd", ".htaccess",
    
    # Common password / user files
    "passwords.txt", "users.json", "credentials.json", "secrets.json", "config.json",
    "settings.json", ".netrc", ".boto", "credentials",
    
    # Scripts that may contain sensitive commands
    ".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1", ".vbs", ".py", ".php", 
    ".rb", ".pl", ".lua",
    
    # Source code (may contain hardcoded secrets)
    ".java", ".ts", ".cpp", ".c", ".cs", ".go", ".swift", ".kt", ".scala",
    ".clj", ".hs", ".rs", ".dart",
    
    # Cloud & infrastructure
    ".tf", ".tfvars", ".tfstate", "Dockerfile", "docker-compose.yml", ".dockerignore",
    "kubernetes.yml", "k8s.yaml", ".kube", "helm-values.yaml",
    
    # Version control & IDE
    ".git", ".svn", ".hg", ".bzr", ".vscode", ".idea", ".sublime-project", ".project",
    
    # Network & VPN configs  
    ".ovpn", ".rdp", ".ssh", ".putty", "authorized_keys", "known_hosts",
    
    # Memory & core dumps
    ".dmp", ".core", ".crashdump", ".mdmp",
    
    # Application configs
    "web.config", "application.properties", "hibernate.cfg.xml", "spring.xml",
    "struts.xml", "tiles.xml", "context.xml",
    
    # Password managers & browser data
    ".kdbx", ".1pif", "cookies.sqlite", "login.keychain", "passwords.csv",
    
    # Email files
    ".pst", ".ost", ".mbox", ".eml", ".msg",
    
    # Virtualization
    ".vmx", ".vdi", ".vmdk", ".qcow2", ".img",
    
    # Archive naming patterns (common backup patterns)
    ".orig", ".copy", ".save",
    
    # Temporary files that might contain sensitive data
    ".tmp", ".temp", ".swp", ".swo", ".DS_Store", "Thumbs.db",
    
    # Other database formats
    ".sqlite-shm", ".sqlite-wal", ".db-shm", ".db-wal", ".db-journal",
    
    # API & service files
    "docker-compose.override.yml", "secrets.yml", "vault.yml", "ansible-vault",
    
    # Mobile development
    ".mobileprovision", ".p8", ".ipa", ".apk", "google-services.json",
    "GoogleService-Info.plist",
    
    # Additional sensitive filenames
    "secret", "private", "confidential", "internal", "admin", "root", "user",
    "password", "credential", "token", "apikey", "oauth"
]

# Base64-encoded ASCII art Banner
encoded_art = """
CiAgICAgX19fICAgICAgICAgXwogX19ffF8gIHwgICAgICBffCB8XyBfIF9fX19fIF9fXyBfX18gX19fCnxfIC18XyAgfCAgICAgfCAuIHwgfCB8ICAgICB8IC4gfCAtX3wgIF98CnxfX198X19ffF9fX19ffF9fX3xfX198X3xffF98ICBffF9fX3xffAogICAgICAgIHxfX19fX3wgICAgICAgICAgICAgfF98CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJ5IERhcmtjYXN0Cgo=
""".strip()

def print_ascii_art(b64_string):
    if b64_string:
        try:
            decoded = base64.b64decode(b64_string).decode('utf-8')
            print(Fore.CYAN + Style.BRIGHT + decoded)
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to decode banner: {e}")

def setup_logging(debug=False):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.WARNING
    
    # Configure main logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s' if debug else '%(message)s',
        handlers=[logging.StreamHandler()] if debug else []
    )
    
    # Configure requests/urllib3 logging
    if debug:
        logging.getLogger("requests").setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
    else:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

# Tor Manager Class - CLEANED UP OUTPUT
class TorManager:
    def __init__(self, 
                 tor_port: int = 9050,
                 control_port: int = 9051,
                 tor_executable: str = "tor",
                 max_retries: int = 3,
                 timeout: int = 30):
        """Initialize Tor Manager"""
        self.tor_port = tor_port
        self.control_port = control_port
        self.tor_executable = tor_executable
        self.max_retries = max_retries
        self.timeout = timeout
        self.tor_process = None
        self.current_ip = None
        
        # Cache for tor status to avoid repeated API calls
        self._cached_status = None
        self._status_cache_time = 0
        self._cache_duration = 30  # Cache for 30 seconds
        
        debug_print(f"Initializing TorManager with port {tor_port}, control port {control_port}")
        
        # Configure logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if DEBUG else logging.WARNING)
        
        # Tor proxy configuration
        self.proxies = {
            'http': f'socks5://127.0.0.1:{self.tor_port}',
            'https': f'socks5://127.0.0.1:{self.tor_port}'
        }
        
        debug_print(f"Proxy configuration: {self.proxies}")
        
        # Check if SOCKS support is available
        self._check_socks_support()

    def _check_socks_support(self):
        """Check if SOCKS support is available"""
        try:
            import socks
            debug_print("SOCKS module imported successfully")
            debug_print("SOCKS support available")
        except ImportError:
            debug_print("SOCKS module not available")
            print(f"{Fore.YELLOW}[!] SOCKS support not available - install with: pdm add requests[socks]")

    def is_tor_running(self) -> bool:
        """Check if Tor process is running on the specified port"""
        debug_print(f"Checking if Tor is running on port {self.tor_port}")
        
        try:
            # First, check if anything is listening on the Tor port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', self.tor_port))
            sock.close()
            
            debug_print(f"Socket connection test result: {result}")
            
            if result == 0:  # Port is open
                debug_print(f"Port {self.tor_port} is open")
                
                # Double-check by looking for Tor processes
                tor_processes = []
                debug_print("Scanning for Tor processes...")
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'] and 'tor' in proc.info['name'].lower():
                            debug_print(f"Found potential Tor process: {proc.info['name']} (PID: {proc.info['pid']})")
                            connections = proc.net_connections()
                            for conn in connections:
                                if (conn.laddr and conn.laddr.port == self.tor_port and 
                                    conn.status == psutil.CONN_LISTEN):
                                    tor_processes.append(proc.info['pid'])
                                    debug_print(f"Confirmed Tor process listening on port {self.tor_port}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        debug_print(f"Cannot access process info: {e}")
                        continue
                
                if tor_processes:
                    debug_print(f"Found Tor processes: {tor_processes}")
                else:
                    debug_print("Port open but no Tor processes found (might be system service)")
                
                return True
            else:
                debug_print(f"Port {self.tor_port} is not open")
            
            return False
        except Exception as e:
            debug_print(f"Exception in is_tor_running: {e}")
            print(f"{Fore.YELLOW}[!] Error checking Tor status: {e}")
            return False

    def test_socks_connection(self) -> bool:
        """Test SOCKS connection without making HTTP requests"""
        debug_print("Testing SOCKS connection...")
        
        try:
            import socks
            import socket
            
            # Create a SOCKS socket
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            s.settimeout(10)
            
            debug_print("Created SOCKS socket, attempting connection to httpbin.org:80")
            
            # Try to connect to a test server through Tor
            try:
                s.connect(("httpbin.org", 80))
                s.close()
                debug_print("SOCKS connection test successful")
                return True
            except Exception as e:
                print(f"{Fore.RED}[!] SOCKS connection test failed: {e}")
                debug_print(f"SOCKS connection failed: {e}")
                s.close()
                return False
                
        except ImportError:
            print(f"{Fore.YELLOW}[!] Cannot test SOCKS - PySocks not installed")
            debug_print("PySocks not available for testing")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] SOCKS test error: {e}")
            debug_print(f"SOCKS test exception: {e}")
            return False

    def get_tor_status(self, use_cache=True) -> dict:
        """Get comprehensive Tor status information using Tor Project's official API"""
        # Check cache first
        if use_cache and self._cached_status and (time.time() - self._status_cache_time) < self._cache_duration:
            debug_print("Using cached Tor status")
            return self._cached_status
        
        debug_print("Getting fresh Tor status from official API...")
        
        try:
            session = requests.Session()
            session.proxies.update(self.proxies)
            
            debug_print(f"Session proxies: {session.proxies}")
            debug_print("Testing connection to check.torproject.org...")
            
            # Use Tor Project's official API
            debug_print("Making request to https://check.torproject.org/api/ip")
            response = session.get('https://check.torproject.org/api/ip', timeout=15)
            
            debug_print(f"Response status code: {response.status_code}")
            debug_print(f"Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                data = response.json()
                debug_print(f"API response data: {data}")
                debug_print("Successfully connected to Tor check API")
                
                status = {
                    'is_tor': data.get('IsTor', False),
                    'ip': data.get('IP', 'Unknown'),
                    'country': data.get('Country', 'Unknown'),
                    'city': data.get('City', 'Unknown'),
                    'success': True
                }
                
                # Cache the result
                self._cached_status = status
                self._status_cache_time = time.time()
                
                return status
            else:
                print(f"{Fore.RED}[!] API returned status code: {response.status_code}")
                debug_print(f"Non-200 response: {response.text}")
                
        except requests.exceptions.ProxyError as e:
            print(f"{Fore.RED}[!] Proxy error: {e}")
            debug_print(f"Proxy error details: {e}")
        except requests.exceptions.ConnectTimeout:
            print(f"{Fore.RED}[!] Connection timeout to Tor check API")
            debug_print("Connection timeout occurred")
        except requests.exceptions.ConnectionError as e:
            print(f"{Fore.RED}[!] Connection error: {e}")
            debug_print(f"Connection error details: {e}")
        except Exception as e:
            print(f"{Fore.RED}[!] Unexpected error: {e}")
            debug_print(f"Unexpected error in get_tor_status: {e}")
        
        return {
            'is_tor': False,
            'ip': 'Unknown',
            'country': 'Unknown', 
            'city': 'Unknown',
            'success': False
        }

    def get_tor_ip(self) -> str:
        """Get current Tor IP address using Tor Project's official check service"""
        debug_print("Getting Tor IP address...")
        status = self.get_tor_status()
        
        if status['success'] and status['is_tor']:
            self.current_ip = status['ip']
            debug_print(f"Successfully got Tor IP: {status['ip']}")
            return status['ip']
        elif status['success'] and not status['is_tor']:
            debug_print("Connection successful but not using Tor")
            return "Not using Tor"
        else:
            debug_print("Failed to get IP information")
            return "Unknown"

    def start_tor(self) -> bool:
        """Start Tor process only if not already running"""
        debug_print("Attempting to start Tor...")
        
        try:
            # Check if Tor is already running first
            if self.is_tor_running():
                print(f"{Fore.CYAN}[i] Tor already running on port {self.tor_port}")
                debug_print("Tor already running, skipping start")
                return True
            
            print(f"{Fore.CYAN}[i] Starting new Tor instance...")
            
            # Create data directory if it doesn't exist
            tor_data_dir = '/tmp/tor_data_s3dumper'
            os.makedirs(tor_data_dir, exist_ok=True)
            debug_print(f"Created Tor data directory: {tor_data_dir}")
            
            # Start Tor with custom configuration
            tor_config = [
                self.tor_executable,
                '--SocksPort', str(self.tor_port),
                '--ControlPort', str(self.control_port),
                '--DataDirectory', tor_data_dir,
                '--Log', 'notice stdout',
                '--RunAsDaemon', '0'
            ]
            
            debug_print(f"Tor command: {' '.join(tor_config)}")
            
            self.tor_process = subprocess.Popen(
                tor_config,
                stdout=subprocess.DEVNULL if not DEBUG else subprocess.PIPE,
                stderr=subprocess.DEVNULL if not DEBUG else subprocess.PIPE,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            debug_print(f"Started Tor process with PID: {self.tor_process.pid}")
            
            # Wait for Tor to start
            for i in range(30):  # 30 second timeout
                debug_print(f"Waiting for Tor to start... ({i+1}/30)")
                if self.is_tor_running():
                    print(f"{Fore.LIGHTGREEN_EX}[✓] Tor started successfully")
                    debug_print("Tor startup confirmed")
                    time.sleep(2)  # Additional wait for full initialization
                    return True
                time.sleep(1)
                
            print(f"{Fore.RED}[!] Tor failed to start within timeout")
            debug_print("Tor startup timeout")
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error starting Tor: {e}")
            debug_print(f"Exception in start_tor: {e}")
            return False

    def stop_tor(self):
        """Stop only our managed Tor process, not system Tor"""
        debug_print("Stopping managed Tor process...")
        
        try:
            # Only stop our managed process, not system Tor
            if self.tor_process:
                print(f"{Fore.YELLOW}[i] Stopping managed Tor process...")
                debug_print(f"Terminating Tor process PID: {self.tor_process.pid}")
                
                if os.name == 'nt':  # Windows
                    self.tor_process.terminate()
                else:  # Unix-like
                    os.killpg(os.getpgid(self.tor_process.pid), signal.SIGTERM)
                try:
                    self.tor_process.wait(timeout=10)
                    debug_print("Tor process terminated gracefully")
                except subprocess.TimeoutExpired:
                    debug_print("Tor process didn't terminate, killing...")
                    self.tor_process.kill()
                self.tor_process = None
                print(f"{Fore.LIGHTGREEN_EX}[✓] Managed Tor process stopped")
            else:
                debug_print("No managed Tor process to stop")
                    
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error stopping Tor: {e}")
            debug_print(f"Exception in stop_tor: {e}")

    def check_tor_connection(self) -> bool:
        """Check if Tor connection is working properly"""
        debug_print("Checking Tor connection...")
        
        if not self.is_tor_running():
            debug_print("Tor is not running")
            return False
        
        # First try SOCKS connection test
        if self.test_socks_connection():
            status = self.get_tor_status()
            result = status['success'] and status['is_tor']
            debug_print(f"Connection check result: {result}")
            return result
        else:
            debug_print("SOCKS test failed")
            return False

    def ensure_tor_connection(self) -> bool:
        """Ensure Tor is running and connected"""
        debug_print("Ensuring Tor connection...")
        print(f"{Fore.CYAN}[i] Checking Tor connection...")
        
        # First check if Tor is already running and working
        if self.is_tor_running():
            debug_print("Found existing Tor instance, testing connection...")
            
            # Give existing Tor more time to initialize
            for i in range(3):
                debug_print(f"Connection test attempt {i+1}/3")
                if self.check_tor_connection():
                    debug_print("Using existing Tor connection")
                    return True
                debug_print(f"Waiting for Tor to initialize... ({i+1}/3)")
                time.sleep(5)
            
            print(f"{Fore.YELLOW}[!] Existing Tor instance not responding properly")
            debug_print("Existing Tor instance failed connection tests")
        
        # Don't try to start new Tor if one is already running
        if self.is_tor_running():
            print(f"{Fore.RED}[!] Tor is running but not accessible - check SOCKS configuration")
            print(f"{Fore.YELLOW}[i] Try: sudo systemctl restart tor")
            debug_print("Tor running but not accessible")
            return False
        
        # Try to start Tor if needed
        for attempt in range(self.max_retries):
            print(f"{Fore.CYAN}[i] Connection attempt {attempt + 1}/{self.max_retries}")
            debug_print(f"Tor startup attempt {attempt + 1}")
            
            if not self.is_tor_running():
                if not self.start_tor():
                    debug_print(f"Failed to start Tor on attempt {attempt + 1}")
                    continue
                time.sleep(3)
            
            if self.check_tor_connection():
                debug_print("Successfully established Tor connection")
                return True
                
        debug_print("All Tor connection attempts failed")
        return False

    def get_proxies(self):
        """Get proxy configuration for requests"""
        debug_print(f"Returning proxy configuration: {self.proxies}")
        return self.proxies.copy()

    def __enter__(self):
        """Context manager entry"""
        debug_print("Entering TorManager context")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        debug_print("Exiting TorManager context")
        # Only stop our managed process
        if self.tor_process:
            self.stop_tor()

# TruffleHog Integration Functions
def check_trufflehog_installed():
    """Check if TruffleHog is available in PATH"""
    result = shutil.which("trufflehog") is not None
    debug_print(f"TruffleHog installed: {result}")
    return result

def get_trufflehog_version():
    """Get TruffleHog version if installed"""
    debug_print("Getting TruffleHog version...")
    try:
        result = subprocess.run(
            ["trufflehog", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        if result.returncode == 0:
            version_line = result.stdout.strip()
            debug_print(f"TruffleHog version: {version_line}")
            return version_line
        debug_print(f"TruffleHog version command failed with code {result.returncode}")
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        debug_print(f"Error getting TruffleHog version: {e}")
        return None

def get_trufflehog_install_instruction():
    """Get platform-specific TruffleHog installation instruction"""
    system = platform.system().lower()
    debug_print(f"Getting TruffleHog install instruction for {system}")
    
    if system == "darwin":  # macOS
        return f"{Fore.WHITE}[i] Install with: {Fore.CYAN}brew install trufflehog"
    elif system == "linux":
        return f"{Fore.WHITE}[i] Install with: {Fore.CYAN}curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
    elif system == "windows":
        return f"{Fore.WHITE}[i] Install with: {Fore.CYAN}Download from https://github.com/trufflesecurity/trufflehog/releases"
    else:
        return f"{Fore.WHITE}[i] Install from: {Fore.CYAN}https://github.com/trufflesecurity/trufflehog"

def get_platform_info():
    """Get detailed platform information"""
    system = platform.system()
    machine = platform.machine()
    info = f"{system} {machine}"
    debug_print(f"Platform info: {info}")
    return info

def show_tool_status(pool_manager, tor_manager=None):
    """Display status of external tools and user agent info"""
    debug_print("Showing tool status...")
    platform_info = get_platform_info()
    
    # Show User-Agent mode and current UA
    mode_desc = pool_manager.get_mode_description()
    current_ua = pool_manager.get_current_user_agent()
    
    print(f"{Fore.WHITE}[*] Mode: {Fore.CYAN}{mode_desc}")
    print(f"{Fore.WHITE}[*] User-Agent: {Fore.CYAN}{current_ua}")
    
    # Show TruffleHog status
    if check_trufflehog_installed():
        version = get_trufflehog_version()
        if version:
            print(f"{Fore.WHITE}[*] TruffleHog: {Fore.LIGHTGREEN_EX}Installed {Fore.CYAN}({version})")
        else:
            print(f"{Fore.WHITE}[*] TruffleHog: {Fore.LIGHTGREEN_EX}Installed")
    else:
        install_instruction = get_trufflehog_install_instruction()
        print(f"{Fore.WHITE}[*] TruffleHog: {Fore.RED}Not Installed {Fore.LIGHTBLACK_EX}({platform_info})")
        print(f"{Fore.WHITE}    {install_instruction}")
    
    # Show enhanced Tor status (use cached status to avoid repeated API calls)
    if tor_manager:
        debug_print("Getting cached Tor status for display...")
        status = tor_manager.get_tor_status(use_cache=True)
        if status['success'] and status['is_tor']:
            location_parts = []
            if status['city'] != 'Unknown':
                location_parts.append(status['city'])
            if status['country'] != 'Unknown':
                location_parts.append(status['country'])
            location = ", ".join(location_parts) if location_parts else "Unknown location"
            print(f"{Fore.WHITE}[*] Tor: {Fore.LIGHTGREEN_EX}Connected {Fore.CYAN}(Exit: {status['ip']} - {location})")
        elif status['success'] and not status['is_tor']:
            print(f"{Fore.WHITE}[*] Tor: {Fore.RED}Not Using Tor {Fore.CYAN}(IP: {status['ip']})")
        else:
            print(f"{Fore.WHITE}[*] Tor: {Fore.RED}Connection Failed")

def run_trufflehog_scan(target_directory):
    """Run TruffleHog on the target directory and return results"""
    debug_print(f"Running TruffleHog scan on {target_directory}")
    
    if not check_trufflehog_installed():
        debug_print("TruffleHog not installed, skipping scan")
        return []
    
    try:
        cmd = [
            "trufflehog", 
            "filesystem", 
            "--json",
            "--no-update",
            str(target_directory)
        ]
        
        debug_print(f"TruffleHog command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300,
            cwd=target_directory
        )
        
        debug_print(f"TruffleHog exit code: {result.returncode}")
        debug_print(f"TruffleHog stdout length: {len(result.stdout) if result.stdout else 0}")
        debug_print(f"TruffleHog stderr: {result.stderr}")
        
        secrets = []
        if result.stdout.strip():
            for line_num, line in enumerate(result.stdout.strip().split('\n'), 1):
                line = line.strip()
                if line:
                    try:
                        secret_data = json.loads(line)
                        secrets.append(secret_data)
                        debug_print(f"Parsed secret on line {line_num}")
                    except json.JSONDecodeError as e:
                        thread_safe_print(f"{Fore.YELLOW}[!] JSON parse error on line {line_num}: {e}")
                        debug_print(f"JSON parse error: {e}")
                        continue
        
        debug_print(f"Found {len(secrets)} secrets")
        return secrets
        
    except subprocess.TimeoutExpired:
        thread_safe_print(f"{Fore.YELLOW}[!] TruffleHog scan timed out after 5 minutes")
        debug_print("TruffleHog scan timeout")
        return []
    except FileNotFoundError:
        debug_print("TruffleHog executable not found")
        return []
    except Exception as e:
        thread_safe_print(f"{Fore.YELLOW}[!] TruffleHog scan error: {e}")
        debug_print(f"TruffleHog scan exception: {e}")
        return []

def parse_trufflehog_results(secrets, base_path):
    """Parse TruffleHog results into our format"""
    debug_print(f"Parsing {len(secrets)} TruffleHog results")
    parsed_secrets = []
    
    for i, secret in enumerate(secrets):
        debug_print(f"Parsing secret {i+1}/{len(secrets)}")
        try:
            detector_name = secret.get('DetectorName', 'Unknown')
            
            source_metadata = secret.get('SourceMetadata', {})
            data = source_metadata.get('Data', {})
            filesystem = data.get('Filesystem', {})
            source_file = filesystem.get('file', 'Unknown')
            line_number = filesystem.get('line', 0)
            
            verified = secret.get('Verified', False)
            raw_data = secret.get('Raw', '')
            redacted = secret.get('Redacted', '')
            extra_data = secret.get('ExtraData', {})
            
            if source_file != 'Unknown' and source_file.startswith(str(base_path)):
                relative_file = source_file[len(str(base_path)):].lstrip('/')
            else:
                relative_file = source_file
            
            secret_type = categorize_secret_type(detector_name, raw_data)
            confidence = "High" if verified else "Medium"
            display_secret = raw_data[:80] + '...' if len(raw_data) > 80 else raw_data
            
            parsed_secrets.append({
                'file': relative_file,
                'line': line_number,
                'type': secret_type,
                'detector': detector_name,
                'verified': verified,
                'confidence': confidence,
                'raw': raw_data,
                'display_secret': display_secret,
                'redacted': redacted,
                'extra_data': extra_data
            })
            
            debug_print(f"Parsed secret: {secret_type} in {relative_file}")
            
        except Exception as e:
            thread_safe_print(f"{Fore.YELLOW}[!] Error parsing secret: {e}")
            debug_print(f"Error parsing secret {i}: {e}")
            continue
    
    debug_print(f"Successfully parsed {len(parsed_secrets)} secrets")
    return parsed_secrets

def categorize_secret_type(detector_name, raw_data):
    """Categorize the type of secret found"""
    detector_lower = detector_name.lower()
    
    if 'api' in detector_lower or 'key' in detector_lower:
        return "API key"
    elif 'password' in detector_lower or 'pass' in detector_lower:
        return "Password"
    elif 'token' in detector_lower or 'jwt' in detector_lower:
        return "Access token"
    elif 'aws' in detector_lower or 'amazon' in detector_lower:
        return "AWS credential"
    elif 'github' in detector_lower or 'gitlab' in detector_lower:
        return "Git credential"
    elif 'database' in detector_lower or 'db' in detector_lower:
        return "Database credential"
    elif 'private' in detector_lower and 'key' in detector_lower:
        return "Private key"
    elif 'oauth' in detector_lower:
        return "OAuth token"
    else:
        return f"{detector_name} secret"

def is_sensitive_file(filename):
    """Check if a file is potentially sensitive"""
    filename_lower = filename.lower()
    
    for pattern in SENSITIVE_FILES:
        if pattern.startswith('.'):
            if filename_lower.endswith(pattern):
                return True, get_file_category(pattern)
        else:
            if pattern in filename_lower:
                return True, get_file_category(pattern)
    
    return False, None

def get_file_category(pattern):
    """Categorize the type of sensitive file"""
    if pattern in [".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb"]:
        return "Database file"
    elif pattern in [".bak", ".backup", ".dump", ".tar", ".tar.gz", ".zip"]:
        return "Backup/Archive file"
    elif pattern in [".env", ".config", ".ini", ".cfg", ".properties", ".toml", ".yml", ".yaml"]:
        return "Configuration file"
    elif pattern in [".key", ".pem", ".ppk", ".csr", ".pfx", ".jks", ".asc", ".gpg"] or "id_" in pattern:
        return "Private key/Certificate"
    elif pattern in [".crt", ".cer", ".cert"]:
        return "Certificate file"
    elif pattern in [".log", ".old", ".history", ".htpasswd"]:
        return "Log/History file"
    elif "password" in pattern or "credential" in pattern or "secret" in pattern:
        return "Credentials file"
    elif pattern in [".sh", ".bat", ".ps1", ".cmd"]:
        return "Script file"
    else:
        return "Sensitive file"

def categorize_file_type(filename):
    """Categorize file for statistics"""
    ext = os.path.splitext(filename)[1].lower()
    
    image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico']
    doc_exts = ['.pdf', '.doc', '.docx', '.txt', '.md', '.rtf', '.odt']
    config_ext = [
    ".env", ".config", ".ini", ".cfg", ".conf", ".cnf", ".properties", ".toml", ".yml", ".yaml", ".xml", ".json", ".plist", ".tf", ".tfvars", ".tfstate", "Dockerfile", "docker-compose.yml", ".dockerignore", "kubernetes.yml", "k8s.yaml", ".kube", "helm-values.yaml", ".ovpn", ".rdp", ".ssh", ".putty", "authorized_keys", "known_hosts", "web.config", "application.properties", "hibernate.cfg.xml", "spring.xml", "struts.xml", "tiles.xml", "context.xml", "docker-compose.override.yml", "secrets.yml", "vault.yml", "ansible-vault"]
    script_exts = ['.js', '.py', '.php', '.rb', '.sh', '.bat', '.ps1', '.cmd']
    
    if ext in image_exts:
        return "images"
    elif ext in doc_exts:
        return "docs"
    elif ext in script_exts:
        return "scripts"
    elif ext in config_ext:
        return "configs"
    else:
        return "others"

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ConnectionPoolManager:
    def __init__(self, pool_connections=10, pool_maxsize=20, random_user_agents=False, tor_manager=None):
        debug_print(f"Initializing ConnectionPoolManager with {pool_connections} connections, max size {pool_maxsize}")
        
        self.session = requests.Session()
        self.random_user_agents = random_user_agents
        self.default_user_agent = f"S3Dumper/{VERSION}"
        self.current_user_agent = None
        self.tor_manager = tor_manager
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        debug_print(f"Retry strategy: {retry_strategy}")
        
        # Configure connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set basic headers
        self.session.headers.update({
            'Connection': 'keep-alive'
        })
        
        # Configure Tor proxy if enabled
        if self.tor_manager:
            debug_print("Configuring Tor proxy for session")
            self.session.proxies.update(self.tor_manager.get_proxies())
        
        # Set initial user agent
        if self.random_user_agents:
            self.current_user_agent = random.choice(bot_user_agents)
            debug_print(f"Selected random user agent: {self.current_user_agent}")
        else:
            self.current_user_agent = self.default_user_agent
            debug_print(f"Using default user agent: {self.current_user_agent}")
    
    def get_current_user_agent(self):
        """Get the current user agent"""
        return self.current_user_agent
    
    def get_mode_description(self):
        """Get user agent mode description"""
        if self.random_user_agents:
            return "Random bot UAs (stealth mode)"
        else:
            return "Native Agent"
    
    def get(self, url, **kwargs):
        debug_print(f"Making request to: {url}")
        
        kwargs.setdefault('timeout', (10, 30))  # (connect, read)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('stream', True)
        
        # Set User-Agent based on mode
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        if 'User-Agent' not in kwargs['headers']:
            if self.random_user_agents:
                self.current_user_agent = random.choice(bot_user_agents)
                kwargs['headers']['User-Agent'] = self.current_user_agent
                debug_print(f"Using random UA: {self.current_user_agent}")
            else:
                kwargs['headers']['User-Agent'] = self.default_user_agent
                debug_print(f"Using default UA: {self.default_user_agent}")
        
        debug_print(f"Request headers: {kwargs.get('headers', {})}")
        debug_print(f"Request proxies: {self.session.proxies}")
        
        return self.session.get(url, **kwargs)
    
    def close(self):
        debug_print("Closing connection pool manager")
        self.session.close()

class AdaptiveThreadManager:
    def __init__(self, initial_threads=10, min_threads=1, max_threads=32, 
                 adjustment_interval=2, enabled=True):
        debug_print(f"Initializing AdaptiveThreadManager: initial={initial_threads}, range=({min_threads}-{max_threads}), enabled={enabled}")
        
        self.enabled = enabled
        self.min_threads = min_threads
        self.max_threads = max_threads
        self.current_threads = initial_threads
        self.adjustment_interval = adjustment_interval
        
        # Performance tracking
        self.download_times = deque(maxlen=20)
        self.success_count = 0
        self.failure_count = 0
        self.last_adjustment = time.time()
        self.lock = threading.Lock()
        self.adjustment_count = 0
        self.peak_threads = initial_threads
        
        # File tracking
        self.sensitive_files = []
        self.secrets_found = []
        self.file_types = Counter()
        self.files_skipped = 0
        self.start_time = time.time()
        
        # For dynamic executor management
        self.executor = None
        self.executor_lock = threading.Lock()
        
        mode = "Adaptive" if enabled else "Fixed"
        if enabled:
            print(f"{Fore.WHITE}[*] Threading mode: {Style.BRIGHT}{mode}{Style.NORMAL} (initial: {initial_threads}, range: {min_threads}-{max_threads})\n")
        else:
            print(f"{Fore.WHITE}[*] Threading mode: {Style.BRIGHT}{mode}{Style.NORMAL} ({initial_threads} threads)\n")
    
    def record_download(self, duration, success=True):
        if not self.enabled:
            return
            
        debug_print(f"Recording download: duration={duration:.2f}s, success={success}")
        
        with self.lock:
            self.download_times.append(duration)
            if success:
                self.success_count += 1
            else:
                self.failure_count += 1
    
    def record_sensitive_file(self, filename, local_path, category):
        """Record a sensitive file that was downloaded"""
        debug_print(f"Recording sensitive file: {filename} ({category})")
        self.sensitive_files.append({
            'filename': filename,
            'local_path': local_path,
            'category': category
        })
    
    def record_file_type(self, filename):
        """Record file type for statistics"""
        file_type = categorize_file_type(filename)
        self.file_types[file_type] += 1
        debug_print(f"Recorded file type: {filename} -> {file_type}")
    
    def get_elapsed_time(self):
        """Get elapsed time in human readable format"""
        elapsed = time.time() - self.start_time
        if elapsed < 60:
            return f"{elapsed:.0f}s"
        elif elapsed < 3600:
            minutes = elapsed // 60
            seconds = elapsed % 60
            return f"{minutes:.0f}m {seconds:.0f}s"
        else:
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            return f"{hours:.0f}h {minutes:.0f}m"
    
    def should_adjust_threads(self):
        if not self.enabled:
            return False
            
        if time.time() - self.last_adjustment < self.adjustment_interval:
            return False
        
        if len(self.download_times) < 5:  # Need some data first
            return False
        
        return True
    
    def get_optimal_thread_count(self):
        if not self.should_adjust_threads():
            return self.current_threads
        
        with self.lock:
            if not self.download_times:
                return self.current_threads
                
            avg_time = sum(self.download_times) / len(self.download_times)
            total_attempts = self.success_count + self.failure_count
            success_rate = self.success_count / total_attempts if total_attempts > 0 else 1.0
            
            old_threads = self.current_threads
            
            debug_print(f"Thread adjustment analysis: avg_time={avg_time:.2f}s, success_rate={success_rate:.1%}")
            
            # Decision logic
            if success_rate < 0.7:  # Too many failures
                self.current_threads = max(self.min_threads, self.current_threads - 2)
                reason = f"low success rate ({success_rate:.1%})"
            
            elif avg_time > 15.0:  # Downloads taking too long
                self.current_threads = max(self.min_threads, self.current_threads - 1)
                reason = f"slow downloads ({avg_time:.1f}s avg)"
            
            elif avg_time < 3.0 and success_rate > 0.95:  # Fast & reliable
                self.current_threads = min(self.max_threads, self.current_threads + 1)
                reason = f"good performance ({avg_time:.1f}s avg, {success_rate:.1%} success)"
            
            else:
                reason = "stable performance"
            
            if old_threads != self.current_threads:
                self.adjustment_count += 1
                self.peak_threads = max(self.peak_threads, self.current_threads)
                thread_safe_print(f"{Fore.MAGENTA}⚡ Thread adjustment: {old_threads} → {self.current_threads} ({reason})")
                debug_print(f"Thread count adjusted: {old_threads} -> {self.current_threads}")
            
            self.last_adjustment = time.time()
            # Reset counters for next interval
            self.success_count = 0
            self.failure_count = 0
            
        return self.current_threads
    
    def get_executor(self, force_new=False):
        """Get current executor or create new one if thread count changed"""
        with self.executor_lock:
            optimal_threads = self.get_optimal_thread_count()
            
            # Create new executor if needed
            if (self.executor is None or 
                force_new or 
                (self.enabled and optimal_threads != getattr(self.executor, '_max_workers', 0))):
                
                debug_print(f"Creating new executor with {optimal_threads} workers")
                
                # Shutdown old executor
                if self.executor is not None:
                    self.executor.shutdown(wait=False)
                
                # Create new one with optimal thread count
                self.executor = ThreadPoolExecutor(max_workers=optimal_threads)
                self.executor._max_workers = optimal_threads  # Store for comparison
            
            return self.executor
    
    def show_summary(self):
        if self.enabled:
            if self.adjustment_count > 0:
                print(f"{Fore.CYAN}📈 Threading summary: {self.adjustment_count} adjustments made, peak: {self.peak_threads} threads")
            else:
                print(f"{Fore.CYAN}📈 Threading summary: No adjustments needed, used {self.current_threads} threads")
        else:
            print(f"{Fore.CYAN}📈 Threading summary: Fixed mode, used {self.current_threads} threads")
    
    def shutdown(self):
        debug_print("Shutting down thread manager")
        with self.executor_lock:
            if self.executor is not None:
                self.executor.shutdown(wait=True)

def retry_with_backoff(max_retries=3, base_delay=1, max_delay=60):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except (requests.RequestException, ConnectionError, TimeoutError) as e:
                    if attempt == max_retries:
                        debug_print(f"Final retry attempt failed for {func.__name__}: {e}")
                        raise e
                    
                    # Exponential backoff with jitter
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    jitter = random.uniform(0.1, 0.3) * delay
                    total_delay = delay + jitter
                    
                    debug_print(f"Retry {attempt + 1} for {func.__name__} failed: {e}, waiting {total_delay:.1f}s")
                    thread_safe_print(f"{Fore.YELLOW}[!] Attempt {attempt + 1} failed: {e}")
                    thread_safe_print(f"{Fore.YELLOW}[*] Retrying in {total_delay:.1f} seconds...")
                    time.sleep(total_delay)
            return None
        return wrapper
    return decorator

def parse_args():
    parser = argparse.ArgumentParser(description="Download all files from an open S3 bucket listing.")

    # Version option
    parser.add_argument("--version", action="version", version=f"S3Dumper {VERSION}")

    # URL input options - mutually exclusive
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="URL to the S3 bucket XML listing")
    group.add_argument("-l", "--list", help="File containing list of S3 bucket URLs (one per line)")

    # Simple threading options
    parser.add_argument("-t", "--threads", type=int, default=10, 
                       help="Number of threads (default: 10, adaptive unless --no-adaptive)")
    
    # Advanced options
    parser.add_argument("-na", "--no-adaptive", action="store_true", 
                       help="Use fixed thread count instead of adaptive")
    parser.add_argument("-ai", "--adjustment-interval", type=int, default=2,
                       help="Seconds between thread adjustments (default: 2)")
    
    # Stealth options
    parser.add_argument("-rua", "--random-user-agent", action="store_true",
                       help="Use random bot user agents for stealth (different per request)")
    
    # Secret scanning
    parser.add_argument("-s", "--secrets", action="store_true",
                       help="Run TruffleHog secret scan on downloaded files")
    
    # Tor option
    parser.add_argument("--tor", action="store_true",
                       help="Route traffic through Tor for anonymity")
    
    # Debug option
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug output for troubleshooting")
    
    return parser.parse_args()

def setup_threading(args):
    debug_print(f"Setting up threading: no_adaptive={args.no_adaptive}, threads={args.threads}")
    
    if args.no_adaptive:
        # Fixed threading - use exact number specified
        return AdaptiveThreadManager(
            initial_threads=args.threads,
            min_threads=args.threads,
            max_threads=args.threads,
            adjustment_interval=args.adjustment_interval,
            enabled=False
        )
    else:
        # Adaptive threading - auto-calculate sensible range around user's preference
        min_threads = max(1, args.threads // 4)      # At least 1, but scale down to 25%
        max_threads = min(64, args.threads * 3)      # Scale up to 3x, but cap at 64
        
        debug_print(f"Adaptive threading range: {min_threads}-{max_threads}")
        
        return AdaptiveThreadManager(
            initial_threads=args.threads,
            min_threads=min_threads,
            max_threads=max_threads,
            adjustment_interval=args.adjustment_interval,
            enabled=True
        )

def fetch_xml(url, pool_manager):
    """Fetch and parse XML from URL - uses the pool manager's UA strategy"""
    debug_print(f"Fetching XML from: {url}")
    response = pool_manager.get(url)
    response.raise_for_status()
    debug_print(f"XML response length: {len(response.text)}")
    return ET.fromstring(response.text)

@retry_with_backoff(max_retries=3)
def download_file_with_adaptive(base_url, key, destination_folder, pool_manager, thread_manager):
    # Skip directory markers (keys ending with '/')
    if key.endswith('/'):
        debug_print(f"Skipping directory marker: {key}")
        thread_safe_print(f"{Fore.YELLOW}⊘ {key} (directory marker)")
        thread_manager.record_download(0.1, success=True)
        return
    
    debug_print(f"Downloading file: {key}")
    start_time = time.time()
    success = False
    
    try:
        file_url = urljoin(base_url + "/", key)
        local_path = destination_folder / key
        
        debug_print(f"File URL: {file_url}")
        debug_print(f"Local path: {local_path}")
        
        # Ensure parent directory exists
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        with pool_manager.get(file_url) as r:
            r.raise_for_status()
            file_size = 0
            with open(local_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    file_size += len(chunk)
        
        debug_print(f"Downloaded {key}: {file_size} bytes in {time.time() - start_time:.2f}s")
        success = True
        
        # Check if file is sensitive
        is_sensitive, category = is_sensitive_file(key)
        if is_sensitive:
            thread_manager.record_sensitive_file(key, local_path, category)
            thread_safe_print(f"{Fore.LIGHTRED_EX}✓ {key} {Fore.RED}🔒")
        else:
            thread_safe_print(f"{Fore.GREEN}✓ {key}")
        
        # Record file type for statistics
        thread_manager.record_file_type(key)
        
    except Exception as e:
        debug_print(f"Failed to download {key}: {e}")
        thread_safe_print(f"{Fore.RED}[!] Failed to download {key}: {e}")
        raise e
    
    finally:
        # Record performance data
        duration = time.time() - start_time
        thread_manager.record_download(duration, success)

def get_clean_domain(url):
    domain = urlparse(url).netloc
    result = domain[4:] if domain.startswith("www.") else domain
    debug_print(f"Clean domain from {url}: {result}")
    return result

@retry_with_backoff(max_retries=3)
def fetch_xml_with_retry(url, pool_manager):
    """Wrapper function to apply retry logic to XML fetching"""
    return fetch_xml(url, pool_manager)

def process_url(url, args, pool_manager, tor_manager=None):
    debug_print(f"Processing URL: {url}")
    print(f"\n[*] Target: {Fore.CYAN}{url}{Style.RESET_ALL}")
    
    try:
        root = fetch_xml_with_retry(url, pool_manager)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch or parse XML from {url}: {e}")
        debug_print(f"XML fetch failed: {e}")
        return 0

    ns = {'s3': 'http://doc.s3.amazonaws.com/2006-03-01'}
    keys = [elem.text for elem in root.findall("s3:Contents/s3:Key", ns) if elem.text]
    
    debug_print(f"Found {len(keys)} keys in XML")

    if not keys:
        print(f"{Fore.YELLOW}[!] No files found in the bucket listing for {url}")
        return 0

    domain = get_clean_domain(url)
    destination = Path.cwd() / "dump" / domain
    
    debug_print(f"Destination directory: {destination}")

    # Initialize adaptive thread manager
    thread_manager = setup_threading(args)

    print(f"{Fore.WHITE}[*] Processing bucket")
    print(f" └─ Found {len(keys)} files to download")
    print(f"\n━━━ {Fore.CYAN}DOWNLOADING{Fore.RESET} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        # Submit all downloads
        futures = []
        completed = 0
        
        # Process downloads in batches to allow for thread adjustments
        batch_size = 50
        for i in range(0, len(keys), batch_size):
            batch_keys = keys[i:i + batch_size]
            debug_print(f"Processing batch {i//batch_size + 1}: {len(batch_keys)} files")
            
            # Get current executor (may be adjusted)
            executor = thread_manager.get_executor()
            
            # Submit batch
            batch_futures = []
            for key in batch_keys:
                future = executor.submit(download_file_with_adaptive, url, key, destination, pool_manager, thread_manager)
                batch_futures.append(future)
                futures.append(future)
            
            # Process this batch
            for future in as_completed(batch_futures):
                try:
                    future.result()
                    completed += 1
                    
                    # Show progress occasionally
                    if completed % 25 == 0:
                        progress_percent = (completed / len(keys)) * 100
                        thread_safe_print(f"\n{Fore.CYAN}📊 Progress: {completed}/{len(keys)} files completed ({progress_percent:.1f}%)\n")
                        
                except Exception as e:
                    thread_safe_print(f"{Fore.RED}[!] Download failed: {e}")
                    debug_print(f"Download future failed: {e}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Download interrupted by user")
        debug_print("Download interrupted by user")
        # Cancel remaining futures
        for future in futures:
            future.cancel()
        raise
    
    finally:
        thread_manager.shutdown()

    # Show security warnings if any sensitive files found
    if thread_manager.sensitive_files:
        debug_print(f"Found {len(thread_manager.sensitive_files)} sensitive files")
        print(f"\n━━━ {Fore.LIGHTRED_EX}SECURITY WARNINGS{Fore.RESET} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"\n{Fore.RED}[!] {len(thread_manager.sensitive_files)} sensitive files found:")
        
        for file_info in thread_manager.sensitive_files:
            print(f"\n{Fore.YELLOW}  - {file_info['filename']:<30} {Fore.RED}({file_info['category']})")
            print(f"{Fore.WHITE}      💾 Saved as: {file_info['local_path']}")

    # NEW: Run TruffleHog secret scan if requested
    if args.secrets:
        debug_print("Running TruffleHog secret scan...")
        secrets = run_trufflehog_scan(destination)
        parsed_secrets = parse_trufflehog_results(secrets, destination) if secrets else []
        thread_manager.secrets_found = parsed_secrets
        
        # Always show SECRETS section if -s flag was used
        print(f"\n━━━ {Fore.LIGHTRED_EX}SECRETS{Fore.RESET} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        if not check_trufflehog_installed():
            install_instruction = get_trufflehog_install_instruction()
            print(f"\n{Fore.YELLOW}[!] TruffleHog not installed - secret scanning skipped")
            print(f"    {install_instruction}")
        elif parsed_secrets:
            print(f"\n{Fore.LIGHTRED_EX}[!] {len(parsed_secrets)} secrets found:")
            
            # Group secrets by confidence for better display
            verified_secrets = [s for s in parsed_secrets if s['verified']]
            unverified_secrets = [s for s in parsed_secrets if not s['verified']]
            
            # Show verified secrets first
            for secret in verified_secrets:
                print(f"\n{Fore.YELLOW}  - {secret['file']:<30} {Fore.LIGHTRED_EX}({secret['type']}) {Fore.LIGHTGREEN_EX}[VERIFIED]")
                print(f"{Fore.WHITE}      💾 Saved as: {destination / secret['file']}")
                print(f"{Fore.LIGHTCYAN_EX}      🔍 Detector: {secret['detector']}")
                if secret['line'] > 0:
                    print(f"{Fore.LIGHTBLACK_EX}      📍 Line: {secret['line']}")
                if secret['display_secret']:
                    print(f"{Fore.LIGHTMAGENTA_EX}      🔑 Secret: {secret['display_secret']}")
            
            # Show unverified secrets
            for secret in unverified_secrets:
                print(f"\n{Fore.YELLOW}  - {secret['file']:<30} {Fore.LIGHTRED_EX}({secret['type']}) {Fore.YELLOW}[UNVERIFIED]")
                print(f"{Fore.WHITE}      💾 Saved as: {destination / secret['file']}")
                print(f"{Fore.LIGHTCYAN_EX}      🔍 Detector: {secret['detector']}")
                if secret['line'] > 0:
                    print(f"{Fore.LIGHTBLACK_EX}      📍 Line: {secret['line']}")
                if secret['display_secret']:
                    print(f"{Fore.LIGHTMAGENTA_EX}      🔑 Secret: {secret['display_secret']}")
        else:
            print(f"\n{Fore.LIGHTGREEN_EX}[✓] TruffleHog scan completed - no secrets detected")

    print(f"\n━━━ {Fore.CYAN}COMPLETE{Fore.RESET} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    # Summary
    elapsed_time = thread_manager.get_elapsed_time()
    print(f"\n{Fore.LIGHTGREEN_EX}✅ Files downloaded: {completed} ({thread_manager.files_skipped} skipped)")
    print(f"{Fore.WHITE}⏱ Elapsed: {elapsed_time}")
    print(f"{Fore.WHITE}💾 Saved location: {destination}")
    thread_manager.show_summary()
    
    # File type breakdown
    if thread_manager.file_types:
        type_summary = ", ".join([f"{count} {file_type}" for file_type, count in thread_manager.file_types.items()])
        print(f"{Fore.CYAN}📂 File types: {type_summary}")
    
    debug_print(f"Process URL complete: {len(keys)} total files")
    return len(keys)

def read_url_list(list_file):
    debug_print(f"Reading URL list from: {list_file}")
    try:
        with open(list_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        debug_print(f"Read {len(urls)} URLs from file")
        return urls
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to read URL list from {list_file}: {e}")
        debug_print(f"Failed to read URL list: {e}")
        sys.exit(1)

def main():
    # Parse arguments first to get debug flag
    args = parse_args()
    
    # Set global debug flag
    global DEBUG
    DEBUG = args.debug
    
    # Setup logging based on debug flag
    setup_logging(DEBUG)
    
    if DEBUG:
        print(f"{Fore.YELLOW}[DEBUG] Debug mode enabled")
        debug_print(f"Command line arguments: {vars(args)}")
    
    # Print banner
    print_ascii_art(encoded_art)

    total_files = 0
    tor_manager = None

    # Initialize Tor if requested
    if args.tor:
        debug_print("Initializing Tor connection...")
        print(f"{Fore.CYAN}[*] Initializing Tor connection...")
        tor_manager = TorManager()
        
        if tor_manager.ensure_tor_connection():
            print(f"{Fore.LIGHTGREEN_EX}[✓] Tor connection established")
            debug_print("Tor connection successfully established")
        else:
            print(f"{Fore.RED}[!] Failed to establish Tor connection")
            print(f"{Fore.YELLOW}[i] Please ensure Tor is installed and accessible")
            print(f"{Fore.YELLOW}    Install: apt install tor  # or  brew install tor")
            debug_print("Tor connection failed")
            sys.exit(1)

    # Initialize connection pool manager with Tor if enabled
    debug_print("Initializing connection pool manager...")
    pool_manager = ConnectionPoolManager(
        random_user_agents=args.random_user_agent, 
        tor_manager=tor_manager
    )
    
    # Show tool status
    show_tool_status(pool_manager, tor_manager)

    try:
        if args.url:
            debug_print(f"Processing single URL: {args.url}")
            # Process single URL
            total_files = process_url(args.url, args, pool_manager, tor_manager)
        elif args.list:
            debug_print(f"Processing URL list: {args.list}")
            # Process multiple URLs from file
            urls = read_url_list(args.list)
            print(f"{Fore.BLUE}[*] Found {Style.BRIGHT}{len(urls)}{Style.NORMAL} URLs in list file")

            for i, url in enumerate(urls, 1):
                print(f"\n{Fore.BLUE}[*] Processing URL {Style.BRIGHT}{i}/{len(urls)}{Style.NORMAL}")
                debug_print(f"Processing URL {i}/{len(urls)}: {url}")
                try:
                    file_count = process_url(url, args, pool_manager, tor_manager)
                    total_files += file_count
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}[!] Operation interrupted. Processed {i-1}/{len(urls)} URLs")
                    debug_print("Operation interrupted by user")
                    break
                except Exception as e:
                    print(f"{Fore.RED}[!] Error processing {url}: {e}")
                    debug_print(f"Error processing URL {url}: {e}")
                    continue

        # Only show multi-bucket summary if processing multiple URLs
        if args.list:
            print(f"\n{Fore.LIGHTGREEN_EX}{Style.BRIGHT}[✓] Multi-bucket operation complete: {total_files} total files downloaded")
            debug_print(f"Multi-bucket operation complete: {total_files} total files")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation interrupted by user")
        debug_print("Main operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}")
        debug_print(f"Fatal error in main: {e}")
        sys.exit(1)
    finally:
        debug_print("Cleaning up...")
        pool_manager.close()
        if tor_manager:
            tor_manager.stop_tor()

if __name__ == "__main__":
    main()
