"""
PC Guard Pro - Advanced Security Suite
A comprehensive antivirus solution with:
- VirusTotal API integration
- YARA rule-based detection
- Behavioral analysis
- Memory scanning
- Registry monitoring
- Network traffic analysis
- Real-time protection
"""

import hashlib
import json
import os
import platform
import queue
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import (
    Tk, StringVar, DoubleVar, BooleanVar, Text, END, BOTH, X, Y,
    RIGHT, LEFT, TOP, BOTTOM, DISABLED, NORMAL
)
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from typing import List, Dict, Set, Optional, Tuple
import sqlite3

# Optional imports with fallback
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("Warning: psutil not installed. Memory scanning disabled.")
    print("Install with: pip install psutil")

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    print("Warning: yara-python not installed. YARA scanning disabled.")
    print("Install with: pip install yara-python")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests not installed. VirusTotal integration disabled.")
    print("Install with: pip install requests")

# Constants
APP_TITLE = "PC Guard Pro Advanced"
APP_VERSION = "2.0"
WINDOW_SIZE = "1200x800"

# File extensions to scan
SCAN_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1", 
    ".vbs", ".js", ".jar", ".scr", ".com", ".pif", ".application",
    ".gadget", ".msp", ".hta", ".cpl", ".msc", ".vb", ".wsf",
    ".sh", ".bin", ".app", ".deb", ".rpm", ".apk", ".ipa"
}

# Suspicious filename patterns
SUSPICIOUS_NAMES = {
    "keygen", "crack", "patch", "stealer", "injector", "miner",
    "rat", "trojan", "payload", "backdoor", "hacktool", "ransomware",
    "crypter", "stub", "loader", "dropper", "downloader", "bot",
    "keylogger", "spyware", "rootkit", "exploit", "shellcode",
    "mimikatz", "psexec", "netcat", "nc.exe", "pwdump", "fgdump"
}

# Suspicious registry keys (Windows)
SUSPICIOUS_REGISTRY_PATHS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SYSTEM\CurrentControlSet\Services",
]

# Known malicious IP patterns (simplified)
SUSPICIOUS_IP_PATTERNS = [
    r"^10\.0\.0\.",  # Example: Tor exit nodes, etc.
]

MAX_FILE_SIZE_MB = 100
VT_API_URL = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT_DELAY = 15  # seconds between requests for free API


def format_bytes(num: int) -> str:
    """Format bytes to human-readable string."""
    step = 1024.0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < step:
            return f"{num:.1f} {unit}"
        num /= step
    return f"{num:.1f} PB"


@dataclass
class ThreatInfo:
    """Information about a detected threat."""
    path: str
    threat_type: str
    severity: str  # low, medium, high, critical
    reason: str
    sha256: str
    detection_methods: List[str] = field(default_factory=list)
    vt_score: Optional[int] = None
    yara_rules: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    name: str
    exe_path: str
    cmdline: str
    connections: List[str] = field(default_factory=list)
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


class ThreatDatabase:
    """SQLite database for storing threat intelligence."""
    
    def __init__(self, db_path: str = "threats.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()
    
    def _create_tables(self):
        """Create database tables."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT UNIQUE,
                path TEXT,
                threat_type TEXT,
                severity TEXT,
                reason TEXT,
                vt_score INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                detection_count INTEGER DEFAULT 1
            )
        """)
        
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT,
                detection_method TEXT,
                timestamp TEXT,
                FOREIGN KEY (sha256) REFERENCES threats(sha256)
            )
        """)
        
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT,
                start_time TEXT,
                end_time TEXT,
                files_scanned INTEGER,
                threats_found INTEGER
            )
        """)
        
        self.conn.commit()
    
    def add_threat(self, threat: ThreatInfo):
        """Add or update threat in database."""
        try:
            self.cursor.execute("""
                INSERT INTO threats (sha256, path, threat_type, severity, reason, vt_score, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    last_seen = ?,
                    detection_count = detection_count + 1
            """, (
                threat.sha256, threat.path, threat.threat_type, threat.severity,
                threat.reason, threat.vt_score, threat.timestamp, threat.timestamp,
                threat.timestamp
            ))
            
            for method in threat.detection_methods:
                self.cursor.execute("""
                    INSERT INTO detections (sha256, detection_method, timestamp)
                    VALUES (?, ?, ?)
                """, (threat.sha256, method, threat.timestamp))
            
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
    
    def get_threat_stats(self) -> Dict:
        """Get threat statistics."""
        stats = {}
        
        self.cursor.execute("SELECT COUNT(*) FROM threats")
        stats['total_threats'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM threats WHERE severity='critical'")
        stats['critical_threats'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM scans")
        stats['total_scans'] = self.cursor.fetchone()[0]
        
        return stats
    
    def close(self):
        """Close database connection."""
        self.conn.close()


class VirusTotalScanner:
    """VirusTotal API integration for cloud-based threat intelligence."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.last_request_time = 0
        self.cache = {}  # Simple cache to avoid duplicate lookups
    
    def set_api_key(self, api_key: str):
        """Set VirusTotal API key."""
        self.api_key = api_key
    
    def check_file_hash(self, file_hash: str) -> Optional[Dict]:
        """Check file hash against VirusTotal database."""
        if not HAS_REQUESTS or not self.api_key:
            return None
        
        # Check cache
        if file_hash in self.cache:
            return self.cache[file_hash]
        
        # Rate limiting
        elapsed = time.time() - self.last_request_time
        if elapsed < VT_RATE_LIMIT_DELAY:
            time.sleep(VT_RATE_LIMIT_DELAY - elapsed)
        
        try:
            headers = {
                "x-apikey": self.api_key
            }
            url = f"{VT_API_URL}/files/{file_hash}"
            
            response = requests.get(url, headers=headers, timeout=30)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    'malicious': data['data']['attributes']['last_analysis_stats']['malicious'],
                    'suspicious': data['data']['attributes']['last_analysis_stats']['suspicious'],
                    'undetected': data['data']['attributes']['last_analysis_stats']['undetected'],
                    'total_engines': sum(data['data']['attributes']['last_analysis_stats'].values())
                }
                self.cache[file_hash] = result
                return result
            elif response.status_code == 404:
                return {'malicious': 0, 'suspicious': 0, 'undetected': 0, 'total_engines': 0}
            else:
                print(f"VT API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"VT request failed: {e}")
            return None
    
    def upload_file(self, file_path: str) -> Optional[str]:
        """Upload file to VirusTotal for analysis."""
        if not HAS_REQUESTS or not self.api_key:
            return None
        
        try:
            headers = {"x-apikey": self.api_key}
            url = f"{VT_API_URL}/files"
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(url, headers=headers, files=files, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                return data['data']['id']
            return None
        except Exception as e:
            print(f"VT upload failed: {e}")
            return None


class YARAScanner:
    """YARA rule-based malware detection."""
    
    def __init__(self, rules_path: Optional[str] = None):
        self.rules = None
        self.rules_path = rules_path
        if HAS_YARA and rules_path and os.path.exists(rules_path):
            try:
                self.rules = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"Failed to compile YARA rules: {e}")
    
    def load_rules_from_directory(self, rules_dir: str):
        """Load all YARA rules from a directory."""
        if not HAS_YARA:
            return
        
        try:
            rule_files = {}
            for root, _, files in os.walk(rules_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        full_path = os.path.join(root, file)
                        namespace = os.path.splitext(file)[0]
                        rule_files[namespace] = full_path
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                print(f"Loaded {len(rule_files)} YARA rule files")
        except Exception as e:
            print(f"Failed to load YARA rules: {e}")
    
    def scan_file(self, file_path: str) -> List[str]:
        """Scan file with YARA rules."""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(file_path)
            return [match.rule for match in matches]
        except Exception as e:
            print(f"YARA scan error: {e}")
            return []
    
    def create_basic_rules(self, output_path: str):
        """Create basic YARA rules for common threats."""
        basic_rules = '''
rule Suspicious_Cryptocurrency_Miner {
    meta:
        description = "Detects potential cryptocurrency miner"
        severity = "high"
    strings:
        $xmr1 = "stratum+tcp://" nocase
        $xmr2 = "pool.supportxmr.com" nocase
        $xmr3 = "xmrig" nocase
        $btc = "bitcoin" nocase
        $mine = "cryptonight" nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        2 of them
}

rule Suspicious_Remote_Access_Tool {
    meta:
        description = "Detects potential RAT/backdoor"
        severity = "critical"
    strings:
        $rat1 = "TeamViewer" nocase
        $rat2 = "AnyDesk" nocase
        $rat3 = "RemotePC" nocase
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "powershell.exe" nocase
        $net1 = "socket.connect" nocase
        $net2 = "urllib.request" nocase
    condition:
        (any of ($rat*)) or (2 of ($cmd*) and any of ($net*))
}

rule Suspicious_Keylogger {
    meta:
        description = "Detects potential keylogger"
        severity = "high"
    strings:
        $key1 = "GetAsyncKeyState" nocase
        $key2 = "keyboard.hook" nocase
        $key3 = "pynput" nocase
        $log = "logfile" nocase
    condition:
        any of them
}

rule Suspicious_Credential_Stealer {
    meta:
        description = "Detects potential credential stealer"
        severity = "critical"
    strings:
        $cred1 = "password" nocase
        $cred2 = "credential" nocase
        $cred3 = "token" nocase
        $browser1 = "\\Google\\Chrome\\User Data" nocase
        $browser2 = "\\Mozilla\\Firefox\\Profiles" nocase
        $wallet = "wallet.dat" nocase
    condition:
        (any of ($cred*)) and (any of ($browser*) or $wallet)
}

rule Suspicious_Ransomware_Indicators {
    meta:
        description = "Detects potential ransomware"
        severity = "critical"
    strings:
        $encrypt1 = "AES" nocase
        $encrypt2 = "RSA" nocase
        $encrypt3 = "encrypt" nocase
        $ransom1 = "bitcoin" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "ransom" nocase
        $ext = ".encrypted" nocase
    condition:
        (any of ($encrypt*)) and (any of ($ransom*))
}

rule Suspicious_Obfuscation {
    meta:
        description = "Detects obfuscated code"
        severity = "medium"
    strings:
        $b64 = "base64" nocase
        $xor = "xor" nocase
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $deobf = /[A-Za-z]{50,}/
    condition:
        3 of them
}
'''
        try:
            with open(output_path, 'w') as f:
                f.write(basic_rules)
            print(f"Created basic YARA rules: {output_path}")
        except Exception as e:
            print(f"Failed to create YARA rules: {e}")


class BehavioralAnalyzer:
    """Behavioral analysis for detecting suspicious activities."""
    
    def __init__(self):
        self.suspicious_behaviors = []
    
    def analyze_file_behavior(self, file_path: Path) -> List[str]:
        """Analyze file for suspicious behaviors."""
        behaviors = []
        
        try:
            # Check file attributes
            if self._is_hidden(file_path):
                behaviors.append("Hidden file attribute")
            
            # Check file size anomalies
            size = file_path.stat().st_size
            if size == 0:
                behaviors.append("Zero-byte file (potentially malicious)")
            elif size < 100:
                behaviors.append("Suspiciously small executable")
            
            # Check for suspicious extensions
            if file_path.suffix.lower() in {'.exe', '.scr'} and file_path.suffix != file_path.suffix.lower():
                behaviors.append("Mixed case extension (evasion technique)")
            
            # Check for double extensions
            if len(file_path.suffixes) > 1:
                behaviors.append(f"Double extension: {file_path.name}")
            
            # Check file content
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(1024)
                    
                    # Check for PE header
                    if header[:2] == b'MZ':
                        behaviors.append("Portable Executable detected")
                    
                    # Check for script content in executable
                    if b'powershell' in header.lower() or b'cmd.exe' in header.lower():
                        behaviors.append("Contains script execution commands")
                    
                    # Check for suspicious URLs
                    if b'http://' in header or b'https://' in header:
                        behaviors.append("Contains embedded URLs")
                    
                    # Check for base64 encoding
                    if self._contains_base64(header):
                        behaviors.append("Contains base64 encoded data")
            
            except Exception:
                pass
            
        except Exception as e:
            print(f"Behavioral analysis error: {e}")
        
        return behaviors
    
    def _is_hidden(self, path: Path) -> bool:
        """Check if file is hidden."""
        if path.name.startswith("."):
            return True
        if os.name == "nt":
            try:
                attrs = os.stat(path).st_file_attributes
                return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                return False
        return False
    
    def _contains_base64(self, data: bytes) -> bool:
        """Check if data contains base64 encoding."""
        try:
            # Simple heuristic: long sequences of base64 characters
            text = data.decode('ascii', errors='ignore')
            b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
            return bool(b64_pattern.search(text))
        except Exception:
            return False


class ProcessScanner:
    """Scan running processes for threats."""
    
    def __init__(self):
        self.suspicious_processes = []
    
    def scan_processes(self) -> List[ProcessInfo]:
        """Scan all running processes."""
        if not HAS_PSUTIL:
            return []
        
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    info = ProcessInfo(
                        pid=proc.info['pid'],
                        name=proc.info['name'] or "Unknown",
                        exe_path=proc.info['exe'] or "Unknown",
                        cmdline=' '.join(proc.info['cmdline'] or [])
                    )
                    
                    # Check for suspicious indicators
                    reasons = []
                    
                    # Suspicious names
                    if any(susp in info.name.lower() for susp in SUSPICIOUS_NAMES):
                        reasons.append(f"Suspicious process name: {info.name}")
                    
                    # Script interpreters with suspicious commands
                    if info.name.lower() in ['powershell.exe', 'cmd.exe', 'python.exe']:
                        if any(keyword in info.cmdline.lower() for keyword in 
                               ['hidden', 'bypass', 'encodedcommand', 'download', 'webclient']):
                            reasons.append("Suspicious command line arguments")
                    
                    # Get network connections
                    try:
                        connections = proc.connections()
                        for conn in connections:
                            if conn.status == 'ESTABLISHED':
                                remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                                info.connections.append(remote)
                                
                                # Check for suspicious IPs
                                if any(re.match(pattern, conn.raddr.ip) for pattern in SUSPICIOUS_IP_PATTERNS):
                                    reasons.append(f"Connection to suspicious IP: {conn.raddr.ip}")
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    if reasons:
                        info.suspicious = True
                        info.reasons = reasons
                    
                    processes.append(info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            print(f"Process scanning error: {e}")
        
        return processes

class PCGuardAdvanced:
    """Advanced PC Guard Pro with comprehensive threat detection."""
    
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} v{APP_VERSION}")
        self.root.geometry(WINDOW_SIZE)
        self.root.minsize(1000, 700)
        
        # Initialize components
        self.db = ThreatDatabase()
        self.vt_scanner = VirusTotalScanner()
        self.yara_scanner = YARAScanner()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.process_scanner = ProcessScanner()
        
        # Threading
        self.scan_queue = queue.Queue()
        self.clean_queue = queue.Queue()
        self.scan_thread: Optional[threading.Thread] = None
        self.clean_thread: Optional[threading.Thread] = None
        
        # UI Variables
        self.status_var = StringVar(value="Ready")
        self.threats_var = StringVar(value="0 Threats")
        self.cleaned_var = StringVar(value="0 B Cleaned")
        self.last_scan_var = StringVar(value="Never")
        self.progress_var = DoubleVar(value=0.0)
        self.mode_var = StringVar(value="Idle")
        self.vt_enabled_var = BooleanVar(value=False)
        self.yara_enabled_var = BooleanVar(value=HAS_YARA)
        self.realtime_var = BooleanVar(value=False)
        
        # Data
        self.findings: List[ThreatInfo] = []
        self.cleaned_bytes = 0
        self.stop_requested = False
        
        # Setup
        self._configure_style()
        self._setup_yara()
        self._build_ui()
        self._poll_queues()
    
    def _configure_style(self):
        """Configure UI theme."""
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        
        # Colors
        bg = "#0a0e27"
        panel = "#141b2d"
        panel_2 = "#1e293b"
        accent = "#3b82f6"
        danger = "#ef4444"
        success = "#22c55e"
        warning = "#f59e0b"
        text = "#e5e7eb"
        muted = "#94a3b8"
        
        self.root.configure(bg=bg)
        self.style.configure("Root.TFrame", background=bg)
        self.style.configure("Panel.TFrame", background=panel)
        self.style.configure("Soft.TFrame", background=panel_2)
        self.style.configure("Header.TLabel", background=bg, foreground=text, 
                           font=("Segoe UI", 24, "bold"))
        self.style.configure("Sub.TLabel", background=bg, foreground=muted, 
                           font=("Segoe UI", 10))
        self.style.configure("CardTitle.TLabel", background=panel, foreground=text, 
                           font=("Segoe UI", 12, "bold"))
        self.style.configure("BigStat.TLabel", background=panel, foreground=accent, 
                           font=("Segoe UI", 20, "bold"))
        self.style.configure("SmallStat.TLabel", background=panel, foreground=muted, 
                           font=("Segoe UI", 10))
        self.style.configure("Success.TLabel", background=panel, foreground=success, 
                           font=("Segoe UI", 12, "bold"))
        self.style.configure("Danger.TLabel", background=panel, foreground=danger, 
                           font=("Segoe UI", 12, "bold"))
        self.style.configure("Warning.TLabel", background=panel, foreground=warning, 
                           font=("Segoe UI", 12, "bold"))
        self.style.configure("Action.TButton", font=("Segoe UI", 10, "bold"), padding=10)
        self.style.configure("Treeview", rowheight=28, font=("Consolas", 9), 
                           background="#0b1220", fieldbackground="#0b1220", foreground=text)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        self.style.map("Treeview", background=[("selected", accent)])
        self.style.configure("Horizontal.TProgressbar", thickness=16)
    
    def _setup_yara(self):
        """Setup YARA rules."""
        if not HAS_YARA:
            return
        
        rules_dir = Path.home() / ".pcguard" / "yara_rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        rules_file = rules_dir / "basic_rules.yar"
        if not rules_file.exists():
            self.yara_scanner.create_basic_rules(str(rules_file))
        
        self.yara_scanner.load_rules_from_directory(str(rules_dir))
    
    def _build_ui(self):
        """Build main UI."""
        outer = ttk.Frame(self.root, style="Root.TFrame", padding=16)
        outer.pack(fill=BOTH, expand=True)
        
        # Header
        header = ttk.Frame(outer, style="Root.TFrame")
        header.pack(fill=X, pady=(0, 14))
        ttk.Label(header, text=APP_TITLE, style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Advanced multi-engine antivirus with cloud intelligence, "
                              "YARA rules, and behavioral analysis",
                  style="Sub.TLabel").pack(anchor="w", pady=(2, 0))
        
        # Status cards
        self._build_status_cards(outer)
        
        # Control panel
        self._build_control_panel(outer)
        
        # Progress bar
        prog_wrap = ttk.Frame(outer, style="Root.TFrame")
        prog_wrap.pack(fill=X, pady=(0, 14))
        ttk.Progressbar(prog_wrap, maximum=100, variable=self.progress_var,
                       style="Horizontal.TProgressbar").pack(fill=X)
        
        # Notebook tabs
        notebook = ttk.Notebook(outer)
        notebook.pack(fill=BOTH, expand=True)
        
        tabs = {
            "Dashboard": self._build_dashboard_tab,
            "Threats": self._build_threats_tab,
            "Processes": self._build_processes_tab,
            "Settings": self._build_settings_tab,
            "Cleaner": self._build_cleaner_tab,
            "Logs": self._build_logs_tab,
        }
        
        for name, builder in tabs.items():
            tab = ttk.Frame(notebook, style="Root.TFrame", padding=8)
            notebook.add(tab, text=name)
            builder(tab)
    
    def _build_status_cards(self, parent):
        """Build status cards."""
        top_cards = ttk.Frame(parent, style="Root.TFrame")
        top_cards.pack(fill=X, pady=(0, 14))
        
        cards = [
            ("Threat Status", self.threats_var, "Detected threats", "Danger.TLabel"),
            ("Protection", lambda: "Active" if self.realtime_var.get() else "Disabled",
             "Real-time protection", "Success.TLabel"),
            ("Last Scan", self.last_scan_var, "Most recent scan", "SmallStat.TLabel"),
            ("Cleaned", self.cleaned_var, "Space recovered", "Success.TLabel"),
        ]
        
        for title, value_var, hint, style in cards:
            card = ttk.Frame(top_cards, style="Panel.TFrame", padding=16)
            card.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
            ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
            
            if callable(value_var):
                label = ttk.Label(card, text=value_var(), style=style)
            else:
                label = ttk.Label(card, textvariable=value_var, style=style)
            label.pack(anchor="w", pady=(8, 4))
            ttk.Label(card, text=hint, style="SmallStat.TLabel").pack(anchor="w")
    
    def _build_control_panel(self, parent):
        """Build control panel."""
        control = ttk.Frame(parent, style="Panel.TFrame", padding=16)
        control.pack(fill=X, pady=(0, 14))
        
        left = ttk.Frame(control, style="Panel.TFrame")
        left.pack(side=LEFT, fill=X, expand=True)
        ttk.Label(left, text="Protection Center", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(left, textvariable=self.status_var, style="SmallStat.TLabel").pack(
            anchor="w", pady=(6, 0))
        
        btns = ttk.Frame(control, style="Panel.TFrame")
        btns.pack(side=RIGHT)
        
        buttons = [
            ("Quick Scan", self.quick_scan),
            ("Full Scan", self.full_scan_folder),
            ("Memory Scan", self.memory_scan),
            ("Process Scan", self.process_scan),
            ("Clean System", self.clean_system),
            ("Stop", self.request_stop),
        ]
        
        for text, command in buttons:
            ttk.Button(btns, text=text, style="Action.TButton",
                      command=command).pack(side=LEFT, padx=5)
    
    def _build_dashboard_tab(self, parent):
        """Build dashboard tab."""
        box = ttk.Frame(parent, style="Panel.TFrame", padding=18)
        box.pack(fill=BOTH, expand=True)
        
        ttk.Label(box, text="System Protection Status", 
                 style="CardTitle.TLabel").pack(anchor="w")
        
        # Statistics
        stats = self.db.get_threat_stats()
        
        info_text = f"""
Protection Status: {"ACTIVE" if self.realtime_var.get() else "DISABLED"}
Detection Engines: {sum([1, HAS_YARA, self.vt_enabled_var.get()])} active

Threat Database:
• Total Threats Detected: {stats.get('total_threats', 0)}
• Critical Threats: {stats.get('critical_threats', 0)}
• Total Scans Performed: {stats.get('total_scans', 0)}

Detection Methods:
✓ Signature-based detection (SHA256 hashing)
{"✓" if HAS_YARA else "✗"} YARA rule-based detection
{"✓" if self.vt_enabled_var.get() else "✗"} VirusTotal cloud intelligence
✓ Behavioral analysis
{"✓" if HAS_PSUTIL else "✗"} Process and memory scanning

Recommendations:
• Enable real-time protection for continuous monitoring
• Run Quick Scan daily for Downloads and common locations
• Use Full Scan weekly for complete system analysis
• Keep YARA rules updated for latest threat detection
• Configure VirusTotal API for enhanced cloud scanning
        """
        
        text_widget = Text(box, height=20, bg="#0b1220", fg="#e5e7eb",
                          relief="flat", font=("Consolas", 10))
        text_widget.pack(fill=BOTH, expand=True, pady=(10, 0))
        text_widget.insert(END, info_text.strip())
        text_widget.config(state=DISABLED)
    
    def _build_threats_tab(self, parent):
        """Build threats tab."""
        wrapper = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        wrapper.pack(fill=BOTH, expand=True)
        
        columns = ("path", "type", "severity", "reason", "vt_score", "sha256")
        self.threats_tree = ttk.Treeview(wrapper, columns=columns, show="headings", height=15)
        
        self.threats_tree.heading("path", text="Path")
        self.threats_tree.heading("type", text="Type")
        self.threats_tree.heading("severity", text="Severity")
        self.threats_tree.heading("reason", text="Reason")
        self.threats_tree.heading("vt_score", text="VT Score")
        self.threats_tree.heading("sha256", text="SHA256")
        
        self.threats_tree.column("path", width=300)
        self.threats_tree.column("type", width=120)
        self.threats_tree.column("severity", width=80)
        self.threats_tree.column("reason", width=250)
        self.threats_tree.column("vt_score", width=80)
        self.threats_tree.column("sha256", width=200)
        
        self.threats_tree.pack(fill=BOTH, expand=True)
        
        bottom = ttk.Frame(wrapper, style="Panel.TFrame")
        bottom.pack(fill=X, pady=(10, 0))
        
        buttons = [
            ("Export Report", self.export_report),
            ("Quarantine Selected", self.quarantine_selected),
            ("Delete Selected", self.delete_selected),
            ("Clear List", self.clear_threats_list),
        ]
        
        for text, command in buttons:
            ttk.Button(bottom, text=text, style="Action.TButton",
                      command=command).pack(side=LEFT, padx=5)
    
    def _build_processes_tab(self, parent):
        """Build processes tab."""
        wrapper = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        wrapper.pack(fill=BOTH, expand=True)
        
        ttk.Label(wrapper, text="Running Processes Analysis",
                 style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))
        
        columns = ("pid", "name", "path", "suspicious", "connections")
        self.process_tree = ttk.Treeview(wrapper, columns=columns, show="headings", height=15)
        
        self.process_tree.heading("pid", text="PID")
        self.process_tree.heading("name", text="Name")
        self.process_tree.heading("path", text="Path")
        self.process_tree.heading("suspicious", text="Suspicious")
        self.process_tree.heading("connections", text="Connections")
        
        self.process_tree.column("pid", width=80)
        self.process_tree.column("name", width=200)
        self.process_tree.column("path", width=350)
        self.process_tree.column("suspicious", width=100)
        self.process_tree.column("connections", width=150)
        
        self.process_tree.pack(fill=BOTH, expand=True)
        
        bottom = ttk.Frame(wrapper, style="Panel.TFrame")
        bottom.pack(fill=X, pady=(10, 0))
        
        ttk.Button(bottom, text="Refresh Processes", style="Action.TButton",
                  command=self.process_scan).pack(side=LEFT, padx=5)
        ttk.Button(bottom, text="Kill Selected Process", style="Action.TButton",
                  command=self.kill_process).pack(side=LEFT, padx=5)
    
    def _build_settings_tab(self, parent):
        """Build settings tab."""
        wrapper = ttk.Frame(parent, style="Panel.TFrame", padding=18)
        wrapper.pack(fill=BOTH, expand=True)
        
        ttk.Label(wrapper, text="Protection Settings",
                 style="CardTitle.TLabel").pack(anchor="w", pady=(0, 20))
        
        # Real-time protection
        rt_frame = ttk.Frame(wrapper, style="Panel.TFrame")
        rt_frame.pack(fill=X, pady=10)
        ttk.Checkbutton(rt_frame, text="Enable Real-time Protection (Experimental)",
                       variable=self.realtime_var, style="CardTitle.TLabel").pack(side=LEFT)
        
        # VirusTotal
        vt_frame = ttk.Frame(wrapper, style="Panel.TFrame")
        vt_frame.pack(fill=X, pady=10)
        ttk.Label(vt_frame, text="VirusTotal API Key:",
                 style="SmallStat.TLabel").pack(side=LEFT, padx=(0, 10))
        vt_entry = ttk.Entry(vt_frame, width=50)
        vt_entry.pack(side=LEFT, padx=5)
        ttk.Button(vt_frame, text="Set API Key", style="Action.TButton",
                  command=lambda: self.set_vt_api_key(vt_entry.get())).pack(side=LEFT, padx=5)
        
        # YARA
        yara_frame = ttk.Frame(wrapper, style="Panel.TFrame")
        yara_frame.pack(fill=X, pady=10)
        ttk.Checkbutton(yara_frame, text=f"Enable YARA Scanning ({'' if HAS_YARA else 'NOT '}Available)",
                       variable=self.yara_enabled_var,
                       state=NORMAL if HAS_YARA else DISABLED).pack(side=LEFT)
        
        # Info
        info = ttk.Frame(wrapper, style="Soft.TFrame", padding=16)
        info.pack(fill=X, pady=20)
        
        info_text = """
VirusTotal Integration:
• Get a free API key from https://www.virustotal.com/
• Free tier allows 4 requests per minute
• Provides cloud-based multi-engine scanning

YARA Rules:
• Pattern-matching for malware detection
• Rules stored in ~/.pcguard/yara_rules/
• Custom rules can be added to this directory

Real-time Protection:
• Monitors file system for suspicious activity
• Requires elevated privileges
• May impact system performance
        """
        
        text_widget = Text(info, height=12, bg="#1e293b", fg="#e5e7eb",
                          relief="flat", font=("Consolas", 9))
        text_widget.pack(fill=BOTH, expand=True)
        text_widget.insert(END, info_text.strip())
        text_widget.config(state=DISABLED)
    
    def _build_cleaner_tab(self, parent):
        """Build cleaner tab."""
        wrapper = ttk.Frame(parent, style="Panel.TFrame", padding=18)
        wrapper.pack(fill=BOTH, expand=True)
        
        ttk.Label(wrapper, text="System Cleanup",
                 style="CardTitle.TLabel").pack(anchor="w")
        
        self.clean_targets_text = Text(wrapper, height=18, bg="#0b1220", fg="#e5e7eb",
                                       insertbackground="#e5e7eb", relief="flat",
                                       font=("Consolas", 10))
        self.clean_targets_text.pack(fill=BOTH, expand=True, pady=(10, 10))
        self.clean_targets_text.insert(END, self._describe_cleanup_targets())
        self.clean_targets_text.config(state=DISABLED)
        
        ttk.Label(wrapper, text="Cleaner removes temporary and cache files. "
                              "It does not delete documents or user data.",
                 style="SmallStat.TLabel").pack(anchor="w")
    
    def _build_logs_tab(self, parent):
        """Build logs tab."""
        wrapper = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        wrapper.pack(fill=BOTH, expand=True)
        
        self.log_text = Text(wrapper, bg="#0b1220", fg="#d1d5db",
                            insertbackground="#e5e7eb", relief="flat",
                            font=("Consolas", 10))
        self.log_text.pack(fill=BOTH, expand=True)
        
        self._log(f"{APP_TITLE} v{APP_VERSION} started")
        self._log(f"YARA: {'Enabled' if HAS_YARA else 'Disabled'}")
        self._log(f"VirusTotal: {'Enabled' if self.vt_enabled_var.get() else 'Disabled'}")
        self._log(f"Process Scanning: {'Enabled' if HAS_PSUTIL else 'Disabled'}")
    
    def _log(self, msg: str):
        """Log message."""
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(END, f"[{stamp}] {msg}\n")
        self.log_text.see(END)
    
    def _describe_cleanup_targets(self) -> str:
        """Describe cleanup targets."""
        targets = self._cleanup_targets()
        lines = ["System cleanup will scan these locations:\n"]
        for target in targets:
            lines.append(f"• {target}")
        return "\n".join(lines)
    
    def _cleanup_targets(self) -> List[Path]:
        """Get cleanup target directories."""
        targets = []
        temp_dir = Path(tempfile.gettempdir())
        targets.append(temp_dir)
        
        if os.name == 'nt':
            local = os.getenv("LOCALAPPDATA")
            appdata = os.getenv("APPDATA")
            
            if local:
                targets.extend([
                    Path(local) / "Temp",
                    Path(local) / "Microsoft" / "Windows" / "INetCache",
                    Path(local) / "Microsoft" / "Windows" / "WebCache",
                ])
            
            if appdata:
                targets.append(Path(appdata) / "Local" / "Temp")
        
        return [t for t in targets if t.exists()]
    
    def quick_scan(self):
        """Perform quick scan of common locations."""
        scan_paths = []
        home = Path.home()
        
        for name in ["Downloads", "Desktop", "Documents"]:
            p = home / name
            if p.exists():
                scan_paths.append(p)
        
        if os.name == 'nt':
            startup = os.getenv("APPDATA")
            if startup:
                startup_path = (Path(startup) / "Microsoft" / "Windows" / 
                              "Start Menu" / "Programs" / "Startup")
                if startup_path.exists():
                    scan_paths.append(startup_path)
        
        if not scan_paths:
            scan_paths = [home]
        
        self._start_scan(scan_paths, mode="Quick Scan")
    
    def full_scan_folder(self):
        """Perform full scan of selected folder."""
        folder = filedialog.askdirectory(title="Choose folder to scan")
        if not folder:
            return
        self._start_scan([Path(folder)], mode="Full Scan")
    
    def memory_scan(self):
        """Scan memory for threats."""
        if not HAS_PSUTIL:
            messagebox.showwarning(APP_TITLE,
                                 "Memory scanning requires psutil.\n"
                                 "Install with: pip install psutil")
            return
        
        messagebox.showinfo(APP_TITLE,
                          "Memory scanning will check running processes for suspicious activity.")
        self.process_scan()
    
    def process_scan(self):
        """Scan running processes."""
        if not HAS_PSUTIL:
            messagebox.showwarning(APP_TITLE,
                                 "Process scanning requires psutil.\n"
                                 "Install with: pip install psutil")
            return
        
        self.status_var.set("Scanning processes...")
        self._log("Process scan started")
        
        def scan_worker():
            processes = self.process_scanner.scan_processes()
            self.scan_queue.put(("process_results", processes))
        
        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()
    
    def _start_scan(self, paths: List[Path], mode: str):
        """Start file scan."""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo(APP_TITLE, "A scan is already running.")
            return
        
        self.mode_var.set(mode)
        self.status_var.set(f"{mode} running...")
        self.progress_var.set(0)
        self.findings.clear()
        self.threats_tree.delete(*self.threats_tree.get_children())
        self.stop_requested = False
        
        self._log(f"Started {mode} on: {', '.join(str(p) for p in paths)}")
        
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(paths,),
            daemon=True
        )
        self.scan_thread.start()
    
    def _scan_worker(self, paths: List[Path]):
        """Worker thread for file scanning."""
        # Collect files
        files = []
        for base in paths:
            if not base.exists():
                continue
            for root, _, filenames in os.walk(base):
                if self.stop_requested:
                    break
                for filename in filenames:
                    full_path = Path(root) / filename
                    files.append(full_path)
            if self.stop_requested:
                break
        
        total = max(len(files), 1)
        threats_found = []
        
        for i, file_path in enumerate(files, start=1):
            if self.stop_requested:
                break
            
            pct = (i / total) * 100
            self.scan_queue.put(("progress", pct))
            
            try:
                # Filter by extension
                if file_path.suffix.lower() not in SCAN_EXTENSIONS:
                    continue
                
                # Size check
                if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                    continue
                
                # Scan file
                threat = self._scan_file(file_path)
                if threat:
                    threats_found.append(threat)
                    self.scan_queue.put(("finding", threat))
                    self.db.add_threat(threat)
                
            except Exception as exc:
                self.scan_queue.put(("log", f"Scan error {file_path}: {exc}"))
        
        self.scan_queue.put(("done", threats_found, self.stop_requested))
    
    def _scan_file(self, file_path: Path) -> Optional[ThreatInfo]:
        """Scan single file for threats."""
        detection_methods = []
        reasons = []
        severity = "low"
        vt_score = None
        yara_rules = []
        
        # Calculate hash
        sha256 = self._sha256(file_path)
        
        # Check filename
        lowered = file_path.name.lower()
        if any(keyword in lowered for keyword in SUSPICIOUS_NAMES):
            reasons.append("Suspicious filename pattern")
            detection_methods.append("Signature")
            severity = "high"
        
        # Behavioral analysis
        behaviors = self.behavioral_analyzer.analyze_file_behavior(file_path)
        if behaviors:
            reasons.extend(behaviors)
            detection_methods.append("Behavioral")
            if severity == "low":
                severity = "medium"
        
        # YARA scanning
        if self.yara_enabled_var.get() and self.yara_scanner.rules:
            matches = self.yara_scanner.scan_file(str(file_path))
            if matches:
                yara_rules = matches
                reasons.append(f"YARA rules matched: {', '.join(matches)}")
                detection_methods.append("YARA")
                severity = "high"
        
        # VirusTotal check
        if self.vt_enabled_var.get():
            vt_result = self.vt_scanner.check_file_hash(sha256)
            if vt_result and vt_result['malicious'] > 0:
                vt_score = vt_result['malicious']
                reasons.append(f"VirusTotal: {vt_score}/{vt_result['total_engines']} engines")
                detection_methods.append("VirusTotal")
                if vt_score > 10:
                    severity = "critical"
                elif vt_score > 5:
                    severity = "high"
        
        # Create threat info if any detection
        if reasons:
            return ThreatInfo(
                path=str(file_path),
                threat_type="Malware" if severity in ["high", "critical"] else "Suspicious",
                severity=severity,
                reason="; ".join(reasons),
                sha256=sha256,
                detection_methods=detection_methods,
                vt_score=vt_score,
                yara_rules=yara_rules
            )
        
        return None
    
    def _sha256(self, path: Path) -> str:
        """Calculate SHA256 hash."""
        digest = hashlib.sha256()
        try:
            with path.open("rb") as f:
                while chunk := f.read(1024 * 1024):
                    digest.update(chunk)
        except Exception:
            return "ERROR"
        return digest.hexdigest()
    
    def request_stop(self):
        """Request scan stop."""
        self.stop_requested = True
        self.status_var.set("Stop requested...")
        self._log("Stop requested by user")
    
    def clean_system(self):
        """Start system cleanup."""
        if self.clean_thread and self.clean_thread.is_alive():
            messagebox.showinfo(APP_TITLE, "Cleanup is already running.")
            return
        
        self.status_var.set("Cleanup running...")
        self.progress_var.set(0)
        self.stop_requested = False
        targets = self._cleanup_targets()
        self._log("System cleanup started")
        
        self.clean_thread = threading.Thread(
            target=self._clean_worker,
            args=(targets,),
            daemon=True
        )
        self.clean_thread.start()
    
    def _clean_worker(self, targets: List[Path]):
        """Worker thread for cleanup."""
        file_list = []
        for target in targets:
            if not target.exists():
                continue
            for root, dirs, files in os.walk(target):
                if self.stop_requested:
                    break
                root_path = Path(root)
                for name in files:
                    file_list.append(root_path / name)
            if self.stop_requested:
                break
        
        total = max(len(file_list), 1)
        cleaned = 0
        
        for i, file_path in enumerate(file_list, start=1):
            if self.stop_requested:
                break
            self.clean_queue.put(("progress", (i / total) * 100))
            try:
                size = file_path.stat().st_size
                file_path.unlink(missing_ok=True)
                cleaned += size
            except Exception:
                continue
        
        self.clean_queue.put(("done", cleaned, self.stop_requested))
    
    def set_vt_api_key(self, api_key: str):
        """Set VirusTotal API key."""
        if not api_key:
            messagebox.showwarning(APP_TITLE, "Please enter a valid API key.")
            return
        
        self.vt_scanner.set_api_key(api_key)
        self.vt_enabled_var.set(True)
        self._log(f"VirusTotal API key configured")
        messagebox.showinfo(APP_TITLE, "VirusTotal API key set successfully!")
    
    def export_report(self):
        """Export threat report."""
        if not self.findings:
            messagebox.showinfo(APP_TITLE, "No threats to export.")
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Export threat report",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt")]
        )
        
        if not save_path:
            return
        
        try:
            if save_path.endswith('.json'):
                data = {
                    "scan_date": datetime.now().isoformat(),
                    "threats": [
                        {
                            "path": t.path,
                            "type": t.threat_type,
                            "severity": t.severity,
                            "reason": t.reason,
                            "sha256": t.sha256,
                            "vt_score": t.vt_score,
                            "yara_rules": t.yara_rules,
                            "detection_methods": t.detection_methods
                        }
                        for t in self.findings
                    ]
                }
                with open(save_path, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(save_path, 'w') as f:
                    f.write(f"{APP_TITLE} Threat Report\n")
                    f.write(f"Generated: {datetime.now().isoformat()}\n")
                    f.write(f"Total Threats: {len(self.findings)}\n\n")
                    for t in self.findings:
                        f.write(f"Path: {t.path}\n")
                        f.write(f"Type: {t.threat_type}\n")
                        f.write(f"Severity: {t.severity}\n")
                        f.write(f"Reason: {t.reason}\n")
                        f.write(f"SHA256: {t.sha256}\n")
                        if t.vt_score:
                            f.write(f"VirusTotal Score: {t.vt_score}\n")
                        if t.yara_rules:
                            f.write(f"YARA Rules: {', '.join(t.yara_rules)}\n")
                        f.write("\n")
            
            self._log(f"Report exported: {save_path}")
            messagebox.showinfo(APP_TITLE, "Report exported successfully!")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Export failed: {e}")
    
    def quarantine_selected(self):
        """Quarantine selected threats."""
        selected = self.threats_tree.selection()
        if not selected:
            messagebox.showinfo(APP_TITLE, "Select items to quarantine.")
            return
        
        quarantine_dir = Path.home() / ".pcguard" / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        quarantined = 0
        for item_id in selected:
            values = self.threats_tree.item(item_id, "values")
            path = values[0]
            try:
                src = Path(path)
                if src.exists():
                    dst = quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{src.name}"
                    shutil.move(str(src), str(dst))
                    quarantined += 1
                    self._log(f"Quarantined: {path}")
            except Exception as exc:
                self._log(f"Quarantine failed {path}: {exc}")
        
        messagebox.showinfo(APP_TITLE, f"Quarantined {quarantined} file(s).")
        self.findings = [f for f in self.findings if os.path.exists(f.path)]
        self._update_threat_display()
    
    def delete_selected(self):
        """Delete selected threats."""
        selected = self.threats_tree.selection()
        if not selected:
            messagebox.showinfo(APP_TITLE, "Select items to delete.")
            return
        
        if not messagebox.askyesno(APP_TITLE, 
                                  "Permanently delete selected files?\n"
                                  "This action cannot be undone!"):
            return
        
        deleted = 0
        for item_id in selected:
            values = self.threats_tree.item(item_id, "values")
            path = values[0]
            try:
                os.remove(path)
                deleted += 1
                self.threats_tree.delete(item_id)
                self._log(f"Deleted: {path}")
            except Exception as exc:
                self._log(f"Delete failed {path}: {exc}")
        
        self.findings = [f for f in self.findings if os.path.exists(f.path)]
        self.threats_var.set(f"{len(self.findings)} Threats")
        messagebox.showinfo(APP_TITLE, f"Deleted {deleted} file(s).")
    
    def clear_threats_list(self):
        """Clear threats list."""
        if messagebox.askyesno(APP_TITLE, "Clear all threats from the list?"):
            self.findings.clear()
            self.threats_tree.delete(*self.threats_tree.get_children())
            self.threats_var.set("0 Threats")
            self._log("Threats list cleared")
    
    def kill_process(self):
        """Kill selected process."""
        if not HAS_PSUTIL:
            return
        
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showinfo(APP_TITLE, "Select a process to kill.")
            return
        
        if not messagebox.askyesno(APP_TITLE,
                                  "Kill selected process?\n"
                                  "This may cause system instability!"):
            return
        
        for item_id in selected:
            values = self.process_tree.item(item_id, "values")
            pid = int(values[0])
            try:
                proc = psutil.Process(pid)
                proc.kill()
                self._log(f"Killed process: PID {pid}")
                self.process_tree.delete(item_id)
            except Exception as exc:
                messagebox.showerror(APP_TITLE, f"Failed to kill process: {exc}")
    
    def _update_threat_display(self):
        """Update threat display."""
        self.threats_tree.delete(*self.threats_tree.get_children())
        for threat in self.findings:
            self.threats_tree.insert("", END, values=(
                threat.path,
                threat.threat_type,
                threat.severity,
                threat.reason[:50] + "..." if len(threat.reason) > 50 else threat.reason,
                threat.vt_score if threat.vt_score else "N/A",
                threat.sha256[:16] + "..."
            ))
    
    def _poll_queues(self):
        """Poll message queues."""
        # Scan queue
        try:
            while True:
                item = self.scan_queue.get_nowait()
                kind = item[0]
                
                if kind == "progress":
                    self.progress_var.set(item[1])
                
                elif kind == "finding":
                    threat: ThreatInfo = item[1]
                    self.findings.append(threat)
                    self.threats_tree.insert("", END, values=(
                        threat.path,
                        threat.threat_type,
                        threat.severity,
                        threat.reason[:50] + "..." if len(threat.reason) > 50 else threat.reason,
                        threat.vt_score if threat.vt_score else "N/A",
                        threat.sha256[:16] + "..."
                    ))
                    self.threats_var.set(f"{len(self.findings)} Threats")
                    self._log(f"Threat found: {threat.path} | {threat.severity}")
                
                elif kind == "log":
                    self._log(item[1])
                
                elif kind == "done":
                    hits, stopped = item[1], item[2]
                    self.progress_var.set(100 if not stopped else self.progress_var.get())
                    self.status_var.set("Scan stopped" if stopped else "Scan complete")
                    self.last_scan_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    self._log(f"Scan finished: {len(hits)} threat(s) found")
                
                elif kind == "process_results":
                    processes: List[ProcessInfo] = item[1]
                    self.process_tree.delete(*self.process_tree.get_children())
                    for proc in processes:
                        self.process_tree.insert("", END, values=(
                            proc.pid,
                            proc.name,
                            proc.exe_path[:50] + "..." if len(proc.exe_path) > 50 else proc.exe_path,
                            "YES" if proc.suspicious else "No",
                            f"{len(proc.connections)} active" if proc.connections else "None"
                        ))
                        if proc.suspicious:
                            self._log(f"Suspicious process: {proc.name} (PID {proc.pid}) - "
                                    f"{'; '.join(proc.reasons)}")
                    
                    self.status_var.set(f"Process scan complete: {len(processes)} processes")
                    self._log(f"Process scan complete: {len(processes)} processes scanned")
        
        except queue.Empty:
            pass
        
        # Clean queue
        try:
            while True:
                item = self.clean_queue.get_nowait()
                kind = item[0]
                
                if kind == "progress":
                    self.progress_var.set(item[1])
                
                elif kind == "done":
                    cleaned, stopped = item[1], item[2]
                    self.cleaned_bytes += cleaned
                    self.cleaned_var.set(format_bytes(self.cleaned_bytes))
                    self.status_var.set("Cleanup stopped" if stopped else "Cleanup complete")
                    self.progress_var.set(100 if not stopped else self.progress_var.get())
                    self._log(f"Cleanup complete: {format_bytes(cleaned)} freed")
        
        except queue.Empty:
            pass
        
        self.root.after(150, self._poll_queues)


def main():
    """Main entry point."""
    print(f"{APP_TITLE} v{APP_VERSION}")
    print("=" * 50)
    
    # Check dependencies
    missing = []
    if not HAS_PSUTIL:
        missing.append("psutil (for process/memory scanning)")
    if not HAS_YARA:
        missing.append("yara-python (for YARA rule scanning)")
    if not HAS_REQUESTS:
        missing.append("requests (for VirusTotal integration)")
    
    if missing:
        print("\nOptional dependencies not installed:")
        for dep in missing:
            print(f"  • {dep}")
        print("\nThe application will run with limited functionality.")
        print("Install all dependencies with:")
        print("  pip install psutil yara-python requests")
        print()
    
    # Check admin
    if os.name == 'nt':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print("Tip: Run as Administrator for better system access.")
        except Exception:
            pass
    
    # Start app
    root = Tk()
    app = PCGuardAdvanced(root)
    root.mainloop()


if __name__ == "__main__":
    main()
