# PC Guard Pro Advanced v2.0

A comprehensive, multi-engine antivirus and security suite built with Python featuring:

## 🚀 Features

### Core Detection Engines
- **Signature-Based Detection** - SHA256 hashing and known malware signatures
- **VirusTotal Integration** - Cloud-based multi-engine scanning (70+ AV engines)
- **YARA Rules** - Pattern matching for advanced malware detection
- **Behavioral Analysis** - Heuristic detection of suspicious file behaviors
- **Process Scanner** - Real-time monitoring of running processes
- **Memory Scanner** - Detection of fileless malware
- **Registry Monitoring** - Windows registry persistence detection

### Advanced Capabilities
- Multi-threaded scanning for performance
- Threat intelligence database (SQLite)
- Quarantine management
- System cleanup (temp/cache files)
- Comprehensive threat reports (JSON/TXT export)
- Network connection monitoring
- Suspicious process detection

## 📋 Requirements

### Core Requirements (Minimal)
```
Python 3.8+
tkinter (usually included with Python)
```

### Recommended Requirements (Full Features)
```bash
pip install -r requirements.txt
```

**Dependencies:**
- `psutil` - Process and memory scanning
- `yara-python` - YARA rule-based detection
- `requests` - VirusTotal API integration

## 🔧 Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd pc-guard-pro
```

### 2. Install Dependencies
```bash
# Install all features
pip install psutil yara-python requests

# Or install from requirements file
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python pc_guard_pro_advanced.py
```

**For Best Results (Windows):**
```bash
# Run as Administrator for full system access
Right-click → Run as Administrator
```

## 🎯 Quick Start Guide

### First Launch
1. The application will automatically create basic YARA rules in `~/.pcguard/yara_rules/`
2. Go to **Settings** tab to configure:
   - VirusTotal API key (get free key from https://www.virustotal.com/)
   - Enable/disable detection engines
   - Configure real-time protection

### Basic Usage

#### Quick Scan
- Scans common locations: Downloads, Desktop, Documents, Startup folders
- Recommended: Run daily
- Click **Quick Scan** button

#### Full Scan
- Scans entire selected directory recursively
- Recommended: Run weekly
- Click **Full Scan Folder** → Select directory

#### Process Scan
- Monitors all running processes
- Detects suspicious behaviors and network connections
- Click **Process Scan** or **Memory Scan**

#### System Cleanup
- Removes temporary files, caches, browser data
- Frees disk space
- Click **Clean System**

## 🛡️ Detection Methods

### 1. Signature-Based Detection
- Checks filenames against known malware patterns
- Analyzes file extensions and attributes
- Uses SHA256 hashing for file identification

### 2. VirusTotal Integration
**Setup:**
1. Get free API key from https://www.virustotal.com/gui/join-us
2. Go to Settings tab
3. Enter API key and click "Set API Key"

**Features:**
- Queries 70+ antivirus engines
- Provides detection scores
- Rate limited: 4 requests/minute (free tier)
- Results cached to avoid duplicate lookups

### 3. YARA Rules
**Built-in Rules Detect:**
- Cryptocurrency miners
- Remote Access Tools (RATs)
- Keyloggers
- Credential stealers
- Ransomware indicators
- Obfuscated code

**Custom Rules:**
- Add your own `.yar` or `.yara` files to `~/.pcguard/yara_rules/`
- Rules automatically loaded on startup
- See YARA documentation: https://yara.readthedocs.io/

### 4. Behavioral Analysis
**Detects:**
- Hidden files/attributes
- Double file extensions
- Suspicious file sizes
- Embedded scripts in executables
- Base64 encoding
- Embedded URLs
- Mixed case extensions (evasion technique)

### 5. Process Monitoring
**Monitors:**
- Running processes and their executables
- Command-line arguments
- Network connections
- Suspicious process names
- Script interpreters with dangerous arguments

## 📊 Dashboard Overview

### Tabs

**Dashboard**
- Protection status overview
- Threat statistics
- Detection engine status
- Recommendations

**Threats**
- Detected threats list
- Severity levels (Low, Medium, High, Critical)
- Export, quarantine, or delete options
- VirusTotal scores

**Processes**
- Running processes analysis
- Network connections
- Suspicious process indicators
- Process termination

**Settings**
- VirusTotal API configuration
- YARA enable/disable
- Real-time protection toggle
- Feature availability

**Cleaner**
- Cleanup target locations
- Temp file removal
- Cache cleanup
- Disk space recovery

**Logs**
- Real-time activity log
- Scan results
- Detection events
- System messages

## 🎨 Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| **Critical** | Red | Confirmed malware, immediate action required |
| **High** | Orange | Highly suspicious, likely malicious |
| **Medium** | Yellow | Suspicious activity, investigate further |
| **Low** | Blue | Potentially unwanted, minor concern |

## 🔒 Threat Management

### Quarantine
- Moves threats to safe location: `~/.pcguard/quarantine/`
- Files renamed with timestamp
- Can be restored manually if needed

### Delete
- Permanently removes files
- **WARNING:** This action cannot be undone!
- Use quarantine first for uncertain threats

### Export Reports
- **JSON Format** - Machine-readable, includes all metadata
- **TXT Format** - Human-readable summary
- Includes: paths, severities, detection methods, hashes, YARA rules, VT scores

## 🔍 Understanding Detection Results

### VirusTotal Score
```
Format: X/Y engines detected
X = Number of engines that flagged the file
Y = Total engines that scanned
```

**Interpretation:**
- 0/70: Likely clean
- 1-5/70: Possibly PUP (Potentially Unwanted Program)
- 5-15/70: Suspicious
- 15+/70: Likely malware

### YARA Rules Matched
- Shows which rule patterns matched
- Multiple rules = higher confidence
- Check rule descriptions for details

### Detection Methods
Shows which engines flagged the file:
- **Signature** - Filename/extension match
- **Behavioral** - Suspicious file characteristics
- **YARA** - Pattern matching
- **VirusTotal** - Cloud intelligence

## ⚙️ Advanced Configuration

### Custom YARA Rules

Create custom rules in `~/.pcguard/yara_rules/custom.yar`:

```yara
rule My_Custom_Malware {
    meta:
        description = "Detects specific malware variant"
        severity = "high"
        author = "Your Name"
    
    strings:
        $string1 = "malicious_pattern" ascii wide
        $hex1 = { 4D 5A 90 00 }  // PE header
        $regex1 = /https?:\/\/evil\.com\/[a-z]{8}/
    
    condition:
        $hex1 and ($string1 or $regex1)
}
```

### Database Location
```
~/.pcguard/threats.db (SQLite)
```

Query directly for advanced analytics:
```bash
sqlite3 ~/.pcguard/threats.db
SELECT * FROM threats WHERE severity='critical';
```

### Performance Tuning

**For Faster Scans:**
- Disable VirusTotal (offline mode)
- Limit file size: Edit `MAX_FILE_SIZE_MB` in code
- Exclude large directories

**For Maximum Detection:**
- Enable all detection engines
- Lower scan speed by adding more YARA rules
- Use VT uploads for unknown files

## 🐛 Troubleshooting

### "VirusTotal integration disabled"
```bash
pip install requests
# Then set API key in Settings tab
```

### "YARA scanning disabled"
```bash
pip install yara-python
```

### "Process scanning disabled"
```bash
pip install psutil
```

### "Permission Denied" errors
- Run as Administrator (Windows) or sudo (Linux)
- Some system files cannot be scanned without elevation

### High False Positives
- Tune YARA rules
- Whitelist known safe applications
- Adjust detection thresholds

### API Rate Limit (VirusTotal)
- Free tier: 4 requests/minute
- Upgrade to paid tier for higher limits
- Results are cached to minimize requests

## 📚 Resources

**VirusTotal**
- API Docs: https://developers.virustotal.com/
- Get API Key: https://www.virustotal.com/gui/join-us

**YARA**
- Documentation: https://yara.readthedocs.io/
- Rule Repository: https://github.com/Yara-Rules/rules
- Writing Rules: https://yara.readthedocs.io/en/stable/writingrules.html

**Community Rules**
- VirusTotal YARA: https://github.com/VirusTotal/yara
- Awesome YARA: https://github.com/InQuest/awesome-yara
- Malware Bazaar: https://bazaar.abuse.ch/

## ⚠️ Important Notes

### Limitations
1. **Not a replacement for professional AV** - This is an educational/supplementary tool
2. **No real-time file system monitoring** - Scans are manual or scheduled
3. **No kernel-level protection** - Runs in userspace
4. **Free VirusTotal limits** - 4 requests/minute
5. **Signature-based only** - No advanced AI/ML detection

### False Positives
- Legitimate software may trigger heuristics
- Always verify before deleting
- Use quarantine for uncertain threats
- Check VirusTotal community comments

### Legal & Ethical Use
- For personal/educational use only
- Respect software licenses
- Don't use to bypass security of systems you don't own
- Follow VirusTotal Terms of Service

## 🔄 Updates & Maintenance

### Update YARA Rules
```bash
# Download community rules
git clone https://github.com/Yara-Rules/rules.git
cp rules/**/*.yar ~/.pcguard/yara_rules/
```

### Clear Database
```bash
rm ~/.pcguard/threats.db
# Will rebuild on next launch
```

### Backup Quarantine
```bash
cp -r ~/.pcguard/quarantine ~/quarantine_backup
```

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional YARA rules
- Better heuristics
- UI enhancements
- Performance optimizations
- Additional integrations (Hybrid Analysis, etc.)

## 📜 License

Educational/Research purposes. Use at your own risk.

## 🆘 Support

For issues, questions, or contributions:
1. Check troubleshooting section
2. Review logs tab for error messages
3. Ensure all dependencies installed
4. Run with elevated privileges if needed

---

**Remember:** This tool supplements but does not replace comprehensive security practices:
- Keep OS and software updated
- Use strong passwords
- Enable firewall
- Regular backups
- Practice safe browsing
- Be cautious with email attachments

**Stay Safe! 🛡️**
