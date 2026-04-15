# PC Guard Pro Advanced - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies

**Windows:**
```batch
# Double-click install.bat
# Or run in Command Prompt:
install.bat
```

**Linux/Mac:**
```bash
chmod +x install.sh
./install.sh
```

**Manual Installation:**
```bash
pip install psutil yara-python requests
```

### Step 2: Run the Application

**Windows:**
```batch
python pc_guard_pro_advanced.py
# Or for Admin privileges:
Right-click → Run as Administrator
```

**Linux:**
```bash
python3 pc_guard_pro_advanced.py
# Or with sudo:
sudo python3 pc_guard_pro_advanced.py
```

### Step 3: Configure VirusTotal (Optional but Recommended)

1. Go to https://www.virustotal.com/gui/join-us
2. Sign up for a free account
3. Get your API key from: https://www.virustotal.com/gui/my-apikey
4. In PC Guard Pro:
   - Click **Settings** tab
   - Paste your API key
   - Click **Set API Key**

### Step 4: Run Your First Scan

**Quick Scan (Recommended for beginners):**
1. Click **Quick Scan** button
2. Wait for scan to complete (usually 1-5 minutes)
3. Review threats in **Threats** tab

**Full Scan:**
1. Click **Full Scan Folder**
2. Select a directory (Downloads, USB drive, etc.)
3. Review results

## 📊 Understanding Results

### Threat Severity

| Color | Level | Action |
|-------|-------|--------|
| 🔴 Red | Critical | Delete or quarantine immediately |
| 🟠 Orange | High | Very suspicious, investigate |
| 🟡 Yellow | Medium | Review and decide |
| 🔵 Blue | Low | Possibly safe, false positive |

### VirusTotal Scores

```
Format: X/Y engines
Example: 15/72 means 15 out of 72 antivirus engines flagged it

0-2/72  : Likely clean or false positive
3-10/72 : Suspicious, investigate
10-30/72: Probably malicious
30+/72  : Definitely malicious
```

## 🛡️ Common Tasks

### Scan a USB Drive

1. Insert USB drive
2. Click **Full Scan Folder**
3. Navigate to USB drive (E:\, F:\, etc.)
4. Click **Select Folder**
5. Wait for scan

### Check Running Processes

1. Click **Process Scan** button
2. Review processes in **Processes** tab
3. Look for "YES" in Suspicious column
4. Right-click suspicious process → Kill if needed

### Clean System

1. Click **Clean System** button
2. Wait for cleanup (2-10 minutes)
3. Check space freed in status card

### Quarantine a Threat

1. Go to **Threats** tab
2. Select threat(s)
3. Click **Quarantine Selected**
4. Files moved to `~/.pcguard/quarantine/`

### Delete a Threat

1. Go to **Threats** tab
2. Select threat(s)
3. Click **Delete Selected**
4. Confirm deletion
5. **Warning:** Cannot be undone!

## ⚡ Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Quick Scan | (Button only) |
| Stop Scan | ESC or Stop button |
| Refresh Processes | F5 (in Processes tab) |
| Export Report | Ctrl+E (in Threats tab) |

## 🔧 Troubleshooting

### "No threats found" but I know there's malware

**Solutions:**
1. Enable VirusTotal in Settings
2. Add custom YARA rules
3. Update YARA rules from community
4. Check if file extension is scanned (see SCAN_EXTENSIONS)

### High false positives

**Solutions:**
1. Review YARA rules in `~/.pcguard/yara_rules/`
2. Comment out overly aggressive rules
3. Whitelist known safe applications
4. Check VirusTotal community comments

### Slow scanning

**Solutions:**
1. Disable VirusTotal (rate limited)
2. Reduce YARA rules
3. Exclude large directories
4. Use Quick Scan instead of Full Scan

### "Permission Denied" errors

**Solutions:**
1. Run as Administrator (Windows) or sudo (Linux)
2. Some system files cannot be scanned
3. Check file/folder permissions

### Missing dependencies

**Error:** "psutil not installed"
```bash
pip install psutil
```

**Error:** "yara-python not installed"
```bash
pip install yara-python
# On Windows, may need Visual C++ Build Tools
```

**Error:** "requests not installed"
```bash
pip install requests
```

## 📁 File Locations

### Configuration & Data
```
~/.pcguard/                    # Main directory
~/.pcguard/yara_rules/         # YARA detection rules
~/.pcguard/quarantine/         # Quarantined files
~/.pcguard/threats.db          # SQLite database
~/.pcguard/logs/               # Log files
```

### Add Custom YARA Rules
```
1. Create .yar or .yara file
2. Place in ~/.pcguard/yara_rules/
3. Restart application
```

## 🎯 Best Practices

### Daily
- Run Quick Scan
- Check process monitor
- Review new threats

### Weekly
- Full scan of Downloads folder
- Clean system temp files
- Export threat reports for records

### Monthly
- Full system scan
- Update YARA rules
- Review quarantine folder
- Backup threat database

## 🆘 Getting Help

### Check Logs
1. Go to **Logs** tab
2. Look for error messages
3. Note timestamps of issues

### Common Error Messages

**"API rate limit exceeded"**
- VirusTotal free tier: 4 requests/minute
- Wait 15 minutes or upgrade to paid tier

**"Failed to compile YARA rules"**
- Syntax error in custom rules
- Check rule file syntax
- Remove or fix problematic rule

**"Database locked"**
- Another instance running
- Close duplicate instances
- Delete threats.db and restart

## 💡 Pro Tips

1. **Run as Admin** - Get full system access
2. **Enable All Engines** - Best detection rate
3. **Export Reports** - Keep records of scans
4. **Update Rules** - Download community YARA rules monthly
5. **Quarantine First** - Safer than immediate deletion
6. **Check VT Comments** - See what others say about detections
7. **Scan New Downloads** - Right after downloading files
8. **Monitor Processes** - Run process scan during suspicious activity

## 🔐 Security Checklist

Before considering your system clean:

- [ ] Run Full Scan on all drives
- [ ] Check running processes
- [ ] Review startup items (Windows: msconfig)
- [ ] Check browser extensions
- [ ] Review installed programs
- [ ] Scan with another AV tool for confirmation
- [ ] Change important passwords if infected
- [ ] Enable Windows Defender / native AV

## 📚 Learn More

- **YARA Documentation**: https://yara.readthedocs.io/
- **VirusTotal API**: https://developers.virustotal.com/
- **Malware Analysis**: https://www.malware-traffic-analysis.net/
- **YARA Rules Repository**: https://github.com/Yara-Rules/rules

## 🎓 Next Steps

### Beginner
1. Run Quick Scan daily
2. Learn to interpret results
3. Practice with quarantine/delete

### Intermediate
1. Configure VirusTotal
2. Understand YARA rules
3. Create custom detection rules
4. Schedule regular scans

### Advanced
1. Write custom YARA rules
2. Integrate with other tools
3. Automate scanning workflows
4. Contribute rules to community

---

**Need more help?** Check the full README_PCGUARD.md for detailed documentation.

**Happy threat hunting! 🛡️**
