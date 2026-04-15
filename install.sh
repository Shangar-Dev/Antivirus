#!/bin/bash
# PC Guard Pro Advanced - Installation Script
# This script sets up PC Guard Pro with all dependencies

echo "=================================================="
echo "  PC Guard Pro Advanced v2.0 - Installation"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Python 3 is not installed!${NC}"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

echo -e "${GREEN}✓ Python $python_version found${NC}"
echo ""

# Check if pip is installed
echo "Checking pip..."
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 is not installed!${NC}"
    echo "Please install pip3"
    exit 1
fi

echo -e "${GREEN}✓ pip3 is available${NC}"
echo ""

# Create directory structure
echo "Creating directory structure..."
mkdir -p ~/.pcguard/yara_rules
mkdir -p ~/.pcguard/quarantine
mkdir -p ~/.pcguard/logs

echo -e "${GREEN}✓ Directories created${NC}"
echo ""

# Install Python dependencies
echo "Installing Python dependencies..."
echo "This may take a few minutes..."
echo ""

# Install each package separately to show progress
packages=("psutil" "yara-python" "requests")
failed_packages=()

for package in "${packages[@]}"; do
    echo "Installing $package..."
    if pip3 install --user "$package" --break-system-packages 2>/dev/null || pip3 install --user "$package" 2>/dev/null; then
        echo -e "${GREEN}✓ $package installed successfully${NC}"
    else
        echo -e "${YELLOW}⚠ $package installation failed (optional)${NC}"
        failed_packages+=("$package")
    fi
    echo ""
done

# Copy YARA rules if they exist
if [ -f "advanced_malware_rules.yar" ]; then
    echo "Installing YARA rules..."
    cp advanced_malware_rules.yar ~/.pcguard/yara_rules/
    echo -e "${GREEN}✓ YARA rules installed${NC}"
    echo ""
fi

# Summary
echo "=================================================="
echo "  Installation Summary"
echo "=================================================="
echo ""

if [ ${#failed_packages[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ All dependencies installed successfully!${NC}"
else
    echo -e "${YELLOW}⚠ Some optional dependencies failed to install:${NC}"
    for pkg in "${failed_packages[@]}"; do
        echo "  - $pkg"
    done
    echo ""
    echo "The application will run with limited functionality."
    echo "You can install missing packages manually:"
    echo "  pip3 install ${failed_packages[@]}"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Directory structure:"
echo "  ~/.pcguard/yara_rules/    - YARA detection rules"
echo "  ~/.pcguard/quarantine/    - Quarantined threats"
echo "  ~/.pcguard/threats.db     - Threat database"
echo ""
echo "To run PC Guard Pro:"
echo "  python3 pc_guard_pro_advanced.py"
echo ""
echo "For best results on Windows:"
echo "  - Run as Administrator"
echo ""
echo "Next steps:"
echo "  1. Get a free VirusTotal API key from:"
echo "     https://www.virustotal.com/gui/join-us"
echo "  2. Configure the API key in Settings tab"
echo "  3. Run a Quick Scan to test"
echo ""
echo "=================================================="
echo "  Ready to protect your system!"
echo "=================================================="
