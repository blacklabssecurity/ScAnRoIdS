#!/bin/bash

# Exit on any error
set -e

# Create the directory structure to support the tool
mkdir -vp /tools/scripts/.ScAnRoIdS/templates/

# Get into proper directory location
cd /tools/scripts/ScAnDrOiDs/

echo "[*] Updating package list and installing system dependencies..."
sudo apt update

# python3-venv is required to create virtual environments on Debian-based systems
sudo apt install -y python3-venv python3-full nmap gowitness exploitdb exploitdb-bin-sploits

# Update SearchSploit and check Gowitness path
sudo searchsploit -u
if ! command -v gowitness &> /dev/null; then
    echo "[!] Warning: gowitness not found in PATH. Ensure /usr/bin or ~/go/bin is set."
fi

# Define the virtual environment directory
VENV_DIR=".venv"


if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment in $VENV_DIR..."
    python3 -m venv $VENV_DIR
else
    echo "[!] Virtual environment already exists."
fi

echo "[*] Activating virtual environment and installing pip packages..."

# Use the direct path to pip inside the venv to ensure isolation
$VENV_DIR/bin/pip install --upgrade pip
# Added 'requests' and 'beautifulsoup4' if we do more web-scraping later
$VENV_DIR/bin/pip install python-nmap flask flask-login lxml requests

echo "------------------------------------------------"
echo "[+] Setup Complete!"
echo "[*] To start your project, run:"
echo "    source $VENV_DIR/bin/activate"
echo "    sudo $PWD/$VENV_DIR/bin/python ScAnRoIdS.py"
echo 
echo "    Exit the venv with: deactivate"
echo "------------------------------------------------"
