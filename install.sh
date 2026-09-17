#!/bin/bash

# ============================================================
# ReverseIP Installer
# Created by: cyb3rconqu3ror
#
# Installs ReverseIP globally on Kali Linux.
#
# Usage:
#   chmod +x install.sh
#   sudo ./install.sh
#
# After installation:
#   reverseip
#   reverseip example.com
#   reverseip 8.8.8.8
# ============================================================

set -e

APP_NAME="reverseip"
INSTALL_DIR="/opt/reverseip"
BIN_PATH="/usr/local/bin/reverseip"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo
echo "=============================================="
echo "        ReverseIP Global Installer"
echo "        Created by: cyb3rconqu3ror"
echo "=============================================="
echo

# ------------------------------------------------------------
# Root check
# ------------------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run the installer with sudo:"
    echo
    echo "    sudo ./install.sh"
    echo
    exit 1
fi

# ------------------------------------------------------------
# Check required files
# ------------------------------------------------------------

if [ ! -f "$SCRIPT_DIR/reverseip.py" ]; then
    echo "[!] reverseip.py not found."
    echo "[!] Keep install.sh, reverseip.py and requirements.txt"
    echo "    in the same directory."
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "[!] requirements.txt not found."
    echo "[!] Keep install.sh, reverseip.py and requirements.txt"
    echo "    in the same directory."
    exit 1
fi

# ------------------------------------------------------------
# Check Python
# ------------------------------------------------------------

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 is not installed."
    echo "[*] Installing Python..."

    apt-get update
    apt-get install -y python3 python3-pip python3-venv
fi

# ------------------------------------------------------------
# Make sure venv support exists
# ------------------------------------------------------------

if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "[*] Installing python3-venv..."
    apt-get update
    apt-get install -y python3-venv
fi

# ------------------------------------------------------------
# Create installation directory
# ------------------------------------------------------------

echo "[*] Creating installation directory:"
echo "    $INSTALL_DIR"

mkdir -p "$INSTALL_DIR"

# ------------------------------------------------------------
# Copy application files
# ------------------------------------------------------------

echo "[*] Installing ReverseIP..."

cp "$SCRIPT_DIR/reverseip.py" "$INSTALL_DIR/reverseip.py"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"

chmod 755 "$INSTALL_DIR/reverseip.py"

# ------------------------------------------------------------
# Create virtual environment
# ------------------------------------------------------------

VENV_DIR="$INSTALL_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

PYTHON="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"

# ------------------------------------------------------------
# Upgrade pip
# ------------------------------------------------------------

echo "[*] Updating pip..."

"$PYTHON" -m pip install --upgrade pip

# ------------------------------------------------------------
# Install requirements
# ------------------------------------------------------------

echo "[*] Installing Python requirements..."

"$PIP" install -r "$INSTALL_DIR/requirements.txt"

# ------------------------------------------------------------
# Create global launcher
# ------------------------------------------------------------

echo "[*] Creating global command..."

cat > "$BIN_PATH" <<EOF
#!/bin/bash
exec "$PYTHON" "$INSTALL_DIR/reverseip.py" "\$@"
EOF

chmod 755 "$BIN_PATH"

# ------------------------------------------------------------
# Verify installation
# ------------------------------------------------------------

echo
echo "[*] Verifying installation..."

if command -v reverseip >/dev/null 2>&1; then
    echo
    echo "=============================================="
    echo "        ReverseIP Installation Complete"
    echo "=============================================="
    echo
    echo "[+] Command installed:"
    echo "    reverseip"
    echo
    echo "[+] Installation directory:"
    echo "    $INSTALL_DIR"
    echo
    echo "[+] Python environment:"
    echo "    $VENV_DIR"
    echo
    echo "[+] Try:"
    echo "    reverseip"
    echo
    echo "    reverseip example.com"
    echo
    echo "    reverseip 8.8.8.8"
    echo
    echo "    reverseip --help"
    echo
else
    echo "[!] Installation finished, but 'reverseip' was not found in PATH."
    echo "[!] Check that /usr/local/bin is in your PATH."
    exit 1
fi
