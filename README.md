# SailScan 🏴‍☠️

A multi-engine security scanner built with Flask for analyzing files, detecting threats, and reverse engineering.

![SailScan Dashboard](screenshot.png)

## ✨ Features

- **🛡️ VirusTotal Integration**: 60+ antivirus engines
- **🔧 Static Analysis**: File structure, hashes, signatures
- **📱 Mobile Analysis**: APK/IPA support, Flutter detection
- **⚡ Frida Integration**: Dynamic instrumentation (optional)
- **🌐 Web Dashboard**: Clean, modern interface
- **📊 REST API**: Full API for automation
- **💾 Database**: Scan history and results storage

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

```bash
# 1. Clone repository
git clone https://github.com/zaephyrz/SailScan.git
cd SailScan

# 2. Run install dependencies script
chmod +x install_dependencies.sh
./install_dependencies.sh

# 3. Edit .env file (add your VirusTotal API key)
nano .env

# 4. Start the application
python sailscan.py
```

## 🖥️ GTK Desktop Application

For users who prefer a native desktop experience, SailScan includes a GTK desktop application built for Linux systems.

![SailScan GTK](screenshot-2.png)

### Installation & Launch

```bash
# Install GTK dependencies
rpm-ostree install python3-gobject gtk4-devel libadwaita-devel

# Run the GTK app directly
python SailScan-GTK.py

# Or install desktop entry
cp sailscan.desktop ~/.local/share/applications/
# Then launch from your application menu
```