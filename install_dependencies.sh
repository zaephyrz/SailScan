#!/bin/bash
# Complete dependency installation for SailScan

echo "Installing SailScan dependencies..."

# Python dependencies
pip install -r requirements.txt

# Frida installation
echo "Installing Frida for dynamic analysis..."
pip install frida==16.0.0 frida-tools==12.0.0

# For Android Frida setup
echo ""
echo "For Android Frida support:"
echo "1. Root your Android device"
echo "2. Enable USB debugging"
echo "3. Download frida-server from: https://github.com/frida/frida/releases"
echo "4. Push to device: adb push frida-server /data/local/tmp/"
echo "5. Set permissions: adb shell chmod 755 /data/local/tmp/frida-server"
echo "6. Run: adb shell /data/local/tmp/frida-server &"

# Initialize database
flask db upgrade

echo ""
echo "Setup complete! Configure VIRUSTOTAL_API_KEY in .env file"