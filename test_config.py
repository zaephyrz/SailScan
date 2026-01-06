#!/usr/bin/env python3
"""
Test SailScan configuration
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import Config, get_virustotal_status, get_app_info

print("🔧 Testing SailScan Configuration")
print("=" * 40)

# Test basic config
print(f"App Name: {Config.APP_NAME}")
print(f"Version: {Config.APP_VERSION}")
print(f"Database URI: {Config.SQLALCHEMY_DATABASE_URI}")
print(f"Upload Folder: {Config.UPLOAD_FOLDER}")
print(f"Max File Size: {Config.MAX_CONTENT_LENGTH / 1024 / 1024} MB")

# Test VirusTotal
vt_status = get_virustotal_status()
print(f"VirusTotal Configured: {'✅ Yes' if vt_status else '❌ No'}")

if not vt_status:
    print("\n⚠️ WARNING: VirusTotal API key not found!")
    print("Get free API key from: https://virustotal.com/gui/join-us")
    print("Add to .env: VIRUSTOTAL_API_KEY=your_key_here")

# Test allowed extensions
print(f"\nAllowed Extensions ({len(Config.ALLOWED_EXTENSIONS)}):")
ext_groups = []
current_group = []
for i, ext in enumerate(sorted(Config.ALLOWED_EXTENSIONS)):
    current_group.append(ext)
    if len(current_group) == 5 or i == len(Config.ALLOWED_EXTENSIONS) - 1:
        ext_groups.append(current_group)
        current_group = []

for group in ext_groups:
    print("  " + ", ".join(group))

print("\n✅ Configuration test complete!")