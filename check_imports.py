#!/usr/bin/env python3
"""Check if all imports work and fix common issues"""

import sys
import os
import subprocess

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_import(import_statement, install_package=None):
    """Try to import a module and install if needed"""
    try:
        exec(import_statement)
        print(f"✓ {import_statement}")
        return True
    except ImportError as e:
        print(f"✗ {import_statement} - {e}")
        if install_package:
            print(f"  Installing {install_package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", install_package])
            # Try again after install
            try:
                exec(import_statement)
                print(f"  ✓ Now works after installing {install_package}")
                return True
            except ImportError:
                print(f"  ✗ Still failed after installation")
        return False

print("Checking imports...")
print("-" * 50)

# Check basic imports
check_import("import fastapi", "fastapi")
check_import("import uvicorn", "uvicorn[standard]")
check_import("import sqlalchemy", "sqlalchemy")
check_import("import pydantic", "pydantic")
check_import("import requests", "requests")

print("\nChecking app imports...")
print("-" * 50)

# Check app imports
try:
    from app.config import settings
    print("✓ app.config.settings")
except ImportError as e:
    print(f"✗ app.config.settings - {e}")

try:
    from app.database import get_db
    print("✓ app.database")
except ImportError as e:
    print(f"✗ app.database - {e}")

# Create minimal files if they don't exist
files_to_create = {
    "app/models/threat.py": """from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer)
    threat_type = Column(String(100))
    severity = Column(String(20))
    description = Column(Text)
""",
    
    "app/services/virus_total.py": """class AntivirusScanner:
    def __init__(self):
        pass
    
    def scan_file(self, file_path):
        return {"status": "mock_scan"}
""",
    
    "app/api/v1/api.py": """from fastapi import APIRouter
api_router = APIRouter()

@api_router.get("/test")
def test():
    return {"message": "API working"}
"""
}

for filepath, content in files_to_create.items():
    if not os.path.exists(filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(content)
        print(f"✓ Created {filepath}")

print("\n" + "=" * 50)
print("To run the app:")
print("1. uvicorn app.main:app --reload")
print("2. Open http://localhost:8000")
print("3. Test API: http://localhost:8000/api/v1/test")