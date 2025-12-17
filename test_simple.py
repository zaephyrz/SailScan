import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Testing minimal setup...")

# Test 1: Can we import config?
try:
    from app.config import settings
    print("✓ Config imported")
    print(f"  Database URL: {settings.DATABASE_URL}")
except Exception as e:
    print(f"✗ Config failed: {e}")

# Test 2: Can we create FastAPI app?
try:
    from fastapi import FastAPI
    app = FastAPI()
    print("✓ FastAPI works")
except Exception as e:
    print(f"✗ FastAPI failed: {e}")

# Test 3: Test database
try:
    from app.database import engine
    print("✓ Database engine created")
except Exception as e:
    print(f"Note: Database not available: {e}")

print("\nTo run: uvicorn app.main:app --reload")