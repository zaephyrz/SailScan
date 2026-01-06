#!/usr/bin/env python3
"""
SailScan - Full Security Scanner
Run: python sailscan.py
"""
import os
import sys
from app import create_app, db

app = create_app()

@app.cli.command("init-db")
def init_db():
    """Initialize database"""
    with app.app_context():
        db.create_all()
        print("✅ Database initialized!")
        print("📁 Uploads directory created")
        os.makedirs('uploads', exist_ok=True)

if __name__ == '__main__':
    # Create uploads directory
    if not os.path.exists('uploads'):
        os.makedirs('uploads', exist_ok=True)
    
    print(f"""
    🚀 SailScan Security Scanner
    ================================
    🌐 Running at: http://localhost:5000
    📊 Dashboard: http://localhost:5000/
    
    Press Ctrl+C to stop
    """)
    
    app.run(host='0.0.0.0', port=5000, debug=True)