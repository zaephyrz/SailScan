#!/usr/bin/env python3
"""
SailScan - Multi-engine Security Scanner
Entry point for Flask application
"""
import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from flask_migrate import Migrate

# Create application instance
app = create_app()
migrate = Migrate(app, db)

@app.cli.command("init-db")
def init_db_command():
    """Initialize the database"""
    with app.app_context():
        db.create_all()
    print("✅ Database initialized!")

@app.cli.command("seed")
def seed_command():
    """Add sample data to database"""
    from app.models import Scan
    from datetime import datetime, timedelta
    
    with app.app_context():
        # Add a sample scan for testing
        sample_scan = Scan(
            filename="sample.exe",
            original_filename="sample.exe",
            file_hash_sha256="a" * 64,
            file_hash_md5="b" * 32,
            file_size=1024,
            status="completed",
            is_malicious=False,
            threat_score=10,
            created_at=datetime.utcnow() - timedelta(hours=1)
        )
        db.session.add(sample_scan)
        db.session.commit()
    
    print("✅ Database seeded with sample data!")

if __name__ == '__main__':
    # Run the application
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    print(f"""
    ⚓ SailScan Security Scanner
    ================================
    🚀 Starting server...
    📍 Host: {host}
    🚪 Port: {port}
    🔧 Debug: {debug}
    
    🌐 Access: http://localhost:{port}
    📊 Dashboard: http://localhost:{port}/
    🔌 API Status: http://localhost:{port}/api/virustotal/status
    
    Press Ctrl+C to stop
    """)
    
    app.run(host=host, port=port, debug=debug)