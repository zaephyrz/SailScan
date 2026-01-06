#!/usr/bin/env python3
"""
SailScan - Main application entry point for Render.com
"""
import os
import sys
from app import create_app, db

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = create_app()

@app.cli.command("create-db")
def create_db():
    """Create database tables"""
    print("🔧 Creating database tables...")
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Create uploads directory
            uploads_dir = app.config.get('UPLOAD_FOLDER', 'uploads')
            if not os.path.exists(uploads_dir):
                os.makedirs(uploads_dir, exist_ok=True)
                print(f"✅ Created uploads directory: {uploads_dir}")
                
        except Exception as e:
            print(f"❌ Error creating database: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    # Get port from environment variable (Render sets this)
    port = int(os.environ.get('PORT', 5000))
    
    print(f"""
    🚀 SailScan Security Scanner
    ================================
    📍 Host: 0.0.0.0
    🚪 Port: {port}
    🔧 Debug: False
    
    🌐 Starting server...
    """)
    
    app.run(host='0.0.0.0', port=port, debug=False)