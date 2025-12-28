from app import create_app, db
from app.models import Scan
import os

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Scan': Scan}

if __name__ == '__main__':
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    print("=" * 60)
    print(f"🚀 {app.config['APP_NAME']} v{app.config['APP_VERSION']}")
    print("=" * 60)
    print(f"📁 Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"💾 Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"🛡️  VirusTotal: {'✅ Enabled' if app.config['VIRUSTOTAL_API_KEY'] else '❌ Not configured'}")
    print(f"🔧 Frida: {'✅ Enabled' if app.config['FRIDA_ENABLED'] else '❌ Disabled'}")
    print("=" * 60)
    print("🌐 Web dashboard: http://localhost:5000")
    print("📚 API Base: http://localhost:5000/api")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)