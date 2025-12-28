#!/bin/bash
echo "=== SailScan Flask Setup ==="

# Create virtual environment
echo "Creating virtual environment..."
python -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create directories
echo "Creating directories..."
mkdir -p uploads
mkdir -p app/static/{css,js}
mkdir -p app/templates

# Create .env file
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat > .env << 'EOF'
# Flask
SECRET_KEY=your-secret-key-change-this-in-production

# Database
DATABASE_URL=sqlite:///sailscan.db

# File Upload
UPLOAD_FOLDER=uploads

# VirusTotal (get from: https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Frida
FRIDA_ENABLED=true
EOF
    echo "✅ .env file created. Please edit it and add your VirusTotal API key."
fi

# Initialize database
echo "Initializing database..."
python -c "
from run import app
with app.app_context():
    from app import db
    db.create_all()
    print('Database tables created.')
"

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start SailScan:"
echo "  source venv/bin/activate"
echo "  python run.py"
echo ""
echo "Then open: http://localhost:5000"