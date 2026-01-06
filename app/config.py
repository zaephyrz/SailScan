import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database - Render provides DATABASE_URL
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///sailscan.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File Upload - Use /tmp for Render
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp/uploads')
    ALLOWED_EXTENSIONS = {
        'exe', 'dll', 'apk', 'ipa', 
        'pdf', 'doc', 'docx', 'js',
        'py', 'jar', 'class', 'so',
        'bin', 'elf'
    }
    
    # VirusTotal
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    
    # Frida
    FRIDA_ENABLED = os.getenv('FRIDA_ENABLED', 'false').lower() == 'true'
    
    # App
    APP_NAME = "SailScan Security Platform"
    APP_VERSION = "1.0.0"
    
    # Production settings
    PREFERRED_URL_SCHEME = 'https'
    SERVER_NAME = None