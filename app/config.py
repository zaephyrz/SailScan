import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///sailscan.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File Upload
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = {
        'exe', 'dll', 'apk', 'ipa', 
        'pdf', 'doc', 'docx', 'js',
        'py', 'jar', 'class', 'so',
        'bin', 'elf'
    }
    
    # VirusTotal
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    
    # Frida
    FRIDA_ENABLED = os.getenv('FRIDA_ENABLED', 'true').lower() == 'true'
    
    # App
    APP_NAME = "SailScan Security Platform"
    APP_VERSION = "1.0.0"