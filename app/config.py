import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """
    Configuration settings for SailScan Security Scanner
    """
    
    # ====================
    # Flask Configuration
    # ====================
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # ====================
    # Database Configuration
    # ====================
    # Use SQLite for development, PostgreSQL for production
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///sailscan.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # ====================
    # File Upload Settings
    # ====================
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_MB', 100)) * 1024 * 1024  # Convert MB to bytes
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'exe', 'dll', 'apk', 'ipa', 
        'pdf', 'doc', 'docx', 'xls', 'xlsx',
        'js', 'vbs', 'ps1', 'bat', 'cmd',
        'py', 'jar', 'class', 'so', 'dylib',
        'bin', 'elf', 'msi', 'scr', 'com',
        'zip', 'rar', '7z', 'tar', 'gz'
    }
    
    # ====================
    # VirusTotal API
    # ====================
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3'
    VIRUSTOTAL_TIMEOUT = 30  # seconds
    
    # ====================
    # Frida Configuration
    # ====================
    FRIDA_ENABLED = os.getenv('FRIDA_ENABLED', 'false').lower() == 'true'
    
    # ====================
    # Application Settings
    # ====================
    APP_NAME = "SailScan Security Platform"
    APP_VERSION = "2.0.0"
    APP_DESCRIPTION = "Multi-engine security scanner with VirusTotal integration"
    
    # ====================
    # Security Settings
    # ====================
    # Set to True in production with HTTPS
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # ====================
    # Performance Settings
    # ====================
    # Number of threads for background tasks
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 4))
    
    # ====================
    # Logging Configuration
    # ====================
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'sailscan.log')
    
    # ====================
    # Development Settings
    # ====================
    DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    TESTING = os.getenv('FLASK_TESTING', 'false').lower() == 'true'
    

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_ECHO = True  # Log SQL queries


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    
    # Production database (example for PostgreSQL)
    # SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    
    # Production upload folder
    UPLOAD_FOLDER = '/var/www/sailscan/uploads'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': Config
}


def get_allowed_extensions():
    """Get allowed extensions as a set"""
    return Config.ALLOWED_EXTENSIONS


def is_extension_allowed(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in get_allowed_extensions()


def get_upload_folder():
    """Get upload folder path, create if doesn't exist"""
    folder = Config.UPLOAD_FOLDER
    os.makedirs(folder, exist_ok=True)
    return folder


def get_virustotal_status():
    """Check if VirusTotal is configured"""
    return bool(Config.VIRUSTOTAL_API_KEY and Config.VIRUSTOTAL_API_KEY.strip())


def get_app_info():
    """Get application information"""
    return {
        'name': Config.APP_NAME,
        'version': Config.APP_VERSION,
        'description': Config.APP_DESCRIPTION,
        'virustotal_configured': get_virustotal_status(),
        'frida_enabled': Config.FRIDA_ENABLED,
        'max_file_size': Config.MAX_CONTENT_LENGTH,
        'allowed_extensions': list(Config.ALLOWED_EXTENSIONS)
    }