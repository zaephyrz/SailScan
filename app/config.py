import os

class Settings:
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./security.db")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
    
    # Application
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"
    APP_NAME: str = "Security Platform"
    APP_VERSION: str = "1.0.0"

settings = Settings()