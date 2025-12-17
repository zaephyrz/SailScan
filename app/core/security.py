import hashlib
from datetime import datetime, timedelta
from typing import Optional

# Simple password hashing without passlib
def get_password_hash(password: str) -> str:
    """Simple password hashing (use passlib in production)"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return get_password_hash(plain_password) == hashed_password

# Simple token generation without python-jose
def create_access_token(data: dict, secret_key: str, expires_minutes: int = 30) -> str:
    """Simple token creation (use JWT in production)"""
    import json
    import base64
    
    data_copy = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    data_copy.update({"exp": expire.isoformat()})
    
    # Simple base64 encoding (not secure for production!)
    token = base64.b64encode(json.dumps(data_copy).encode()).decode()
    return token

def create_default_admin():
    """Create default admin user if not exists"""
    try:
        from app.database import SessionLocal
        from app.models.user import User
        
        db = SessionLocal()
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@security.local",
                hashed_password=get_password_hash("admin123"),
                is_admin=True
            )
            db.add(admin)
            db.commit()
            print("Default admin user created")
        db.close()
    except Exception as e:
        print(f"Note: Could not create admin user: {e}")