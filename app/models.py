from datetime import datetime
from app import db

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255))
    file_hash_md5 = db.Column(db.String(32))
    file_hash_sha1 = db.Column(db.String(40))
    file_hash_sha256 = db.Column(db.String(64))
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    
    # Scan results
    virustotal_result = db.Column(db.JSON)
    static_analysis = db.Column(db.JSON)
    frida_analysis = db.Column(db.JSON)
    ghidra_analysis = db.Column(db.JSON)
    flutter_analysis = db.Column(db.JSON)
    
    # Threat indicators
    is_malicious = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Integer, default=0)
    detected_threats = db.Column(db.JSON)
    
    # Status
    status = db.Column(db.String(50), default='pending')  # pending, scanning, completed, failed
    error_message = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'hash_sha256': self.file_hash_sha256,
            'file_size': self.file_size,
            'status': self.status,
            'is_malicious': self.is_malicious,
            'threat_score': self.threat_score,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }