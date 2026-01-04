"""Background task system for SailScan"""
import threading
import time
import os
from datetime import datetime
from app import db
from app.models import Scan
from app.services.scanner import SecurityScanner
from app.services.virustotal import VirusTotalService

def analyze_file_async(scan_id, filepath):
    """Analyze file in background thread"""
    thread = threading.Thread(target=_analyze_file_task, args=(scan_id, filepath))
    thread.daemon = True
    thread.start()
    return thread

def _analyze_file_task(scan_id, filepath):
    """Background task to analyze file"""
    try:
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        
        scan.status = 'scanning'
        scan.started_at = datetime.utcnow()
        db.session.commit()
        
        # Calculate hash if not already done
        import hashlib
        with open(filepath, 'rb') as f:
            file_content = f.read()
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            md5_hash = hashlib.md5(file_content).hexdigest()
            sha1_hash = hashlib.sha1(file_content).hexdigest()
        
        # Update scan with hashes if not set
        if not scan.file_hash_sha256:
            scan.file_hash_sha256 = sha256_hash
        if not scan.file_hash_md5:
            scan.file_hash_md5 = md5_hash
        if not scan.file_hash_sha1:
            scan.file_hash_sha1 = sha1_hash
        if not scan.file_size:
            scan.file_size = len(file_content)
        
        # Static analysis
        scanner = SecurityScanner()
        static_analysis = scanner.analyze_file(filepath)
        scan.static_analysis = static_analysis
        
        # VirusTotal analysis
        vt_service = VirusTotalService()
        if vt_service.is_available():
            vt_result = vt_service.get_report(sha256_hash)
            
            # If not found, upload the file
            if vt_result.get('status') == 'not_found':
                # Upload file to VirusTotal
                with open(filepath, 'rb') as f:
                    files = {'file': f}
                    upload_response = vt_service.session.post(
                        f'{vt_service.base_url}/files',
                        files=files,
                        timeout=60
                    )
                
                if upload_response.status_code == 200:
                    vt_result = {
                        'status': 'uploaded',
                        'message': 'File uploaded to VirusTotal. Report available in 30-60 seconds.',
                        'malicious': 0,
                        'total_engines': 0
                    }
            
            scan.virustotal_result = vt_result
            
            # Check if malicious
            if vt_result and 'malicious' in vt_result:
                malicious_count = vt_result.get('malicious', 0)
                if malicious_count > 0:
                    scan.is_malicious = True
                    scan.threat_score = min(malicious_count * 10, 100)
                    scan.detected_threats = vt_result.get('popular_threat_names', [])
        
        scan.status = 'completed'
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        
    except Exception as e:
        scan = Scan.query.get(scan_id)
        if scan:
            scan.status = 'failed'
            scan.error_message = str(e)
            db.session.commit()
        print(f"Error in background task: {e}")
    finally:
        # Clean up file
        if os.path.exists(filepath):
            try:
                os.unlink(filepath)
            except:
                pass

def check_virustotal_async(scan_id):
    """Check VirusTotal for existing hash"""
    thread = threading.Thread(target=_check_virustotal_task, args=(scan_id,))
    thread.daemon = True
    thread.start()
    return thread

def _check_virustotal_task(scan_id):
    """Background task to check VirusTotal"""
    try:
        scan = Scan.query.get(scan_id)
        if not scan or not scan.file_hash_sha256:
            return
        
        vt_service = VirusTotalService()
        if vt_service.is_available():
            vt_result = vt_service.get_report(scan.file_hash_sha256)
            
            # Update scan result
            scan.virustotal_result = vt_result
            
            if vt_result and 'malicious' in vt_result:
                malicious_count = vt_result.get('malicious', 0)
                if malicious_count > 0:
                    scan.is_malicious = True
                    scan.threat_score = min(malicious_count * 10, 100)
                    scan.detected_threats = vt_result.get('popular_threat_names', [])
            
            db.session.commit()
            
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")