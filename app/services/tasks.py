"""Background task system for SailScan"""
import threading
import time
import os
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
        scan.started_at = time.time()
        db.session.commit()
        
        # Static analysis
        scanner = SecurityScanner()
        static_analysis = scanner.analyze_file(filepath)
        scan.static_analysis = static_analysis
        
        # VirusTotal analysis
        vt_service = VirusTotalService()
        if vt_service.is_available():
            vt_result = vt_service.get_report(scan.file_hash_sha256)
            scan.virustotal_result = vt_result
            
            if vt_result and 'malicious' in vt_result and vt_result['malicious'] > 0:
                scan.is_malicious = True
                scan.threat_score = vt_result.get('malicious', 0) * 10
        
        scan.status = 'completed'
        scan.completed_at = time.time()
        db.session.commit()
        
    except Exception as e:
        scan = Scan.query.get(scan_id)
        if scan:
            scan.status = 'failed'
            scan.error_message = str(e)
            db.session.commit()
    finally:
        # Clean up file
        if os.path.exists(filepath):
            os.unlink(filepath)

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
        if not scan:
            return
        
        vt_service = VirusTotalService()
        if vt_service.is_available():
            vt_result = vt_service.get_report(scan.file_hash_sha256)
            scan.virustotal_result = vt_result
            
            if vt_result and 'malicious' in vt_result and vt_result['malicious'] > 0:
                scan.is_malicious = True
                scan.threat_score = vt_result.get('malicious', 0) * 10
            
            db.session.commit()
            
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")