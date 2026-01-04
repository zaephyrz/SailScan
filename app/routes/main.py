from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import hashlib
import threading
import datetime
from app import db
from app.models import Scan
from app.services.scanner import SecurityScanner
from app.services.virustotal import VirusTotalService
from app.config import Config

bp = Blueprint('main', __name__)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@bp.route('/')
def dashboard():
    """Main dashboard"""
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    stats = {
        'total_scans': Scan.query.count(),
        'malicious_scans': Scan.query.filter_by(is_malicious=True).count(),
        'completed_scans': Scan.query.filter_by(status='completed').count()
    }
    
    vt_service = VirusTotalService()
    
    return render_template('dashboard.html', 
                         scans=recent_scans,
                         stats=stats,
                         vt_available=vt_service.is_available())

@bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('main.dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('main.dashboard'))
    
    if not allowed_file(file.filename):
        flash('File type not allowed', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Ensure upload directory exists
    os.makedirs('uploads', exist_ok=True)
    
    # Save file
    filename = secure_filename(file.filename)
    filepath = os.path.join('uploads', filename)
    file.save(filepath)
    
    # Calculate hashes
    with open(filepath, 'rb') as f:
        file_content = f.read()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        md5_hash = hashlib.md5(file_content).hexdigest()
    
    # Create scan record
    scan = Scan(
        filename=filename,
        original_filename=file.filename,
        file_hash_sha256=sha256_hash,
        file_hash_md5=md5_hash,
        file_size=len(file_content),
        status='pending',
        created_at=datetime.datetime.utcnow()
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Start analysis in background thread
    thread = threading.Thread(target=analyze_file_background, args=(scan.id, filepath))
    thread.daemon = True
    thread.start()
    
    flash(f'File uploaded and scanning started (ID: {scan.id})', 'success')
    return redirect(url_for('main.dashboard'))  # FIXED: Redirect to dashboard, not scan details

def analyze_file_background(scan_id, filepath):
    """Background file analysis"""
    try:
        # Import inside function to avoid circular imports
        from app import create_app, db
        from app.models import Scan
        
        # Create app context for database operations
        app = create_app()
        with app.app_context():
            scan = Scan.query.get(scan_id)
            if not scan:
                return
            
            scan.status = 'scanning'
            scan.started_at = datetime.datetime.utcnow()
            db.session.commit()
            
            # Calculate hashes again to ensure we have them
            with open(filepath, 'rb') as f:
                file_content = f.read()
                sha256_hash = hashlib.sha256(file_content).hexdigest()
                md5_hash = hashlib.md5(file_content).hexdigest()
            
            scan.file_hash_sha256 = sha256_hash
            scan.file_hash_md5 = md5_hash
            
            # Perform static analysis
            scanner = SecurityScanner()
            static_analysis = scanner.analyze_file(filepath)
            scan.static_analysis = static_analysis
            
            # VirusTotal analysis
            vt_service = VirusTotalService()
            if vt_service.is_available():
                # First try to get existing report
                vt_result = vt_service.get_report(sha256_hash)
                
                # If not found, upload the file
                if vt_result and vt_result.get('status') == 'not_found':
                    # Upload file to VirusTotal
                    upload_result = vt_service.scan_file(filepath)
                    if upload_result and upload_result.get('success'):
                        vt_result = {
                            'status': 'uploaded',
                            'message': 'File uploaded to VirusTotal. Analysis pending.',
                            'malicious': 0,
                            'total_engines': 0
                        }
                
                scan.virustotal_result = vt_result
                
                # Check if malicious
                if vt_result and 'malicious' in vt_result and vt_result['malicious'] > 0:
                    scan.is_malicious = True
                    scan.threat_score = min(vt_result.get('malicious', 0) * 10, 100)
                    if 'popular_threat_names' in vt_result:
                        scan.detected_threats = vt_result['popular_threat_names']
                else:
                    # Set default threat score based on static analysis
                    threat_indicators = static_analysis.get('threat_indicators', [])
                    if threat_indicators:
                        scan.threat_score = min(len(threat_indicators) * 10, 100)
                    else:
                        scan.threat_score = 0
                    scan.is_malicious = False
            else:
                # VirusTotal not available, use static analysis only
                threat_indicators = static_analysis.get('threat_indicators', [])
                if threat_indicators:
                    scan.threat_score = min(len(threat_indicators) * 10, 100)
                    scan.is_malicious = len(threat_indicators) >= 3
                else:
                    scan.threat_score = 0
                    scan.is_malicious = False
            
            scan.status = 'completed'
            scan.completed_at = datetime.datetime.utcnow()
            db.session.commit()
            
    except Exception as e:
        print(f"Error in background analysis: {e}")
        try:
            with app.app_context():
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.status = 'failed'
                    scan.error_message = str(e)
                    db.session.commit()
        except:
            pass
    finally:
        # Clean up uploaded file
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
        except:
            pass

@bp.route('/api/scans')
def get_scans():
    """API endpoint to get all scans"""
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return jsonify([scan.to_dict() for scan in scans])

@bp.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan_api(scan_id):
    """API endpoint to get scan details"""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())

@bp.route('/api/scan/<int:scan_id>/rescan', methods=['POST'])
def rescan_file_api(scan_id):
    """Re-scan an existing file via API"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if file exists in uploads (simulate for now)
    # In a real app, you'd store the file or hash for re-scanning
    
    return jsonify({
        'message': 'Re-scan initiated',
        'scan_id': scan_id,
        'filename': scan.filename,
        'note': 'Re-scan functionality requires file storage implementation'
    })