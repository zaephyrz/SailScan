from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import hashlib
import threading
import time
from app import db
from app.models import Scan
from app.services.scanner import SecurityScanner
from app.services.virustotal import VirusTotalService
from app.config import Config  # Add this import

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
        status='pending'
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Start analysis in background thread (simplified)
    thread = threading.Thread(target=analyze_file_background, args=(scan.id, filepath))
    thread.daemon = True
    thread.start()
    
    flash(f'File uploaded and scanning started (ID: {scan.id})', 'success')
    return redirect(url_for('main.scan_details', scan_id=scan.id))

def analyze_file_background(scan_id, filepath):
    """Background file analysis"""
    try:
        # Get scan from database
        from app import db
        with db.session.no_autoflush:
            scan = Scan.query.get(scan_id)
            if not scan:
                return
            
            scan.status = 'scanning'
            scan.started_at = time.time()
            db.session.commit()
            
            # Perform static analysis
            scanner = SecurityScanner()
            static_analysis = scanner.analyze_file(filepath)
            scan.static_analysis = static_analysis
            
            # VirusTotal analysis
            vt_service = VirusTotalService()
            if vt_service.is_available():
                vt_result = vt_service.get_report(scan.file_hash_sha256)
                scan.virustotal_result = vt_result
                
                # Check if malicious
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
        # Clean up uploaded file
        if os.path.exists(filepath):
            os.unlink(filepath)

@bp.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    """Show scan details"""
    scan = Scan.query.get_or_404(scan_id)
    return render_template('scan.html', scan=scan)

@bp.route('/api/scans')
def get_scans():
    """API endpoint to get all scans"""
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return jsonify([scan.to_dict() for scan in scans])