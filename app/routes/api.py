from flask import Blueprint, jsonify, request
from app import db
from app.models import Scan
from app.services.scanner import SecurityScanner

bp = Blueprint('api', __name__)

@bp.route('/scan/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get scan details"""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())

@bp.route('/scan/<int:scan_id>/full', methods=['GET'])
def get_scan_full(scan_id):
    """Get full scan details with analysis results"""
    scan = Scan.query.get_or_404(scan_id)
    
    result = scan.to_dict()
    result.update({
        'virustotal_result': scan.virustotal_result,
        'static_analysis': scan.static_analysis,
        'detected_threats': scan.detected_threats,
        'flutter_analysis': scan.flutter_analysis,
        'error_message': scan.error_message
    })
    
    return jsonify(result)

@bp.route('/scan/file', methods=['POST'])
def scan_file_api():
    """API endpoint to scan file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # Save to temp location
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        file.save(tmp.name)
        filepath = tmp.name
    
    try:
        # Perform static analysis
        scanner = SecurityScanner()
        analysis = scanner.analyze_file(filepath)
        
        # Calculate hash
        import hashlib
        with open(filepath, 'rb') as f:
            sha256_hash = hashlib.sha256(f.read()).hexdigest()
        
        return jsonify({
            'filename': file.filename,
            'sha256': sha256_hash,
            'analysis': analysis,
            'message': 'Analysis complete'
        })
        
    finally:
        # Cleanup
        if os.path.exists(filepath):
            os.unlink(filepath)

@bp.route('/stats', methods=['GET'])
def get_stats():
    """Get application statistics"""
    total_scans = Scan.query.count()
    malicious = Scan.query.filter_by(is_malicious=True).count()
    completed = Scan.query.filter_by(status='completed').count()
    
    return jsonify({
        'total_scans': total_scans,
        'malicious': malicious,
        'completed': completed,
        'success_rate': f'{(completed/total_scans*100):.1f}%' if total_scans > 0 else '0%'
    })