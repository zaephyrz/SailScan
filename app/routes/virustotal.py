from flask import Blueprint, jsonify, request, current_app
from app.services.virustotal import VirusTotalService

bp = Blueprint('virustotal', __name__)

# Create service instance
vt_service = VirusTotalService()

@bp.before_request
def init_vt_service():
    """Initialize VirusTotal service before handling any request"""
    vt_service.initialize_from_app()

@bp.route('/status', methods=['GET'])
def status():
    """Check VirusTotal API status"""
    return jsonify({
        'available': vt_service.is_available(),
        'message': 'VirusTotal API is configured' if vt_service.is_available() 
                  else 'VirusTotal API key not configured'
    })

@bp.route('/scan', methods=['POST'])
def scan():
    """Scan file with VirusTotal"""
    if not vt_service.is_available():
        return jsonify({'error': 'VirusTotal API key not configured'}), 400
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # Save to temp file
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        file.save(tmp.name)
        filepath = tmp.name
    
    try:
        result = vt_service.scan_file(filepath)
        return jsonify(result)
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)

@bp.route('/report/<hash_value>', methods=['GET'])
def report(hash_value):
    """Get VirusTotal report for hash"""
    if not vt_service.is_available():
        return jsonify({'error': 'VirusTotal API key not configured'}), 400
    
    result = vt_service.get_report(hash_value)
    return jsonify(result)

@bp.route('/url', methods=['GET'])
def scan_url():
    """Scan URL with VirusTotal"""
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    if not vt_service.is_available():
        return jsonify({'error': 'VirusTotal API key not configured'}), 400
    
    result = vt_service.scan_url(url)
    return jsonify(result)
