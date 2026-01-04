from flask import Blueprint, jsonify, request, current_app
from app.services.virustotal import VirusTotalService

# Define blueprint FIRST
bp = Blueprint('virustotal', __name__)

# Then create service instance
vt_service = VirusTotalService()

@bp.before_request
def init_vt_service():
    """Initialize VirusTotal service with app configuration"""
    # Check if we have an API key from environment
    if not vt_service.api_key:
        vt_service.api_key = current_app.config.get('VIRUSTOTAL_API_KEY')
        if vt_service.api_key:
            vt_service.headers = {'x-apikey': vt_service.api_key}
            vt_service.session.headers.update(vt_service.headers)

@bp.route('/status', methods=['GET'])
def status():
    """Check VirusTotal API status"""
    is_available = vt_service.is_available()
    return jsonify({
        'available': is_available,
        'message': 'VirusTotal API is configured' if is_available 
                  else 'VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env file.'
    })

@bp.route('/scan', methods=['POST'])
def scan():
    """Scan file with VirusTotal"""
    if not vt_service.is_available():
        return jsonify({'error': 'VirusTotal API key not configured'}), 400
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
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

@bp.route('/upload-scan', methods=['POST'])
def upload_and_scan():
    """Upload and scan a new file with VirusTotal"""
    if not vt_service.is_available():
        return jsonify({'error': 'VirusTotal API key not configured'}), 400
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    # Save to temp file
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        file.save(tmp.name)
        filepath = tmp.name
    
    try:
        # Upload to VirusTotal
        with open(filepath, 'rb') as f:
            files = {'file': f}
            response = vt_service.session.post(
                f'{vt_service.base_url}/files',
                files=files,
                timeout=60
            )
        
        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get('data', {}).get('id')
            
            # Also get the file hash from response
            file_hash = data.get('data', {}).get('id', '').split('-')[0]
            
            return jsonify({
                'success': True,
                'analysis_id': analysis_id,
                'file_hash': file_hash,
                'message': 'File uploaded for analysis. Use /report/<hash> after 30-60 seconds.'
            })
        else:
            return jsonify({
                'error': f'Upload failed: {response.status_code}',
                'details': response.text[:200]
            }), 400
            
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