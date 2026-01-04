from flask import Blueprint, jsonify, request, current_app
import sys

# Define blueprint
bp = Blueprint('frida', __name__)

# Try to import Frida service, but handle gracefully if not available
try:
    from app.services.frida_service import FridaService
    frida_service = FridaService()
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print("Note: Frida service not available")
    frida_service = None

@bp.route('/status', methods=['GET'])
def status():
    """Check Frida availability"""
    if not FRIDA_AVAILABLE or frida_service is None:
        return jsonify({
            'available': False,
            'message': 'Frida not installed. Install with: pip install frida frida-tools',
            'instructions': [
                '1. Install: pip install frida frida-tools',
                '2. For Android: Connect rooted device with USB debugging',
                '3. Download frida-server from GitHub releases',
                '4. Push to device: adb push frida-server /data/local/tmp/',
                '5. Run: adb shell /data/local/tmp/frida-server &'
            ]
        })
    
    return jsonify(frida_service.get_device_info())

@bp.route('/scripts', methods=['GET'])
def get_scripts():
    """Get available Frida scripts"""
    if not FRIDA_AVAILABLE:
        return jsonify({
            'scripts': [],
            'message': 'Frida not available',
            'documentation': 'https://frida.re/docs/javascript-api/'
        })
    
    return jsonify({
        'scripts': frida_service.get_scripts_library(),
        'documentation': 'https://frida.re/docs/javascript-api/'
    })

@bp.route('/analyze-apk', methods=['POST'])
def analyze_apk():
    """Analyze Android APK with Frida"""
    if not FRIDA_AVAILABLE or frida_service is None:
        return jsonify({
            'error': 'Frida not installed',
            'message': 'Install frida-tools to enable dynamic analysis'
        }), 400
    
    if 'file' not in request.files:
        return jsonify({'error': 'No APK file provided'}), 400
    
    file = request.files['file']
    package_name = request.form.get('package_name')
    
    # Save to temp file
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp:
        file.save(tmp.name)
        apk_path = tmp.name
    
    try:
        result = frida_service.analyze_android_apk(apk_path, package_name)
        return jsonify(result)
    finally:
        if os.path.exists(apk_path):
            os.unlink(apk_path)

@bp.route('/trace', methods=['POST'])
def trace_process():
    """Trace a running process"""
    if not FRIDA_AVAILABLE:
        return jsonify({
            'error': 'Frida not available',
            'instruction': 'Install frida-tools first'
        }), 400
    
    data = request.json
    process_name = data.get('process_name')
    pid = data.get('pid')
    
    if not process_name and not pid:
        return jsonify({'error': 'Provide process_name or pid'}), 400
    
    return jsonify({
        'message': 'Frida tracing endpoint',
        'instruction': 'Implement specific tracing based on your needs',
        'resources': [
            'Frida JavaScript API: https://frida.re/docs/javascript-api/',
            'Frida CodeShare: https://codeshare.frida.re/',
            'Example scripts: https://github.com/t0thkr1s/frida'
        ]
    })