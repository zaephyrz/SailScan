"""Frida service with graceful fallback"""
import subprocess
import json
import tempfile
import os

# Try to import frida, but handle if it's not available
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print("Note: Frida not available. Dynamic analysis features disabled.")

class FridaService:
    """Dynamic analysis with Frida (optional)"""
    
    def __init__(self):
        self.enabled = FRIDA_AVAILABLE
    
    def is_available(self) -> bool:
        """Check if Frida is available"""
        return self.enabled and FRIDA_AVAILABLE
    
    def analyze_process(self, process_name: str):
        """Analyze running process with Frida"""
        if not self.is_available():
            return {
                'error': 'Frida not available',
                'message': 'Install frida-tools: pip install frida-tools',
                'note': 'Frida requires additional system setup'
            }
        
        try:
            # This is a simplified example
            # In a real implementation, you would connect to device and attach
            return {
                'success': True,
                'process': process_name,
                'message': 'Frida analysis would run here',
                'note': 'Full Frida integration requires USB debugging (Android) or process injection'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def trace_executable(self, executable_path: str):
        """Trace executable with Frida"""
        if not self.is_available():
            return {
                'error': 'Frida not available',
                'message': 'Install frida-tools to enable dynamic analysis'
            }
        
        try:
            # Create a simple analysis script
            script_content = f"""
            console.log('Frida would trace: {executable_path}');
            // In real implementation, this would load and instrument the executable
            """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script_content)
                script_path = f.name
            
            os.unlink(script_path)
            
            return {
                'success': True,
                'message': 'Frida tracing ready (simulated)',
                'note': 'For production use, implement actual process spawning and instrumentation'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_device_info(self):
        """Get Frida device information"""
        if not self.is_available():
            return {'available': False}
        
        try:
            # Try to get USB device
            devices = frida.enumerate_devices()
            device_info = []
            
            for device in devices:
                device_info.append({
                    'id': device.id,
                    'name': device.name,
                    'type': str(device.type)
                })
            
            return {
                'available': True,
                'devices': device_info,
                'device_count': len(devices)
            }
            
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }