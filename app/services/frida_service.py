"""Frida service with graceful fallback"""
import subprocess
import json
import tempfile
import os
import threading
import time
from typing import Dict, Any, List, Optional

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
        self.device = None
        self.sessions = {}
        
    def is_available(self) -> bool:
        """Check if Frida is properly installed"""
        if not FRIDA_AVAILABLE:
            return False
        
        try:
            # Test Frida installation
            frida.get_local_device()
            return True
        except:
            return False
    
    def get_device_info(self):
        """Get Frida device information"""
        if not self.is_available():
            return {
                'available': False,
                'error': 'Frida not properly installed',
                'instructions': [
                    'Install: pip install frida frida-tools',
                    'For Android: Download frida-server from GitHub',
                    'Push to device: adb push frida-server /data/local/tmp/',
                    'Run: adb shell /data/local/tmp/frida-server &'
                ]
            }
        
        try:
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
            return {
                'success': True,
                'process': process_name,
                'message': 'Frida analysis would run here',
                'note': 'Full Frida integration requires USB debugging (Android) or process injection'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_scripts_library(self) -> List[Dict[str, str]]:
        """Get available Frida scripts for common tasks"""
        return [
            {
                'name': 'Root Detection Bypass',
                'description': 'Bypass common root detection methods',
                'category': 'Android',
                'complexity': 'Beginner'
            },
            {
                'name': 'SSL Pinning Bypass',
                'description': 'Bypass SSL certificate pinning',
                'category': 'Android/iOS',
                'complexity': 'Intermediate'
            },
            {
                'name': 'Method Tracing',
                'description': 'Trace method calls in real-time',
                'category': 'Universal',
                'complexity': 'Beginner'
            }
        ]