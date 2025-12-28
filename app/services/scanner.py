import hashlib
import os
import zipfile
import json
from typing import Dict, Any

class SecurityScanner:
    """Security scanner without external dependencies"""
    
    def __init__(self):
        pass  # No magic dependency
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file analysis without magic"""
        results = {
            'basic_analysis': {},
            'hashes': {},
            'file_info': {},
            'threat_indicators': [],
            'scan_results': {}
        }
        
        try:
            # Basic file info
            file_stats = os.stat(file_path)
            filename = os.path.basename(file_path)
            extension = os.path.splitext(filename)[1].lower()
            
            results['basic_analysis'] = {
                'size': file_stats.st_size,
                'created': file_stats.st_ctime,
                'modified': file_stats.st_mtime,
                'permissions': oct(file_stats.st_mode)[-3:]
            }
            
            results['file_info'] = {
                'filename': filename,
                'extension': extension,
                'path': file_path
            }
            
            # Calculate hashes
            results['hashes'] = self._calculate_hashes(file_path)
            
            # Check for suspicious extensions
            suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']
            if extension in suspicious_extensions:
                results['threat_indicators'].append({
                    'type': 'suspicious_extension',
                    'severity': 'low',
                    'description': f'Suspicious file extension: {extension}'
                })
            
            # Check for double extensions (e.g., .pdf.exe)
            if filename.count('.') > 1 and extension in ['.exe', '.dll', '.bat']:
                results['threat_indicators'].append({
                    'type': 'double_extension',
                    'severity': 'medium',
                    'description': 'File has double extension (possible disguise)'
                })
            
            # Platform-specific analysis
            if extension == '.apk':
                results.update(self._analyze_android_apk(file_path))
            elif extension in ['.exe', '.dll']:
                results.update(self._analyze_windows_pe(file_path))
            elif extension == '.pdf':
                results.update(self._analyze_pdf(file_path))
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hash algorithms"""
        hashes = {}
        algorithms = ['md5', 'sha1', 'sha256']
        
        for algo in algorithms:
            hash_obj = hashlib.new(algo)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            hashes[algo] = hash_obj.hexdigest()
        
        return hashes
    
    def _analyze_android_apk(self, file_path: str) -> Dict[str, Any]:
        """Analyze Android APK files"""
        analysis = {
            'apk_analysis': {},
            'flutter_detected': False,
            'file_count': 0,
            'interesting_files': []
        }
        
        try:
            with zipfile.ZipFile(file_path, 'r') as apk:
                file_list = apk.namelist()
                analysis['file_count'] = len(file_list)
                
                # Check for Flutter
                flutter_files = [f for f in file_list if 'flutter' in f.lower()]
                if flutter_files:
                    analysis['flutter_detected'] = True
                    analysis['flutter_files'] = flutter_files[:5]
                
                # Find interesting files
                interesting_patterns = ['.so', '.dex', 'AndroidManifest', 'META-INF', 'lib/', 'assets/']
                interesting_files = []
                for f in file_list:
                    if any(pattern in f for pattern in interesting_patterns):
                        interesting_files.append(f)
                
                analysis['interesting_files'] = interesting_files[:10]
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_windows_pe(self, file_path: str) -> Dict[str, Any]:
        """Analyze Windows PE files (EXE/DLL)"""
        analysis = {
            'pe_analysis': {
                'is_pe': False,
                'has_valid_header': False
            }
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB
                
                # Check for MZ header (DOS header)
                if data[:2] == b'MZ':
                    analysis['pe_analysis']['is_pe'] = True
                    
                    # Check for PE header
                    if len(data) > 64:
                        pe_offset = int.from_bytes(data[60:64], 'little')
                        if pe_offset < len(data):
                            f.seek(pe_offset)
                            pe_header = f.read(4)
                            if pe_header == b'PE\x00\x00':
                                analysis['pe_analysis']['has_valid_header'] = True
                            else:
                                analysis['threat_indicators'].append({
                                    'type': 'corrupted_pe',
                                    'severity': 'high',
                                    'description': 'Invalid PE header - file may be corrupted or malicious'
                                })
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_pdf(self, file_path: str) -> Dict[str, Any]:
        """Analyze PDF files for basic threats"""
        analysis = {
            'pdf_analysis': {},
            'javascript_detected': False,
            'embedded_files': False
        }
        
        try:
            with open(file_path, 'rb', encoding='latin-1') as f:
                content = f.read(8192)  # Read first 8KB
                
                # Check for JavaScript
                if b'/JavaScript' in content or b'/JS' in content or b'/AA' in content:
                    analysis['javascript_detected'] = True
                    analysis['threat_indicators'].append({
                        'type': 'pdf_javascript',
                        'severity': 'medium',
                        'description': 'PDF contains JavaScript - potential security risk'
                    })
                
                # Check for embedded files
                if b'/EmbeddedFiles' in content or b'/EmbeddedFile' in content:
                    analysis['embedded_files'] = True
                
        except:
            # If we can't read as text, try binary
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(8192)
                    if b'/JavaScript' in content:
                        analysis['javascript_detected'] = True
            except Exception as e:
                analysis['error'] = str(e)
        
        return analysis