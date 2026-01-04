import requests
import os
import time
from typing import Dict, Any, Optional

class VirusTotalService:
    def __init__(self, api_key=None):
        # Initialize with API key from parameter or environment
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {'x-apikey': self.api_key} if self.api_key else {}
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update(self.headers)
    
    def is_available(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key and self.api_key.strip())
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Upload and scan a file with VirusTotal"""
        if not self.is_available():
            return {'error': 'API key not configured'}
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f'{self.base_url}/files',
                    files=files,
                    timeout=60
                )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'analysis_id': data.get('data', {}).get('id'),
                    'message': 'File uploaded for analysis'
                }
            elif response.status_code == 401:
                return {'error': 'Invalid VirusTotal API key'}
            elif response.status_code == 429:
                return {'error': 'API quota exceeded. Try again later.'}
            else:
                return {
                    'error': f'Upload failed: {response.status_code}',
                    'details': response.text[:200]
                }
                
        except Exception as e:
            return {'error': str(e)}
    
    def get_report(self, file_hash: str) -> Dict[str, Any]:
        """Get existing report for a file hash"""
        if not self.is_available():
            return {'error': 'API key not configured'}
        
        try:
            # Check hash format (SHA-256 should be 64 hex chars)
            if len(file_hash) != 64 or not all(c in '0123456789abcdef' for c in file_hash.lower()):
                return {'error': 'Invalid SHA-256 hash format'}
            
            response = self.session.get(
                f'{self.base_url}/files/{file_hash}',
                timeout=30
            )
            
            if response.status_code == 200:
                return self._parse_report(response.json())
            elif response.status_code == 404:
                return {
                    'status': 'not_found', 
                    'message': 'File not in VirusTotal database. Upload it first.',
                    'malicious': 0,
                    'total_engines': 0
                }
            elif response.status_code == 401:
                return {'error': 'Invalid VirusTotal API key'}
            elif response.status_code == 429:
                return {'error': 'API quota exceeded. Try again later.'}
            else:
                return {
                    'error': f'API error: {response.status_code}',
                    'details': response.text[:200]
                }
                
        except requests.exceptions.Timeout:
            return {'error': 'VirusTotal API timeout'}
        except Exception as e:
            return {'error': f'Connection failed: {str(e)}'}
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL with VirusTotal"""
        if not self.is_available():
            return {'error': 'API key not configured'}
        
        try:
            # URL encode the URL
            import urllib.parse
            url_id = urllib.parse.quote(url, safe='')
            response = self.session.get(
                f'{self.base_url}/urls/{url_id}',
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'URL not in VirusTotal database'}
            else:
                return {'error': f'URL scan failed: {response.status_code}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_report(self, report: Dict) -> Dict[str, Any]:
        """Parse VirusTotal report data"""
        data = report.get('data', {})
        attributes = data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        total = malicious + suspicious + undetected + harmless
        
        # Get popular threat names
        threat_names = set()
        results = attributes.get('last_analysis_results', {})
        for engine, result in results.items():
            if result.get('category') == 'malicious':
                threat_name = result.get('result', 'Unknown')
                if threat_name and threat_name != 'None':
                    threat_names.add(threat_name)
        
        return {
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': undetected,
            'harmless': harmless,
            'total_engines': total,
            'detection_rate': f'{(malicious/total*100):.1f}%' if total > 0 else '0%',
            'popular_threat_names': list(threat_names)[:5] if threat_names else []
        }

# Create global service instance
vt_service = VirusTotalService()