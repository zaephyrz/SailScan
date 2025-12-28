import requests
import time
from typing import Dict, Any, Optional
from flask import current_app

class VirusTotalService:
    def __init__(self, api_key=None):
        # Don't use current_app in __init__
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'
    
    def initialize_from_app(self):
        """Initialize from current_app when in app context"""
        if not self.api_key:
            self.api_key = current_app.config.get('VIRUSTOTAL_API_KEY')
        self.headers = {'x-apikey': self.api_key} if self.api_key else {}
    
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if not self.is_available():
            return {'error': 'API key not configured'}
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(
                    f'{self.base_url}/files',
                    headers=self.headers,
                    files=files
                )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'analysis_id': data.get('data', {}).get('id'),
                    'message': 'File uploaded for analysis'
                }
            else:
                return {
                    'error': f'Upload failed: {response.status_code}',
                    'details': response.text[:200]
                }
                
        except Exception as e:
            return {'error': str(e)}
    
    def get_report(self, file_hash: str) -> Dict[str, Any]:
        if not self.is_available():
            return {'error': 'API key not configured'}
        
        try:
            response = requests.get(
                f'{self.base_url}/files/{file_hash}',
                headers=self.headers
            )
            
            if response.status_code == 200:
                return self._parse_report(response.json())
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'File not in VirusTotal database'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        if not self.is_available():
            return {'error': 'API key not configured'}
        
        try:
            import urllib.parse
            url_id = urllib.parse.quote(url, safe='')
            response = requests.get(
                f'{self.base_url}/urls/{url_id}',
                headers=self.headers
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'URL scan failed: {response.status_code}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_report(self, report: Dict) -> Dict[str, Any]:
        data = report.get('data', {})
        attributes = data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious = stats.get('malicious', 0)
        total = sum(stats.values())
        
        return {
            'malicious': malicious,
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'total_engines': total,
            'detection_rate': f'{(malicious/total*100):.1f}%' if total > 0 else '0%',
            'popular_threat_names': list(set(
                result.get('result')
                for result in attributes.get('last_analysis_results', {}).values()
                if result.get('category') == 'malicious'
            ))[:5]
        }

# Create service instance without initializing from app yet
vt_service = VirusTotalService()
