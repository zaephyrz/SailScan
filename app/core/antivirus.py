import requests
from typing import Dict, Any, Optional
import json
from app.config import settings

class AntivirusScanner:
    def __init__(self):
        self.virustotal_api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        
    def scan_file_virustotal(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Scan file using VirusTotal API"""
        if not self.virustotal_api_key:
            return None
            
        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            
            # Upload file
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=headers,
                    files=files
                )
                
            if response.status_code == 200:
                upload_result = response.json()
                analysis_id = upload_result.get("data", {}).get("id")
                
                # Get analysis results
                analysis_response = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=headers
                )
                
                if analysis_response.status_code == 200:
                    return analysis_response.json()
                    
        except Exception as e:
            print(f"VirusTotal scan error: {e}")
            
        return None
    
    def scan_hash_virustotal(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check file hash against VirusTotal"""
        if not self.virustotal_api_key:
            return None
            
        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            print(f"VirusTotal hash check error: {e}")
            
        return None