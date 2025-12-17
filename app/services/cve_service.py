import requests
from typing import List, Dict, Any
import json
from datetime import datetime, timedelta
from app.config import settings

class CVEService:
    def __init__(self):
        self.nvd_api_key = settings.NVD_API_KEY
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def fetch_cves(self, 
                   keyword: str = None,
                   cvss_score_min: float = None,
                   cvss_score_max: float = None,
                   published_last_days: int = 7,
                   limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD database"""
        try:
            params = {
                "resultsPerPage": limit,
                "startIndex": 0
            }
            
            if keyword:
                params["keywordSearch"] = keyword
                
            if cvss_score_min is not None:
                params["cvssV3Severity"] = "HIGH"  # Can be customized
            
            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key
            
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._process_cves(data.get("vulnerabilities", []))
                
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            
        return []
    
    def _process_cves(self, vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        """Process raw CVE data"""
        processed = []
        
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id")
            
            # Get CVSS scores
            metrics = cve_data.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", metrics.get("cvssMetricV2", [])))
            
            cvss_score = None
            cvss_severity = None
            
            if cvss_v3:
                cvss_data = cvss_v3[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), "")
            
            # Get references
            references = cve_data.get("references", [])
            
            processed.append({
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "published_date": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "references": [ref.get("url") for ref in references],
                "affected_products": self._extract_affected_products(cve_data),
                "exploit_available": self._check_exploit_available(cve_data),
                "metadata": {
                    "source": "NVD",
                    "weaknesses": cve_data.get("weaknesses", [])
                }
            })
            
        return processed
    
    def _extract_affected_products(self, cve_data: Dict) -> List[str]:
        """Extract affected products from CVE data"""
        products = []
        configurations = cve_data.get("configurations", [])
        
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    if cpe.get("vulnerable"):
                        products.append(cpe.get("criteria"))
                        
        return products
    
    def _check_exploit_available(self, cve_data: Dict) -> str:
        """Check if exploit is available"""
        # This could be enhanced with additional sources
        references = cve_data.get("references", [])
        exploit_keywords = ["exploit", "poc", "proof-of-concept", "metasploit"]
        
        for ref in references:
            tags = ref.get("tags", [])
            if any(keyword in tag.lower() for keyword in exploit_keywords for tag in tags):
                return "Yes"
                
        return "Unknown"