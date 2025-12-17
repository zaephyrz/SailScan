import hashlib
import os
from typing import Dict, Any

class FileScanner:
    def __init__(self):
        pass  # No magic module needed
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Simple file analysis without magic"""
        results = {
            "file_info": {},
            "hashes": {},
            "status": "basic_analysis_complete"
        }
        
        try:
            file_size = os.path.getsize(file_path)
            extension = os.path.splitext(file_path)[1]
            
            results["file_info"] = {
                "size": file_size,
                "extension": extension,
                "name": os.path.basename(file_path)
            }
            
            # Calculate basic hashes
            results["hashes"] = {
                "md5": self._calculate_hash(file_path, "md5"),
                "sha256": self._calculate_hash(file_path, "sha256")
            }
            
        except Exception as e:
            results["error"] = str(e)
            
        return results
    
    def _calculate_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """Calculate file hash"""
        hash_func = hashlib.new(algorithm)
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
                
        return hash_func.hexdigest()