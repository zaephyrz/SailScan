from fastapi import APIRouter, HTTPException
from app.core.antivirus import AntivirusScanner

router = APIRouter()

@router.get("/scan/{file_hash}")
async def scan_hash(file_hash: str):
    """Scan file hash using antivirus engines"""
    scanner = AntivirusScanner()
    result = scanner.scan_hash_virustotal(file_hash)
    
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found or API key missing")
    
    return result

@router.get("/engines")
async def get_av_engines():
    """Get available antivirus engines"""
    return {
        "engines": [
            {"name": "VirusTotal", "enabled": True},
            {"name": "ClamAV", "enabled": False},
            {"name": "Malwarebytes", "enabled": False}
        ]
    }