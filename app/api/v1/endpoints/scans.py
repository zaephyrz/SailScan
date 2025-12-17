from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
import os
import tempfile

from app.database import get_db
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.threat import Threat  # Add this import
from app.core.scanner import FileScanner
from app.core.antivirus import AntivirusScanner
from app.services.re_tools import ReverseEngineeringTools

router = APIRouter()

@router.post("/scan/file", response_model=dict)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_type: ScanType = ScanType.FILE,
    db: Session = Depends(get_db)
):
    """Upload and scan a file"""
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        
        # Create scan record
        scan = Scan(
            scan_type=scan_type,
            target=file.filename,
            filename=file.filename,
            status=ScanStatus.PENDING
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Start background scan
        background_tasks.add_task(
            perform_scan,
            scan.id,
            tmp_path,
            file.filename,
            scan_type,
            db
        )
        
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "message": "Scan started in background"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def perform_scan(scan_id: int, file_path: str, filename: str, scan_type: ScanType, db: Session):
    """Background task to perform comprehensive scan"""
    try:
        # Update scan status
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
            
        scan.status = ScanStatus.SCANNING
        db.commit()
        
        results = {
            "basic_analysis": {},
            "antivirus": {},
            "reverse_engineering": {},
            "threats": []
        }
        
        # Basic file analysis
        scanner = FileScanner()
        basic_results = scanner.analyze_file(file_path)
        results["basic_analysis"] = basic_results
        
        # Antivirus scan
        av_scanner = AntivirusScanner()
        vt_results = av_scanner.scan_file_virustotal(file_path)
        if vt_results:
            results["antivirus"]["virustotal"] = vt_results
            
            # Check for threats in VT results
            if vt_results.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                results["threats"].append({
                    "type": "malware",
                    "severity": "critical",
                    "description": f"Detected by {vt_results['data']['attributes']['last_analysis_stats']['malicious']} antivirus engines",
                    "detection": "VirusTotal"
                })
        
        # Reverse engineering analysis for executables
        if filename.lower().endswith(('.exe', '.dll', '.apk', '.ipa')):
            re_tools = ReverseEngineeringTools()
            
            # Ghidra analysis
            try:
                ghidra_results = re_tools.analyze_with_ghidra(file_path)
                if ghidra_results:
                    results["reverse_engineering"]["ghidra"] = ghidra_results
            except Exception as e:
                print(f"Ghidra analysis failed: {e}")
            
            # Check for Flutter apps
            if filename.lower().endswith('.apk'):
                flutter_results = re_tools.analyze_flutter_app(file_path)
                if flutter_results:
                    results["reverse_engineering"]["flutter"] = flutter_results
        
        # Update scan results
        scan.results = results
        scan.status = ScanStatus.COMPLETED
        
        # Create threat records if any
        if results["threats"]:
            for threat_data in results["threats"]:
                threat = Threat(
                    scan_id=scan.id,
                    threat_type=threat_data["type"],
                    severity=threat_data["severity"],
                    description=threat_data["description"],
                    detection=threat_data.get("detection"),
                    location=file_path,
                    metadata=threat_data
                )
                db.add(threat)
        
        db.commit()
        
        # Clean up temp file
        if os.path.exists(file_path):
            os.unlink(file_path)
        
    except Exception as e:
        # Update scan status to failed
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.results = {"error": str(e)}
            db.commit()