from fastapi import APIRouter, HTTPException
import tempfile
import os
from app.services.re_tools import ReverseEngineeringTools

router = APIRouter()

@router.post("/analyze/ghidra")
async def analyze_with_ghidra(file: bytes = None, file_path: str = None):
    """Analyze binary with Ghidra"""
    if not file and not file_path:
        raise HTTPException(status_code=400, detail="Either file or file_path must be provided")
    
    tools = ReverseEngineeringTools()
    
    if file:
        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(file)
            tmp_path = tmp.name
        
        try:
            result = tools.analyze_with_ghidra(tmp_path)
        finally:
            os.unlink(tmp_path)
    else:
        result = tools.analyze_with_ghidra(file_path)
    
    if not result:
        raise HTTPException(status_code=500, detail="Ghidra analysis failed")
    
    return result

@router.post("/analyze/frida/{process_name}")
async def analyze_with_frida(process_name: str):
    """Analyze process with Frida"""
    tools = ReverseEngineeringTools()
    result = tools.attach_with_frida(process_name)
    
    return result

@router.post("/analyze/flutter")
async def analyze_flutter(file: bytes = None, file_path: str = None):
    """Analyze Flutter application"""
    if not file and not file_path:
        raise HTTPException(status_code=400, detail="Either file or file_path must be provided")
    
    tools = ReverseEngineeringTools()
    
    if file:
        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(file)
            tmp_path = tmp.name
        
        try:
            result = tools.analyze_flutter_app(tmp_path)
        finally:
            os.unlink(tmp_path)
    else:
        result = tools.analyze_flutter_app(file_path)
    
    if not result:
        raise HTTPException(status_code=500, detail="Flutter analysis failed")
    
    return result