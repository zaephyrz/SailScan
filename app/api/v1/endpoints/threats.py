from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.threat import Threat

router = APIRouter()

@router.get("/", response_model=List[dict])
async def get_threats(
    skip: int = 0,
    limit: int = 100,
    severity: str = None,
    db: Session = Depends(get_db)
):
    """Get all threats with optional filtering"""
    query = db.query(Threat)
    
    if severity:
        query = query.filter(Threat.severity == severity)
    
    threats = query.offset(skip).limit(limit).all()
    
    return [
        {
            "id": threat.id,
            "scan_id": threat.scan_id,
            "threat_type": threat.threat_type,
            "severity": threat.severity,
            "description": threat.description,
            "detection": threat.detection,
            "created_at": threat.created_at.isoformat() if threat.created_at else None
        }
        for threat in threats
    ]

@router.get("/{threat_id}", response_model=dict)
async def get_threat(threat_id: int, db: Session = Depends(get_db)):
    """Get specific threat by ID"""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return {
        "id": threat.id,
        "scan_id": threat.scan_id,
        "threat_type": threat.threat_type,
        "severity": threat.severity,
        "description": threat.description,
        "detection": threat.detection,
        "location": threat.location,
        "metadata": threat.metadata,
        "created_at": threat.created_at.isoformat() if threat.created_at else None
    }