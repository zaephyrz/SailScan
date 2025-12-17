from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.database import get_db
from app.models.cve import CVE
from app.services.cve_service import CVEService

router = APIRouter()

@router.get("/cves", response_model=List[dict])
async def get_cves(
    keyword: Optional[str] = Query(None, description="Search keyword"),
    severity: Optional[str] = Query(None, description="CVSS severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    days: int = Query(7, description="Published in last N days"),
    limit: int = Query(100, description="Maximum results"),
    db: Session = Depends(get_db)
):
    """Get CVEs with filters"""
    
    # Build query
    query = db.query(CVE)
    
    if keyword:
        query = query.filter(CVE.description.ilike(f"%{keyword}%"))
    
    if severity:
        query = query.filter(CVE.cvss_severity == severity.upper())
    
    if days:
        date_filter = datetime.utcnow() - timedelta(days=days)
        query = query.filter(CVE.published_date >= date_filter)
    
    query = query.order_by(CVE.published_date.desc()).limit(limit)
    
    cves = query.all()
    
    # Convert to dict
    result = []
    for cve in cves:
        result.append({
            "id": cve.id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "cvss_severity": cve.cvss_severity,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "exploit_available": cve.exploit_available,
            "patch_available": cve.patch_available
        })
    
    return result

@router.post("/cves/sync")
async def sync_cves(
    days: int = Query(7, description="Sync CVEs from last N days"),
    db: Session = Depends(get_db)
):
    """Sync CVEs from external sources"""
    cve_service = CVEService()
    
    # Fetch CVEs
    cves_data = cve_service.fetch_cves(published_last_days=days)
    
    # Store in database
    for cve_data in cves_data:
        cve = CVE(
            id=cve_data["id"],
            description=cve_data["description"],
            cvss_score=cve_data["cvss_score"],
            cvss_severity=cve_data["cvss_severity"],
            published_date=datetime.fromisoformat(cve_data["published_date"].replace("Z", "+00:00")),
            last_modified=datetime.fromisoformat(cve_data["last_modified"].replace("Z", "+00:00")),
            references=cve_data["references"],
            affected_products=cve_data["affected_products"],
            exploit_available=cve_data["exploit_available"],
            patch_available="Unknown",
            metadata=cve_data["metadata"]
        )
        
        # Update or insert
        existing = db.query(CVE).filter(CVE.id == cve.id).first()
        if existing:
            for key, value in cve.__dict__.items():
                if not key.startswith("_"):
                    setattr(existing, key, value)
        else:
            db.add(cve)
    
    db.commit()
    
    return {
        "message": f"Synced {len(cves_data)} CVEs",
        "count": len(cves_data)
    }