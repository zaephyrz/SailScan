from fastapi import APIRouter
from app.api.v1.endpoints import scans, threats, cves, av, reverse_engineering

api_router = APIRouter()

api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
api_router.include_router(cves.router, prefix="/cves", tags=["cves"])
api_router.include_router(av.router, prefix="/av", tags=["antivirus"])
api_router.include_router(reverse_engineering.router, prefix="/re", tags=["reverse-engineering"])