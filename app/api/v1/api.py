from fastapi import APIRouter

api_router = APIRouter()

# Try to import endpoints, but don't fail if they don't exist
try:
    from app.api.v1.endpoints import scans
    api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
except ImportError:
    print("Warning: scans endpoint not available")

try:
    from app.api.v1.endpoints import threats
    api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
except ImportError:
    print("Warning: threats endpoint not available")

# Add a simple test endpoint that always works
@api_router.get("/test")
async def test():
    return {"message": "API is working"}