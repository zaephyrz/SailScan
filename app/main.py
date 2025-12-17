from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import uvicorn

# Try to set up database
try:
    from app.database import engine
    from app.models.scan import Base
    Base.metadata.create_all(bind=engine)
    print("✓ Database initialized")
except Exception as e:
    print(f"Note: Database setup skipped: {e}")

app = FastAPI(title="Security Platform", version="1.0")

# Setup templates
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "Security Platform"}

@app.post("/scan/test")
async def test_scan():
    return {"message": "Scan endpoint works", "status": "success"}

# Simple file scan endpoint
@app.post("/scan/upload")
async def upload_file():
    return {"message": "File upload received", "status": "queued"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)