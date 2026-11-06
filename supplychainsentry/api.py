from __future__ import annotations
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .engine import analyze_components, generate_cyclonedx, parse_manifest, analyze_workflow

app = FastAPI(title="SupplyChainSentry API", version="0.1.0", description="Offline-first dependency and software supply-chain risk analysis")
WEB = Path(__file__).resolve().parent.parent / "web"
app.mount("/assets", StaticFiles(directory=WEB), name="assets")

class AnalyzeRequest(BaseModel):
    filename: str = "requirements.txt"
    content: str
    project_name: str = "analyzed-project"

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SupplyChainSentry API", "mode": "offline-static"}

@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    try:
        if request.filename.lower().endswith((".yml", ".yaml")):
            return analyze_components([], analyze_workflow(request.content, request.filename))
        components, extra = parse_manifest(request.filename, request.content)
        return analyze_components(components, extra)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.post("/api/sbom")
def sbom(request: AnalyzeRequest):
    try:
        components, _ = parse_manifest(request.filename, request.content)
        return generate_cyclonedx(components, request.project_name)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.get("/")
def dashboard():
    return FileResponse(WEB / "index.html")
