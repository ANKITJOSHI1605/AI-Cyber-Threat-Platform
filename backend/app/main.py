import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .database import initialize_database, list_scans, save_scan, scan_summary
from .schemas import ScanRecord, ScanSummary, URLAnalysisRequest, URLAnalysisResponse
from .services.url_analyzer import analyze_url


app = FastAPI(
    title="AI Cyber Threat Intelligence API",
    description="Explainable URL threat analysis and phishing-risk scoring.",
    version="0.1.0",
)

initialize_database()

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "AI Cyber Threat Intelligence API",
        "version": "0.1.0",
        "documentation": "/docs",
    }


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze-url", response_model=ScanRecord)
def analyze_url_endpoint(payload: URLAnalysisRequest) -> ScanRecord:
    try:
        return ScanRecord(**save_scan(analyze_url(payload.url)))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/scans", response_model=list[ScanRecord])
def recent_scans(limit: int = Query(default=20, ge=1, le=100)) -> list[ScanRecord]:
    return [ScanRecord(**scan) for scan in list_scans(limit)]


@app.get("/api/v1/summary", response_model=ScanSummary)
def summary() -> ScanSummary:
    return ScanSummary(**scan_summary())
