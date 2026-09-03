import os
import csv
import io

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from .database import analytics_summary, create_incident, initialize_database, list_incidents, list_scans, save_scan, save_security_event, scan_summary, update_incident_status
from .schemas import AnalyticsSummary, EmailAnalysisRequest, Incident, IncidentCreate, IncidentStatusUpdate, NetworkAnalysisRequest, ScanRecord, ScanSummary, SecurityAnalysisResponse, URLAnalysisRequest
from .services.security_analyzer import analyze_email, analyze_network_event
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


@app.post("/api/v1/analyze-email", response_model=SecurityAnalysisResponse)
def analyze_email_endpoint(payload: EmailAnalysisRequest) -> SecurityAnalysisResponse:
    try:
        return SecurityAnalysisResponse(**save_security_event(analyze_email(payload.text, payload.sender)))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/analyze-network", response_model=SecurityAnalysisResponse)
def analyze_network_endpoint(payload: NetworkAnalysisRequest) -> SecurityAnalysisResponse:
    return SecurityAnalysisResponse(**save_security_event(analyze_network_event(payload.model_dump())))


@app.get("/api/v1/incidents", response_model=list[Incident])
def incidents(limit: int = Query(default=50, ge=1, le=100)) -> list[Incident]:
    return [Incident(**item) for item in list_incidents(limit)]


@app.post("/api/v1/incidents", response_model=Incident, status_code=201)
def add_incident(payload: IncidentCreate) -> Incident:
    return Incident(**create_incident(payload.model_dump()))


@app.patch("/api/v1/incidents/{incident_id}", response_model=Incident)
def change_incident_status(incident_id: int, payload: IncidentStatusUpdate) -> Incident:
    incident = update_incident_status(incident_id, payload.status)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return Incident(**incident)


@app.get("/api/v1/analytics", response_model=AnalyticsSummary)
def analytics() -> AnalyticsSummary:
    return AnalyticsSummary(**analytics_summary())


@app.get("/api/v1/reports/incidents.csv")
def incident_report() -> StreamingResponse:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "severity", "status", "source", "created_at", "updated_at", "description"])
    for item in list_incidents(100):
        writer.writerow([item[key] for key in ("id", "title", "severity", "status", "source", "created_at", "updated_at", "description")])
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=sentinel-incidents.csv"})
