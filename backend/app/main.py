from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .schemas import URLAnalysisRequest, URLAnalysisResponse
from .services.url_analyzer import analyze_url


app = FastAPI(
    title="AI Cyber Threat Intelligence API",
    description="Explainable URL threat analysis and phishing-risk scoring.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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


@app.post("/api/v1/analyze-url", response_model=URLAnalysisResponse)
def analyze_url_endpoint(payload: URLAnalysisRequest) -> URLAnalysisResponse:
    try:
        return URLAnalysisResponse(**analyze_url(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
