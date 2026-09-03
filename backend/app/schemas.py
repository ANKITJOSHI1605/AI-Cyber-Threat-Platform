from pydantic import BaseModel, Field


class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048, examples=["https://example.com"])


class RiskSignal(BaseModel):
    name: str
    weight: int
    description: str


class URLFeatures(BaseModel):
    length: int
    subdomain_count: int
    digit_count: int
    special_character_count: int
    uses_https: bool
    host_is_ip: bool


class URLAnalysisResponse(BaseModel):
    normalized_url: str
    verdict: str
    risk_score: int = Field(ge=0, le=100)
    signals: list[RiskSignal]
    features: URLFeatures


class ScanRecord(URLAnalysisResponse):
    id: int
    created_at: str


class ScanSummary(BaseModel):
    scanned: int
    threats: int
    safe: int


class EmailAnalysisRequest(BaseModel):
    text: str = Field(min_length=10, max_length=20_000)
    sender: str | None = Field(default=None, max_length=320)


class NetworkAnalysisRequest(BaseModel):
    failed_login_count: int = Field(default=0, ge=0, le=10_000)
    requests_per_minute: int = Field(default=1, ge=0, le=1_000_000)
    bytes_out: int = Field(default=0, ge=0)
    hour: int = Field(default=12, ge=0, le=23)
    is_new_country: bool = False
    privileged_action: bool = False


class SecurityAnalysisResponse(BaseModel):
    analysis_type: str
    verdict: str
    risk_score: int = Field(ge=0, le=100)
    signals: list[RiskSignal]
    features: dict
    summary: str
    id: int | None = None
    created_at: str | None = None


class AnalyticsSummary(BaseModel):
    url_verdicts: list[dict]
    event_verdicts: list[dict]
    incidents: list[dict]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=4000)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    source: str = Field(min_length=2, max_length=100)


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved)$")


class Incident(IncidentCreate):
    id: int
    status: str
    created_at: str
    updated_at: str
