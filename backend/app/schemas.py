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
