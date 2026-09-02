# AI Cyber Threat Intelligence Platform

An explainable cybersecurity platform for detecting suspicious URLs, scoring risk, and presenting actionable threat signals. The current milestone provides a tested FastAPI backend and URL-analysis engine; the React dashboard and trained ML classifier are the next development stage.

## Current milestone

- URL normalization and validation
- Explainable phishing-risk scoring
- Detection of IP-based hosts, suspicious keywords, URL shorteners, punycode, excessive subdomains, unusual ports and insecure HTTP
- REST API with interactive Swagger documentation
- Health endpoint
- Unit and API tests
- Docker and GitHub Actions support

## Architecture

```text
Client / React dashboard (next milestone)
                |
                v
          FastAPI REST API
                |
                v
    URL feature and risk engine
                |
                v
 ML classifier + PostgreSQL (planned)
```

## API

### Analyze a URL

`POST /api/v1/analyze-url`

```json
{
  "url": "http://secure-account-login.example.com/verify"
}
```

Example response:

```json
{
  "normalized_url": "http://secure-account-login.example.com/verify",
  "verdict": "suspicious",
  "risk_score": 55,
  "signals": [
    {
      "name": "insecure_protocol",
      "weight": 15,
      "description": "The URL uses HTTP instead of HTTPS."
    }
  ]
}
```

Other endpoints:

- `GET /` — service information
- `GET /api/v1/health` — health check
- `GET /docs` — Swagger UI

## Run locally

```bash
git clone https://github.com/ANKITJOSHI1605/AI-Cyber-Threat-Platform.git
cd AI-Cyber-Threat-Platform
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

## Tests

```bash
pytest backend/tests -q
```

## Docker

```bash
docker build -t cyber-threat-api .
docker run -p 8000:8000 cyber-threat-api
```

## Roadmap

- [x] Explainable URL-risk engine
- [x] FastAPI endpoints and automated tests
- [x] Docker and continuous integration
- [ ] Train and evaluate phishing URL classifier
- [ ] Store scans and incidents in PostgreSQL
- [ ] Add JWT authentication and role-based access
- [ ] Build React security dashboard
- [ ] Integrate VirusTotal threat intelligence
- [ ] Add network anomaly-detection module
- [ ] Deploy frontend, API and database

## Technology stack

Python, FastAPI, Pydantic, Pytest, Docker, GitHub Actions. Planned additions include scikit-learn/XGBoost, PostgreSQL and React.
