# MailGuard AI — README

## Overview

**MailGuard AI** is a professional SOC-grade email threat detection platform built for **Smart India Hackathon 2026**.

It analyses emails for phishing, BEC (Business Email Compromise), credential theft, payment fraud, and social engineering using a multi-pillar heuristic scoring engine with full explainability.

---

## Architecture

```
Browser  →  http://127.0.0.1:8000
              ↓  (same-origin API calls: /api/...)
         FastAPI (app.py)
              ↓
         Detection Engine (detector.py)
              ↓
         SQLite (data/mailguard.db)
```

Single-origin design — FastAPI serves **both** the frontend and the API. No separate dev server, no CORS issues, no hard-coded ports in JavaScript.

---

## Quick Start (Windows)

### 1. Navigate to the project directory

```cmd
cd "d:\project 1"
```

### 2. Create and activate a virtual environment

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```cmd
pip install -r requirements.txt
```

### 4. Run the server

```cmd
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Open the application

Open your browser and go to:

```
http://127.0.0.1:8000
```

The application will seed six demo emails automatically on first launch.

---

## Project Structure

```
d:\project 1\
├── app.py               # FastAPI entry point + demo seeder
├── detector.py          # Multi-pillar threat detection engine
├── db.py                # SQLite layer (auto-initialised)
├── geo.py               # IP geolocation (graceful fallback)
├── models.py            # Pydantic request/response models
├── requirements.txt
├── .env.example         # Copy to .env for optional configuration
├── README.md
│
├── static/
│   ├── index.html       # SPA shell
│   ├── css/
│   │   └── app.css      # Dark SOC theme
│   └── js/
│       ├── app.js       # SPA router + shared utilities
│       ├── analyze.js   # Analyze page
│       ├── dashboard.js # SOC dashboard + charts
│       ├── reports.js   # Case list + filters
│       ├── report.js    # Single case forensic view
│       └── about.js     # About page
│
├── data/
│   └── mailguard.db     # Created automatically on first run
│
└── tests/
    └── test_api.py      # Automated API + unit tests
```

---

## API Reference

All endpoints are at `http://127.0.0.1:8000/api/`.

Interactive docs: `http://127.0.0.1:8000/api/docs`

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/health` | Liveness check |
| `POST` | `/api/analyze` | Analyse an email |
| `GET`  | `/api/emails` | List all analysed emails |
| `GET`  | `/api/emails/{id}` | Get full analysis for one email |
| `PATCH`| `/api/emails/{id}/status` | Update analyst status |
| `GET`  | `/api/dashboard` | Dashboard statistics |
| `GET`  | `/api/reports` | All reports (full records) |

### POST /api/analyze — Request body

```json
{
  "subject":      "Email subject",
  "from_address": "Sender Name <sender@domain.com>",
  "reply_to":     "reply@domain.com",
  "sender_ip":    "185.220.101.45",
  "headers":      "Received: from ...\nAuthentication-Results: spf=fail",
  "body":         "Email body text..."
}
```

All fields are optional — provide at least `body`, `headers`, or `from_address`.

---

## Running Tests

```cmd
pytest tests/ -v
```

---

## Detection Engine

The threat score (0–100) is computed from five pillars:

| Pillar | Max Score | Description |
|--------|-----------|-------------|
| Header Forensics | 25 | Reply-To mismatch, SPF/DKIM/DMARC, typosquatting, display-name spoofing |
| Content Analysis | 25 | Urgency, credentials, financial, threatening, sensitive info patterns |
| URL Intelligence | 20 | IP URLs, shortened URLs, bad TLDs, lookalike domains, obfuscation |
| Behavioural Signals | 15 | New bank accounts, executive impersonation, confidentiality pressure |
| Heuristic ML Layer | 15 | Weighted multi-pillar corroboration (transparent, not a neural net) |

### Verdict Thresholds

| Score | Verdict |
|-------|---------|
| 0–29  | SAFE |
| 30–59 | SUSPICIOUS |
| 60–79 | HIGH RISK |
| 80–100| CRITICAL |

---

## External Services

| Service | Purpose | API Key Required |
|---------|---------|-----------------|
| ip-api.com | IP Geolocation | **No** (free, 45 req/min) |

If ip-api.com is unreachable, analysis continues with `Country: Unknown`.

---

## Honest Capability Statement

| Feature | Type |
|---------|------|
| Header forensics | ✅ Real rule-based checks |
| Content pattern detection | ✅ Real regex pattern bank |
| URL extraction & scoring | ✅ Real |
| IP Geolocation | ✅ Real (ip-api.com) |
| Geolocation fallback | ✅ Real graceful fallback |
| Threat scoring | ✅ Real multi-signal composite |
| "ML" layer | ⚠ Heuristic (weighted combination, labelled clearly) |
| Demo seed emails | 📋 Demo/sample data |

---

## Environment Configuration (optional)

Copy `.env.example` to `.env` to override defaults:

```
MAX_BODY_SIZE=100000
DB_PATH=data/mailguard.db
```

---

## Troubleshooting

### Port already in use
```cmd
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```
Or use a different port:
```cmd
python -m uvicorn app:app --host 127.0.0.1 --port 8001 --reload
```

### Python not found
Install Python 3.10+ from https://www.python.org/downloads/  
Ensure "Add Python to PATH" is checked during installation.

### pip install fails
```cmd
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Virtual environment activation fails
```cmd
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.venv\Scripts\activate
```

### Database issues
Delete `data/mailguard.db` and restart — the schema is recreated automatically.

### Browser shows blank page
Ensure you are opening `http://127.0.0.1:8000` (not `file://...`).  
Check the uvicorn terminal for errors.

### Geolocation shows "Unknown"
This is normal if ip-api.com is unreachable (offline, rate-limited, or the IP is private).  
Analysis results and scoring are not affected.

---

## SIH 2026 Demonstration Guide

1. Start the server and open `http://127.0.0.1:8000`
2. Navigate to **Analyze** — load any demo email and click **Analyze Email**
3. Review the threat score, breakdown, reasons, and forensic details
4. Navigate to **Dashboard** — show live statistics and charts
5. Navigate to **Reports** — filter by verdict or category
6. Click any row to open the full **Case Report** view
7. Change the status (Reviewed / Quarantined) to demonstrate case management
8. Navigate to **About** for capability summary and transparency notes
