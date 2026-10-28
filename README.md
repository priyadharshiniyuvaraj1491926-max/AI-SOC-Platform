# AI-SOC Platform

AI-SOC is a local-first, SIEM-agnostic investigation workspace. It ingests
uploaded security logs, normalizes event fields, runs deterministic detection
rules, calculates explainable priority scores, and creates analyst investigations.
It is a decision-support companion, not a replacement for a SIEM.

## Features

- React, TypeScript, Vite, Framer Motion, Lucide, and Recharts frontend with a
  reduced-motion-aware network canvas, responsive SOC workspace, and dark red theme.
- FastAPI API with Argon2 password hashing, signed HTTP-only session cookies,
  CSRF checks, explicit CORS, login throttling, and per-user data isolation.
- JSON, JSONL, CSV, TXT, and LOG parsers that normalize vendor aliases while
  retaining raw event evidence and reporting malformed rows.
- Deterministic authentication, process, port-scan, DNS, baseline, lab hash, and
  repeated-activity detections; explainable 0–100 score breakdowns.
- Alert triage, status audit, investigations, analyst checklist and notes,
  time-window correlations, MITRE ATT&CK mapping, and validated IOC extraction.
- Data-backed dashboard and analytics, a labeled sample scenario through the
  same ingestion pipeline, and safe demo-data cleanup.
- Optional connectors are displayed truthfully as not implemented. No external
  AI service or automatic response action is configured.

## Windows PowerShell quick start

Open PowerShell in this `AI-SOC-Platform` folder. Python 3.11+ and Node.js 20+
with npm are recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Copy-Item .env.example .env
npm --prefix frontend install
$env:APP_SECRET_KEY = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))")
```

Start the API in the first PowerShell window:

```powershell
Set-Location backend
$env:PYTHONPATH = (Get-Location).Path
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8009
```

Start the frontend in a second window from the project folder:

```powershell
Set-Location frontend
npm run dev
```

Then open [http://127.0.0.1:5173](http://127.0.0.1:5173) and create an account.
The API health endpoint is [http://127.0.0.1:8009/api/health](http://127.0.0.1:8009/api/health)
and interactive API docs are at [http://127.0.0.1:8009/docs](http://127.0.0.1:8009/docs).

If PowerShell blocks local scripts, use the direct commands above or invoke a
script for this process with
`powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1`.
Convenience launch scripts are `scripts\run-backend.ps1` and
`scripts\run-frontend.ps1`.

## Tests and production build

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m pytest -q
Set-Location ..\frontend
npm run build
```

## Sample data

Use **Load demo scenario** in the Ingestion page. Demo events are explicitly
labeled, stored as demo records, and processed by the normal pipeline. The
**Clear demo data** action asks for confirmation and removes records associated
with demo ingestions. Other examples are under `data/samples/`.

## Configuration and deployment

Copy `.env.example` to `.env`. The backend loads it from the project root. Set a
unique secret in the shell before starting the API; the secret is not shipped in
the frontend. Configure `DATABASE_URL`, exact `ALLOWED_ORIGINS`, upload limit,
session lifetime, and secure cookies for the target environment. Vite reads the
public `VITE_API_BASE_URL` from the project root at build time.

See [API routes](docs/API.md), [security decisions](docs/SECURITY.md), and
[deployment notes](docs/DEPLOYMENT.md). Production deployment has not occurred.
The current connector adapters, external AI configuration, password reset,
Alembic migrations, and production-grade shared rate limiting remain outside
this local implementation.
