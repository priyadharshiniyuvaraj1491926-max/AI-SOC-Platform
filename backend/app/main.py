from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import time

ROOT = Path(__file__).resolve().parents[2]
from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from argon2 import PasswordHasher, exceptions as argon2_errors
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .db import Base, DATA_DIR, SessionLocal, engine, get_db
from .models import Alert, AuditLog, Connector, Correlation, Event, Ingestion, Investigation, IOC, MitreMapping, Note, User, utcnow
from .parsing import parse_content
from .engine import RULES, correlate, detect
from .schemas import (
    AlertDetailResponse, AlertPageResponse, AlertResponse, AnalyticsResponse,
    AuditResponse, ChecklistResponse, ChecklistUpdate, ClearDemoResponse,
    ConnectorResponse, CorrelationResponse, EventPageResponse, HealthResponse,
    IngestionResponse, InvestigationDetailResponse, InvestigationStatusResponse,
    InvestigationSummaryResponse, IOCResponse, LoginRequest, MitreResponse,
    NoteCreate, NoteResponse, OkResponse, RegisterRequest, ReprocessResponse,
    StatusUpdate, UploadBatchResponse, UserResponse, DashboardResponse,
)

APP_SECRET = os.getenv("APP_SECRET_KEY")
if os.getenv("APP_ENV", "development").lower() == "production" and (not APP_SECRET or APP_SECRET.lower().startswith("replace")):
    raise RuntimeError("APP_SECRET_KEY must be configured in production")
APP_SECRET = APP_SECRET if APP_SECRET and not APP_SECRET.lower().startswith("replace") else secrets.token_urlsafe(48)
SIGNER = URLSafeTimedSerializer(APP_SECRET, salt="aisoc-session-v1")
PASSWORDS = PasswordHasher()
SESSION_COOKIE = "aisoc_session"
CSRF_COOKIE = "aisoc_csrf"
SESSION_TTL = int(os.getenv("SESSION_TTL_SECONDS", "28800"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024
ALLOWED_EXTENSIONS = {".txt", ".log", ".json", ".jsonl", ".csv"}
ALLOWED_ORIGINS = [x.strip() for x in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if x.strip()]
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
AUTH_ATTEMPTS = {}

Base.metadata.create_all(bind=engine)
app = FastAPI(title="AI-SOC Investigation Platform", version="1.0.0", description="SIEM-agnostic, local-first security event ingestion and investigation API.")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"])

@app.middleware("http")
async def origin_guard(request: Request, call_next):
    origin = request.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        return Response(content='{"detail":"Origin is not allowed"}', status_code=403, media_type="application/json")
    return await call_next(request)

def _session_data(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token: return None
    try: return SIGNER.loads(token, max_age=SESSION_TTL)
    except (BadSignature, SignatureExpired): return None

def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    session = _session_data(request)
    if not session or not session.get("sub"):
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, int(session["sub"]))
    if not user: raise HTTPException(status_code=401, detail="Authentication required")
    return user

def csrf_guard(request: Request, x_csrf_token: str | None = Header(default=None)):
    session = _session_data(request)
    cookie = request.cookies.get(CSRF_COOKIE)
    if not session or not cookie or not x_csrf_token or not secrets.compare_digest(str(session.get("csrf", "")), str(cookie)) or not secrets.compare_digest(str(cookie), str(x_csrf_token)):
        raise HTTPException(status_code=403, detail="CSRF check failed. Refresh the page and try again.")

def _set_session(response: Response, user: User):
    csrf = secrets.token_urlsafe(24)
    value = SIGNER.dumps({"sub": user.id, "csrf": csrf})
    response.set_cookie(SESSION_COOKIE, value, httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=SESSION_TTL, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=COOKIE_SECURE, samesite="lax", max_age=SESSION_TTL, path="/")
    return csrf

def _audit(db, user_id, action, kind, entity_id, details=None):
    db.add(AuditLog(owner_id=user_id, action=action, entity_type=kind, entity_id=str(entity_id), details=details or {}))

def _iso(dt):
    if dt is None: return None
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def _event_dict(event: Event):
    return {"id": event.id, "event_id": event.event_id, "timestamp": _iso(event.timestamp), "source": event.source, "host": event.host, "user": event.user, "src_ip": event.src_ip, "dst_ip": event.dst_ip, "src_port": event.src_port, "dst_port": event.dst_port, "event_type": event.event_type, "action": event.action, "status": event.status, "process_name": event.process_name, "process_command_line": event.process_command_line, "process_hash": event.process_hash, "destination_domain": event.destination_domain, "raw_event": event.raw_event, "ingestion_id": event.ingestion_id}

def _alert_dict(alert: Alert):
    return {"id": alert.id, "rule_id": alert.rule_id, "name": alert.name, "description": alert.description, "severity": alert.severity, "risk_score": alert.risk_score, "risk_breakdown": alert.risk_breakdown, "confidence": alert.confidence, "status": alert.status, "evidence": alert.evidence, "event_ids": alert.event_ids, "mitre": alert.mitre, "recommendations": alert.recommendations, "created_at": _iso(alert.created_at), "ingestion_id": alert.ingestion_id}

def _upsert_alert_candidates(db: Session, user: User, ingestion: Ingestion, candidates):
    created, refreshed = [], []
    stored_alerts = db.scalars(select(Alert).where(Alert.owner_id == user.id)).all()
    for candidate in candidates:
        event_ids = [e.id for e in candidate["events"] if isinstance(e, Event) and e.id]
        event_id_set = set(event_ids)
        exact = next((a for a in stored_alerts if a.dedupe_key == candidate["dedupe_key"]), None)
        if exact:
            continue
        overlaps = [a for a in stored_alerts if a.rule_id == candidate["rule_id"] and event_id_set.intersection(a.event_ids or [])]
        if overlaps:
            alert = max(overlaps, key=lambda a: len(event_id_set.intersection(a.event_ids or [])))
            old_score = alert.risk_score
            alert.name = candidate["name"]
            alert.description = candidate["description"]
            alert.severity = candidate["severity"]
            alert.risk_score = candidate["risk_score"]
            alert.risk_breakdown = candidate["risk_breakdown"]
            alert.confidence = candidate["confidence"]
            alert.evidence = candidate["evidence"]
            alert.event_ids = event_ids
            alert.mitre = candidate["mitre"]
            alert.recommendations = candidate["recommendations"]
            alert.dedupe_key = candidate["dedupe_key"]
            alert.ingestion_id = ingestion.id
            mappings = db.scalars(select(MitreMapping).where(MitreMapping.owner_id == user.id, MitreMapping.alert_id == alert.id)).all()
            by_technique = {m.technique_id: m for m in mappings}
            wanted = {m["id"] for m in candidate["mitre"]}
            for technique_id, mapping in by_technique.items():
                if technique_id not in wanted: db.delete(mapping)
            for mapping in candidate["mitre"]:
                existing = by_technique.get(mapping["id"])
                if existing: existing.rationale = candidate["description"]
                else: db.add(MitreMapping(owner_id=user.id, alert_id=alert.id, technique_id=mapping["id"], technique_name=mapping["name"], rationale=candidate["description"]))
            investigation = db.scalar(select(Investigation).where(Investigation.owner_id == user.id, Investigation.alert_id == alert.id))
            if investigation:
                investigation.title = alert.name
                investigation.priority = alert.severity
            _audit(db, user.id, "alert_evidence_refreshed", "alert", alert.id, {"previous_risk_score": old_score, "risk_score": alert.risk_score, "event_count": len(event_ids)})
            refreshed.append(alert)
            continue
        alert = Alert(owner_id=user.id, ingestion_id=ingestion.id, rule_id=candidate["rule_id"], name=candidate["name"], description=candidate["description"], severity=candidate["severity"], risk_score=candidate["risk_score"], risk_breakdown=candidate["risk_breakdown"], confidence=candidate["confidence"], evidence=candidate["evidence"], event_ids=event_ids, mitre=candidate["mitre"], recommendations=candidate["recommendations"], dedupe_key=candidate["dedupe_key"])
        db.add(alert); db.flush()
        for mapping in candidate["mitre"]:
            db.add(MitreMapping(owner_id=user.id, alert_id=alert.id, technique_id=mapping["id"], technique_name=mapping["name"], rationale=candidate["description"]))
        checklist = [{"label": x, "done": False} for x in ["Validate the alert and timestamp", "Identify affected host and account", "Review related authentication and process activity", "Check available IOCs", "Document findings and next action"]]
        db.add(Investigation(owner_id=user.id, alert_id=alert.id, title=alert.name, priority=alert.severity, checklist=checklist))
        stored_alerts.append(alert)
        created.append(alert)
    return created, refreshed

def _ingest_bytes(db: Session, user: User, filename: str, content: bytes, source="upload", is_demo=False):
    if len(content) > MAX_UPLOAD_BYTES: raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS: raise HTTPException(status_code=415, detail="Unsupported file format. Use .txt, .log, .json, .jsonl, or .csv")
    safe_name = Path(filename.replace("\\", "/")).name[:255] or "uploaded-log"
    ingestion = Ingestion(owner_id=user.id, filename=safe_name, source=source, is_demo=is_demo)
    db.add(ingestion); db.flush()
    try:
        normalized, errors, row_count = parse_content(safe_name, content)
    except ValueError as exc:
        ingestion.status = "failed"; ingestion.summary = {"error": str(exc)}; db.commit()
        raise HTTPException(status_code=415, detail=str(exc))
    existing = set(db.scalars(select(Event.fingerprint).where(Event.owner_id == user.id)).all())
    inserted = []
    for item in normalized:
        fingerprint = item["fingerprint"]
        if fingerprint in existing: continue
        existing.add(fingerprint)
        fields = {k: v for k, v in item.items() if k not in {"fingerprint", "raw_event"}}
        event = Event(owner_id=user.id, ingestion_id=ingestion.id, fingerprint=fingerprint, raw_event=item["raw_event"], **fields)
        db.add(event); inserted.append(event)
    db.flush()
    all_events = db.scalars(select(Event).where(Event.owner_id == user.id)).all()
    candidates = detect(all_events)
    new_alerts, refreshed_alerts = _upsert_alert_candidates(db, user, ingestion, candidates)
    for group in correlate(all_events):
        event_ids = group["event_ids"]
        already = db.scalars(select(Correlation).where(Correlation.owner_id == user.id)).all()
        if not any(sorted(x.event_ids or []) == sorted(event_ids) for x in already):
            db.add(Correlation(owner_id=user.id, ingestion_id=ingestion.id, entity_type=group["entity_type"], entity_value=str(group["entity"]), event_ids=event_ids, reason=group["why"], uncertainty=group["uncertainty"]))
    # Extract format-validated indicators; unknown reputation stays explicit.
    seen_iocs = set(db.execute(select(IOC.value, IOC.kind).where(IOC.owner_id == user.id)).all())
    for event in inserted:
        values = []
        for raw, kind in ((event.src_ip, "IPv4/IPv6"), (event.dst_ip, "IPv4/IPv6")):
            if raw:
                try: values.append((str(ipaddress.ip_address(raw)), kind))
                except ValueError: pass
        if event.destination_domain and re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", event.destination_domain): values.append((event.destination_domain.lower(), "Domain"))
        if event.process_hash: values.append((event.process_hash, "File hash"))
        for value, kind in values:
            if (value, kind) not in seen_iocs:
                seen_iocs.add((value, kind))
                db.add(IOC(owner_id=user.id, value=value, kind=kind, match_status="Local test IOC match" if value == "44d88612fea8a8f36de82e1278abb02f" else "Unknown reputation", source="Extracted from uploaded event"))
    ingestion.status = "completed" if inserted or not errors else "completed_with_errors"
    ingestion.event_count = len(inserted)
    rejected = sum(1 for issue in errors if issue.get("severity") != "warning")
    ingestion.rejected_count = rejected
    ingestion.alert_count = len(new_alerts)
    ingestion.summary = {"rows_seen": row_count, "events_parsed": len(normalized), "events_stored": len(inserted), "duplicates_skipped": len(normalized) - len(inserted), "rejected_rows": rejected, "alerts_generated": len(new_alerts), "alerts_refreshed": len(refreshed_alerts), "detection_summary": dict(Counter(a.rule_id for a in new_alerts + refreshed_alerts)), "errors": errors[:100], "demo_data": is_demo}
    _audit(db, user.id, "log_ingested", "ingestion", ingestion.id, {"filename": safe_name, "events_stored": len(inserted), "is_demo": is_demo})
    db.commit(); db.refresh(ingestion)
    return {"id": ingestion.id, "filename": ingestion.filename, "status": ingestion.status, "event_count": ingestion.event_count, "rejected_count": ingestion.rejected_count, "alert_count": ingestion.alert_count, "summary": ingestion.summary, "created_at": _iso(ingestion.created_at), "is_demo": ingestion.is_demo}

@app.get("/api/health", response_model=HealthResponse)
def health(): return {"status": "ok", "service": "AI-SOC API", "database": "connected"}

@app.post("/api/auth/register", status_code=201, response_model=UserResponse)
def register(payload: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    email = payload.email.lower()
    if db.scalar(select(User.id).where(User.email == email)): raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(name=payload.name.strip(), email=email, password_hash=PASSWORDS.hash(payload.password))
    db.add(user)
    try: db.commit(); db.refresh(user)
    except IntegrityError: db.rollback(); raise HTTPException(status_code=409, detail="An account with this email already exists")
    csrf = _set_session(response, user)
    return {"id": user.id, "name": user.name, "email": user.email, "csrf_token": csrf}

@app.post("/api/auth/login", response_model=UserResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    key = request.client.host if request.client else "unknown"
    now = time.time(); recent = [t for t in AUTH_ATTEMPTS.get(key, []) if now - t < 60]
    if len(recent) >= 10: raise HTTPException(status_code=429, detail="Too many login attempts. Wait a minute and retry.")
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    try: valid = bool(user and PASSWORDS.verify(user.password_hash, payload.password))
    except argon2_errors.VerificationError: valid = False
    if not valid:
        recent.append(now); AUTH_ATTEMPTS[key] = recent
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    AUTH_ATTEMPTS.pop(key, None)
    csrf = _set_session(response, user)
    return {"id": user.id, "name": user.name, "email": user.email, "csrf_token": csrf}

@app.get("/api/auth/me", response_model=UserResponse)
def me(request: Request, user: User = Depends(current_user)):
    session = _session_data(request)
    return {"id": user.id, "name": user.name, "email": user.email, "csrf_token": session.get("csrf")}

@app.post("/api/auth/logout", dependencies=[Depends(csrf_guard)], response_model=OkResponse)
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/"); response.delete_cookie(CSRF_COOKIE, path="/")
    return {"ok": True}

@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db), days: int = 7):
    days = min(max(days, 7), 90)
    events = db.scalars(select(Event).where(Event.owner_id == user.id)).all()
    alerts = db.scalars(select(Alert).where(Alert.owner_id == user.id)).all()
    investigations = db.scalars(select(Investigation).where(Investigation.owner_id == user.id)).all()
    ingestions = db.scalars(select(Ingestion).where(Ingestion.owner_id == user.id).order_by(Ingestion.created_at.desc()).limit(5)).all()
    severity = Counter(a.severity for a in alerts)
    today = datetime.now(timezone.utc).date()
    event_by_day, alert_by_day = Counter(), Counter()
    for e in events:
        if e.timestamp: event_by_day[e.timestamp.date().isoformat()] += 1
    for a in alerts: alert_by_day[(a.created_at.date() if a.created_at else today).isoformat()] += 1
    trend = [{"date": (today - timedelta(days=i)).isoformat(), "events": event_by_day[(today-timedelta(days=i)).isoformat()], "alerts": alert_by_day[(today-timedelta(days=i)).isoformat()]} for i in reversed(range(days))]
    sources = Counter(e.source or "Unspecified" for e in events)
    detections = Counter(a.name for a in alerts)
    return {"metrics": {"events": len(events), "alerts": len(alerts), "critical": severity["Critical"], "high": severity["High"], "medium": severity["Medium"], "low": severity["Low"], "open_investigations": sum(i.status.lower() not in {"resolved", "closed"} for i in investigations)}, "severity_distribution": [{"name": s, "value": severity[s]} for s in ("Critical", "High", "Medium", "Low")], "detection_categories": [{"name": k, "value": v} for k,v in detections.most_common()], "data_source_distribution": [{"name": k, "value": v} for k,v in sources.items()], "event_trend": trend, "recent_alerts": [_alert_dict(a) for a in sorted(alerts, key=lambda a:a.created_at or utcnow(), reverse=True)[:6]], "recent_ingestions": [{"id": i.id, "filename": i.filename, "created_at": _iso(i.created_at), "event_count": i.event_count, "alert_count": i.alert_count, "status": i.status, "is_demo": i.is_demo} for i in ingestions], "demo_events": sum(1 for e in events if e.ingestion_id and db.get(Ingestion, e.ingestion_id) and db.get(Ingestion, e.ingestion_id).is_demo)}

@app.get("/api/events", response_model=EventPageResponse)
def list_events(search: str = "", page: int = 1, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    page, limit = max(page, 1), min(max(limit, 1), 200)
    query = select(Event).where(Event.owner_id == user.id)
    if search.strip():
        needle = f"%{search.strip()}%"
        query = query.where((Event.host.ilike(needle)) | (Event.user.ilike(needle)) | (Event.src_ip.ilike(needle)) | (Event.event_type.ilike(needle)) | (Event.destination_domain.ilike(needle)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(Event.timestamp.desc().nullslast(), Event.id.desc()).offset((page-1)*limit).limit(limit)).all()
    return {"items": [_event_dict(e) for e in rows], "total": total, "page": page, "limit": limit}

@app.get("/api/ingestions", response_model=list[IngestionResponse])
def list_ingestions(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Ingestion).where(Ingestion.owner_id == user.id).order_by(Ingestion.created_at.desc()).limit(100)).all()
    return [{"id": i.id, "filename": i.filename, "source": i.source, "is_demo": i.is_demo, "status": i.status, "event_count": i.event_count, "rejected_count": i.rejected_count, "alert_count": i.alert_count, "summary": i.summary, "created_at": _iso(i.created_at)} for i in rows]

@app.post("/api/ingestions/{ingestion_id}/reprocess", dependencies=[Depends(csrf_guard)], response_model=ReprocessResponse)
def reprocess_ingestion(ingestion_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ingestion = db.scalar(select(Ingestion).where(Ingestion.id == ingestion_id, Ingestion.owner_id == user.id))
    if not ingestion: raise HTTPException(status_code=404, detail="Ingestion not found")
    events = db.scalars(select(Event).where(Event.owner_id == user.id)).all()
    candidates = detect(events)
    created, refreshed = _upsert_alert_candidates(db, user, ingestion, candidates)
    ingestion.alert_count = len(created)
    ingestion.summary = {**(ingestion.summary or {}), "alerts_generated": len(created), "alerts_refreshed": len(refreshed), "reprocessed_at": _iso(utcnow()), "reprocess_note": "Detections were rerun on the user's stored normalized events; original file bytes are not retained."}
    _audit(db, user.id, "ingestion_reprocessed", "ingestion", ingestion.id, {"alerts_created": len(created), "alerts_refreshed": len(refreshed)})
    db.commit()
    return {"ingestion_id": ingestion.id, "alerts_created": len(created), "alerts_updated": len(refreshed), "alerts": [_alert_dict(a) for a in created], "note": "Reprocessed stored normalized events with duplicate safeguards and refreshed changed evidence."}

@app.post("/api/ingestions", status_code=201, dependencies=[Depends(csrf_guard)], response_model=UploadBatchResponse)
async def upload_logs(files: list[UploadFile] = File(...), user: User = Depends(current_user), db: Session = Depends(get_db)):
    if len(files) > 10: raise HTTPException(status_code=400, detail="Upload at most 10 files at a time")
    results = []
    for file in files:
        try:
            chunks, size = [], 0
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES: raise HTTPException(status_code=413, detail=f"Exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit")
                chunks.append(chunk)
            try: results.append(_ingest_bytes(db, user, file.filename or "uploaded.log", b"".join(chunks)))
            except HTTPException as exc: results.append({"filename": Path((file.filename or "uploaded.log").replace("\\", "/")).name, "status": "failed", "error": exc.detail, "event_count": 0, "alert_count": 0, "rejected_count": 0})
        except HTTPException as exc:
            results.append({"filename": Path((file.filename or "uploaded.log").replace("\\", "/")).name, "status": "failed", "error": exc.detail, "event_count": 0, "alert_count": 0, "rejected_count": 0})
        finally: await file.close()
    return {"results": results}

@app.post("/api/ingestions/sample", status_code=201, dependencies=[Depends(csrf_guard)], response_model=IngestionResponse)
def load_sample(user: User = Depends(current_user), db: Session = Depends(get_db)):
    sample_path = ROOT / "data" / "samples" / "blue_team_scenario.jsonl"
    return _ingest_bytes(db, user, sample_path.name, sample_path.read_bytes(), source="sample", is_demo=True)

@app.delete("/api/ingestions/demo-data", dependencies=[Depends(csrf_guard)], response_model=ClearDemoResponse)
def clear_demo(user: User = Depends(current_user), db: Session = Depends(get_db)):
    ids = list(db.scalars(select(Ingestion.id).where(Ingestion.owner_id == user.id, Ingestion.is_demo.is_(True))).all())
    if not ids: return {"deleted_ingestions": 0, "deleted_events": 0}
    demo_event_ids = set(db.scalars(select(Event.id).where(Event.owner_id == user.id, Event.ingestion_id.in_(ids))).all())
    demo_alerts = list(db.scalars(select(Alert).where(Alert.owner_id == user.id, Alert.ingestion_id.in_(ids))).all())
    alerts_to_remove = []
    for alert in demo_alerts:
        if set(alert.event_ids or []).issubset(demo_event_ids): alerts_to_remove.append(alert.id)
        else: alert.ingestion_id = None  # Keep detections that also use real events.
    if alerts_to_remove:
        db.query(MitreMapping).filter(MitreMapping.owner_id == user.id, MitreMapping.alert_id.in_(alerts_to_remove)).delete(synchronize_session=False)
        inv_ids = list(db.scalars(select(Investigation.id).where(Investigation.owner_id == user.id, Investigation.alert_id.in_(alerts_to_remove))).all())
        if inv_ids: db.query(Note).filter(Note.owner_id == user.id, Note.investigation_id.in_(inv_ids)).delete(synchronize_session=False)
        db.query(Investigation).filter(Investigation.owner_id == user.id, Investigation.alert_id.in_(alerts_to_remove)).delete(synchronize_session=False)
        db.query(Alert).filter(Alert.owner_id == user.id, Alert.id.in_(alerts_to_remove)).delete(synchronize_session=False)
    correlations = list(db.scalars(select(Correlation).where(Correlation.owner_id == user.id, Correlation.ingestion_id.in_(ids))).all())
    for correlation in correlations:
        if set(correlation.event_ids or []).issubset(demo_event_ids): db.delete(correlation)
        else: correlation.ingestion_id = None
    event_count = db.query(Event).filter(Event.owner_id == user.id, Event.ingestion_id.in_(ids)).delete(synchronize_session=False)
    db.query(Ingestion).filter(Ingestion.owner_id == user.id, Ingestion.id.in_(ids)).delete(synchronize_session=False)
    remaining = db.scalars(select(Event).where(Event.owner_id == user.id)).all()
    observed = set()
    for event in remaining:
        if event.src_ip: observed.add((event.src_ip, "IPv4/IPv6"))
        if event.dst_ip: observed.add((event.dst_ip, "IPv4/IPv6"))
        if event.destination_domain: observed.add((event.destination_domain.lower(), "Domain"))
        if event.process_hash: observed.add((event.process_hash, "File hash"))
    stale_iocs = db.scalars(select(IOC).where(IOC.owner_id == user.id)).all()
    for ioc in stale_iocs:
        if (ioc.value, ioc.kind) not in observed: db.delete(ioc)
    _audit(db, user.id, "demo_data_cleared", "ingestion", "demo", {"ingestions": len(ids), "events": event_count})
    db.commit()
    return {"deleted_ingestions": len(ids), "deleted_events": event_count, "deleted_alerts": len(alerts_to_remove)}

@app.get("/api/alerts", response_model=AlertPageResponse)
def list_alerts(search: str = "", severity: str = "", status: str = "", days: int = 0, sort: str = "time", page: int = 1, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = select(Alert).where(Alert.owner_id == user.id)
    if severity: query = query.where(Alert.severity == severity)
    if status: query = query.where(Alert.status == status)
    if days > 0: query = query.where(Alert.created_at >= utcnow() - timedelta(days=min(days, 365)))
    if search.strip():
        needle = f"%{search.strip()}%"; query = query.where((Alert.name.ilike(needle)) | (Alert.description.ilike(needle)) | (Alert.rule_id.ilike(needle)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    ordering = (Alert.risk_score.desc(), Alert.created_at.desc()) if sort == "risk" else Alert.created_at.desc()
    rows = db.scalars(query.order_by(ordering).offset((max(page,1)-1)*min(max(limit,1),200)).limit(min(max(limit,1),200))).all()
    return {"items": [_alert_dict(a) for a in rows], "total": total, "page": page, "limit": limit}

def _owned_alert(db, owner_id, alert_id):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.owner_id == owner_id))
    if not alert: raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.get("/api/alerts/{alert_id}", response_model=AlertDetailResponse)
def alert_detail(alert_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    alert = _owned_alert(db, user.id, alert_id)
    events = db.scalars(select(Event).where(Event.owner_id == user.id, Event.id.in_(alert.event_ids or [])).order_by(Event.timestamp)).all() if alert.event_ids else []
    return {**_alert_dict(alert), "events": [_event_dict(e) for e in events], "investigation_id": db.scalar(select(Investigation.id).where(Investigation.owner_id == user.id, Investigation.alert_id == alert.id))}

@app.patch("/api/alerts/{alert_id}/status", dependencies=[Depends(csrf_guard)], response_model=AlertResponse)
def update_alert_status(alert_id: int, payload: StatusUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    allowed = {"New", "Investigating", "Escalated", "Resolved", "False Positive"}
    if payload.status not in allowed: raise HTTPException(status_code=422, detail=f"Status must be one of {', '.join(sorted(allowed))}")
    alert = _owned_alert(db, user.id, alert_id); old = alert.status; alert.status = payload.status
    _audit(db, user.id, "alert_status_changed", "alert", alert.id, {"from": old, "to": alert.status}); db.commit()
    return _alert_dict(alert)

@app.get("/api/investigations", response_model=list[InvestigationSummaryResponse])
def list_investigations(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Investigation).where(Investigation.owner_id == user.id).order_by(Investigation.updated_at.desc())).all()
    return [{"id": i.id, "alert_id": i.alert_id, "title": i.title, "status": i.status, "priority": i.priority, "created_at": _iso(i.created_at), "updated_at": _iso(i.updated_at)} for i in rows]

def _owned_investigation(db, owner_id, investigation_id):
    inv = db.scalar(select(Investigation).where(Investigation.id == investigation_id, Investigation.owner_id == owner_id))
    if not inv: raise HTTPException(status_code=404, detail="Investigation not found")
    return inv

@app.get("/api/investigations/{investigation_id}", response_model=InvestigationDetailResponse)
def investigation_detail(investigation_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    inv = _owned_investigation(db, user.id, investigation_id)
    alert = db.scalar(select(Alert).where(Alert.id == inv.alert_id, Alert.owner_id == user.id)) if inv.alert_id else None
    events = db.scalars(select(Event).where(Event.owner_id == user.id, Event.id.in_(alert.event_ids or [])).order_by(Event.timestamp)).all() if alert and alert.event_ids else []
    notes = db.scalars(select(Note).where(Note.owner_id == user.id, Note.investigation_id == inv.id).order_by(Note.created_at)).all()
    related = correlate(events)
    history = db.scalars(select(AuditLog).where(AuditLog.owner_id == user.id, AuditLog.entity_type == "investigation", AuditLog.entity_id == str(inv.id)).order_by(AuditLog.created_at.desc()).limit(30)).all()
    return {"id": inv.id, "alert_id": inv.alert_id, "title": inv.title, "status": inv.status, "priority": inv.priority, "created_at": _iso(inv.created_at), "updated_at": _iso(inv.updated_at), "checklist": inv.checklist, "alert": _alert_dict(alert) if alert else None, "events": [_event_dict(e) for e in events], "correlations": [{"entity_type": g["entity_type"], "entity": g["entity"], "event_ids": g["event_ids"], "why": g["why"], "uncertainty": g["uncertainty"]} for g in related], "notes": [{"id": n.id, "body": n.body, "created_at": _iso(n.created_at)} for n in notes], "history": [{"action": h.action, "details": h.details, "created_at": _iso(h.created_at)} for h in history], "assistant": _advisory(alert, events)}

@app.patch("/api/investigations/{investigation_id}", dependencies=[Depends(csrf_guard)], response_model=InvestigationStatusResponse)
def update_investigation(investigation_id: int, payload: StatusUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if payload.status not in {"Open", "Investigating", "Escalated", "Resolved", "Closed"}: raise HTTPException(status_code=422, detail="Invalid investigation status")
    inv = _owned_investigation(db, user.id, investigation_id); old = inv.status; inv.status = payload.status
    _audit(db, user.id, "investigation_status_changed", "investigation", inv.id, {"from": old, "to": inv.status}); db.commit()
    return {"id": inv.id, "status": inv.status, "updated_at": _iso(inv.updated_at)}

@app.patch("/api/investigations/{investigation_id}/checklist", dependencies=[Depends(csrf_guard)], response_model=ChecklistResponse)
def update_checklist(investigation_id: int, payload: ChecklistUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    inv = _owned_investigation(db, user.id, investigation_id)
    inv.checklist = [{"label": str(x.get("label", ""))[:300], "done": bool(x.get("done"))} for x in payload.checklist[:30] if isinstance(x, dict)]
    _audit(db, user.id, "investigation_checklist_updated", "investigation", inv.id, {"items": len(inv.checklist)}); db.commit()
    return {"checklist": inv.checklist}

@app.post("/api/investigations/{investigation_id}/notes", status_code=201, dependencies=[Depends(csrf_guard)], response_model=NoteResponse)
def add_note(investigation_id: int, payload: NoteCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    inv = _owned_investigation(db, user.id, investigation_id)
    note = Note(owner_id=user.id, investigation_id=inv.id, body=payload.body.strip()); db.add(note)
    _audit(db, user.id, "analyst_note_added", "investigation", inv.id, {}); db.commit(); db.refresh(note)
    return {"id": note.id, "body": note.body, "created_at": _iso(note.created_at)}

def _advisory(alert, events):
    if not alert: return {"label": "Rule-based advisory", "summary": "No alert is linked to this investigation yet.", "next_steps": ["Review available events", "Collect additional source and host context"], "missing_evidence": ["A linked detection alert"]}
    entity = alert.evidence.get("user") or alert.evidence.get("host") or alert.evidence.get("source_ip") or "the affected entity"
    missing = []
    if not any(e.src_ip for e in events): missing.append("Source IP evidence")
    if not any(e.host for e in events): missing.append("Host attribution")
    if len(events) < 2: missing.append("Corroborating events")
    return {"label": "Deterministic rule-based advisory (no AI model used)", "summary": f"Observed {len(events)} event(s) supporting {alert.name} for {entity}. This is a prioritization signal, not proof of compromise.", "why_alerted": alert.description, "risk_score": alert.risk_score, "risk_breakdown": alert.risk_breakdown, "mitre": alert.mitre, "evidence": alert.evidence, "next_steps": alert.recommendations, "missing_evidence": missing, "response_note": "Review containment through approved organizational procedures. No response action was executed."}

@app.get("/api/analytics", response_model=AnalyticsResponse)
def analytics(user: User = Depends(current_user), db: Session = Depends(get_db), days: int = 0):
    event_query = select(Event).where(Event.owner_id == user.id); alert_query = select(Alert).where(Alert.owner_id == user.id)
    if days > 0:
        cutoff = utcnow() - timedelta(days=min(days, 365)); event_query = event_query.where(Event.timestamp >= cutoff); alert_query = alert_query.where(Alert.created_at >= cutoff)
    events = db.scalars(event_query).all(); alerts = db.scalars(alert_query).all()
    def top(items, key, limit=8):
        values = Counter(getattr(x, key) for x in items if getattr(x, key)); return [{"name": k, "value": v} for k,v in values.most_common(limit)]
    severities = Counter(a.severity for a in alerts); rules = Counter(a.name for a in alerts)
    source_counts = Counter(e.source or "Unspecified" for e in events)
    risk = [{"range": "0–24", "value": sum(a.risk_score < 25 for a in alerts)}, {"range": "25–49", "value": sum(25 <= a.risk_score < 50 for a in alerts)}, {"range": "50–74", "value": sum(50 <= a.risk_score < 75 for a in alerts)}, {"range": "75–100", "value": sum(a.risk_score >= 75 for a in alerts)}]
    correlation_query = select(func.count()).select_from(Correlation).where(Correlation.owner_id == user.id)
    if days > 0: correlation_query = correlation_query.where(Correlation.created_at >= cutoff)
    trend = dashboard(user=user, db=db, days=min(max(days or 7, 7), 90))["event_trend"]
    return {"total_events": len(events), "total_alerts": len(alerts), "severity_distribution": [{"name": s, "value": severities[s]} for s in ("Critical", "High", "Medium", "Low")], "detection_categories": [{"name": k, "value": v} for k,v in rules.most_common()], "data_sources": [{"name": k, "value": v} for k,v in source_counts.items()], "risk_distribution": risk, "top_hosts": top(events, "host"), "top_accounts": top(events, "user"), "frequent_rules": [{"name": k, "value": v} for k,v in rules.most_common()], "correlation_count": db.scalar(correlation_query) or 0, "trend": trend}

@app.get("/api/iocs", response_model=list[IOCResponse])
def list_iocs(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(IOC).where(IOC.owner_id == user.id).order_by(IOC.first_seen.desc()).limit(500)).all()
    output = []
    for x in rows:
        if x.kind == "IPv4/IPv6": related = db.scalars(select(Event).where(Event.owner_id == user.id, (Event.src_ip == x.value) | (Event.dst_ip == x.value))).all()
        elif x.kind == "Domain": related = db.scalars(select(Event).where(Event.owner_id == user.id, Event.destination_domain == x.value)).all()
        else: related = db.scalars(select(Event).where(Event.owner_id == user.id, Event.process_hash == x.value)).all()
        event_ids = [e.id for e in related]
        alert_ids = [a.id for a in db.scalars(select(Alert).where(Alert.owner_id == user.id)).all() if set(a.event_ids or []).intersection(event_ids)]
        output.append({"id": x.id, "value": x.value, "kind": x.kind, "match_status": x.match_status, "source": x.source, "first_seen": _iso(x.first_seen), "event_ids": event_ids, "alert_ids": alert_ids})
    return output

@app.get("/api/correlations", response_model=list[CorrelationResponse])
def list_correlations(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Correlation).where(Correlation.owner_id == user.id).order_by(Correlation.created_at.desc()).limit(200)).all()
    return [{"id": c.id, "entity_type": c.entity_type, "entity": c.entity_value, "event_ids": c.event_ids, "reason": c.reason, "uncertainty": c.uncertainty, "created_at": _iso(c.created_at)} for c in rows]

@app.get("/api/mitre", response_model=list[MitreResponse])
def list_mitre(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(MitreMapping).where(MitreMapping.owner_id == user.id).order_by(MitreMapping.id.desc()).limit(500)).all()
    return [{"id": x.id, "alert_id": x.alert_id, "technique_id": x.technique_id, "technique_name": x.technique_name, "rationale": x.rationale, "url": f"https://attack.mitre.org/techniques/{x.technique_id.replace('.', '/')}/"} for x in rows]

@app.get("/api/connectors", response_model=list[ConnectorResponse])
def list_connectors(user: User = Depends(current_user), db: Session = Depends(get_db)):
    implemented = [{"name": "File upload", "status": "Available", "description": "Normalized-event interface used by the ingestion workflow."}]
    optional = [{"name": x, "status": "Not implemented", "description": "Connector adapter is not implemented; no connection is claimed."} for x in ("Splunk", "Wazuh", "Microsoft Sentinel", "Elastic Security", "Generic API")]
    saved = {c.name: c for c in db.scalars(select(Connector).where(Connector.owner_id == user.id)).all()}
    for item in optional:
        if item["name"] in saved: item["status"] = saved[item["name"]].status
    return implemented + optional

@app.get("/api/audit", response_model=list[AuditResponse])
def audit_log(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).where(AuditLog.owner_id == user.id).order_by(AuditLog.created_at.desc()).limit(100)).all()
    return [{"id": x.id, "action": x.action, "entity_type": x.entity_type, "entity_id": x.entity_id, "details": x.details, "created_at": _iso(x.created_at)} for x in rows]
