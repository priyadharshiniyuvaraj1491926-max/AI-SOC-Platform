import pytest
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    def override_db():
        session = TestingSession()
        try: yield session
        finally: session.close()
    app.dependency_overrides[get_db] = override_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


async def register(client, email="analyst@example.org"):
    response = await client.post("/api/auth/register", json={"name":"Analyst One", "email":email, "password":"VeryStrong!Pass2026"})
    assert response.status_code == 201, response.text
    return response.json()["csrf_token"]


@pytest.mark.anyio
async def test_health_asgi(client):
    response = await client.get("/api/health")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_httpx_transport_smoke():
    from fastapi import FastAPI
    simple_app = FastAPI()
    @simple_app.get("/")
    async def ping(): return {"ok": True}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=simple_app), base_url="http://testserver") as test_client:
        response = await test_client.get("/")
        assert response.json() == {"ok": True}


@pytest.mark.anyio
async def test_auth_protection_registration_login_and_bad_password(client):
    assert (await client.get("/api/dashboard")).status_code == 401
    csrf = await register(client)
    assert (await client.get("/api/auth/me")).json()["email"] == "analyst@example.org"
    assert (await client.post("/api/auth/logout", headers={"X-CSRF-Token":csrf})).status_code == 200
    response = await client.post("/api/auth/login", json={"email":"analyst@example.org", "password":"wrong-password"})
    assert response.status_code == 401
    response = await client.post("/api/auth/login", json={"email":"analyst@example.org", "password":"VeryStrong!Pass2026"})
    assert response.status_code == 200
    assert (await client.get("/api/dashboard")).status_code == 200


@pytest.mark.anyio
async def test_upload_detection_persistence_and_investigation_update(client):
    csrf = await register(client)
    lines = "\n".join([f'{{"timestamp":"2026-10-27T10:0{i}:00Z","host":"lab-ws","user":"alex","src_ip":"192.0.2.8","event_type":"authentication","status":"failed"}}' for i in range(5)])
    response = await client.post("/api/ingestions", headers={"X-CSRF-Token":csrf}, files={"files":("auth.jsonl", lines.encode(), "application/jsonl")})
    assert response.status_code == 201, response.text
    body = response.json()["results"][0]
    assert body["event_count"] == 5 and body["alert_count"] >= 1
    repeated = await client.post("/api/ingestions", headers={"X-CSRF-Token":csrf}, files={"files":("auth.jsonl", lines.encode(), "application/jsonl")})
    assert repeated.status_code == 201 and repeated.json()["results"][0]["event_count"] == 0
    assert repeated.json()["results"][0]["summary"]["duplicates_skipped"] == 5
    assert (await client.get("/api/events")).json()["total"] == 5
    alerts = (await client.get("/api/alerts")).json()["items"]
    alert = next(item for item in alerts if item["rule_id"] == "AUTH-001")
    detail = (await client.get(f"/api/alerts/{alert['id']}")).json()
    assert len(detail["events"]) == 5
    inv_id = detail["investigation_id"]
    updated = await client.patch(f"/api/investigations/{inv_id}", json={"status":"Investigating"}, headers={"X-CSRF-Token":csrf})
    assert updated.status_code == 200 and updated.json()["status"] == "Investigating"
    note = await client.post(f"/api/investigations/{inv_id}/notes", json={"body":"Reviewed authentication sequence."}, headers={"X-CSRF-Token":csrf})
    assert note.status_code == 201
    assert (await client.get(f"/api/investigations/{inv_id}")).json()["notes"][0]["body"] == "Reviewed authentication sequence."
    retry = await client.post(f"/api/ingestions/{body['id']}/reprocess", headers={"X-CSRF-Token":csrf})
    assert retry.status_code == 200 and retry.json()["alerts_created"] == 0


@pytest.mark.anyio
async def test_related_evidence_refreshes_existing_alert_risk(client):
    csrf = await register(client)
    first_five = "\n".join([f'{{"timestamp":"2026-10-27T10:0{i}:00Z","host":"lab-ws","user":"alex","src_ip":"192.0.2.8","event_type":"authentication","status":"failed"}}' for i in range(5)])
    uploaded = await client.post("/api/ingestions", headers={"X-CSRF-Token":csrf}, files={"files":("first.jsonl", first_five.encode(), "application/jsonl")})
    assert uploaded.status_code == 201
    alert = next(x for x in (await client.get("/api/alerts")).json()["items"] if x["rule_id"] == "AUTH-001")
    assert alert["risk_score"] == 47 and alert["severity"] == "Medium"
    sixth = b'{"timestamp":"2026-10-27T10:05:00Z","host":"lab-ws","user":"alex","src_ip":"192.0.2.8","event_type":"authentication","status":"failed"}'
    second = await client.post("/api/ingestions", headers={"X-CSRF-Token":csrf}, files={"files":("additional.json", sixth, "application/json")})
    assert second.status_code == 201
    refreshed = next(x for x in (await client.get("/api/alerts")).json()["items"] if x["rule_id"] == "AUTH-001")
    assert refreshed["id"] == alert["id"]
    assert refreshed["risk_score"] == 50 and refreshed["severity"] == "High"
    assert len(refreshed["event_ids"]) == 6
    assert second.json()["results"][0]["summary"]["alerts_refreshed"] == 1


@pytest.mark.anyio
async def test_upload_validation_csrf_and_user_isolation(client):
    csrf = await register(client, "first@example.org")
    unauthorized = await client.post("/api/ingestions", files={"files":("x.json", b"{}", "application/json")})
    assert unauthorized.status_code == 403
    invalid = await client.post("/api/ingestions", headers={"X-CSRF-Token":csrf}, files={"files":("x.exe", b"not executable", "application/octet-stream")})
    assert invalid.status_code == 201 and invalid.json()["results"][0]["status"] == "failed"
    payload = b'{"event_id":"record-1","host":"private-host","event_type":"test"}'
    uploaded = await client.post("/api/ingestions", headers={"X-CSRF-Token":csrf}, files={"files":("x.json", payload, "application/json")})
    assert uploaded.status_code == 201 and (await client.get("/api/events")).json()["total"] == 1
    assert (await client.get("/api/events")).json()["items"][0]["event_id"] == "record-1"
    await client.post("/api/auth/logout", headers={"X-CSRF-Token":csrf})
    await register(client, "second@example.org")
    assert (await client.get("/api/events")).json()["total"] == 0
    assert (await client.get("/api/iocs")).json() == []


@pytest.mark.anyio
async def test_sample_demo_pipeline_and_safe_clear(client):
    csrf = await register(client)
    result = await client.post("/api/ingestions/sample", headers={"X-CSRF-Token":csrf})
    assert result.status_code == 201
    assert result.json()["is_demo"] is True
    assert result.json()["event_count"] >= 15
    assert (await client.get("/api/alerts")).json()["total"] >= 4
    cleared = await client.delete("/api/ingestions/demo-data", headers={"X-CSRF-Token":csrf})
    assert cleared.status_code == 200 and cleared.json()["deleted_events"] == result.json()["event_count"]
    assert (await client.get("/api/events")).json()["total"] == 0
