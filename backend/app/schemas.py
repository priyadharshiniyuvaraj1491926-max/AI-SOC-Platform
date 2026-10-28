from datetime import datetime
from typing import Any
from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class StatusUpdate(BaseModel):
    status: str

class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=10000)

class ChecklistUpdate(BaseModel):
    checklist: list[dict]

class HealthResponse(BaseModel):
    status: str
    service: str
    database: str

class OkResponse(BaseModel):
    ok: bool

class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    csrf_token: str | None = None

class EventResponse(BaseModel):
    id: int
    event_id: str | None = None
    timestamp: datetime | None = None
    source: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    event_type: str | None = None
    action: str | None = None
    status: str | None = None
    process_name: str | None = None
    process_command_line: str | None = None
    process_hash: str | None = None
    destination_domain: str | None = None
    raw_event: Any = None
    ingestion_id: int | None = None

class EventPageResponse(BaseModel):
    items: list[EventResponse]
    total: int
    page: int
    limit: int

class AlertResponse(BaseModel):
    id: int
    rule_id: str
    name: str
    description: str
    severity: str
    risk_score: int
    risk_breakdown: dict[str, Any]
    confidence: str
    status: str
    evidence: dict[str, Any]
    event_ids: list[int]
    mitre: list[dict[str, Any]]
    recommendations: list[str]
    created_at: datetime | None = None
    ingestion_id: int | None = None

class AlertDetailResponse(AlertResponse):
    events: list[EventResponse]
    investigation_id: int | None = None

class AlertPageResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    limit: int

class IngestionResponse(BaseModel):
    id: int
    filename: str
    source: str | None = None
    is_demo: bool = False
    status: str
    event_count: int
    rejected_count: int
    alert_count: int
    summary: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None

class IngestionFailureResponse(BaseModel):
    filename: str
    status: str
    error: str
    event_count: int = 0
    rejected_count: int = 0
    alert_count: int = 0

class UploadBatchResponse(BaseModel):
    results: list[IngestionResponse | IngestionFailureResponse]

class ReprocessResponse(BaseModel):
    ingestion_id: int
    alerts_created: int
    alerts_updated: int
    alerts: list[AlertResponse]
    note: str

class ClearDemoResponse(BaseModel):
    deleted_ingestions: int
    deleted_events: int
    deleted_alerts: int = 0

class DistributionResponse(BaseModel):
    name: str
    value: int

class TrendResponse(BaseModel):
    date: str
    events: int
    alerts: int

class DashboardMetricsResponse(BaseModel):
    events: int
    alerts: int
    critical: int
    high: int
    medium: int
    low: int
    open_investigations: int

class RecentIngestionResponse(BaseModel):
    id: int
    filename: str
    created_at: datetime | None = None
    event_count: int
    alert_count: int
    status: str
    is_demo: bool

class DashboardResponse(BaseModel):
    metrics: DashboardMetricsResponse
    severity_distribution: list[DistributionResponse]
    detection_categories: list[DistributionResponse]
    data_source_distribution: list[DistributionResponse]
    event_trend: list[TrendResponse]
    recent_alerts: list[AlertResponse]
    recent_ingestions: list[RecentIngestionResponse]
    demo_events: int

class InvestigationSummaryResponse(BaseModel):
    id: int
    alert_id: int | None = None
    title: str
    status: str
    priority: str
    created_at: datetime | None = None
    updated_at: datetime | None = None

class CorrelationResponse(BaseModel):
    id: int | None = None
    entity_type: str
    entity: str
    event_ids: list[int]
    reason: str | None = None
    why: str | None = None
    uncertainty: str
    created_at: datetime | None = None

class NoteResponse(BaseModel):
    id: int
    body: str
    created_at: datetime | None = None

class ActivityResponse(BaseModel):
    action: str
    details: dict[str, Any]
    created_at: datetime | None = None

class InvestigationDetailResponse(InvestigationSummaryResponse):
    checklist: list[dict[str, Any]]
    alert: AlertResponse | None = None
    events: list[EventResponse]
    correlations: list[CorrelationResponse]
    notes: list[NoteResponse]
    history: list[ActivityResponse]
    assistant: dict[str, Any]

class InvestigationStatusResponse(BaseModel):
    id: int
    status: str
    updated_at: datetime | None = None

class ChecklistResponse(BaseModel):
    checklist: list[dict[str, Any]]

class AnalyticsRiskBandResponse(BaseModel):
    range: str
    value: int

class AnalyticsResponse(BaseModel):
    total_events: int
    total_alerts: int
    severity_distribution: list[DistributionResponse]
    detection_categories: list[DistributionResponse]
    data_sources: list[DistributionResponse]
    risk_distribution: list[AnalyticsRiskBandResponse]
    top_hosts: list[DistributionResponse]
    top_accounts: list[DistributionResponse]
    frequent_rules: list[DistributionResponse]
    correlation_count: int
    trend: list[TrendResponse]

class IOCResponse(BaseModel):
    id: int
    value: str
    kind: str
    match_status: str
    source: str
    first_seen: datetime | None = None
    event_ids: list[int]
    alert_ids: list[int]

class ConnectorResponse(BaseModel):
    name: str
    status: str
    description: str

class MitreResponse(BaseModel):
    id: int
    alert_id: int
    technique_id: str
    technique_name: str
    rationale: str
    url: str

class AuditResponse(BaseModel):
    id: int
    action: str
    entity_type: str
    entity_id: str
    details: dict[str, Any]
    created_at: datetime | None = None

class NoteCreateResponse(NoteResponse):
    pass
