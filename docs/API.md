# API overview

FastAPI provides the interactive OpenAPI schema at `/docs` and `/openapi.json`.
All workspace records are scoped to the authenticated user. Responses never
include password hashes or connector credentials.

## Routes

| Group | Routes |
| --- | --- |
| Health | `GET /api/health` |
| Authentication | `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout` |
| Dashboard and analytics | `GET /api/dashboard?days=7`, `GET /api/analytics?days=30` |
| Ingestion | `POST /api/ingestions` (multipart `files`), `GET /api/ingestions`, `POST /api/ingestions/{id}/reprocess`, `POST /api/ingestions/sample`, `DELETE /api/ingestions/demo-data` |
| Evidence | `GET /api/events`, `GET /api/iocs`, `GET /api/correlations`, `GET /api/mitre` |
| Alerts | `GET /api/alerts`, `GET /api/alerts/{id}`, `PATCH /api/alerts/{id}/status` |
| Investigations | `GET /api/investigations`, `GET /api/investigations/{id}`, `PATCH /api/investigations/{id}`, `PATCH /api/investigations/{id}/checklist`, `POST /api/investigations/{id}/notes` |
| Workspace | `GET /api/connectors`, `GET /api/audit` |

Authenticated mutations require the `X-CSRF-Token` header matching the CSRF
cookie issued by login or signup. The frontend client handles this automatically.
List endpoints use bounded page and limit arguments where they return event or
alert collections.
