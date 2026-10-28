# Deployment preparation

The Vite frontend builds to `frontend/dist` and can be hosted as static assets.
FastAPI runs as an independent ASGI service. Set `VITE_API_BASE_URL` at frontend
build time and configure the exact frontend origin in `ALLOWED_ORIGINS` on the
API. Keep frontend and API on the same site (for example, separate subdomains of
one organization domain) so the SameSite=Lax session cookie is sent. Terminate
TLS at the host or trusted reverse proxy and set `COOKIE_SECURE=true`.

For production, use PostgreSQL or another durable database, persistent encrypted
storage and backups, a managed secret for `APP_SECRET_KEY`, and shared request
rate limiting. SQLite and the local filesystem are development defaults. The
current schema initializes with SQLAlchemy `create_all`; Alembic migrations have
not been added, so production schema evolution needs a migration workflow before
upgrades. Do not deploy with the development server or a placeholder secret.

No deployment has been performed by this project setup.
