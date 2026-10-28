# Security decisions and limits

- Passwords are hashed with Argon2id through `argon2-cffi`.
- Login uses a signed, HTTP-only, SameSite=Lax cookie with expiry. Mutations use
  a double-submit CSRF token; configured origins are checked and CORS is explicit.
- The local development secret is randomly generated per API process if no real
  key is configured. Set a stable random `APP_SECRET_KEY`; production mode refuses
  a missing or placeholder key. Set `COOKIE_SECURE=true` behind HTTPS.
- Authentication throttling is an in-memory 10 failed attempts per minute per
  client IP. Production deployments should also apply shared rate limiting at
  the reverse proxy or gateway.
- Detection thresholds and the failed-login/correlation windows can be adjusted
  with `FAILED_LOGIN_THRESHOLD`, `BRUTE_FORCE_THRESHOLD`, `PORT_SCAN_THRESHOLD`,
  `FAILED_LOGIN_WINDOW_MINUTES`, and `CORRELATION_WINDOW_MINUTES`.
- Uploads are size-limited, parsed in memory, never executed, and never saved as
  original files. Normalized fields and raw event evidence are persisted.
  Reprocessing reruns detections on stored normalized events; it does not replay
  original file bytes.
- Every query scopes records by the signed-in user's owner ID. SQLite is intended
  for local use and single-process development.
- AI is not configured. Investigation guidance is deterministic and labeled as
  rule-based advisory. No event content leaves the host. Response steps never
  execute containment actions.
- `data/test_ioc_hashes.txt` contains only the harmless EICAR test signature,
  labeled as a local lab indicator. A match is not an assertion of compromise.
- Optional SIEM connectors are listed as not implemented. No connector health or
  external intelligence lookup is simulated.
- The application does not include a password reset, invite flow, role-based
  administration, multi-factor authentication, or account deletion workflow.
