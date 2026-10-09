# SBOM Risk & Trust Auditor – Backend

Express API: parses CycloneDX / SPDX JSON, looks up vulnerabilities in **OSV**, computes contextual risk and an SBOM trust score.

## Run
```bash
npm install
npm start          # http://localhost:5000
npm test           # uses a local mock of OSV (no network needed)
```
Env (all optional): `PORT=5000`, `CORS_ORIGIN=http://localhost:5173`, `OSV_BASE_URL`, `OSV_TIMEOUT_MS`, `BODY_LIMIT=25mb`, `PERSIST_SCANS=true` (writes `data/scans.json`; default is in-memory only). For Groq AI features, set `GROQ_API_KEY` in `backend/sbomback/.env`; `GROQ_MODEL` can optionally override the default `qwen/qwen3.8-27b`. Restart the backend after setting the key. Never put the key in frontend environment variables or commit `.env`.

Copy `.env.example` to `.env` and replace the placeholder with a valid API key from the Groq Console. The health endpoint reports whether a key is present, not whether the provider accepts it.

## Endpoints (`/api`)
| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Public liveness/feed status |
| POST | `/auth/register` | Create an account with email and a password of at least 8 characters; starts a secure server session |
| POST | `/auth/login` | Verify credentials and start a server session |
| GET | `/auth/me` | Return the current session user |
| POST | `/auth/logout` | Revoke the current server session |
| POST | `/scans` (alias `/analyze`) | body `{fileName, name?, sbom}` (sbom = parsed object or raw string). Returns full scan (201) |
| POST | `/sbom/compare` | body `{baseline, updated}`; each value is an SBOM JSON object/string or `{fileName, content}`. Returns added, removed, unchanged and version-changed components; does not scan for vulnerabilities |
| POST | `/sbom/generate-updated` | body `{fileName, sbom, findings?}`. Reuses supplied completed-scan findings when present; otherwise runs OSV analysis. Returns a copy with available higher fixed versions applied and suggested changes, without saving a scan |
| GET | `/scans` | scan history rows |
| GET/DELETE | `/scans/:id` | `:id` may be `latest` |
| POST | `/scans/:id/ai-summary` | Generates a Groq explanation and next steps from verified scan metrics and up to 15 highest-priority findings |
| POST | `/scans/:id/ai-chat` | body `{question, history?}`; asks Groq about the selected scan (question max 1000 chars, up to 8 prior messages) |
| GET | `/scans/:id/overview` | metrics, risk, trust, top 10 findings, distribution, quality, uncertain |
| GET | `/scans/:id/vulnerabilities` | `q, severity, fixAvailable, dependencyType, environment, confidence, sort=risk, page, pageSize` |
| GET | `/scans/:id/vulnerabilities/:findingId` | detail: factors, remediation command, affected ranges, dependency path |
| GET | `/scans/:id/components[/:componentId]` | `q, dependencyType, environment, vulnerable` |
| GET | `/scans/:id/quality` | trust breakdown, NTIA checks, warnings |
| GET | `/scans/:id/report` | report summary |
| GET | `/scans/:id/export?format=json\|csv` | file download |

Errors: `{error:{code,message,reason,action}}` with codes `INVALID_JSON, UNSUPPORTED_FORMAT, EMPTY_SBOM, MISSING_REQUIRED_INFORMATION, OSV_UNAVAILABLE (502), SCAN_NOT_FOUND, FILE_TOO_LARGE`.

Frontend: read the file with `file.text()` and `POST` `{fileName, sbom: text}` to `${VITE_API_URL ?? 'http://localhost:5000'}/api/scans`.

All scan and AI endpoints require an authenticated session. Password hashes are stored in the ignored `data/accounts.json` file; opaque session IDs are kept server-side and sent only in HttpOnly, SameSite=Strict cookies. Authentication attempts are rate-limited. Scan history and details are scoped to the account that created each scan. Sessions expire after 12 hours and are invalidated when the backend restarts. Set `COOKIE_SECURE=true` when serving over HTTPS (it is enabled automatically in production mode).

## What is real vs. not assessed
- Real: format validation, component extraction, OSV lookup (`/v1/querybatch` + `/v1/vulns/{id}`), CVSS v3 scoring, alias de-duplication, fixed versions, direct/transitive from SBOM relationships.
- **Unknown stays unknown**: no relationships → `DEPENDENCY: UNKNOWN`; no scope → environment `UNKNOWN`; unversioned components are listed as `unassessedComponents`, never counted as clean.
- **Not assessed**: exploitability (EPSS/KEV), reachability, provenance. Findings carry `exploitability.status = NOT_ASSESSED`.
- CVSS v4-only advisories fall back to the advisory's severity label, else `UNKNOWN`.
- OSV down → HTTP 502 `OSV_UNAVAILABLE` (never a fake "no vulnerabilities").
- Groq AI is optional; missing credentials return HTTP 503 `AI_NOT_CONFIGURED`. AI responses are advisory, are not vulnerability evidence, and are only generated on user request. The backend sends scan summary metrics, up to 15 findings, and (for chat) recent conversation messages to Groq; the raw SBOM is not sent.
- SBOM comparison validates and parses both SPDX and CycloneDX inventories, then compares package URLs (or ecosystem/name where a PURL is unavailable) and versions. It does not call OSV and does not detect vulnerabilities.
- Updated-SBOM generation uses OSV-listed fixed versions to create a suggested inventory copy and does not guarantee dependency compatibility or vulnerability-free software; review and test generated updates before adopting them.

## Risk model (`src/services/risk.js`)
`score = base × dependency × environment (+4 if no fix)`; base = CVSS×10 (or label default). Direct 1.0 / transitive 0.85 / unknown 0.92; production 1.0 / development 0.6 / unknown 0.95. Confidence HIGH/MEDIUM/LOW/UNKNOWN from how many of severity, dependency type, environment, version are known. Overall risk = 60% top finding + 40% mean of top 5.
