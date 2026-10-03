# Anisakys v2 — Roadmap

Working memory for the v2 programme. Every phase ships as one branch
`feat/v2-faseN-<topic>` per affected repository and one PR into `dev`.
Tick boxes only when the change is merged into the phase branch **and**
covered by a test. Numbers in this file are measured, never estimated.

- Backend: `JuanVilla424/anisakys` (base `dev`)
- Frontend: `JuanVilla424/anisakys-frontend` (base `dev`)
- Audit baseline: backend `c1640eb`, frontend `a49b3bf` (2026-10-03)

## Baseline (measured 2026-10-03, before phase 0)

| Metric | Value | How |
|---|---|---|
| Backend tests | 576 passed, 1 failed (env-dependent) | `pytest -k "not real"` against PostgreSQL 16 |
| Backend coverage | 47.9 % overall (detection 46.2 %, intelligence 41.2 %, reporting 45.0 %, api 45.1 %) | `pytest --cov=src` |
| Undefined names (F821) | 31 | `ruff check --select F821` |
| Other pyflakes findings | 324 | `ruff check --select F` |
| Files not black-formatted | 31 | `black --check -l 100 src tests` |
| CI running tests | No | `.github/workflows/*.yml` |
| Frontend test files | 6 | `src/**/__tests__` |
| Detection quality (precision/recall/TTD/TTT) | **Not measurable** — no labels, no harness | Phase 1 |

## Decisions

| # | Decision | Why / alternatives |
|---|---|---|
| D1 | Commits are authored as the project's existing automation identity (`Cloud Agent <cloud-agent@hichigo>`, the identity of the latest commits) with no AI attribution trailers. | Owner's authorship rule. |
| D2 | Phase 0 runs as parallel workstreams (A: API & security, B: reporting & processes, C: detection & providers, D: schema, platform & CI, F: frontend) on sub-branches merged into the phase branch; one PR per repository. | Independent files, faster; merge conflicts resolved by the lead. |
| D3 | `src/main.py` stays a re-export facade (ruff `F401` ignored there). | Tests and scripts import through it; removing the facade is a phase 6 refactor. |
| D4 | Ruff gate starts with pyflakes (`F`) and widens per phase (`E,W,B,I,UP,S` for new/changed code in phase 6). | Turning on the full rule set at once would be a 1000+ line cosmetic diff. |
| D5 | `SecretStr` conversion of every credential setting happens once the phase 0 workstreams are merged. | It touches every provider client; doing it in parallel guarantees conflicts. |
| D6 | Frontend phase 0 removes fabricated data and fixes correctness/security bugs; the WebGL graph rewrite and the design system land in phase 7. | The prompt lists the graph under phase 0 *and* 7; a rewrite before the data model of phase 4 would be thrown away. |
| D7 | Phase 0 hardens the SPA with a strict CSP and security headers; the `HttpOnly` cookie session with CSRF lands with RBAC/users in phase 6. | The backend has API keys but no user/session model yet; a cookie session needs it. |
| D8 | STIX bundles are generated server-side from phase 0 (`POST /api/v2/stix/bundle`, STIX 2.1, TLP 2.0, AMBER by default); the frontend only sends indicators and downloads. | Moves trust-sensitive formatting to the server as required. |
| D9 | All DDL moves into Alembic in phase 0 (migration `003`), runtime `CREATE/ALTER/DROP` is removed and tests build their schema with `alembic upgrade head`. | Needed to create `redirect_chains`, kill the `DROP TABLE` self-healing and stop schema drift. |
| D10 | Providers that cannot be verified from the build sandbox (URLVoid endpoint) are disabled by default with a startup warning until verified with a real key. | Avoids presenting a dead integration as a clean verdict. |

## Risks

| Risk | Mitigation |
|---|---|
| Phase 0 touches the reporting path that sends real e-mail. | Every reporting test runs with SMTP mocked and `SMTP_PORT=2`; no real report is sent without the owner's approval. |
| Schema consolidation could diverge from existing production databases. | Migration `003` uses `IF NOT EXISTS` for every object and is tested from an empty DB and from a DB created by the old runtime DDL. |
| Free/public feeds (OpenPhish community, VirusTotal public, GSB v4) are non-commercial. | Provider plugins carry `commercial_ok`; startup warns when non-commercial sources are active. |
| No production traffic or labels available in the sandbox. | Phase 1 builds the labelled dataset and harness; until then quality claims are not made. |

## Phase 0 — Fix every known bug (branch `feat/v2-fase0-estabilizacion`)

### Foundation (lead)
- [x] Black formatting baseline (separate cosmetic commit).
- [x] Undefined names fixed: scanner (gc/json/text/datetime/log_with_context + JSONB cast), abuse_manager (create_report_record/timeout/serialize_for_json), analyzer (thresholds/json/datetime/AttachmentConfig), API `/stats` (GRINDER0X_API_URL), main `--reset-offset` (save_offset). Regression tests in `tests/regressions/`.
- [x] Confidence thresholds default to 85/70 (were `None` → `TypeError`).
- [x] Shutdown via `threading.Event`, signal handlers installed, worker threads joined; second signal forces exit.
- [x] Pyflakes clean; ruff `F` configured as the gate; `.env.test.example`.

### A — API, auth & HTTP serving
- [ ] `PATCH /api/v1/reports` int/bool `CASE` (always 500).
- [ ] `/multi-scan` uses `conn` outside its `with`.
- [ ] `/reports` parses JSON recipients by splitting on commas.
- [ ] `/graph` `focus` case bug; `/campaigns` N+1.
- [ ] Validated query parameters (no unhandled `int()`), no `str(e)` in responses.
- [ ] gunicorn entrypoint, no debug server, bind `127.0.0.1` by default, configurable `ProxyFix`.
- [ ] Rate limiting backed by Redis (shared across workers).
- [ ] `/metrics` requires a token; `/health` pings the DB via `observability/health.py`.
- [ ] Scopes `email_admin` and `report_send`; mailbox allowlist; API-submitted URLs require analyst approval before any report; SSRF check on `/report`.
- [ ] `POST /api/v2/stix/bundle` (STIX 2.1, TLP 2.0, AMBER default); stop exporting registrar abuse mailboxes as IOCs.

### B — Reporting pipeline & process roles
- [ ] One scheduler process role runs reporting/takedown/follow-up/GSB jobs; API and scanner roles do not.
- [ ] Workers claim rows with `SELECT … FOR UPDATE SKIP LOCKED`; short per-site transactions.
- [ ] SMTP rate limiter shared through the database.
- [ ] Outbox `pending → sending → sent/failed`, idempotent per (site, recipient, report).
- [ ] Stable report IDs carried in the subject; escalation CCs only when escalating.
- [ ] Template: no hard-coded FCM/SIMIT text, no "manual report" wording, renders threat level and confidence, `text/plain` part, defanged URL.
- [ ] Screenshot actually reaches GSB submission (reads the file, base64-encodes it).
- [ ] Form-only providers produce an analyst task instead of an e-mail.
- [ ] Recipient safety: never registrant/WHOIS-wide addresses, never MX hosts as hosting; recipient domain validated against the site's eTLD+1 (public suffix list).
- [ ] Follow-up advances `sla_deadline`.

### C — Detection & threat-intel providers
- [ ] Takedown status: N consecutive failures from ≥2 probe profiles; classify `nxdomain`/`http_error`/`parked`/`waf_challenge`; no content substring heuristics; reports are not auto-resolved on a single probe.
- [ ] GSB: `checked` only on HTTP 200; rescan does not overwrite on error; key in `X-Goog-Api-Key`; URLs redacted in logs.
- [ ] VirusTotal and PhishTank timeouts; PhishTank honours `valid` and reads `phish_detail_page`.
- [ ] URLVoid disabled by default until verified (D10).
- [ ] `multi_api_validator`: "all errored" only when no source (incl. GSB and kit) returned data.
- [ ] `GOOGLE_WEB_RISK_API_KEY` wired; Web Risk submission endpoint uses the documented `projects/{p}/uris:submit` shape.
- [ ] Hard-coded Workspace tenant removed (`blocked_senders_client.py`).

### D — Schema, platform & CI
- [ ] Alembic `003`: every runtime-created table/column/index (incl. `redirect_chains`, `abuse_reports` canonical definition, indexes on hot filters); runtime DDL removed; `report_tracker` self-healing `DROP TABLE` removed.
- [ ] Tests build schema with `alembic upgrade head`.
- [ ] Logger honours `LOG_LEVEL`; one log file per process.
- [ ] Docker: `.env*`, `screenshots/`, `attachments/` ignored; non-root user; `whois` + `dnsutils`.
- [ ] `pyproject.toml` is the single dependency source with a lockfile; `requirements*.txt` generated from it.
- [ ] CI on `pull_request` and push to `dev`: ruff, black, pyright (touched modules), pytest with `postgres:16`, coverage floor, pip-audit, Docker build; no `continue-on-error`.
- [ ] Live-network tests marked `network` and excluded by default.

### F — Frontend
- [ ] No fabricated data (`stores/integrations.ts` `Math.random()` series, CommandPalette demo pivots).
- [ ] Graph: no silent truncation; honest "limited" state; server-side STIX export.
- [ ] Loading/error/empty states in every view; 401/403/429/5xx handling; timer/listener leaks; store races.
- [ ] Strict CSP + security headers in `nginx.conf`; no unsafe `v-html`; malicious URLs defanged with explicit copy.
- [ ] Tests for stores, API client, router guards and critical views; CI workflow.

### Exit criteria
- [ ] CI green and blocking in both repositories.
- [ ] 0 `F821`, 0 type and lint errors in touched code.
- [ ] One regression test per bug.
- [ ] Scanner processes 10 consecutive batches without restarting (test `tests/regressions`).
- [ ] A test report is tracked with an SLA and its follow-up is scheduled.
- [ ] The UI shows no fabricated data.

## Phase 1 — Measure before improving
- [ ] `labels` table + API + UI actions (confirm / dismiss / report).
- [ ] Versioned evaluation dataset (`eval/`, manifest + hashes, no personal data): live-verified positives; hard negatives (official brand domains and logins, Tranco top, benign SaaS-hosted sites, homonyms such as `phase.com`, `zoom.us`, `banco.info`); temporal split; dedupe by eTLD+1 and kit.
- [ ] `python -m anisakys.eval run`: precision, recall, PR-AUC, TPR at FPR 1e-3/1e-4, precision@k, per-brand confusion, reliability diagram, cost/latency per stage; JSON + HTML.
- [ ] Operational metrics from every process: TTD, TTR, TTT (first/last outage, re-emergence), feed lag, queue depth, bounces/responses, screenshot/RDAP success.
- [ ] Baseline published here; per-brand targets agreed.

## Phase 2 — Detection core v2
- [ ] Brand catalogue in the database (aliases, official eTLD+1, apps, reference logos/favicons with pHash + mmh3, reference logins, Spanish/English lure vocabulary, priority, takedown preferences), managed from the UI.
- [ ] Single normalisation module: IDNA UTS-46, UTS-39 skeletons, eTLD+1 via PSL, official-domain allowlist first, token-boundary brand matching, rapidfuzz, abuse-data TLD list, SaaS hosting context.
- [ ] Real-browser capture (isolated worker): redirects incl. meta-refresh/JS/iframes, HTML/DOM, HAR, headers, TLS cert, IP/ASN, viewport + full-page screenshots, favicon, cloaking across UA/geo/mobile profiles, CAPTCHA/Turnstile as signals.
- [ ] Content features: credential/OTP/card forms and action targets, exfiltration endpoints (Telegram tokens, Socket.IO, webhooks), GA4/GTM IDs, HTML TLSH, screenshot pHash, QR decoding (split/nested), versioned PhaaS/AiTM kit signatures.
- [ ] Reference-based visual brand identification + brand↔domain consistency.
- [ ] Optional multimodal judge (`src/detection/llm_judge.py`) with structured output, prompt-injection defences, refusal handling, batch path, audit log and daily budget; measured before enabling.
- [ ] Calibrated fusion (log-odds + isotonic/Platt on `labels`), missing ≠ clean, strong-signal floors, probability and coverage reported separately.
- [ ] Shared validator with TTL cache, parallel provider calls with token buckets, locked circuit breaker counting 429/5xx.

## Phase 3 — Discovery
- [ ] Candidate queue (eTLD+1 dedupe, risk/freshness/brand priority, lifecycle re-checks) replaces the permutation file.
- [ ] Self-hosted certstream-server-go ≥ 1.9 (tiled logs), bounded queue, token-boundary seeds ≥ 5 chars.
- [ ] NRD/NOD ingestion (CZDS, dns0 NOD, WhoisDS); `.co`/`.com.co` via CT/NOD/passive DNS.
- [ ] SaaS/free-hosting discovery via urlscan (`date:>now-1h`, official domains excluded, scored).
- [ ] Feeds as sources (OpenPhish, PhishStats, Phishing.Database, ThreatFox).
- [ ] Ads transparency, abuse mailbox and QR intake; e-mail module fixes (HTML/hrefs, first Authentication-Results + ARC, own-domain spoofing, attachment types, historyId after commit).

## Phase 4 — Infrastructure & campaigns
- [ ] Time-bounded entity graph with shared-infrastructure suppression.
- [ ] Hash-stable campaign IDs with explained pivots; kit/operator clustering.
- [ ] Guided pivots (values shared by ≤ 500 domains).
- [ ] STIX/TAXII/MISP: confidence, `valid_until`, Sightings, pagination, `added_after`, TLP tags, dedupe.
- [ ] Grinder/AbuseIPDB excludes CDN/shared hosting IPs.

## Phase 5 — Evidence & takedown
- [ ] Immutable evidence store (SHA-256, UTC, final URL, IP/ASN, vantage point, capturer version; S3/MinIO WORM).
- [ ] Append-only `cases`, `takedown_requests`, `status_events` with stable IDs.
- [ ] Per-channel routing (registrar, host/ASN, Cloudflare, Web Risk, Netcraft, APWG eCX, Microsoft WDSI task, ColCERT/CSIRT, .CO RDC).
- [ ] Per-brand/per-channel templates aligned with the ICANN guide (2025-11-20) and the RAA/RA amendments (2024-04-05).
- [ ] Follow-up and escalation rules; multi-vantage verification every 15–30 min; TTT first/last outage.

## Phase 6 — Platform & security
- [ ] Normalised schema with `/api/v1` compatibility views; RBAC and `tenant_id`.
- [ ] Pydantic validation, cursor pagination, no N+1; OpenAPI for `/api/v2`.
- [ ] OpenTelemetry, Prometheus rules + Alertmanager, versioned Grafana dashboards.
- [ ] STARTTLS, `SecretStr`, `sslmode`, hashed dependencies, bandit, SBOM.
- [ ] Honest README, ARCHITECTURE with diagrams, runbooks.

## Phase 7 — Analyst console
- [ ] Design system with tokens, light/dark, tabular numerals, documented base components.
- [ ] ECharts (modular), WebGL graph (Cytoscape.js/Sigma.js), MapLibre; i18n es-CO/en.
- [ ] Views: Overview (KPIs, funnel, brand×week heatmap), Takedowns (Kaplan–Meier, ECDF, provider responsiveness), Graph, Campaigns (swimlanes), geo/ASN map, model quality, pipeline health, case view, Settings, Scan/Threads.
- [ ] WCAG 2.2 AA, Lighthouse ≥ 90, e2e green, zero console errors, screenshots in both themes.

## Changelog of this file
- 2026-10-03 — Created with the audit baseline; phase 0 foundation done.
