# Anisakys v2 — Roadmap

Working memory for the v2 programme. Every phase ships as one branch
`feat/v2-faseN-<topic>` per affected repository and one PR into `dev`.
Tick boxes only when the change is merged into the phase branch **and**
covered by a test. Numbers in this file are measured, never estimated.

- Backend: `JuanVilla424/anisakys` (base `dev`)
- Frontend: `JuanVilla424/anisakys-frontend` (base `dev`)
- Audit baseline: backend `c1640eb`, frontend `a49b3bf` (2026-10-03)

## Baseline and phase 0 results (measured)

| Metric | Before phase 0 (2026-10-03) | After phase 0 (2026-10-04) | How |
|---|---|---|---|
| Backend tests | 576 passed, 1 failed (env-dependent) | 1332 passed, 0 failed | `pytest` (network tests excluded by marker) against PostgreSQL 16 |
| Backend coverage | 47.9 % (detection 46.2 %, intelligence 41.2 %, reporting 45.0 %, api 45.1 %) | 69.6 % (detection 57.0 %, intelligence 67.4 %, reporting 82.2 %, api 74.9 %) | `pytest --cov=src`; CI floor raised to 69 % |
| Undefined names (F821) | 31 | 0 (blocking gate) | `ruff check src tests` |
| Other pyflakes findings | 324 | 0 (blocking gate) | `ruff check src tests` |
| Type checking | none | pyright clean on the modules listed in `pyrightconfig.json` (blocking) | `pyright` |
| Runtime DDL statements in `src/` | dozens, incl. `DROP TABLE abuse_reports CASCADE` | 0 (regression test) | `tests/regressions/test_no_runtime_ddl.py` |
| CI running tests | No | Yes: lint, types, tests + coverage floor, pip-audit, Docker build | `.github/workflows/ci.yml` |
| Known vulnerable dependencies | requests 2.32.5 (PYSEC-2026-2275) | none | `pip-audit` |
| Frontend tests | 9 files / 45 tests | 52 files / 367 tests + Playwright smoke under the production CSP | `npm run test`, `npm run test:e2e` |
| Fabricated data in the console | Takedowns view, latency sparklines, demo pivots, fake thread controls/queue/progress, invented identity | none | frontend phase 0 review |
| Detection quality (precision/recall/TTD/TTT) | **Not measurable** — no labels, no harness | still not measurable | Phase 1 |

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
| D11 | Process roles `all`/`api`/`scanner`/`scheduler`; only `scheduler` (or `all` in single-process dev) runs background jobs, guarded by a PostgreSQL advisory leader lock; gunicorn workers never run jobs. | One sender of abuse e-mail; docker-compose gains a `scheduler` service. |
| D12 | Abuse e-mail goes through a transactional outbox claimed with `SKIP LOCKED`; at-most `max_attempts` copies per (report, recipient, follow-up) with a stable `Message-ID`; the SMTP cap is a database ledger shared by every process. | Exactly-once over SMTP is impossible; this bounds duplicates and makes them identifiable. |
| D13 | Each primary recipient gets its own message without `Cc`; the CC list gets one copy; escalation level 2/3 CCs only from the 2nd/3rd follow-up. | No address receives N duplicates; first contact never escalates. |
| D14 | Form-only providers (Cloudflare, GoDaddy, …) produce analyst tasks (`/api/v1/reports/tasks`) instead of e-mails. | The providers ignore e-mail; tasks make the manual step visible. |
| D15 | API scopes gain `report_send` (send without approval), `email_admin` (mailbox monitors, allowlisted) and `metrics`; `/report` without `report_send` waits for analyst approval. | Least privilege for external integrations. |
| D16 | API timestamps are ISO-8601 with `+00:00`; naive legacy DB values are treated as UTC (DB and app run in UTC); unknown values are `null`, never `now()`/0/"medium". | Honest console; full TIMESTAMPTZ normalisation is phase 6. |
| D17 | A site is `down` only after N consecutive failing probe cycles from every client profile, with a canary check against local outages; WAF challenges and parking never count as down; only the takedown monitor writes `down`. | Removes false takedowns that auto-closed reports. |
| D18 | Origin-IP candidates behind Cloudflare (from `origin.`/`direct.` sub-domains) are informational only. | The phishing operator controls that DNS and could aim complaints at a third party. |
| D19 | `pyproject.toml` (PEP 621) is the single dependency source, locked with Poetry; `requirements*.txt` are generated (`tools/sync-requirements.sh`, checked in CI). | Reproducible installs for Docker/systemd. |

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
- [x] `PATCH /api/v1/reports` int/bool `CASE` (always 500).
- [x] `/multi-scan` uses `conn` outside its `with`.
- [x] `/reports` parses JSON recipients by splitting on commas.
- [x] `/graph` `focus` case bug; `/campaigns` N+1.
- [x] Validated query parameters (no unhandled `int()`), no `str(e)` in responses.
- [x] gunicorn entrypoint, no debug server, bind `127.0.0.1` by default, configurable `ProxyFix`.
- [x] Rate limiting backed by Redis (shared across workers).
- [x] `/metrics` requires a token; `/health` pings the DB via `observability/health.py`.
- [x] Scopes `email_admin` and `report_send`; mailbox allowlist; API-submitted URLs require analyst approval before any report; SSRF check on `/report`.
- [x] `POST /api/v2/stix/bundle` (STIX 2.1, TLP 2.0, AMBER default); stop exporting registrar abuse mailboxes as IOCs.

### B — Reporting pipeline & process roles
- [x] One scheduler process role runs reporting/takedown/follow-up/GSB jobs; API and scanner roles do not.
- [x] Workers claim rows with `SELECT … FOR UPDATE SKIP LOCKED`; short per-site transactions.
- [x] SMTP rate limiter shared through the database.
- [x] Outbox `pending → sending → sent/failed`, idempotent per (site, recipient, report).
- [x] Stable report IDs carried in the subject; escalation CCs only when escalating.
- [x] Template: no hard-coded FCM/SIMIT text, no "manual report" wording, renders threat level and confidence, `text/plain` part, defanged URL.
- [x] Screenshot actually reaches GSB submission (reads the file, base64-encodes it).
- [x] Form-only providers produce an analyst task instead of an e-mail.
- [x] Recipient safety: never registrant/WHOIS-wide addresses, never MX hosts as hosting; recipient domain validated against the site's eTLD+1 (public suffix list).
- [x] Follow-up advances `sla_deadline`.

### C — Detection & threat-intel providers
- [x] Takedown status: N consecutive failures from ≥2 probe profiles; classify `nxdomain`/`http_error`/`parked`/`waf_challenge`; no content substring heuristics; reports are not auto-resolved on a single probe.
- [x] GSB: `checked` only on HTTP 200; rescan does not overwrite on error; key in `X-Goog-Api-Key`; URLs redacted in logs.
- [x] VirusTotal and PhishTank timeouts; PhishTank honours `valid` and reads `phish_detail_page`.
- [x] URLVoid disabled by default until verified (D10).
- [x] `multi_api_validator`: "all errored" only when no source (incl. GSB and kit) returned data.
- [x] `GOOGLE_WEB_RISK_API_KEY` wired; Web Risk submission endpoint uses the documented `projects/{p}/uris:submit` shape.
- [x] Hard-coded Workspace tenant removed (`blocked_senders_client.py`).

### D — Schema, platform & CI
- [x] Alembic `003`: every runtime-created table/column/index (incl. `redirect_chains`, `abuse_reports` canonical definition, indexes on hot filters); runtime DDL removed; `report_tracker` self-healing `DROP TABLE` removed.
- [x] Tests build schema with `alembic upgrade head`.
- [x] Logger honours `LOG_LEVEL`; one log file per process.
- [x] Docker: `.env*`, `screenshots/`, `attachments/` ignored; non-root user; `whois` + `dnsutils`.
- [x] `pyproject.toml` is the single dependency source with a lockfile; `requirements*.txt` generated from it.
- [x] CI on `pull_request` and push to `dev`: ruff, black, pyright (touched modules), pytest with `postgres:16`, coverage floor, pip-audit, Docker build; no `continue-on-error`.
- [x] Live-network tests marked `network` and excluded by default.

### F — Frontend
- [x] No fabricated data (`stores/integrations.ts` `Math.random()` series, CommandPalette demo pivots).
- [x] Graph: no silent truncation; honest "limited" state; server-side STIX export.
- [x] Loading/error/empty states in every view; 401/403/429/5xx handling; timer/listener leaks; store races.
- [x] Strict CSP + security headers in `nginx.conf`; no unsafe `v-html`; malicious URLs defanged with explicit copy.
- [x] Tests for stores, API client, router guards and critical views; CI workflow.

### Exit criteria (all met; see tests/regressions and tests/reporting)
- [ ] CI green and blocking in both repositories (verify on the phase 0 pull requests).
- [x] 0 `F821`, 0 type and lint errors in touched code.
- [x] One regression test per bug.
- [x] Scanner processes 10 consecutive batches without restarting (test `tests/regressions`).
- [x] A test report is tracked with an SLA and its follow-up is scheduled.
- [x] The UI shows no fabricated data.

### Carried over from phase 0 (tracked, not blocking)
- [ ] `HttpOnly` cookie session + CSRF for the console (D7) → phase 6 with RBAC.
- [ ] WebGL graph engine and design system (D6) → phase 7.
- [ ] Normalise legacy `TIMESTAMP`/`INTEGER`-boolean/`TEXT`-JSON columns to `TIMESTAMPTZ`/`BOOLEAN`/`JSONB` → phase 6.
- [ ] Capture page text so the recipient policy can reject addresses published on the phishing page (`site_content` is wired but empty) → phase 2 capture.
- [ ] Leader-lock hand-over: if the leader's DB session dies a standby may start while the old leader still runs; row claiming prevents duplicate e-mail, but the takedown monitor/GSB rescan could briefly overlap → phase 6.
- [ ] `/api/v1/sites` cannot filter by a null `source`; IOC ids are positional; `/nav/counts` "campaigns" counts clusters with live sites (active + monitoring) → phase 4/6.
- [ ] Docker runtime layer with `whois`/`dnsutils` could not be built in the development sandbox (egress to the Debian mirror blocked); CI builds the full image.
- [ ] URLVoid/APIVoid, PhishTank and Web Risk Submission clients follow vendor documentation but could not be exercised live from the sandbox; verify with real credentials before enabling.
- [ ] Coverage of `src/detection` (57 %) and `src/monitoring` (62 %) below the 75 % target → phases 2–3.
- [ ] API gaps reported by the console (phase 0 round 2) → phase 1 (labels/approval) and phase 6 (API):
  - approval queue for `/report` submissions waiting on `report_send` (list + approve/reject);
  - audit trail of closed analyst tasks (outcome, note, who, when) and filters by report/channel;
  - `/campaigns` search and status filters; paging of the threats inside a cluster; `/sites` registrar filter;
  - `/sites` filter for `source IS NULL`; stable IOC ids;
  - say which limit tripped (per thread or per key) in `/threads/<id>/results` 429 bodies;
  - rename the misleading `/stats` fields (`total_reports` counts sites, `recent_reports` counts sites first seen in 7 days) behind `/api/v2`;
  - integration health shared across gunicorn workers (today it reflects the answering worker only);
  - STIX bundles: omit `confidence` when the caller gives none instead of defaulting to 50.

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
- 2026-10-04 — Phase 0 completed: workstreams A, A2, B, C, D (backend) and F (frontend) merged; results table and decisions D11–D19 added.
