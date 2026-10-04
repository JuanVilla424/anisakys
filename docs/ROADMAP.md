# Anisakys v2 — Roadmap

Working memory for the v2 programme. Phase 0 shipped as one branch
`feat/v2-fase0-<topic>` per affected repository and one PR into `dev`; from
phase 1 on, every phase ships as one commit per affected repository directly
on `dev` (D20). Tick boxes only when the change is on `dev` **and** covered by
a test. Numbers in this file are measured, never estimated.

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
| D20 | From phase 1 on, work is committed directly to `dev`, one commit per repository, without feature branches or agent-opened PRs. | Owner's branch rule for agents; CI on push to `dev` is the gate. |
| D21 | Ground truth is the append-only `labels` table (migration `006`) with the latest verdict denormalised on `phishing_sites`; `benign` keeps a site out of reporting and analysis and cancels its queued e-mails and open analyst tasks; `report` needs `report_send`; `detector_snapshot` freezes what the detector said when the analyst decided. | The `stored` predictor measures the decision the analyst actually saw, not a later re-scan. |
| D22 | Evaluation datasets version their manifest (sources, parameters, counts, SHA-256) and the seed lists in git; samples built from third-party feeds and run reports stay local. URLs are sanitised (no query, fragment, credentials or port; e-mail/token path segments redacted). | Feed licences forbid redistribution; no personal data in samples. |
| D23 | The baseline score is ordinal (threat level first, confidence second) and explicitly uncalibrated; `unknown` is an abstention reported as coverage, never as clean; TPR at a fixed FPR is flagged as not resolvable with fewer than 1/FPR negatives. | Honest numbers until phase 2 calibrates the fusion on `labels`. |
| D24 | Operational metrics (TTD/TTR/TTT, queues, outcomes) are computed from the shared database and exposed through `GET /api/v1/metrics/operational` and a Prometheus collector on `/metrics` (60 s cache). | Every process writes to the database; one measurement point instead of per-process exporters. |

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
- [x] CI green and blocking in both repositories (JuanVilla424/anisakys#214 and JuanVilla424/anisakys-frontend#18, 2026-10-04).
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
- [x] `labels` table + API + UI actions (confirm / dismiss / report): migration `006`, `src/labels.py`, `POST/GET /api/v1/sites/<id>/labels`, `GET /api/v1/labels`, `label` filter on `/api/v1/sites`, console drawer actions (D21).
- [x] Approval queue for `/report` submissions without `report_send`: `GET /api/v1/reports/approvals`; approve = `report`, reject = `dismiss`; console tab "Waiting for approval".
- [x] Versioned evaluation dataset (`python -m src.eval build|verify`, `eval/`): manifest + SHA-256, sanitised URLs, live-verified positives, hard negatives (official brand pages from `KNOWN_BRANDS` + `eval/seeds/`, homonyms such as `phase.com`, `zoom.us`, `banco.info`, benign SaaS-hosted pages, Tranco top), dedupe by eTLD+1 with a per-kit cap, deterministic temporal split (D22).
- [x] `python -m src.eval run` (`live`, `heuristic`, `stored` predictors): precision/recall/F1 per operating point, PR-AUC, TPR at FPR 1e-3/1e-4 (flagged when not resolvable), precision@k, per-brand and per-category confusion, reliability diagram + ECE, coverage, latency and cost per stage (`eval/costs.json`); JSON + self-contained HTML (D23).
- [x] Operational metrics from the shared database: `GET /api/v1/metrics/operational`, Prometheus gauges on `/metrics`, `python -m src.eval ops` — TTD, TTR, TTT (first/last outage, re-emergence), lead over public feeds, queue depth, deliveries, responses, screenshot and abuse-contact success (D24).
- [x] Baseline published here.
- [ ] Per-brand targets agreed with the owner (proposal below).

### Phase 1 baseline (measured 2026-10-04)

Dataset `baseline/2026-10-04` (samples SHA-256 `3e807846f1ec…`, manifest in `eval/datasets/`): 466 samples — 91 phishing (OpenPhish community feed, live when the dataset was built) and 375 benign (287 Tranco top-500 list `Y83KG`, 62 official brand pages, 20 homonyms, 6 benign SaaS pages). 929 candidates were probed: 553 up, 113 WAF challenge, 134 NXDOMAIN, 92 HTTP error, 33 connection error, 4 SSRF-blocked. Split: train 328 (64 phishing), test 138 (27 phishing). The deployment had no analyst labels yet.

Threat-intel providers configured: none (VirusTotal, Google Safe Browsing, PhishTank app key and URLVoid unset). PhishTank still answered 50 of 138 keyless lookups (4 listed, 88 errors).

| Test split, live run (27 phishing / 111 benign) | Deployed detector | Heuristics only (same signals, no abstention rule) |
|---|---|---|
| Coverage (verdict other than `unknown`) | 34.8 % (48/138) | 94.9 % (131/138) |
| Precision / recall at level ≥ high | 0.667 / 0.148 (4 TP, 2 FP) | 0.750 / 0.222 (6 TP, 2 FP) |
| FPR at level ≥ high | 1.8 % (2/111) | 1.8 % (2/111) |
| Precision / recall at level ≥ medium | 0.636 / 0.259 | 0.545 / 0.444 |
| FPR at level ≥ medium | 3.6 % (4/111) | 9.0 % (10/111) |
| PR-AUC | 0.359 | 0.438 |
| Precision@10 | 0.6 | 0.7 |
| ECE | 0.165 | 0.114 |
| TPR at FPR 1e-3 / 1e-4 | not resolvable (111 negatives; 1 000 / 10 000 needed) | not resolvable |

With every threat-intel provider disabled (`--predictor heuristic`) the deployed detector abstains on 136 of 138 URLs (its only two verdicts are the two false positives below); the heuristic score keeps PR-AUC 0.379 (≥ high: 0.667 / 0.148; ≥ medium: 0.55 / 0.407 at 8.1 % FPR).

Latency per URL (live run): total p50 1.9 s / p95 7.2 s; WHOIS p50 0.33 s / p95 1.8 s; page fetch + kit fingerprint p50 1.1 s / p95 5.2 s. Cost: 0 USD (free tiers only).

Findings for phase 2:
- Without provider keys the deployed detector abstains on 65 % of URLs and flags 4 of 27 live phishing sites at `high`; the heuristics rank better (PR-AUC 0.44) but are never allowed to decide on their own.
- Both false positives are Google-owned domains (`googleblog.com`, `googledomains.com`) rated `critical` by the kit fingerprint: its brand-domain check treats official sister domains as attacker infrastructure (fix: official-domain allowlist first).
- The lexical combo-squatting check matches brand tokens inside unrelated words (`meridian-shop.example` → `dian`, pattern `meri[BRAND]-shop`) (fix: token-boundary brand matching).
- Only 91 of the 300 OpenPhish URLs survived liveness verification and de-duplication: feed positives must be verified live when a dataset is built.

Operational baseline (demo database, `python -m src.eval ops`): in the last 30 days 1 site was first seen and no report, delivery or outage happened, so TTD/TTR/TTT have n = 0 and every queue is empty. Over 365 days (18 sites) TTD has a median of 18 h (n = 16), but p90 is 135 443 h because old or compromised domains count from their registration date (TTD needs a second definition for those in phase 3); no abuse report has been sent from this database, so TTR, TTT, response and enrichment rates stay unmeasured until the pipeline runs on real traffic.

Proposed targets (owner to confirm, per protected brand): precision ≥ 0.95 and FPR ≤ 0.1 % at the auto-report operating point; recall ≥ 0.80 for live phishing of protected brands; median TTD ≤ 24 h, TTR ≤ 1 h, TTT ≤ 48 h.

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
- 2026-10-04 — Phase 1 completed: labels, approval queue, evaluation harness and operational metrics; measured baseline and decisions D20–D24 added; file renamed from `ROADMAP-v2.md`.
