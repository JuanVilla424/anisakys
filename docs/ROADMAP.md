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
| D25 | Quality targets live in `eval/targets.json` and every `python -m src.eval run`/`ops` checks them: detection targets on the deployed verdict at the `auto_report` operating point (level high/critical with confidence ≥ `AUTO_REPORT_THRESHOLD_CONFIDENCE`, the detection side of `src/detection/analyzer.py`), overall and for every brand; pipeline targets on medians. A target is `met`, `missed` or `not_resolvable`: precision needs ≥ 10 flagged samples, recall ≥ 10 positives, an FPR ceiling ≥ 1/FPR negatives, a median ≥ 5 events. | Phase 2 has a fixed, versioned bar; too little data never reads as success. |
| D26 | The scheduler (no HTTP) writes a heartbeat file every 30 s; it is healthy while the heartbeat is < 120 s old, the database answers and it is either the leader with its four job loops alive or a hot standby (`python -m src.runtime.health`, compose healthcheck). | A dead job loop or a lost database shows as `unhealthy` instead of a false alarm on an HTTP probe. |
| D27 | Brand catalogue in the database (`brands`, `brand_domains`, `brand_assets`, migration `007`), managed from the console (`/api/v1/brands`, scope `write` to change). The application starts empty: no seed data. Detection merges the built-in `KNOWN_BRANDS` with the active console brands (a console brand extends the built-in one with the same slug), reads it through a 60 s in-process cache and falls back to the built-in brands when the database cannot be read. Reference favicons/logos are kept only as hashes (SHA-256, Shodan mmh3, pHash, dHash), validated with Pillow, ≤ 1 MB. | The owner loads the brands they protect; detection never queries the database per URL and never stops on a database outage. |
| D28 | One normalisation module (`src/detection/normalize.py`): IDNA UTS-46, UTS-39 skeletons from Unicode 16 `confusables.txt`, eTLD+1 from the PSL including private suffixes (`x.vercel.app`), official-domain allowlist first (an official registrable domain is never impersonation), brand matching at token boundaries with partial matches only for aliases of ≥ 5 characters, rapidfuzz typosquatting, SaaS/free-hosting context. The URL analyser, the kit fingerprint and the evaluation's brand inference share it. | Fixes both baseline false-positive families (Google sister domains, `meridian` → `dian`) at their root. |
| D29 | Page capture reuses the SSRF-guarded fetch (every redirect hop checked, hops recorded), the sandboxed screenshot worker and a favicon fetch. Each scan keeps its capture in `captures` (summary, hashes, content features and brand identification; never the page), the newest 20 per site, written in a savepoint so a capture that cannot be stored never loses the scan results; `GET /api/v1/sites/<id>/capture` serves the newest one to the console. A page with an invalid certificate is re-read without verification for analysis only (read-only, recorded as `tls_valid: false`). | One fetch feeds the kit fingerprint, the content features and the brand identification; the console shows what the detector saw. |
| D30 | Content features (`src/detection/features.py`): credential/OTP/card fields and form targets, exfiltration endpoints, tracker IDs, QR codes (zxing-cpp), HTML TLSH; kit traits versioned in `src/detection/kits/signatures.json` with their public sources. TLSH is a pure Python/numpy port (`src/detection/tlsh.py`, byte-compatible with the reference implementation) because `py-tlsh` has no CPython 3.12 wheels. | Signals reproducible from a capture, versioned with the code that produced them. |
| D31 | Reference-based brand identification (`src/detection/visual_brand.py`): exact favicon mmh3 or pHash Hamming ≤ 8 against the catalogue, plus title/text mentions; a brand identified on a domain that is not one of its own is a mismatch, and a strong signal with a credential form. | The brand↔domain inconsistency is the core phishing evidence and works without third-party feeds. |
| D32 | Optional LLM judge (`src/detection/llm_judge.py`): an OpenAI-compatible adapter (default DeepSeek `deepseek-flash`) or the native Anthropic API over `requests`. The page is untrusted data: quoted between per-request nonce markers, stripped of control characters and capped; the model gets no tools; the answer must match a strict schema or it is `invalid`. Every call is audited in `llm_judgements` (no key stored), stops once the daily USD budget of the UTC day is spent (counted across processes in the database), reuses the verdict of an identical input for 7 days and goes through a circuit breaker without retries. It identifies itself (`User-Agent: anisakys-llm-judge/<version>`), sends one stable session ID per process to gateways that route by conversation (`x-opencode-session` for OpenCode Go, which rejects requests without it) and paces its requests (`LLM_JUDGE_REQUESTS_PER_MINUTE`, default 20). Off by default (`LLM_JUDGE_ENABLED`); when on it is evidence attached to the scan, not part of the deployed verdict, until `python -m src.eval run --judge` shows it helps. | Cost and prompt-injection risk stay bounded, and the judge must earn its place with numbers. |
| D33 | One validator per process (`get_shared_validator`): providers, WHOIS and the capture run in parallel; answers (never errors) are cached per provider stage with a TTL, and every provider that actually sends requests draws from a per-process budget (`*_REQUESTS_PER_MINUTE`, `src/intelligence/provider_runtime.py`) — a provider without key or disabled answers at once without waiting for one. A request the budget refuses is "no data", never an answer; WHOIS (budget 120/min) waits up to 15 s for it, as long as the capture. Per-scan state is never kept on the shared instance. | Free-tier quotas are spent once per URL, not once per caller; scans stay thread-safe. The first phase 2 measurement showed why each rule matters: refused WHOIS lookups counted as answers dropped the domain age from 57 % of scans, and budgets on unconfigured providers added ~4 s to each. |
| D34 | `src.detection` resolves its package exports lazily (PEP 562): importing a light module such as `normalize` or `imagehash` must not import the scanner and analyzer, which import the validator, which imports those light modules. A regression test imports every entry module first, each in a fresh interpreter. | That cycle broke `import src.api.phishing_api` (the API entry point) while the test suite, importing in another order, stayed green. |
| D35 | A brand in the name of an established domain (registered ≥ 1 year ago per WHOIS) is treated as the brand's own property: there, combo-squatting no longer counts in the rules nor gives the kit fingerprint its brand hint; the brand's exact name under another suffix is a separate lexical signal (`tld_swap`) that counts only on a domain known to be younger than a year; a lookalike (typosquatting, homoglyphs) always counts. | On the phase 2 dataset the kit fingerprint rated 49 Google/Amazon/eBay/Apple country and sister domains `critical` (`google.com.pe`, `amazon.fr`, `thinkwithgoogle.com`): the brand's real domain inside a page proves a reverse proxy only on a fresh domain. |

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
  - ~~approval queue for `/report` submissions waiting on `report_send` (list + approve/reject)~~ — done in phase 1;
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
- [x] Per-brand targets agreed with the owner (2026-10-04): `eval/targets.json`, checked by every run (D25); status at the baseline below.
- [x] Scheduler healthcheck from a heartbeat instead of the inherited HTTP probe (D26).

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

### Targets (agreed 2026-10-04, `eval/targets.json`, D25)

At the `auto_report` operating point, overall and for every brand: precision ≥ 0.95, recall ≥ 0.80, FPR ≤ 0.1 %. Pipeline medians: TTD ≤ 24 h, TTR ≤ 1 h, time to first outage ≤ 48 h. Thresholds can be raised per brand with `brand_overrides`.

Status at the baseline (the same scans, `python -m src.eval run eval/datasets/baseline/2026-10-04 --predictor live --reuse-cache eval/cache/live-baseline-2026-10-04-2f189a1-dirty.jsonl --auto-report-confidence 85`; 85 is the product default, the demo `.env` uses 99):

| Target | Value | Status |
|---|---|---|
| Precision ≥ 0.95 | 1.0 (1 flagged) | not resolvable: needs ≥ 10 flagged |
| Recall ≥ 0.80 | 0.037 (1 of 27) | missed |
| FPR ≤ 0.1 % | 0 (0 of 111) | not resolvable: needs ≥ 1 000 negatives |
| Per brand | 1 brand in the test split (`paypal`, 1 sample) | not resolvable |
| TTD / TTR / first outage medians | n = 0 in the demo's last 30 days | not resolvable |

At the auto-report point the deployed detector flags 1 of 27 live phishing sites and none of the benign ones: the two `critical` false positives stay below confidence 85. Phase 2 must lift recall without losing that precision, and the dataset needs ≥ 1 000 negatives and ≥ 10 positives per protected brand for the FPR and per-brand targets to become measurable.

## Phase 2 — Detection core v2
- [x] Brand catalogue in the database (aliases, official eTLD+1, login/app hosts, reference logos/favicons with pHash + mmh3, Spanish/English lure vocabulary, priority, takedown preferences), managed from the console's Brands view (D27). It starts empty by the owner's decision: no seed data.
- [x] Single normalisation module: IDNA UTS-46, UTS-39 skeletons, eTLD+1 via PSL, official-domain allowlist first, token-boundary brand matching, rapidfuzz, SaaS hosting context (D28). The abuse-data TLD table is generated from the phase 2 train split by `python -m src.eval tld-stats` (`src/data/tld_abuse.json`, 48 TLDs, provenance inside); it is an input for the fusion and no deployed rule reads it.
- [ ] Real-browser capture — partly: every scan captures the page through the SSRF-guarded fetch (redirect hops, headers, TLS validity, server IP, HTML, favicon) and the existing screenshot worker, and keeps it in `captures` (D29). Not built yet: the multi-profile browser worker (meta-refresh/JS/iframe redirects, HAR, cloaking across UA/geo/mobile profiles, CAPTCHA/Turnstile signals).
- [x] Content features: credential/OTP/card forms and action targets, exfiltration endpoints, GA4/UA/GTM/Meta Pixel IDs, HTML TLSH, screenshot pHash and QR decoding when a screenshot exists, versioned kit traits (D30).
- [x] Reference-based visual brand identification + brand↔domain consistency (D31), shown in the Threats drawer with the capture summary.
- [x] Optional multimodal judge with structured output, prompt-injection defences, refusal handling, measurement path (`run --judge`), audit log and daily budget (D32). Measured 2026-10-06 (below); it stays off: alone it misses the precision and FPR targets.
- [ ] Calibrated fusion (log-odds + isotonic/Platt on `labels`), missing ≠ clean, strong-signal floors, probability and coverage reported separately — not built yet. The deployed verdict is still the phase 1 rule aggregation, now fed by the fixed lexical and kit signals; the new capture, content and brand signals are recorded and measured (signal table below) but no verdict uses them until the fusion exists.
- [x] Shared validator with TTL cache, parallel provider calls with token buckets; the existing locked circuit breaker counting 429/5xx covers every client, the judge included (D33).
- [x] Console: Brands view (list, search, create/edit, deactivate, reference images; `write` scope) and the page capture in the Threats drawer; every URL defanged.

### Phase 2 results (measured 2026-10-06)

Dataset `phase2/2026-10-05` (samples SHA-256 `1711edc381ca…`, manifest in `eval/datasets/`): 4 337 samples — 73 phishing (OpenPhish community feed, live when the dataset was built) and 4 264 benign (4 176 Tranco top-6000 list `56WKN`, 62 official brand pages, 20 homonyms, 6 benign SaaS pages). 6 429 candidates were probed: 3 891 up, 667 WAF challenge, 1 127 NXDOMAIN, 403 HTTP error, 312 connection error, 24 SSRF-blocked, 5 parked. Split: train 3 039 (51 phishing), test 1 298 (22 phishing, 1 276 benign), so an FPR ceiling of 0.1 % is now resolvable. No analyst labels (the application starts empty) and, as in phase 1, no threat-intel provider keys.

v1 is the phase 1 code (commit `983e5ca`, exported with `git archive`) and v2 this phase's code, both run with `python -m src.eval run eval/datasets/phase2/2026-10-05 --predictor live --split test --auto-report-confidence 85` on the same split:

| Test split (22 phishing / 1 276 benign) | v1 deployed | v2 deployed | v1 heuristics | v2 heuristics |
|---|---|---|---|---|
| Coverage (verdict other than `unknown`) | 0.4 % (5) | 0 % | 93.1 % | 94.5 % |
| `auto_report` flagged | 0 | 0 | 0 | 0 |
| Precision / recall at level ≥ high | 0 / 0 (0 TP, 5 FP) | — / 0 (nothing flagged) | 0.455 / 0.227 (5 TP, 6 FP) | **1.0 / 0.227 (5 TP, 0 FP)** |
| FPR at level ≥ high | 0.39 % | 0 % | 0.47 % | **0 %** |
| Precision / recall / FPR at level ≥ medium | 0 / 0 / 0.39 % | — / 0 / 0 % | 0.105 / 0.455 / 6.7 % | 0.146 / 0.545 / 5.5 % |
| PR-AUC | 0.017 | 0.017 | 0.179 | **0.466** |
| Precision@10 | 0.0 | 0.0 | 0.4 | 0.9 |

Latency per URL, wall clock: v1 p50 1.7 s / p95 10.8 s (stages in sequence); v2 p50 4.0 s / p95 10.4 s with 8 scans in parallel — the stages overlap, and the p50 is the keyless PhishTank lookups waiting for their 30/min budget (3.9 s); capture p50 1.5 s / p95 5.2 s, WHOIS p50 0.39 s, content features p50 53 ms. Cost: 0 USD.

The new signals, each alone on the test split (descriptive, `report.json` → `signals`): credential form 5/22 phishing vs 54/1 276 benign; combo-squatting 2/22 vs 6; brand↔domain mismatch 1/22 vs 25; suspicious TLD 3/22 vs 70; kit traits 0/22 vs 2; `tld_swap` 0/22 vs 43 (all brand-owned country domains).

Targets at `auto_report` (D25): precision not resolvable (nothing flagged), recall 0 (missed), FPR 0 (met, and resolvable for the first time); 3 brands in the test split, none resolvable. TPR at FPR 1e-3 is resolvable (1 276 negatives) and 0.

Findings:
- The measurement caught three phase 2 defects before they shipped, all fixed and re-measured: 49 `critical` false positives on Google/Amazon/eBay/Apple country and sister domains (D35); WHOIS lookups refused by the request budget counted as answers, which dropped the domain age from 57 % of scans (heuristic coverage 36 % instead of 94 %); budgets on unconfigured providers adding ~4 s per scan (D33).
- With no provider keys the deployed verdict still abstains on every URL (the phase 1 rule: no external evidence, no verdict), so v2 only removes v1's five false positives. The heuristics, meanwhile, now flag 5 of 22 live phishing sites at ≥ high with no false positive among 1 276 benign and rank far better (PR-AUC 0.18 → 0.47). Letting calibrated heuristics and the new signals decide is the fusion's job; its activation gate (precision ≥ v1, recall > v1, FPR not worse at `auto_report`) applies when it exists.
- The brand↔domain signal is weak with an empty console catalogue: the built-in brands carry names but no reference favicons or logos. Loading the protected brands with their reference images is what makes it useful.
- The TLD table comes from 51 training positives: the per-TLD estimates are rough until the dataset grows (labels, more feed days).
- The LLM judge, measured on the same split through OpenCode Go (`deepseek-v4.1-flash`, `python -m src.eval run … --judge`, run `phase2-2026-10-05-test-live+judge-20261006T184804Z`): 1 259 valid verdicts of 1 298 (8 off-schema, 1 refusal, 30 without capture). Alone, at level ≥ high it flags 9 of 22 phishing sites with 3 false positives (precision 0.75, FPR 0.24 %; `auto_report` 8 TP / 3 FP), PR-AUC 0.36, ~0.0006 USD per verdict at DeepSeek list prices. It is complementary to the rules: of its 9 hits only 3 are also flagged by the rules at ≥ high in that run, so together they reach 15 of 22. Off by default until the fusion weighs it (its 3 false positives are what a calibrated combination must absorb). That run also had a Google Safe Browsing key configured, so its rule-based numbers are not comparable with the table above.

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
- 2026-10-04 — Targets agreed and measured at the baseline (D25); scheduler heartbeat healthcheck (D26). Ready for phase 2.
- 2026-10-06 — Phase 2: brand catalogue, normalisation, page capture, content and brand signals, optional LLM judge, shared validator and console views (D27–D35); measured against phase 1 on the `phase2/2026-10-05` dataset. The calibrated fusion and the multi-profile browser capture are not built yet.
