## [Unreleased] - v2 phase 0 (stabilisation)

### Security

- **api**: serve through gunicorn, never run the Werkzeug debugger, bind to 127.0.0.1 by default; configurable ProxyFix
- **api**: scopes `report_send`, `email_admin` and `metrics`; `/report` submissions wait for analyst approval; SSRF check on `/report`; mailbox allowlist for e-mail monitors
- **api**: `/metrics` requires a token or API key; errors never echo exception text and carry a request id
- **config**: every credential is a `SecretStr`; secrets are redacted from logs
- **reporting**: never e-mail registrant/WHOIS-wide addresses, MX hosts or networks reached through attacker-controlled origin DNS; SMTP credentials only over TLS
- **docker**: secrets and data directories kept out of the image; non-root user
- **deps**: requests bumped past PYSEC-2026-2275

### Bug Fixes

- **core**: 31 undefined names that silently broke scanning, report tracking, auto-analysis, `/stats` and `--reset-offset`
- **core**: shutdown is observable by every worker loop; signals are handled gracefully
- **core**: testing mode now actually blocks CC recipients
- **db**: all schema in Alembic (revisions 003–005); runtime DDL, including a `DROP TABLE abuse_reports CASCADE` fallback, removed
- **reporting**: transactional outbox with row claiming (no duplicate e-mails across processes), shared SMTP rate limit, stable report ids, follow-ups that advance the SLA, brand-neutral templates with a text part and defanged URLs, screenshot submission to Safe Browsing
- **monitoring**: a site is down only after consecutive failing probes from several profiles; WAF challenges and parked pages no longer close reports
- **intel**: provider errors and missing data are never counted as clean; Safe Browsing social engineering raises the verdict to at least high; VirusTotal/PhishTank timeouts and field fixes; Web Risk submission via the documented API; URLVoid disabled until verified
- **api**: PATCH `/reports`, `/multi-scan`, `/reports` recipients, `/graph` focus, `/campaigns` N+1 and stable ids, validated parameters, honest nulls instead of invented values, JSON 429s with Retry-After
- **scripts**: manual report CLI escapes HTML, strips `www.` correctly and uses the shared mailer

### Features

- **api**: `POST /api/v2/stix/bundle` (STIX 2.1, TLP 2.0), `GET /api/v1/session`, `GET /api/v1/sites/sources`, analyst tasks for form-only providers, delivery state in `/api/v1/stats`
- **core**: process roles with a single scheduler and a docker-compose scheduler service
- **ci**: one blocking pipeline (ruff, black, pyright, pytest with PostgreSQL and a 69 % coverage floor, pip-audit, Docker build); dependencies locked from `pyproject.toml`

## [1.1.2] - 2026-10-02

### Features

- **core**: add google alerts, domain scan and blocklist endpoints (`patch candidate`)
- **core**: add RDAP-first abuse contacts, MISP/TAXII sharing, and AiTM kit fingerprinting
- **core**: add openphish/urlhaus corroboration and urlscan.io brand discovery feeds
- **core**: sandbox screenshot capture in a low-privilege worker process
- **core**: expose app version in health endpoint
- **core**: add certificate transparency log monitoring for proactive phishing detection
- **core**: close remaining ssrf sinks and add api-key rate limiting
- **core**: add ssrf guard for url scanner and tighten report scope
- **core**: add graph api endpoint with real data and fix latent runtime bugs
- **core**: add email threat enrichment, discard, own-domain whitelist and backfill script
- **core**: add smtp send rate limiting
- **core**: add multi-tenant api keys with scopes
- **core**: add grafana monitoring dashboard with prometheus and loki stack
- **core**: add alembic migrations with baseline schema
- **core**: instrument business logic with application metrics
- **core**: add prometheus metrics endpoint
- **core**: add observability modules and update architecture doc
- **core**: add abuse email resolution and registrar form database
- **core**: add thread executions tracking and image search scheduling tables
- **core**: add minimum threat level for suspicious tlds and incident columns
- **core**: modularize main.py and add url lexical analysis

### Bug Fixes

- **core**: unify divergent screenshots dir/socket fallbacks and add pyright venv config
- **core**: track real per-call latency in circuit breaker and expose api key configuration state
- **core**: return 404 on nonexistent thread/result ids instead of a silent no-op success
- **core**: use https url for database submodule
- **deps**: Update requests requirement from ~2.32.3 to >=2.32.3,<2.35.0 (#197)
- **deps**: Update cryptography requirement from ~=46.0.5 to ~=48.0.0 (#198)
- **deps**: Update beautifulsoup4 requirement from >=4.12.0 to >=4.14.3 (#199)
- **deps**: Update alembic requirement from ~=1.14 to ~=1.18 (#201)
- **deps**: Update google-api-python-client requirement from >=2.100.0 to >=2.197.0 (#202)
- **core**: align pylint ignore with .venv and comment suggestion-mode
- **core**: anchor bumpversion search so deps stay fixed
- **core**: exempt health and metrics endpoints from rate limiting
- **core**: fix email attachments, browser sandboxing and missing imports
- **deps**: Update cryptography requirement from ~=45.0.5 to ~=46.0.5 (#187)
- **deps**: Update flask requirement from ~=3.1.1 to ~=3.1.3 (#188)
- **deps**: Update setuptools requirement from ^80.10.2 to ^82.0.0 (#189)
- **deps**: Update pylint requirement from ^3.3.0 to ^4.0.5 (#190)
- **deps**: Update sqlalchemy requirement from ~=2.0.46 to ~=2.0.48 (#191)
- **deps**: Update sqlalchemy requirement from ~=2.0.46 to ~=2.0.48
- **deps**: Update pylint requirement from ^3.3.0 to ^4.0.5
- **deps**: Update setuptools requirement from ^80.10.2 to ^82.0.0
- **deps**: Update flask requirement from ~=3.1.1 to ~=3.1.3
- **deps**: Update cryptography requirement from ~=45.0.5 to ~=46.0.5
- **security**: use constant-time comparison and parameterized SQL queries
- **deps**: Update pytest requirement from ^8.3.1 to ^9.0.2 (#182)
- **deps**: Update flask-limiter requirement from ~=3.12 to ~=4.1 (#183)
- **deps**: Update certifi requirement from ^2025.1.31 to ^2026.1.4 (#184)
- **deps**: Update setuptools requirement from ^75.2.0 to ^80.10.2 (#185)
- **deps**: Update sqlalchemy requirement from ~=2.0.43 to ~=2.0.46 (#186)
- **deps**: Update sqlalchemy requirement from ~=2.0.43 to ~=2.0.46
- **deps**: Update setuptools requirement from ^75.2.0 to ^80.10.2
- **deps**: Update certifi requirement from ^2025.1.31 to ^2026.1.4
- **deps**: Update flask-limiter requirement from ~=3.12 to ~=4.1
- **deps**: Update pytest requirement from ^8.3.1 to ^9.0.2

### Documentation

- **core**: update epic documentation for redirect detection and logging
- **core**: update readme with gsb and threat level rules

### Refactors

- **core**: relocate legacy modules and restore ads detector

### Tests

- **core**: add test coverage for reporting and monitoring modules

### Chores

- **core**: add docker compose stack and backend entrypoint
- **core**: remove database submodule
- **core**: track scripts submodule on main
- **core**: bump scripts submodule to v1.1.23
- **core**: exclude docs directory from git tracking

## [1.1.1] - 2025-11-22

### Features

- **core**: extract network utilities to dns module (`patch candidate`)
- **core**: create module structure for EPIC-006 modularization (`minor candidate`)
- **core**: add AbuseContactResolver for multi-contact handling (`patch candidate`)
- **core**: normalize ASN/Provider databases to lists for multi-contact handling (`patch candidate`)
- **core**: implement redirect chain detection and analysis (`minor candidate`)
- **core**: refactor baseline
- **core**: implement structured logging, circuit breakers, and database migrations (`minor candidate`)

### Bug Fixes

- **deps**: Update sqlalchemy requirement from ~=2.0.42 to ~=2.0.43 (#166)
- **deps**: Update sqlalchemy requirement from ~=2.0.42 to ~=2.0.43

### Chores

- ignore database submodule in pylint
- **deps**: update database submodule

## [1.1.0] - 2025-08-26

### Features

- **core**: add ads controller and database (`minor candidate`)
- **core**: add ads controller and database [minor update]

## [1.0.51] - 2025-08-09

### Bug Fixes

- **core**: fixed providers and flows (`patch candidate`)

## [1.0.50] - 2025-08-06

### Bug Fixes

- **core**: fixed attachments values (`patch candidate`)

## [1.0.49] - 2025-08-06

### Bug Fixes

- **core**: fixed screenshots err (`patch candidate`)

## [1.0.48] - 2025-08-05

### Bug Fixes

- **core**: fixed follow up times (`patch candidate`)

## [1.0.47] - 2025-08-05

### Bug Fixes

- **core**: rebased follow up due to overdues (`patch candidate`)

## [1.0.46] - 2025-08-05

### Bug Fixes

- **core**: fixed ccs and follow correlation (`patch candidate`)

## [1.0.45] - 2025-08-05

### Bug Fixes

- **core**: fixed log level err (`patch candidate`)

## [1.0.44] - 2025-08-05

### Bug Fixes

- **core**: fixed log level (`patch candidate`)

## [1.0.43] - 2025-08-05

### Bug Fixes

- **core**: fixed sender email err (`patch candidate`)

## [1.0.42] - 2025-08-04

### Bug Fixes

- **core**: fixed api process thread (`patch candidate`)

## [1.0.41] - 2025-08-04

### Bug Fixes

- **core**: fixed main thread execution (`patch candidate`)

## [1.0.40] - 2025-08-04

### Bug Fixes

- **core**: fixed timeout err (`patch candidate`)

## [1.0.39] - 2025-08-04

### Bug Fixes

- **core**: fixed report from grinder (`patch candidate`)
- **deps**: Update sqlalchemy requirement from ~=2.0.41 to ~=2.0.42 (#122)
- **deps**: Update sqlalchemy requirement from ~=2.0.41 to ~=2.0.42

## [1.0.38] - 2025-08-04

### Bug Fixes

- **core**: fixed hang flow (`patch candidate`)

## [1.0.37] - 2025-08-01

### Bug Fixes

- **core**: fixed database hangup screenshot (`patch candidate`)
- **core**: add missing running attribute to abusereportmanager

## [1.0.36] - 2025-08-01

### Chores

- **core**: fixed issue templates (`patch candidate`)

## [1.0.35] - 2025-07-30

### Bug Fixes

- **core**: fixed hangs on all (`patch candidate`)

## [1.0.34] - 2025-07-30

### Bug Fixes

- **core**: fixed hang on db lock (`patch candidate`)

## [1.0.33] - 2025-07-30

### Bug Fixes

- **core**: fixed abuse_list cannot got (`patch candidate`)

## [1.0.32] - 2025-07-30

### Bug Fixes

- **core**: fixed serialization err (`patch candidate`)

## [1.0.31] - 2025-07-30

### Bug Fixes

- **core**: fixed error when send reports due to validation (`patch candidate`)

## [1.0.30] - 2025-07-30

### Bug Fixes

- **core**: fixed err while report flow (`patch candidate`)

## [1.0.29] - 2025-07-30

### Bug Fixes

- **core**: fixed reports sends flow (`patch candidate`)
- **deps**: Update cryptography requirement from ~=44.0.1 to ~=45.0.5 (#81)
- **deps**: Update sqlalchemy requirement from ~=2.0.38 to ~=2.0.41 (#82)
- **deps**: Update cryptography requirement from ~=44.0.1 to ~=45.0.5
- **deps**: Update sqlalchemy requirement from ~=2.0.38 to ~=2.0.41

## [1.0.28] - 2025-07-30

### Bug Fixes

- **core**: fixed screenshots (`patch candidate`)

## [1.0.27] - 2025-07-30

### Bug Fixes

- **core**: fixed forms (`patch candidate`)

## [1.0.26] - 2025-07-29

### Features

- **core**: added screenshots and icann comp (`patch candidate`)

## [1.0.25] - 2025-07-29

### Bug Fixes

- **core**: fixed required rows on database (`patch candidate`)

## [1.0.24] - 2025-07-27

### Documentation

- **core**: refactor readme file to add new feats (`patch candidate`)

## [1.0.23] - 2025-07-27

### Documentation

- **core**: refactor readme file to add new feats (`patch candidate`)

## [1.0.22] - 2025-07-25

### Features

- **core**: added api and grinder integration (`patch candidate`)

## [1.0.21] - 2025-07-25

### Features

- **core**: added asn hosting discovery styles and api for remote report from a grinder waf log reader (`patch candidate`)

## [1.0.20] - 2025-07-21

### Features

- **core**: added asn additional support virtus total and more apis to test (`patch candidate`)
- **core**: upgrade to postgres and enhanced asn method and abuse method, already aligned with icann

## [1.0.19] - 2025-03-06

### Bug Fixes

- **core**: fixed report threads and templates (`patch candidate`)

## [1.0.18] - 2025-03-01

### Other Changes

- ️ perf(core): perpetual scan memory leak solved 1b uris [patch candidate]

## [1.0.17] - 2025-02-27

### Bug Fixes

- **core**: fixed scan memory overhealm (`patch candidate`)

## [1.0.16] - 2025-02-27

### Features

- **core**: added asn info and cloudflare check (`patch candidate`)

## [1.0.15] - 2025-02-27

### Bug Fixes

- **core**: fixed cc mails and escalations (`patch candidate`)

## [1.0.14] - 2025-02-27

### Features

- **core**: added auto raise hand for report (`patch candidate`)

## [1.0.13] - 2025-02-25

### Documentation

- **core**: fix doc error (`patch candidate`)

## [1.0.12] - 2025-02-25

### Features

- **core**: added report threads well docs (`patch candidate`)

## [1.0.11] - 2025-02-25

### Bug Fixes

- **core**: fixed destination abuse fix mail by registar using sqlite table (`patch candidate`)

## [1.0.10] - 2025-02-25

### Features

- **core**: added report thread (`patch candidate`)

## [1.0.9] - 2025-02-25

### Features

- **core**: added report thread on system (`patch candidate`)

## [1.0.8] - 2025-02-24

### Documentation

- **core**: fixed badge sec (`patch candidate`)

## [1.0.7] - 2025-02-24

### Documentation

- **core**: fixed docs bad entries (`patch candidate`)

## [1.0.6] - 2025-02-24

### Features

- **core**: added sqlite and well docs (`patch candidate`)

## [1.0.5] - 2025-02-24

### Features

- **core**: added sqlite and well docs (`patch candidate`)

## [1.0.4] - 2025-02-23

### Other Changes

- ️ refactor(core): added new thread processor [patch candidate]

## [1.0.3] - 2025-02-23

### Bug Fixes

- **core**: fixed logger and repo extra files (`patch candidate`)
- **deps**: update pytest-cov requirement from ^5.0.0 to ^6.0.0 (#2)
- **deps**: update pytest-cov requirement from ^5.0.0 to ^6.0.0

## [1.0.2] - 2025-02-23

### Features

- **core**: added initial version (`patch candidate`)
- **core**: init dev

### Other Changes

- Initial commit
