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
