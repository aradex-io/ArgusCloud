# CloudGraph — Remediation Summary

**Branch:** claude/app-review-findings-W0QvG
**Findings doc:** REVIEW_FINDINGS.md
**Date:** 2026-05-11
**Reviewer (PR7):** Claude Code (self-review pass)

---

## Commits

| SHA | PR | Summary |
|-----|----|---------|
| 6412f0f | — | Add phased application review findings doc |
| 6e05eef | PR1 | Repo hygiene, build fixes, CI bootstrap |
| e5c618d | PR2 | Critical security fixes (Cypher injection, defaults, CORS, leak) |
| 54b4077 | PR3 | Wire dormant API infrastructure into create_app |
| 41b5714 | PR4 | Activate new rules engine; fix false positives, severity drift, missing rules |
| dab21b8 | PR5 | Data layer atomicity, schema constraints, validation |
| becba74 | PR6 | UI XSS hardening, CSP, bug fixes, settings persistence |
| dccecce | PR7 | Fix CORS test regressions (Origin header missing in two tests) |

---

## Findings Status (cross-reference REVIEW_FINDINGS.md)

| Finding | Severity | Status | Commit | Notes |
|---------|----------|--------|--------|-------|
| C-01 | Critical | DEFERRED | — | Requires git filter-repo + cred rotation by repo owner. `data/` files removed from HEAD (git rm) but history not purged. |
| C-02 | Critical | FIXED | 6e05eef | Dockerfile `COPY` and CMD now use `cloudgraph/` throughout. |
| C-03 | Critical | FIXED | e5c618d | `VALID_EDGE_TYPES` frozenset allowlist + ValueError on unknown type. |
| C-04 | Critical | FIXED | e5c618d | All `letmein123` defaults removed; `start.sh` now explicitly rejects that value as a production guard; `.env.example` uses `<CHANGE_ME>`. |
| C-05 | Critical | FIXED | e5c618d | `AUTH_ENABLED` defaults to `true` in dev compose and `start.sh`. |
| C-06 | Critical | FIXED | 54b4077 | `init_metrics`, `init_graceful_shutdown`, `init_rate_limiting`, `handle_api_errors` all called inside `create_app()`. |
| C-07 | Critical | FIXED | 41b5714 | `cmd_analyze` now calls `evaluate_all_rules` from the new engine; both engines' results are merged. |
| H-01 | High | FIXED | becba74 | `escapeHtml()` applied to 32 call sites in `app.js`; no remaining `innerHTML = ...${serverValue}` sinks. |
| H-02 | High | FIXED | becba74 | CSP header added to `nginx.conf`; `crossorigin="anonymous"` added to CDN scripts in `index.html`. Note: SRI `integrity=` hashes not yet added. |
| H-03 | High | NOT-DONE | — | UI auth flow (login form, token storage, fetch wrapper) not implemented. Deferred — requires significant frontend architecture work. |
| H-04 | High | FIXED | e5c618d | `CORS(app)` wildcard removed; `after_request` hook gates `Allow-Credentials` on origin allowlist. |
| H-05 | High | PARTIAL | 6e05eef | `git rm -r --cached data/` committed; files removed from HEAD. History purge (filter-repo) blocked on repo owner action. |
| H-06 | High | FIXED | 6e05eef | `pyproject.toml` URLs updated to cloudgraph; `.env.example` declares `0.5.0`; Dockerfile OCI labels aligned. |
| H-07 | High | FIXED | 6e05eef | `SECURITY.md` now instructs GitHub Security Advisories; table updated to `0.5.x` supported. |
| H-08 | High | FIXED | dab21b8 | `_upsert_profile_atomic` wraps all writes in `session.execute_write` with UNWIND batching. |
| H-09 | High | FIXED | dab21b8 | `_ensure_schema()` called on driver init; `CREATE CONSTRAINT resource_id_unique` runs at startup. |
| H-10 | High | NOT-DONE | — | Two divergent normalizer paths still exist. Consolidation deferred — large refactor. |
| H-11 | High | NOT-DONE | — | EC2/SG/VPC node IDs still use bare AWS IDs, not ARNs. Deferred. |
| H-12 | High | FIXED | 41b5714 | Both `awshound/rules.py` and `cloudgraph/normalizers/aws/ec2.py` now check `Ipv6Ranges` / `::/0`. |
| H-13 | High | FIXED | 41b5714 | `rule_codepipeline_risk` disabled with comment explaining reason; `rule_codebuild_secret_exfil` uses keyword filter from new engine. |
| H-14 | High | NOT-DONE | — | Pydantic models still not used for validation at request boundaries. Deferred. |
| H-15 | High | NOT-DONE | — | `app.run()` still used in `cmd_serve`. Deferred (gunicorn exec replacement). |
| H-16 | High | FIXED | 54b4077 | `handle_api_errors(app)` called in `create_app()`; `APIError` hierarchy in use. |
| H-17 | High | FIXED | e5c618d | `logger.exception()` used in collect.py; sanitized error messages stored on jobs; `str(e)` leakage removed from save_profile. |
| H-18 | High | NOT-DONE | — | OpenAPI spec still hand-authored and not served. Deferred. |
| H-19 | High | FIXED | 6e05eef | `start.sh` uses `set -euo pipefail`. |
| H-20 | High | NOT-DONE | — | Docker base images still use floating tags. Deferred (Renovate/Dependabot setup needed). |
| H-21 | High | FIXED | 6e05eef | `.github/workflows/ci.yml` added with ruff, mypy, pytest, and build matrix. |
| M-01 | Medium | FIXED | 54b4077 | `AuthConfig` accepts `jwt_expiry` param; `create_jwt_token` uses it; compose default 3600. |
| M-02 | Medium | NOT-DONE | — | Rate limiter still defaults to in-memory storage. Deferred (Redis requirement). |
| M-03 | Medium | FIXED | e5c618d | Region validated against `^[a-z]{2,}-[a-z]+-\d+$` before passing to boto3. |
| M-04 | Medium | FIXED | e5c618d | ZIP filenames normalized with `posixpath.normpath`; path traversal sequences rejected. |
| M-05 | Medium | FIXED | 54b4077 | Module-level `_job_manager_lock` and `_upload_manager_lock` (`threading.Lock`) guard singleton init. |
| M-06 | Medium | NOT-DONE | — | Cancellation granularity still per-service, not per-API-call. Deferred. |
| M-07 | Medium | FIXED | dab21b8 | `list_profiles` uses single aggregating Cypher query (no N+1 loop). |
| M-08 | Medium | FIXED | 41b5714 | `rule_public_s3` skips KMS resource policies (`if "kms" not in node.id`). |
| M-09 | Medium | FIXED | 41b5714 | `kms-cross-account` compares key account ID to principal account ID; same-account skipped. |
| M-10 | Medium | NOT-DONE | — | `extract_principals` still ignores `Effect`/`Condition`/`NotPrincipal`. Deferred. |
| M-11 | Medium | FIXED | 41b5714 | `cloudtrail-missing` severity upgraded to `high` in active engine. |
| M-12 | Medium | NOT-DONE | — | Public EC2 snapshot detection still conflated (encryption vs is_public). Deferred. |
| M-13 | Medium | FIXED | 41b5714 | `rule_rds_publicly_accessible` added to both `cloudgraph/rules/aws/data.py` and `awshound/rules.py`. |
| M-14 | Medium | NOT-DONE | — | IAM privilege escalation rules (PassRole, UpdateFunctionCode, CloudFormation) not yet added. Deferred. |
| M-15 | Medium | NOT-DONE | — | `assume-role-chain` BFS still O(P×A×BFS). Deferred. |
| M-16 | Medium | FIXED | becba74 | `cloudgraph/exporters/html.py` uses `html.escape()` on all dynamic values (5 call sites). |
| M-17 | Medium | FIXED | becba74 | `applyFilters(nodes, edges)` call at line 350 now passes module-level args. |
| M-18 | Medium | FIXED | becba74 | `debounce()` utility added; search input uses 300ms debounce; Cytoscape updates use `cy.batch()`. |
| M-19 | Medium | NOT-DONE | — | ARIA attributes and focus trap not added to modals. Deferred. |
| M-20 | Medium | NOT-DONE | — | No responsive CSS breakpoints. Deferred. |
| M-21 | Medium | FIXED | 6e05eef | Both `docker-compose.yml` and `docker-compose.prod.yml` use `condition: service_healthy` (verified ≥4 matches). |
| M-22 | Medium | NOT-DONE | — | `tests/test_rules_rds.py` still imports legacy awshound module. Deferred. |
| M-23 | Medium | NOT-DONE | — | `test_normalize.py` still covers only ~4 of 36 normalizer functions. Deferred. |
| M-24 | Medium | NOT-DONE | — | Only IAM collector has a test; S3, EC2, STS untested. Deferred. |
| M-25 | Medium | FIXED | 6e05eef | `pyproject.toml` `addopts` includes `--cov-fail-under=40` (gate at 40%; floor to be raised). |
| M-26 | Medium | NOT-DONE | — | Integration tests still skip when testcontainers absent; no CI step installs it. Deferred. |
| M-27 | Medium | FIXED | e5c618d | `.env.example` uses `<CHANGE_ME>` with generation instructions. |
| M-28 | Medium | FIXED | 6e05eef | `.pre-commit-config.yaml` and `Makefile` added. |
| M-29 | Medium | NOT-DONE | — | Plugin registry bridge not implemented. Deferred. |
| M-30 | Medium | NOT-DONE | — | Dual codebase (awshound vs cloudgraph collectors) still present. Long-term migration needed. |
| L-01 | Low | FIXED | e5c618d | JWT `iss="cloudgraph"` and `aud="cloudgraph-api"` required at encode/decode. |
| L-02 | Low | FIXED | e5c618d | `/plugins` strips `errors` key from unauthenticated responses. |
| L-03 | Low | NOT-DONE | — | CLI commands still raise raw tracebacks. Deferred. |
| L-04 | Low | NOT-DONE | — | `get_job`/`list_jobs` dict access still lock-free. Deferred. |
| L-05 | Low | FIXED | dab21b8 | `Node`, `Edge`, and `AttackPath` all have `__post_init__` validation. |
| L-06 | Low | NOT-DONE | — | Mutable class-level default lists in `BaseCollector`/`BaseRule`. Deferred. |
| L-07 | Low | NOT-DONE | — | SARIF `fixes` block still omits `artifactChanges`. Deferred. |
| L-08 | Low | NOT-DONE | — | SQS node ID still uses queue URL. Deferred. |
| L-09 | Low | NOT-DONE | — | `AWSCredentials.clear()` false zeroization assurance. Deferred (documented limitation). |
| L-10 | Low | NOT-DONE | — | 28+ near-duplicate normalizer handlers. Deferred (accelerate M-30 retirement). |
| L-11 | Low | NOT-DONE | — | `NodeFilter.limit` int not validated/capped. Deferred. |
| L-12 | Low | FIXED | e5c618d | `get_profile` and `delete_profile` now call `validate_profile_name`. |
| L-13 | Low | FIXED | becba74 | `cloudgraph_saved_filters` JSON.parse wrapped in try/catch. |
| L-14 | Low | NOT-DONE | — | Upload modal interval leak. Deferred. |
| L-15 | Low | FIXED | becba74 | `<pre>` node detail uses `textContent` (not innerHTML). |
| L-16 | Low | FIXED | becba74 | API base URL persisted to `localStorage` and restored on init. |
| L-17 | Low | FIXED | 6e05eef | `ui/index.original.html` deleted. |
| L-18 | Low | NOT-DONE | — | `demo/demo-lite.pdf` binary still in repo. Deferred (release asset). |
| L-19 | Low | NOT-DONE | — | `pyproject.toml` `all` extra omits `prod`. Deferred. |
| I-01 | Info | NOT-DONE | — | GCP/Azure stubs; README implies parity. Deferred (documentation). |
| I-02 | Info | NOT-DONE | — | No MITRE/CIS mapping on rules. Deferred. |

---

## Test Results

### Pre-PR baseline (per PR5 agent report)
- 705 passed, 3 failed, 21 errors

### Post-PR7 (verified)
- **707 passed, 1 failed, 21 errors** (net: +2 pass, -2 fail vs baseline)

#### Remaining failure
- `tests/collectors/test_iam_collector.py::TestIAMRoleCollection::test_collect_attached_policies`
  — moto fixture issue: `arn:aws:iam::aws:policy/ReadOnlyAccess` not available in the moto mock version. **Pre-existing; not introduced by PRs 1-6.**

#### Fixed regressions (PR7)
- `tests/security/test_api_security.py::TestCORSSecurity::test_cors_headers_set` — test was not sending an `Origin` header; PR2's correct CORS fix (no wildcard) requires an Origin for the header to be echoed back.
- `tests/test_api_server.py::TestCORSHeaders::test_cors_headers_present` — same root cause.

#### Errors (21)
All are `tests/integration/test_api_integration.py` — these require a live Neo4j instance (testcontainers). They skip/error when testcontainers is absent, matching the pre-PR baseline.

### Lint (ruff)
- **373 errors** post-PR7 vs **374 errors** at baseline — no lint regressions introduced. Most errors are pre-existing style issues (import sort order, line length, unused imports in test files). All are auto-fixable with `ruff --fix`; none are logic errors.

### Smoke test
```
routes: 26
```
`create_app()` constructs successfully with required args (`uri`, `user`, `password`). Warnings emitted for missing optional dependencies (`prometheus_client`, `flask-limiter[redis]`) — expected in dev environment, both are optional extras. **No crash. PASS.**

Note: The smoke test verified via `create_app(uri, user, password, auth_config)` signature — three positional arguments are required (not read from env vars). This is by design; the `wsgi.py` entrypoint reads env vars and passes them.

---

## Open Items (Prioritised)

### Priority 1 — Blocking security (repo owner action required)
- **C-01 / H-05**: History purge of `data/` directory. Run `git filter-repo --path data/ --invert-paths` and force-push. Rotate credentials for AWS account `180294212498`.

### Priority 2 — High security gaps remaining
- **H-03**: UI has no authentication — no login flow, no Authorization header on any fetch. Without this, auth enforcement at the API layer cannot be used from the UI.
- **H-02 (partial)**: SRI `integrity=` hashes still missing from CDN script tags. CSP is added, but SRI completes the supply-chain protection.
- **H-20**: Docker base image digest pinning — floating tags (`python:3.11-slim`) are supply-chain risk.
- **H-10**: Two divergent normalizer paths with incompatible schemas. Rules silently get wrong data.
- **H-11**: EC2/SG/VPC node IDs use bare AWS IDs (not ARNs) — multi-account graph corruption.

### Priority 3 — Medium correctness/completeness
- **M-30 / H-10**: Retire one of the two collector codebases (awshound vs cloudgraph/collectors/aws/).
- **M-10**: `extract_principals` ignores `Effect`/`Condition` — false positives on restricted policies.
- **M-12**: Public EC2 snapshot rule conflates encryption with is_public.
- **M-14**: Missing IAM privilege escalation rules (PassRole, UpdateFunctionCode, CloudFormation).
- **M-22 / M-23 / M-24**: Test coverage gaps in normalizers and collectors.
- **M-26**: Integration tests not wired into CI.
- **M-02**: Rate limiter in-memory default ineffective with multiple gunicorn workers.

### Priority 4 — Low/deferred hygiene
- **H-14**: Pydantic models not used at request boundaries (validation bypassed).
- **H-15**: `app.run()` dev server in `cmd_serve` path.
- **H-18**: OpenAPI spec hand-authored, not served, and drifting.
- **L-03**: CLI raw tracebacks.
- **L-07**: SARIF `fixes.artifactChanges` missing.
- **L-18**: `demo/demo-lite.pdf` binary in repo.
- **L-19**: `pyproject.toml` `all` extra omits `prod`.
- **I-01 / I-02**: GCP/Azure stub documentation; MITRE/CIS rule mapping.

---

## Verification Spot-Check Results

| Check | File(s) | Result |
|-------|---------|--------|
| C-02: no cloudhound in Dockerfile | `Dockerfile` | PASS |
| H-06: CLOUDGRAPH_VERSION in .env.example | `.env.example` | PASS (0.5.0) |
| H-07: GitHub Security Advisories in SECURITY.md | `SECURITY.md` | PASS |
| H-19: set -euo pipefail in start.sh | `start.sh` | PASS |
| L-17: index.original.html deleted | `ui/` | PASS |
| M-21: service_healthy conditions | `docker-compose.yml`, `docker-compose.prod.yml` | PASS (4 matches) |
| M-25: cov-fail-under in pyproject.toml | `pyproject.toml` | PASS (40%) |
| M-28: Makefile and .pre-commit-config.yaml | repo root | PASS |
| H-21: CI workflow exists | `.github/workflows/ci.yml` | PASS |
| H-05: data/ untracked | `git ls-files data/` | PASS (0 files) |
| C-03: VALID_EDGE_TYPES allowlist + check | `cloudgraph/repositories/neo4j_repository.py` | PASS |
| C-04: letmein123 as a default | all source files | PASS (only in validation guard) |
| C-05: AUTH_ENABLED defaults to true | `docker-compose.yml` | PASS |
| H-04: no CORS(app) wildcard | `cloudgraph/api/server.py` | PASS |
| H-17: logger.exception in collect.py | `cloudgraph/api/collect.py` | PASS (3 call sites) |
| L-01: JWT_ISSUER/JWT_AUDIENCE | `cloudgraph/api/auth.py` | PASS |
| C-06/H-16: all 4 init functions in create_app | `cloudgraph/api/server.py` | PASS |
| M-01: jwt_expiry in AuthConfig | `cloudgraph/api/auth.py` | PASS |
| M-05: _job_manager_lock/threading.Lock | `cloudgraph/api/collect.py`, `uploads.py` | PASS |
| C-07: evaluate_all_rules called | `cloudgraph/cli/main.py` | PASS |
| H-12: Ipv6Ranges/::/0 check | `awshound/rules.py`, `cloudgraph/normalizers/aws/ec2.py` | PASS |
| H-13: rule_codepipeline_risk disabled | `awshound/rules.py` | PASS (disabled with comment) |
| M-08: KMS skip in rule_public_s3 | `awshound/rules.py` | PASS |
| M-09: same-account KMS skip | `awshound/rules.py` | PASS |
| M-11: cloudtrail-missing severity=high | `awshound/rules.py` | PASS |
| M-13: rule_rds_publicly_accessible | `cloudgraph/rules/aws/data.py`, `awshound/rules.py` | PASS |
| H-09: _ensure_schema/CREATE CONSTRAINT | `cloudgraph/repositories/neo4j_repository.py` | PASS |
| H-08: _upsert_profile_atomic/execute_write | `cloudgraph/repositories/neo4j_repository.py` | PASS |
| M-07: list_profiles no N+1 loop | `cloudgraph/repositories/neo4j_repository.py` | PASS (single aggregating query) |
| L-05: __post_init__ on Node/Edge | `cloudgraph/core/graph.py` | PASS (3 classes) |
| H-01: escapeHtml call count | `ui/js/app.js` | PASS (32 calls) |
| H-02: CSP in nginx.conf | `ui/nginx.conf` | PASS |
| H-02: crossorigin on CDN scripts | `ui/index.html` | PASS |
| M-16: html.escape count | `cloudgraph/exporters/html.py` | PASS (5 calls) |
| M-17: applyFilters(nodes, edges) | `ui/js/app.js` | PASS |
| M-18: debounce present | `ui/js/app.js` | PASS |
| L-13: try/catch on saved filters JSON.parse | `ui/js/app.js` | PASS |
| L-15: textContent for JSON stringify | `ui/js/app.js` | PASS |
| L-16: apiBase localStorage persistence | `ui/js/app.js` | PASS |
