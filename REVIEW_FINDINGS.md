# ArgusCloud — Application Review Findings

**Review date:** 2026-05-11
**Branch:** `claude/app-review-findings-W0QvG`
**Version reviewed:** 0.5.0 (per `pyproject.toml`)
**Scope:** Full application — architecture, security, API, data layer, rules engine, UI, testing & DevOps.
**Method:** Seven-phase parallel review with planning by Opus and per-phase execution by Sonnet sub-agents. Findings below are de-duplicated and re-rated against a single severity scale.

---

## Severity scale

| Severity | Definition |
|----------|------------|
| **Critical** | Direct exploitability or guaranteed runtime failure; ship-blocker. |
| **High** | Likely exploitability under realistic conditions, or major correctness defect that affects the primary product surface. |
| **Medium** | Conditional exploitability, defense-in-depth gap, or significant correctness/maintainability issue. |
| **Low** | Hygiene, code quality, or minor correctness; should be fixed but not urgent. |
| **Info** | Observation, future risk, or documentation/process suggestion. |

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High     | 21 |
| Medium   | 30 |
| Low      | 19 |
| Info     | 2 |
| **Total**| **79** |

Where two phases independently flagged the same defect, the items have been merged and the severities reconciled.

---

## Critical

### C-01 — Real AWS account data and credentials artifacts committed to repository
**Location:** `data/sts.jsonl`, `data/iam-users.jsonl`, `data/iam-roles.jsonl`, `data/s3.jsonl`, `data/ec2.jsonl`, `data/nodes.jsonl` (35 files total)
**Evidence:** AWS account ID `180294212498` is embedded in ARNs across 7+ files (e.g., `arn:aws:iam::180294212498:user/cloudhound_tester`). `sts.jsonl` records the IAM user ARN and `UserId` `AIDAST6S7LOJMO7NF2XES` used to collect the data. S3 HostIds, real STS request IDs, and SageMaker roles dated December 2024 are present.
**Impact:** Permanent exposure of a real AWS account number, IAM principal names, role names, S3 bucket names, and S3 canonical owner ID. Enables targeted enumeration (cross-account role assumption attempts, S3 bucket guessing) against the real account. The `.gitignore` already lists `data/`, but the files were committed before the rule was added and remain tracked.
**Recommendation:** (1) Rotate any credential associated with account `180294212498`. (2) `git rm -r --cached data/ normalized/` and commit. (3) Purge from git history with `git filter-repo`. (4) Replace with synthetic data using account ID `123456789012`. (5) Add a pre-commit hook blocking real AWS account-ID patterns.

### C-02 — Dockerfile references non-existent `cloudhound/` directory; image build is broken
**Location:** `Dockerfile:34-37, 53-55, 64`
**Evidence:** `COPY cloudhound/ ./cloudhound/`, `COPY cloudhound.py ./`, `CMD ["gunicorn", ..., "cloudhound.api.wsgi:application"]`. The package was renamed to `arguscloud/` and `cloudhound.py` is in `.gitignore`.
**Impact:** Every `docker build` / `docker compose up` fails at the first COPY step. The containerized deployment path is entirely non-functional.
**Recommendation:** Replace all `cloudhound/` and `cloudhound.py` references with `arguscloud/` and update the gunicorn target to `arguscloud.api.wsgi:application`.

### C-03 — Cypher injection via interpolated relationship type in `save_profile` / repository
**Location:** `arguscloud/repositories/neo4j_repository.py:443-448`
**Evidence:**
```python
edge_type = edge.get("type", "RELATES_TO")
edge_query = f"""
MATCH (a {{id: $src}}), (b {{id: $dst}})
MERGE (a)-[r:{edge_type}]->(b)
"""
```
`edge_type` is sourced from caller-supplied JSON (upload / profile-save bodies). Cypher cannot parameterize relationship types, but the value is interpolated with no validation.
**Impact:** Any authenticated user able to POST a profile can break out of the relationship-type position with payloads such as `REL]->(b) DETACH DELETE n //` and execute arbitrary Cypher — full read, modify, delete on the graph database, including credential / profile node tampering.
**Recommendation:** Validate `edge_type` against a strict allowlist (e.g., regex `^[A-Z_]{1,60}$`) and reject unknown values. Define an enum of valid relationship types and reject anything outside it.

### C-04 — Hardcoded weak default credentials in code, compose, and `.env.example`
**Location:** `arguscloud/api/wsgi.py:41`, `arguscloud/api/server.py:990`, `arguscloud/cli/main.py:181, 209`, `start.sh:24-27`, `.env.example:18`, `docker-compose.yml:63`
**Evidence:**
```python
neo4j_password = os.environ.get("ARGUSCLOUD_NEO4J_PASSWORD", "letmein123")
parser.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD", "letmein123"))
```
```yaml
JWT_SECRET: ${JWT_SECRET:-dev-secret-change-in-production}
```
**Impact:** Any deployment that does not explicitly set `ARGUSCLOUD_NEO4J_PASSWORD` and `ARGUSCLOUD_JWT_SECRET` runs with publicly known credentials. The fallback JWT secret allows token forgery against any user. The Neo4j fallback exposes the full graph database to anyone reachable on port 7687.
**Recommendation:** Remove every literal `letmein123` and `dev-secret-change-in-production`. Fail-fast at startup if the env vars are unset (mirror the `${VAR:?error}` pattern already used in `docker-compose.prod.yml`). Centralize on `arguscloud/config.py` (which correctly defaults to empty string).

### C-05 — Authentication disabled by default in dev compose and `start.sh`
**Location:** `docker-compose.yml:59`, `start.sh:25`
**Evidence:** `ARGUSCLOUD_AUTH_ENABLED: ${AUTH_ENABLED:-false}` and `DEFAULT_AUTH_ENABLED="false"`.
**Impact:** The documented quickstart (`docker compose up`) launches the API with no authentication. Combined with exposed Neo4j ports (7474, 7687), the entire database and all collected cloud data is reachable by anyone on the network. A developer who runs dev compose on a non-isolated host trivially exposes their data.
**Recommendation:** Default to `AUTH_ENABLED=true`. Document a one-liner to generate a JWT secret (`openssl rand -base64 32`). Treat dev compose as production-shaped, with auth on by default.

### C-06 — `init_metrics`, `init_graceful_shutdown`, `init_rate_limiting`, and `handle_api_errors` are never wired into the Flask app
**Location:** `arguscloud/api/server.py:create_app()` (and `wsgi.py`); `arguscloud/api/metrics.py`, `arguscloud/api/shutdown.py`, `arguscloud/api/ratelimit.py`, `arguscloud/api/errors.py`
**Evidence:** Searching `server.py` and `wsgi.py` for `init_metrics|init_graceful_shutdown|init_rate_limiting|handle_api_errors` returns zero matches. The error classes (`APIError`, `NotFoundError`, `ConflictError`) and the `safe_endpoint` decorator are imported nowhere.
**Impact:** Four substantial subsystems documented as supported are inert at runtime: (1) no Prometheus metrics, no `/metrics` endpoint; (2) Neo4j driver and threads never closed on shutdown — leaks on every restart; (3) no rate limiting at all (the OpenAPI doc claims 100 req/min on `/query`, 10/hour on collect, but no limit fires); (4) Flask's default 500 handler returns full HTML tracebacks instead of the standardized error envelope. Combined with C-04, this means a misconfigured production deployment has no metrics, no graceful drain, no rate limit, and leaks tracebacks.
**Recommendation:** In `create_app()`, after configuration, call all four init functions in order. Add a startup self-test that asserts each initializer ran. Fail-fast if `flask-limiter` is missing in non-dev environments.

### C-07 — Entire new rules engine (`arguscloud/rules/aws/`) is dead code; only legacy `awshound` rules execute
**Location:** `arguscloud/cli/main.py:328-351`
**Evidence:**
```python
from awshound import rules
...
attack_edges = rules.evaluate_rules(nodes, edges)
```
The 23 modular rules under `arguscloud/rules/aws/` (better-structured, with remediation, severity enums, IMDSv2-aware checks) are registered via decorators but never invoked. `arguscloud.rules.evaluate_all_rules` has no call sites.
**Impact:** Every architectural improvement in the new engine — including correct severity for CloudTrail-missing (High vs legacy Medium), correct public-snapshot detection (vs the legacy snapshot-encryption confusion), CodeBuild secret keyword filtering, structured remediation guidance — is silently bypassed. Users believe they are getting the documented detections; they are not.
**Recommendation:** Switch `cmd_analyze` to call `arguscloud.rules.evaluate_all_rules` (or call both engines and union the results, deduplicating). Add an end-to-end integration test asserting the new engine fires on a known fixture.

---

## High

### H-01 — XSS via unescaped API data injected into `innerHTML` (multiple sinks)
**Location:** `ui/js/app.js:1742-1746, 2856-2867, 3713-3726, 3717-3718, 3896-3900, 4231, 4477-4479`; `arguscloud/exporters/html.py:183-191`
**Evidence:** Template literals interpolate API-sourced strings (`n.type`, `n.id`, `e.src`, `e.dst`, `rule`, `description`, server error text, `progress.errors[i]`) directly into `innerHTML` with no escaping. Example:
```js
document.getElementById('uploadErrors').innerHTML =
  progress.errors.map(e => `<div style="padding: 2px 0;">${e}</div>`).join('');
```
The HTML exporter has the equivalent issue when emitting standalone reports.
**Impact:** Attacker-controlled resource names (S3 buckets, IAM roles, Lambda functions named `<script>...</script>`) execute JavaScript in any user's browser when the graph is viewed. Server-supplied error messages are also injected verbatim, providing a second injection channel from a backend compromise. Stored XSS in downloaded HTML reports persists offline.
**Recommendation:** Apply `escapeHtml()` (already defined at `app.js:3854`) to every server-sourced value before template-string interpolation. Prefer `textContent` for leaf inserts. Replace the inline `onclick="..."` strings with `addEventListener` to eliminate attribute-injection variants. In `exporters/html.py`, wrap every dynamic interpolation in `html.escape()`.

### H-02 — No Content-Security-Policy header; CDN scripts loaded without SRI
**Location:** `ui/nginx.conf:14-18`, `ui/index.html:47-48` (CDN scripts), no `<meta http-equiv="Content-Security-Policy">` anywhere
**Evidence:** nginx sets X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy — but no CSP. `<script src="https://unpkg.com/cytoscape@3.28.1/...">` and `<script src="https://unpkg.com/jszip@3.10.1/...">` lack `integrity` and `crossorigin` attributes.
**Impact:** CSP is the primary mitigation for the XSS sinks in H-01 — its absence makes those bugs maximally exploitable. SRI absence means a unpkg.com compromise (or package hijack) yields full code execution in every user's browser, with access to AWS ARNs and Cypher query results.
**Recommendation:** Add `Content-Security-Policy: default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' http://127.0.0.1:9847; object-src 'none'` to nginx. Compute and add `integrity="sha384-..."` to both unpkg scripts. Consider vendoring them to the repo entirely.

### H-03 — UI has no authentication: hardcoded API URL, no Authorization header on any fetch
**Location:** `ui/index.html:821`, `ui/js/app.js` (all `fetch()` call sites)
**Evidence:** `<input type="text" id="apiBase" value="http://127.0.0.1:9847">`. No `Authorization` header is added in any of the 5006 lines of `app.js`. No 401 detection, no login flow.
**Impact:** Even with the API correctly enforcing auth (which it does not by default — see C-05), the UI is incapable of authenticating. The shipped frontend is unusable against a secured backend, which incentivizes operators to disable auth (closing the loop on C-05).
**Recommendation:** Add a token entry / login flow, store the token in a non-JS-readable httpOnly cookie if the API is co-hosted, and attach it via a central fetch wrapper that intercepts 401 → redirect to login.

### H-04 — CORS misconfiguration: `flask_cors.CORS(app)` (wildcard) plus manual after-request hook
**Location:** `arguscloud/api/server.py:129, 144-155`
**Evidence:**
```python
CORS(app)  # default — Access-Control-Allow-Origin: *
@app.after_request
def add_cors(resp):
    ...
    resp.headers["Access-Control-Allow-Credentials"] = "true"
```
**Impact:** Two CORS configurations run on every response. Depending on header-merge order, the wildcard can win. `Access-Control-Allow-Credentials: true` is set unconditionally (not gated on origin allowlist), and combined with a wildcard origin would either be rejected by browsers or — if a proxy reorders headers — enable cross-origin authenticated requests from any site.
**Recommendation:** Remove `CORS(app)`. Keep only the manual hook, and only set `Access-Control-Allow-Credentials: true` when the request `Origin` is in `ALLOWED_ORIGINS`.

### H-05 — `data/` and `normalized/` directories tracked in git despite being in `.gitignore`
**Location:** `.gitignore` (entries `data/`, `normalized/`); `git ls-files data/` returns 35 tracked files
**Evidence:** Files were committed before the gitignore entry was added. The current real-data files (see C-01) remain tracked.
**Impact:** Silent violation of intended exclusion rules. Combined with C-01, the real account data persists. Any normal `git add .` workflow would re-commit updated dumps.
**Recommendation:** `git rm -r --cached data/ normalized/`, commit, and history-purge per C-01.

### H-06 — `pyproject.toml` URLs and CHANGELOG version skew with Dockerfile/`.env.example`
**Location:** `pyproject.toml` `[project.urls]`, `Dockerfile` OCI labels, `.env.example` `ARGUSCLOUD_VERSION`
**Evidence:** All four URLs (`Homepage`, `Documentation`, `Repository`, `Issues`) point to `github.com/jeremylaratro/cloudhound`. Dockerfile labels and `.env.example` declare `0.3.0`; pyproject and CHANGELOG are at `0.5.0`.
**Impact:** PyPI metadata directs users to a wrong/non-existent repo (and a typosquattable name). Container images built today are labeled `0.3.0` even though they contain `0.5.0` code, breaking version-based rollback and audit trails.
**Recommendation:** Update URLs to `arguscloud`. Derive version from a single source (`importlib.metadata.version("arguscloud")`) and add a CI assertion that all version strings agree before release.

### H-07 — `SECURITY.md` instructs reporters to use public GitHub issues; supported-versions table is stale
**Location:** `SECURITY.md:13`
**Evidence:** "Please open a GitHub issue for security vulnerabilities." Table lists `0.3.x` and `0.2.x` as supported; current version is `0.5.0`.
**Impact:** Researchers following the policy publicly disclose vulnerabilities before any fix exists, defeating the purpose of a coordinated disclosure process.
**Recommendation:** Replace with GitHub Security Advisories private channel or a dedicated `security@` email. Update the supported-versions table to `0.5.x`.

### H-08 — Profile save runs as autocommit batch, not a transaction; partial-write corruption on failure
**Location:** `arguscloud/api/server.py:495-577`, `arguscloud/repositories/neo4j_repository.py:393-465`
**Evidence:** `save_profile` issues 6+ independent `session.run()` calls (existence check, delete, profile create, per-node insert, per-edge insert, count update). Each runs as its own implicit transaction.
**Impact:** A crash, network blip, or Neo4j timeout mid-operation leaves the database in a partial state: old profile deleted, new nodes partially inserted, counts never updated. There is no rollback path. For overwriting a large profile, this is a real data-integrity hazard.
**Recommendation:** Wrap the whole operation in `session.execute_write(lambda tx: ...)` with `UNWIND $batch` for nodes and edges, ensuring atomicity in a single round-trip per type.

### H-09 — No Neo4j indexes or uniqueness constraints; every `MERGE` performs a full node scan
**Location:** `arguscloud/repositories/neo4j_repository.py` (entire), `awshound/storage.py:50-58`
**Evidence:** No `CREATE INDEX` or `CREATE CONSTRAINT` statement appears in either file. The MERGE pattern `MERGE (n {id: $id})` without a label cannot use indexes.
**Impact:** Each write performs an O(n) scan. For a graph with tens of thousands of nodes, write throughput collapses and lock contention blocks concurrent profile uploads.
**Recommendation:** On driver connect, run `CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (n:Resource) REQUIRE n.id IS UNIQUE`. Apply a consistent `:Resource` label to every node so the index is usable.

### H-10 — Two divergent normalization paths (`awshound/normalize.py` vs `arguscloud/normalizers/aws/`) produce different node schemas
**Location:** `awshound/normalize.py:197-209` vs `arguscloud/normalizers/aws/iam.py:86-99` (and many more)
**Evidence:** Same resource, different keys: `role_name` vs `name`, `user_name` vs `name`. Date fields are raw `datetime` in awshound, stringified in arguscloud. `_extract_principals` and `_is_admin_policy` are duplicated verbatim across both codebases.
**Impact:** Rules and Cypher queries that target `n.name` silently produce empty results when consuming awshound-origin data, and vice versa. Bug fixes do not propagate. Combined with C-07 (only legacy engine runs), the schemas the rules expect and the schemas they receive are not always aligned.
**Recommendation:** Pick one normalizer codebase as canonical and remove the other. If migration is staged, define the canonical property schema as a `TypedDict`/dataclass and validate both writers against it in tests.

### H-11 — EC2 / SecurityGroup / Subnet / VPC / Snapshot nodes use bare AWS IDs (not ARNs); cross-account/region collisions
**Location:** `arguscloud/normalizers/aws/ec2.py:34`, `awshound/normalize.py:552-572`
**Evidence:** `Node(id=inst.get("InstanceId"), ...)` — `i-0a1b2c3d` is region- and account-scoped but not globally unique.
**Impact:** A multi-account or multi-region scan merged into one Neo4j graph silently overwrites nodes with the same short-ID. Data loss is invisible in the UI; attack-path analysis becomes incorrect.
**Recommendation:** Use full ARNs (`arn:aws:ec2:{region}:{account}:instance/{id}`) as node IDs across all resources lacking native ARNs (Instance, SecurityGroup, Subnet, VPC, Snapshot, Route Table, NACL).

### H-12 — Open-security-group rule misses IPv6 (`::/0`)
**Location:** `awshound/rules.py:99-101`, `arguscloud/normalizers/aws/ec2.py:216-218`
**Evidence:** Both engines iterate only `IpRanges` for `0.0.0.0/0`. `Ipv6Ranges` with `CidrIpv6: "::/0"` is never checked.
**Impact:** False negative for any dual-stack or IPv6-only VPC. Instances that appear "closed" can be reached over IPv6.
**Recommendation:** Iterate both `IpRanges` and `Ipv6Ranges`, checking `0.0.0.0/0` and `::/0`.

### H-13 — `rule_codepipeline_risk` and `rule_codebuild_secret_exfil` produce guaranteed false positives in the active engine
**Location:** `awshound/rules.py:351-364, 253-263`
**Evidence:** `rule_codepipeline_risk` flags any pipeline that has a `role_arn` (every valid pipeline has one — required by AWS). `rule_codebuild_secret_exfil` flags any project that has any environment variable, regardless of name. The new engine in `arguscloud/rules/aws/compute.py:129` correctly checks for sensitive keywords; that engine is dead code (C-07).
**Impact:** Every account scan emits noise findings, eroding analyst trust. Legitimate signals get buried.
**Recommendation:** Port the keyword filtering from the new engine into the active path, or fix C-07 so the new engine actually runs.

### H-14 — Pydantic request models defined but never used; manual `body.get()` validation throughout
**Location:** `arguscloud/api/models.py`, all POST handlers in `arguscloud/api/server.py`
**Evidence:** `CollectAWSRequest`, `ProfileRequest`, `QueryRequest` exist in `models.py`. POST handlers call `get_validated_json()` then `body.get("field")`, never `Model.model_validate(body)`. The `AWS_ACCESS_KEY_PATTERN` regex on `access_key` and the 40-char check on `secret_key` are silently bypassed at runtime.
**Impact:** Documented validation rules are not enforced. Schema drift between code, OpenAPI, and three parallel pydantic definitions (one in `models.py`, another in `openapi.py`).
**Recommendation:** Replace each `body = get_validated_json()` block with `req = Model.model_validate(body)` inside a `try/except pydantic.ValidationError` that returns a structured 422. Delete the duplicate model definitions in `openapi.py`.

### H-15 — `app.run()` (Flask dev server) used in both `cli serve` and `server.main()`
**Location:** `arguscloud/api/server.py:1002`, `arguscloud/cli/main.py:459`
**Evidence:** `app.run(host=args.host, port=args.port)` — single-threaded, not production-grade. The `wsgi.py` gunicorn entrypoint exists but is bypassed.
**Impact:** Operators following the README (`arguscloud serve --port 5000`) get a development server in production with poor concurrency, no graceful shutdown integration, and no signal handling consistent with gunicorn workers.
**Recommendation:** Make `cmd_serve` exec gunicorn (`subprocess.run(["gunicorn", "arguscloud.api.wsgi:application", ...])`) or refuse to start when `ARGUSCLOUD_ENV=production`. At minimum print a loud warning.

### H-16 — `errors.py` infrastructure not registered: full Flask tracebacks leak to clients
**Location:** `arguscloud/api/errors.py:85-147`, `arguscloud/api/server.py:create_app()`
**Evidence:** `handle_api_errors(app)` is never called; `safe_endpoint` decorator is applied to zero routes; `APIError`/`NotFoundError`/`ConflictError` are unused. Subset of C-06 but called out separately because it directly leaks server internals.
**Impact:** Any unhandled exception (Neo4j driver error, network failure, KeyError) is rendered as Flask's default HTML 500 page including a full traceback when `FLASK_DEBUG=1`, or a bare 500 otherwise. Combined with several routes that already do `return jsonify({"error": str(e)}), 500`, internal exception messages reach clients.
**Recommendation:** Call `handle_api_errors(app)` in `create_app()`. Replace direct `jsonify({"error": ...})` patterns with raised `APIError` subclasses.

### H-17 — Job-status endpoint returns raw exception strings to clients
**Location:** `arguscloud/api/collect.py:237, 263, 274`; `arguscloud/api/server.py:587, 709`
**Evidence:** `job.error = f"Failed to save to database: {str(e)}"` and `job.error = str(e)` get serialized via `to_dict()` and exposed through `GET /collect/<job_id>`. Save-profile and AWS-credentials handlers similarly do `return jsonify({"error": str(e)}), 5xx`.
**Impact:** Authenticated users (and combined with C-05, anonymous users) read internal Neo4j error codes, filesystem paths, library internals.
**Recommendation:** Categorize exceptions, store a sanitized `job.error_code` + `user_message`, and log full detail server-side via `logger.exception()`.

### H-18 — Hand-authored 1274-line OpenAPI spec drifts from actual routes; never served
**Location:** `arguscloud/api/openapi.py:652-1230`, `arguscloud/api/server.py` (no route serves the spec)
**Evidence:** `JobStatusResponse` documents `updated_at`; the actual `CollectionJob.to_dict()` doesn't emit it. `JobStartResponse` shows `status: "running"`; the real first status is `"pending"`. Documents `/auth/token` and rate limits that are inert (see C-06).
**Impact:** Any client generated from this spec receives unexpected responses. Drift compounds over time.
**Recommendation:** Switch to schema-first generation via `flask-smorest` or `apiflask` driven by the existing pydantic models. Add a CI test that hits each documented endpoint and asserts response shape.

### H-19 — `start.sh` lacks `set -u` and `set -o pipefail`
**Location:** `start.sh:6`
**Evidence:** Only `set -e`. Unset variable references silently expand to empty string; pipeline failures are swallowed.
**Impact:** Misconfigured environments pass validation silently. Stale variable values may be used after partial `source` failures.
**Recommendation:** `set -euo pipefail`, then audit `${VAR:-default}` patterns to ensure they still behave under `-u`.

### H-20 — Base Docker images use floating tags, no digest pinning
**Location:** `Dockerfile:7, 45`; `ui/Dockerfile:3, 13`; `docker-compose.yml:15`; `docker-compose.prod.yml:22`
**Evidence:** `FROM python:3.11-slim`, `FROM nginx:1.25-alpine`, `image: neo4j:5`. No `@sha256:...`.
**Impact:** Supply-chain risk: a compromised or breaking upstream change enters every build silently with no source-control diff.
**Recommendation:** Pin to digests. Use Renovate/Dependabot for automated, reviewable bumps.

### H-21 — No CI/CD pipeline exists
**Location:** Repository root — no `.github/workflows/`, no `.gitlab-ci.yml`, no equivalent
**Evidence:** `ls .github/` returns "No such file or directory".
**Impact:** No automated lint, type-check, or test execution. Combined with H-22 below, regressions and broken builds (e.g., C-02) are merged undetected.
**Recommendation:** Add `.github/workflows/ci.yml` running `ruff check`, `mypy`, `pytest --cov=arguscloud --cov-fail-under=60`, plus a Python matrix (3.9-3.12) and an integration job that exercises the testcontainers path.

---

## Medium

### M-01 — JWT expiry env var silently ignored; `AuthConfig` doesn't accept it
**Location:** `arguscloud/api/auth.py`, `arguscloud/api/wsgi.py:41`, `docker-compose.yml:64`
**Evidence:** `wsgi.py` instantiates `AuthConfig(jwt_expiry=jwt_expiry)`, but `AuthConfig.__init__` has no `jwt_expiry` parameter. `create_jwt_token` always uses the hardcoded `DEFAULT_JWT_EXPIRY = 3600`. Dev compose exposes `${JWT_EXPIRY:-86400}` (24 h) — if the bug is ever fixed, dev tokens become unreasonably long-lived.
**Recommendation:** Add `jwt_expiry: int` to `AuthConfig`, thread through `create_jwt_token`, and unify the default to 3600 across all compose files.

### M-02 — Rate limiter uses in-memory storage by default; per-worker counters multiply limits by worker count
**Location:** `arguscloud/api/ratelimit.py:89, 98-105`
**Evidence:** `storage_uri = os.environ.get("ARGUSCLOUD_RATELIMIT_STORAGE", "memory://")`. Default gunicorn config is 4 workers; each has its own counter, so a documented "100 req/min" effectively becomes 400.
**Recommendation:** Default to `redis://` in production; document the requirement. Make `flask-limiter` a hard dependency or refuse to start in non-dev environments without it.

### M-03 — Unvalidated `region` parameter passed to boto3
**Location:** `arguscloud/api/server.py:686, 706`; `arguscloud/collectors/session.py:86`
**Evidence:** `region = body.get("region")` → `AWSCredentials(..., region=region)` → `session_kwargs["region_name"]`. No format check.
**Impact:** Defense-in-depth gap: malformed regions trigger boto3 errors with messages that reach the client; some boto3 paths use `region_name` for endpoint construction.
**Recommendation:** Validate against `^[a-z]{2,}-[a-z]+-\d+$` or a known-region allowlist.

### M-04 — ZIP filenames not sanitized; profile-name path traversal
**Location:** `arguscloud/api/server.py:815-820`
**Evidence:** Iteration over `zf.namelist()` checks for trailing `/` and leading `__`, but `../../foo.jsonl` passes both. The first path segment becomes a profile name.
**Impact:** Traversal sequences are stored as Neo4j profile names; collisions with reserved names or unexpected behavior in downstream UI.
**Recommendation:** Reject entries where `posixpath.normpath(zip_name).startswith('..')` or apply `os.path.basename` to each.

### M-05 — Singleton job/upload managers lack initialization lock; race on first request
**Location:** `arguscloud/api/collect.py:148-156`, `arguscloud/api/uploads.py:110-118`
**Evidence:** `if _job_manager is None: _job_manager = JobManager()` outside any lock.
**Impact:** Two concurrent requests pre-init can each create a `JobManager`. Jobs created on the loser instance are invisible. Self-resolves but causes intermittent "job not found" bugs.
**Recommendation:** Initialize eagerly in `create_app()`, or guard with a module-level `threading.Lock`.

### M-06 — Profile cancellation only checked between services, not within a service
**Location:** `arguscloud/api/collect.py:209-224`
**Evidence:** Status check loop runs once per service iteration; the inner `collect_services([service])` blocks for the duration of that service.
**Impact:** `POST /collect/<id>/cancel` returns success but the worker continues for minutes.
**Recommendation:** Pass a `threading.Event` into the collector and check between AWS API calls; document the granularity.

### M-07 — `save_profile` runs N+1 query loop in `list_profiles`
**Location:** `arguscloud/repositories/neo4j_repository.py:314-325`
**Evidence:** Per-profile edge-count query inside a Python for-loop.
**Impact:** 100 profiles → 101 round trips; blocks API thread.
**Recommendation:** Single aggregating Cypher query returning per-profile counts.

### M-08 — KMS rule double-fires; `rule_public_s3` flags KMS resource policies too
**Location:** `awshound/rules.py:65-88, 146-187`
**Evidence:** `rule_public_s3` doesn't filter by node ID prefix; `rule_kms_external_access` also fires on the same `Principal: *`. Same node yields two AttackPath edges per run.
**Recommendation:** Add `if "kms" not in node.id` guard, or consolidate into one ResourcePolicy rule that dispatches.

### M-09 — `kms-cross-account` rule flags same-account principals
**Location:** `awshound/rules.py:177-186`
**Evidence:** `if ":iam::" in str(p)` matches any IAM ARN, including same-account.
**Impact:** Same-account KMS grants (normal practice) generate noise findings.
**Recommendation:** Compare the principal's account ID to the key's owning account; skip same-account.

### M-10 — `extract_principals` ignores `Effect`, `Condition`, and `NotPrincipal`
**Location:** `arguscloud/core/base.py:179-200, 203-223`
**Evidence:** Function collects all principals regardless of `Allow`/`Deny`; `Condition` blocks (e.g., `aws:SourceVpce` restricting to a VPC endpoint) are dropped. `is_admin_policy` similarly ignores `NotAction`/`NotPrincipal`/`Condition`/`Deny`.
**Impact:** False positives on policies that are restricted by condition or by Deny. False negatives on `NotAction` overshoot policies.
**Recommendation:** Filter to `Effect: Allow`, propagate `Condition` so callers can suppress, and add explicit handling for `NotAction`/`NotPrincipal` semantics.

### M-11 — Severity drift: `cloudtrail-missing` is Medium in active engine, High in dead engine
**Location:** `awshound/rules.py:124` vs `arguscloud/rules/aws/logging.py:16`
**Evidence:** Active path emits `severity: "medium"`; new path uses `high`. CIS AWS Foundations 3.1 treats CloudTrail absence as high.
**Recommendation:** Upgrade legacy severity to High; align with CIS.

### M-12 — Severity / detection drift: public EC2 snapshot
**Location:** `awshound/rules.py:286` vs `arguscloud/rules/aws/ec2.py:88`
**Evidence:** Legacy rule fires on `state==completed AND encrypted==False`; new rule fires on `is_public==True`. They detect different conditions and rate them differently. The legacy rule's name implies public-share but it actually checks encryption.
**Recommendation:** Two distinct rules: one for `is_public`, one for unencrypted; align severities; rename for clarity.

### M-13 — Missing rule: RDS instance `PubliclyAccessible: true`
**Location:** Both engines — gap
**Evidence:** Both detect publicly shared RDS snapshots; neither checks the instance flag itself.
**Impact:** Misses CIS AWS Foundations 2.3.3 — a publicly reachable RDS instance is a direct credential-bruteforce surface.
**Recommendation:** Add a High-severity rule on `RDSInstance.publicly_accessible == True`.

### M-14 — Missing rules: IAM privilege escalation patterns (PassRole, UpdateFunctionCode, CloudFormation)
**Location:** Both engines — gap
**Evidence:** No rule covers `iam:PassRole + ec2:RunInstances`, `lambda:UpdateFunctionCode` on a privileged execution role, or CloudFormation stacks with admin service roles. CloudFormation node type is collected but not analyzed.
**Recommendation:** Add three rules covering these well-known escalation paths.

### M-15 — `assume-role-chain` is O(P × A × BFS) — quadratic at scale
**Location:** `awshound/rules.py:224-245`, `arguscloud/rules/aws/iam.py:83-95`
**Evidence:** For each principal, for each admin role, run a fresh BFS without sharing visited state.
**Impact:** Large org graphs hit timeouts.
**Recommendation:** One reverse multi-source BFS from all admin roles, marking reachable principals in a single O(V+E) pass.

### M-16 — HTML exporter emits unescaped strings (stored XSS in downloaded reports)
**Location:** `arguscloud/exporters/html.py:183-191`
**Evidence:** Direct f-string interpolation of `rule`, `description`, `edge.src` into HTML.
**Impact:** A malicious resource name persists into the offline HTML report and executes when opened.
**Recommendation:** Use `html.escape()` on every dynamic value.

### M-17 — `applyFilters()` invoked with no arguments — TypeError on every preset query
**Location:** `ui/js/app.js:337`
**Evidence:** `applyQueryFilters` calls `applyFilters()`; the definition is `applyFilters(nodesList, edgesList)` and immediately does `[...nodesList]`.
**Impact:** Activating any "All Attack Paths" / preset query throws silently — the graph never updates and the user sees no feedback.
**Recommendation:** Pass module-level `nodes, edges` to the call.

### M-18 — Cytoscape full graph rebuild on every filter apply; no debounce on inputs
**Location:** `ui/js/app.js:1632-1635, 2697-2700`
**Evidence:** `cy.elements().remove(); cy.add(elements); cy.layout({...}).run()` runs synchronously on each apply. Search input has no debounce.
**Impact:** UI freezes on >500-node graphs; rapid keystrokes during filter typing trigger repeated full layouts.
**Recommendation:** Debounce search (300-500ms). Use `cy.batch()` for bulk updates. Disable Apply button + show spinner during layout. Switch to incremental layout (fcose/cola) for large graphs.

### M-19 — No ARIA, no focus trap, Escape doesn't close modals
**Location:** `ui/index.html` modal divs (~lines 900, 940, 1065, 1180)
**Evidence:** No `role="dialog"`, `aria-modal`, `aria-labelledby`. Escape only exits fullscreen (`app.js:4899`).
**Impact:** Screen readers cannot announce modal context. Keyboard users tab behind the overlay. WCAG 2.1 SC 4.1.2 / 2.1.1 fail.
**Recommendation:** Add ARIA attributes, implement focus trap, wire Escape to close any open modal.

### M-20 — No responsive CSS — desktop-only layout
**Location:** `ui/css/main.css` — zero `@media` queries
**Evidence:** `grep "@media" main.css` returns nothing. Pixel-based grid columns.
**Impact:** Unusable on viewports < 1024px; touch interaction not handled.
**Recommendation:** At minimum add a 768px breakpoint that collapses sidebar to a drawer and stacks panels.

### M-21 — UI service `depends_on` lacks `condition: service_healthy`
**Location:** `docker-compose.yml:97-99`, `docker-compose.prod.yml:138-140`
**Evidence:** UI block: `depends_on: - api` (no condition). API block correctly uses `service_healthy` for Neo4j.
**Impact:** UI starts before API is ready; users see "API unreachable" during slow starts.
**Recommendation:** Match the api/Neo4j pattern.

### M-22 — `tests/test_rules_rds.py` imports legacy `awshound.rules`; doesn't cover the new `arguscloud/rules/aws/data.py`
**Location:** `tests/test_rules_rds.py:1-8`
**Evidence:** 8-line file, one test, uses legacy module. The 5 functions in `arguscloud/rules/aws/data.py` are uncovered there.
**Recommendation:** Rewrite to cover all 5 functions; follow the pattern in `tests/test_rules_data.py`.

### M-23 — `awshound/normalize.py` (1115 LoC) covered by 70-line `test_normalize.py`
**Location:** `tests/test_normalize.py`
**Evidence:** ~4 of 36 normalizer functions exercised. Lambda, EC2 instance, RDS, CloudTrail, STS paths uncovered.
**Recommendation:** Parameterize tests per resource type; load fixtures from `tests/fixtures/`.

### M-24 — `arguscloud/collectors/aws/` has 11 untested service collectors
**Location:** `tests/collectors/` contains only `test_iam_collector.py`
**Evidence:** Source has compute/devops/ec2/identity/messaging/org/s3/security/storage/sts/utils — none have a corresponding test file.
**Recommendation:** Add moto-backed tests for at least S3, EC2, STS.

### M-25 — Coverage 34% (per project plan); `--cov` not in pytest `addopts`; no coverage gate
**Location:** `pyproject.toml:107`, `docs/TEST_COVERAGE_PLAN.md`
**Evidence:** `addopts = "-v --tb=short"` — no `--cov`, no `--cov-fail-under`. Plan targets 70%+ but is not enforced.
**Recommendation:** `addopts = "-v --tb=short --cov=arguscloud --cov=awshound --cov-report=term-missing --cov-fail-under=60"`. Increase floor over time.

### M-26 — Integration tests skip silently when `testcontainers` is missing; no CI to install it
**Location:** `tests/integration/conftest.py:14-28`
**Evidence:** `pytestmark = pytest.mark.skipif(not HAS_TESTCONTAINERS, ...)`. No CI runs them.
**Recommendation:** CI job installs `.[dev]` and runs integration tests under `-m integration`.

### M-27 — `.env.example` ships plaintext defaults (`letmein123`)
**Location:** `.env.example:17`
**Evidence:** `NEO4J_PASSWORD=letmein123`. `start.sh` may copy this verbatim to `.env` on first run.
**Recommendation:** Use `<CHANGE_ME>` placeholder + comment with `openssl rand -base64 32` instruction.

### M-28 — No pre-commit hooks, no Makefile; quality tooling is opt-in
**Location:** Repo root — neither file exists
**Evidence:** ruff/black/mypy in dev extras with no enforcement mechanism.
**Recommendation:** Add `.pre-commit-config.yaml` with ruff/black/mypy hooks; add `Makefile` targets `lint`, `test`, `build`, `serve`.

### M-29 — Plugin system defines collector/normalizer/rule registries but does not expose them to plugins
**Location:** `arguscloud/plugins/registry.py:18`, `arguscloud/core/registry.py:148-151`
**Evidence:** Two separate registry systems with no bridge. `Plugin.on_load()` cannot register a normalizer through the plugin system.
**Recommendation:** Either add `register_collectors`/`register_normalizers`/`register_rules` hooks to `Plugin`, or document clearly that core registries are populated by decorator imports only.

### M-30 — Dual codebase: `arguscloud/collectors/aws/` is unused dead weight (or `awshound/` is)
**Location:** `arguscloud/api/collect.py:176-177`, `arguscloud/cli/main.py:250-291`
**Evidence:** Both API and CLI shell out to `awshound.collector`, `awshound.normalize`, `awshound.bundle`. `arguscloud/collectors/aws/` (~2K LoC) has no live call path.
**Impact:** Duplicate maintenance burden, confused contributor experience, drift bugs (H-10).
**Recommendation:** Pick one and delete the other; document the migration plan in CHANGELOG.

---

## Low

### L-01 — JWT tokens lack `iss` and `aud` claims
**Location:** `arguscloud/api/auth.py:62-69, 84-89`
**Recommendation:** Add `iss="arguscloud"`, `aud="arguscloud-api"` at issuance and require them at decode.

### L-02 — `/plugins` endpoint discloses load errors unauthenticated
**Location:** `arguscloud/api/server.py:191-200`
**Recommendation:** Require auth, or strip `errors` from anonymous responses.

### L-03 — CLI commands lack top-level exception handling
**Location:** `arguscloud/cli/main.py:229-546`
**Evidence:** `cmd_collect`, `cmd_normalize`, `cmd_analyze`, `cmd_import` raise raw tracebacks. Output is text on success, traceback on failure — inconsistent for shell scripts.
**Recommendation:** Wrap each command body in `try/except Exception as e: print(json.dumps({"error": str(e)})); return 1`.

### L-04 — Job manager dict access without lock (CPython-only safe)
**Location:** `arguscloud/api/collect.py:106-124`
**Recommendation:** Acquire `self._lock` in `get_job` and `list_jobs` for forward-compatibility with non-CPython worker models.

### L-05 — `Node` / `Edge` dataclasses don't validate required fields; `id=""` accepted
**Location:** `arguscloud/core/graph.py:27-83`
**Evidence:** `MERGE (n {id: ""})` would match all empty-id nodes. `GraphData.deduplicate()` is never called in the new path.
**Recommendation:** Add `__post_init__` validation; ensure `deduplicate()` runs after multi-normalizer merges.

### L-06 — Mutable class-level default lists in `BaseCollector` and `BaseRule`
**Location:** `arguscloud/core/base.py:32, 147`
**Evidence:** `services: List[str] = []`, `tags: List[str] = []`.
**Recommendation:** Move to dataclass with `field(default_factory=list)` or annotate `ClassVar`.

### L-07 — SARIF `fixes` block omits required `artifactChanges`
**Location:** `arguscloud/exporters/sarif.py:127-133`
**Impact:** Invalid SARIF 2.1.0 — fails GitHub Code Scanning upload validation.
**Recommendation:** Either omit `fixes` entirely (remediation already in `rules[].help.text`) or include a stub `artifactChanges: []`.

### L-08 — `SQSQueue` node ID is queue URL (account- and region-encoded)
**Location:** `awshound/normalize.py:821-823`
**Recommendation:** Derive ARN from URL or use `QueueArn` attribute.

### L-09 — `AWSCredentials.clear()` provides false zeroization assurance
**Location:** `arguscloud/collectors/session.py:47-52`
**Evidence:** Reassigning a Python `str` doesn't overwrite the original heap allocation.
**Recommendation:** Document the limitation; consider `bytearray` + explicit zero for true wipe.

### L-10 — `awshound/normalize.py` has 28+ near-duplicate per-service handlers
**Location:** `awshound/normalize.py:407-768` (many copies)
**Recommendation:** Extract `_attach_resource_policy(...)` helper. Or accelerate retirement (M-30).

### L-11 — `f"... LIMIT {filters.limit}"` uses int from a dataclass with no enforcement
**Location:** `arguscloud/repositories/neo4j_repository.py:62, 96`
**Evidence:** Currently safe (default is int) but no `__post_init__` guard on `NodeFilter`.
**Recommendation:** Validate `isinstance(filters.limit, int)` and cap at `MAX_QUERY_LIMIT`.

### L-12 — Profile name not validated in `get_profile` / `delete_profile`
**Location:** `arguscloud/api/server.py:405-451, 589-612`
**Evidence:** Other profile endpoints call `validate_profile_name`; these do not.
**Recommendation:** Add the same guard for consistency and to short-circuit garbage URLs before they hit Neo4j.

### L-13 — Saved filters in localStorage parsed without try/catch; rendered into innerHTML
**Location:** `ui/js/app.js:26, 2129`
**Evidence:** `JSON.parse(localStorage.getItem(...) || '[]')` at module top level — malformed JSON breaks app init. Stored values rendered without escape.
**Recommendation:** Wrap in try/catch; validate shape; escape on render.

### L-14 — Bulk-upload modal close handler can leak the polling interval
**Location:** `ui/js/app.js:4288`
**Evidence:** Close-on-backdrop check `!uploadPollInterval` prevents clearing a non-null interval.
**Recommendation:** Always clear unconditionally; cancel the backend job.

### L-15 — `<pre>${JSON.stringify(...)}</pre>` can be broken out of by a property containing `</pre>`
**Location:** `ui/js/app.js:2864`
**Recommendation:** `preEl.textContent = JSON.stringify(...)`.

### L-16 — API base URL and layout/label settings not persisted across sessions
**Location:** `ui/js/app.js:4865, 4872, 4976`; `ui/index.html:821`
**Recommendation:** Save to localStorage on change; restore on init.

### L-17 — `ui/index.original.html` 316KB fossil committed in repo
**Location:** `ui/index.original.html`
**Impact:** Inflates clone size; confuses contributors; may contain outdated insecure patterns that get copied.
**Recommendation:** Delete and history-purge.

### L-18 — `demo/demo-lite.pdf` 351KB binary committed
**Location:** `demo/demo-lite.pdf`
**Recommendation:** Host as a release asset or external link.

### L-19 — `pyproject.toml` `all` extra omits `prod`
**Location:** `pyproject.toml` `[project.optional-dependencies]`
**Evidence:** `all = ["arguscloud[dev,gcp,azure]"]` — `prod` (gunicorn, flask-limiter, prometheus-client) is missing.
**Recommendation:** Add `prod` to `all`, or rename to `all-cloud` to be explicit.

---

## Info

### I-01 — GCP and Azure collectors are stubs only; README implies parity is approaching
**Location:** `arguscloud/collectors/gcp/__init__.py`, `arguscloud/collectors/azure/__init__.py`, `README.md:9, 57-58`, `pyproject.toml` extras
**Evidence:** Both subpackages contain only `__init__.py` placeholders. `pip install -e ".[gcp]"` installs deps that have no consumer.
**Recommendation:** Add a "not yet implemented" note to extras and to README, or remove until implemented.

### I-02 — No benchmark / MITRE ATT&CK mapping on any rule
**Location:** All rule files
**Evidence:** No reference to CIS AWS Foundations, NIST, AWS Well-Architected, or MITRE ATT&CK techniques.
**Recommendation:** Add optional `mitre_techniques`, `cis_controls` metadata fields to the rule decorator and populate for high-severity rules; enables compliance correlation.

---

## Top remediation priorities

If you can only do one PR per category this week:

1. **C-01 + H-05** — purge `data/` from history, rotate credentials, add pre-commit hook for AWS account IDs.
2. **C-02 + H-21** — fix Dockerfile rename and add a minimal CI workflow that would have caught it.
3. **C-04 + C-05** — remove `letmein123` everywhere; default `AUTH_ENABLED=true`; require `JWT_SECRET` at startup.
4. **C-03 + H-04** — allowlist `edge_type` values; remove duplicate `CORS(app)`.
5. **C-06 + H-16 + H-17** — wire all four init functions into `create_app()`; replace `str(e)` leakage with sanitized envelopes.
6. **C-07** — switch `cmd_analyze` to the new rules engine (or run both); add an end-to-end test.
7. **H-01 + H-02** — add CSP + SRI; convert all `innerHTML` template literals to use `escapeHtml` or `textContent`.

These seven PRs eliminate every Critical and the most exposed High-severity issues.
