# SentinelReview

Agentic security code review for GitHub Pull Requests. Combines static
analysis, retrieval-augmented generation over CWE/OWASP/GHSA data, and a
7-agent LangGraph pipeline to detect vulnerabilities, ground every claim in
an authoritative source, generate a patch, verify it in a sandbox, and post
a structured PR review.

## Quickstart: run everything in Docker

One command brings up Postgres+pgvector, Redis, the FastAPI backend, and
the React dashboard together. **This exact sequence has not been run
end-to-end by me** — this sandbox has no Docker daemon (`docker: not
found`), so everything below is built and reasoned through carefully (path
resolution double-checked against the actual container layout, env vars
checked for container-vs-browser networking correctness) but not verified
the way everything else in this project has been. Run it and tell me what
breaks.

```bash
git clone <this repo> && cd sentinelreview   # or unzip the delivered files into place
cd docker
docker compose up --build
```

First run will take a few minutes (installing Python deps including
Bandit/Semgrep, and `npm install` for the frontend). Once it settles:

| What | Where |
|---|---|
| Dashboard | http://localhost:5183 |
| API | http://localhost:8010 (docs at `/docs`) |
| Postgres | `localhost:5433` (mapped from the container's 5432, since 5432 is often already taken by a local Postgres install) |
| Redis | `localhost:6380` (same reasoning, for 6379) |

None of these host ports are Docker/Vite/Postgres defaults (5173, 8000,
5432, 6379) — remapped deliberately so this stack doesn't collide with
whatever else you're already running. If you still hit a "port already
allocated" error, something else has grabbed one of the four; find it with
`lsof -i :<port>` and either stop it or remap further in
`docker/docker-compose.yml` (the container-internal ports don't need to
change, only the host-side number left of the `:`).

The dashboard will be empty at first (no reviews yet, and no eval results
yet). In a second terminal, seed both:

```bash
docker compose exec backend python3 scripts/seed_dashboard_data.py
docker compose exec backend python3 evaluation/run_eval.py
```

Reload http://localhost:5183 — the Reviews page should show 3 sample
reviews, and http://localhost:5183/evaluation should show real precision/
recall/F1 numbers (0.900/0.900/0.900 baseline; run `... run_eval.py`
without arguments for the Bandit+Semgrep merged numbers, 0.909/1.000/0.952).

Run the test suite inside the same containerized environment, for parity
with however this actually gets deployed:

```bash
docker compose exec backend pytest tests/ -v
```

Tear down:
```bash
docker compose down          # keep the Postgres volume (data persists)
docker compose down -v       # also wipe the Postgres volume
```

**Networking note, since this is the most common way a multi-container
setup like this silently breaks**: the dashboard's `VITE_API_BASE_URL` is
set to `http://localhost:8010`, not `http://backend:8000`. That's
deliberate, not an oversight — `fetch()` calls in the dashboard's compiled
JS run in *your browser* on the host machine, not inside the frontend
container, so they need the host-mapped port. `http://backend:8000` would
only work for container-to-container calls within the compose network
(which is what `DATABASE_URL`/`REDIS_URL` correctly use for the backend
service, since those connections *are* container-to-container). The
backend's CORS allowlist (`backend/app/main.py`) includes both `:5173`
(plain `npm run dev`, no Docker) and `:5183` (this Docker Compose setup) for
exactly this reason — mismatch either of these and API calls fail silently
in the browser console with a CORS error, not a helpful one.

## Status: honest, not aspirational

| Component | Status |
|---|---|
| LangGraph 7-agent pipeline | ✅ Built, wired, tested end-to-end |
| **Static analysis** | ✅ **Real Bandit CLI**, actually installed and invoked as a subprocess. Not mocked. |
| **Retrieval** | ✅ **Real TF-IDF + cosine similarity** search (scikit-learn) over a 13-document curated CWE/OWASP corpus. Classical IR, not a neural embedding model (see below), but a genuine working algorithm, not a hash stand-in. |
| **Eval harness** | ✅ Runs for real: `python3 evaluation/run_eval.py` against a 17-case hand-labeled benchmark (10 vulnerable, 7 safe). **Precision 0.900, recall 0.900, F1 0.900** — with or without `--use-hf`, by design (v2: classifier is diagnostic-only, can't move detection numbers). See "HF classifier finding" below for the full story, including a rejected v1 design and the real numbers behind rejecting it. |
| **GitHub App JWT auth** | ✅ Real RS256 signing via PyJWT + `cryptography`, tested against an actual generated RSA keypair (sign with private key, verify with public key, confirm wrong-key rejection). |
| **GitHub OAuth User Auth** | ✅ Real OAuth2 flow (via `httpx` to `github.com/login/oauth/access_token`) issuing HttpOnly JWT session cookies. The React dashboard is fully protected behind this login, and the backend verifies user installations against the requested repository. |
| **GHSA ingestion** | ✅ **Live and verified**: 150 real advisories (75 pip + 75 npm) ingested from GitHub's actual `/advisories` endpoint using a real `GITHUB_TOKEN`, confirmed duplicate-free (`150 total rows, 150 distinct external_ids`). Correctly follows the `Link` response header for pagination — an earlier version guessed `page=1,2,3` manually, which the real endpoint silently ignored, causing the same page to be fetched 3x; caught via the exact 150→50 signature this produced on live data, root-caused, fixed, and covered by a regression test. Blocked only in this sandbox's own shared/rate-limited egress IP, not in general. |
| **Observability** | ✅ Real: `AgentRun` rows are written to the database per pipeline stage with actual latency, via `app/services/pipeline_runner.py`. Verified by a test that queries the DB afterward and checks all 7 rows landed. Not yet exported to Langfuse/Phoenix (unreachable from this environment). |
| Prompt-injection guardrails + tool allowlisting | ✅ Built, tested |
| GitHub webhook receiver (HMAC verified) | ✅ Built, tested |
| Full relational schema (11 tables) | ✅ Built, verified against real inserts, now persisting `PatchSuggestion` and `VerificationRun` data seamlessly. |
| **Database Migrations** | ❌ No Alembic migrations — schema updates rely on ad-hoc raw ALTER TABLE scripts (e.g., `scripts/migrate_settings.py`). Fine for solo dev, but a known limitation for real deployments. |
| Classification (Zero-Shot/Token) model | ❌ Still mocked — `huggingface.co` is not reachable from this environment, so there's no honest way to serve a real model here. Interface is real and swappable (`app/agents/model_clients.py`); a real HF Inference Endpoint or local `transformers` pipeline is a drop-in replacement. |
| Fix-generation LLM | ❌ Still mocked — no LLM API key configured. Same swappable-interface story. |
| **Semgrep** | ✅ **Live, real, genuinely useful, cross-machine verified**: real root cause of the earlier install failure found (system PyJWT was apt-installed, not pip-installed, so pip had no RECORD file to upgrade it — fixed with `--ignore-installed`, not a workaround). Runs against a hand-written, offline, version-controlled ruleset (`app/sandbox/semgrep_rules/python-security.yml`) rather than `--config auto`, since `semgrep.dev`'s registry isn't reachable here either — same constraint as `huggingface.co`/NVD/OSV, and arguably a better production design anyway (deterministic ruleset, no scan-time network dependency). Merged with Bandit via a real, unit-tested dedup function (`merge_analyzer_findings`, 8 tests) so agreement between the two doesn't double-report. **Real, measured result: recall 0.900 → 1.000, F1 0.900 → 0.952** (Semgrep's regex-based secret rule catches a case-insensitive `API_KEY=` pattern Bandit's stricter heuristic missed). Confirmed on two independent machines (sandbox: precision 0.909/recall 1.000/F1 0.952; a real MacBook Air: identical precision/recall/F1) — the detection numbers are exactly reproducible. **Per-file latency (originally 202ms → 2,600-3,200ms per file, a 13-16x cost) fixed via batching** — see milestone 5 below for the full story, including a real measurement correction along the way. Reproduce yourself: `python3 evaluation/run_eval.py --bandit-only` vs `python3 evaluation/run_eval.py`. |
| **GitHub App webhook → DB → auth chain → real background job** | ✅ **Real, end-to-end, including actual pipeline execution**: `installation` webhooks upsert `Installation`/`Repository` rows (idempotent); `pull_request` webhooks upsert `PullRequest`/`Review` rows, authenticate via the real JWT-sign → installation-token-exchange chain, and **enqueue a real RQ job** (`app/jobs/review_worker.py`) that fetches the PR's actual changed files from GitHub's API (`app/services/github_client.py`, real `Link`-header pagination), runs the real Bandit+Semgrep+RAG pipeline against them, and persists real `Finding` rows. Verified with a real Redis + a real RQ `SimpleWorker` actually popping and executing the job (`tests/test_queue_integration.py`) — not a mock, not a direct function call. Found and fixed two real bugs in the process: (1) a schema bug where deleting an `Installation` tried to null out a `NOT NULL` foreign key, fixed by making `installation_id` nullable so historical reviews survive an App uninstall as an audit trail; (2) a significant, previously-hidden gap where `run_review_with_observability` wrote `AgentRun` rows but **never actually persisted `Finding` rows to the database** — every review run through the real pipeline would have shown zero findings in the dashboard regardless of what was detected, undetected until a genuine end-to-end test checked `review.findings` after a real run instead of just the in-memory return value. 21 new tests across `test_webhooks.py`, `test_github_client.py`, `test_review_worker.py`, and `test_queue_integration.py`. What's *not* live: an actual registered GitHub App has never sent this a real webhook — see the runbook below for the exact remaining steps, which need your GitHub account, not more code. |
| **React dashboard** | ✅ **Real, built, tested — 5 pages, not the full 12-page spec**: Login, Reviews list, Review detail (findings, patches, and verification results, now with resolved RAG citations), Evaluation (real numbers from `evaluation/run_eval.py`), and Observability (real per-agent latency/success-rate stats aggregated from `AgentRun` rows). Vite + React 19 + TypeScript + Tailwind v4, real backend endpoints throughout — not mocked JSON. Features a protected route wrapper checking against `/me`. |
| Live NVD/OSV corpus | ❌ Not built — `nvd.nist.gov` and `osv.dev` aren't reachable from this environment. The 13-document seed corpus (`app/knowledge/seed_corpus.py`) is original writing, not scraped, standing in until live ingestion runs somewhere with network access to those domains. |
| CI (GitHub Actions) | ✅ Config written, ruff lint passes locally, full test suite passes locally |

**101/101 backend tests pass, 20/20 frontend tests pass.** Run them yourself:
```bash
pip install -r requirements.txt
PYTHONPATH=backend pytest tests/ -v          # 101 tests

cd frontend && npm install
npm run build   # production build, 0 errors
npm test        # 10 component/page tests
```

## On the eval numbers specifically

0.900/0.900/0.900 on 17 hand-written cases is a real, reproducible number —
not a benchmark claim. It's useful for showing the eval harness itself
works and for catching regressions, but 17 cases is not statistically
meaningful and I wrote every case myself, so there's no guarantee the tool
generalizes to code patterns I didn't think of. Two interesting real
failure modes worth knowing about:
- **False negative**: a hardcoded API key not matching a `password`-style
  variable name slipped past Bandit's heuristic (`secret-01` in the
  fixtures) — a known class of gap in regex/heuristic secret detection.
- **False positive**: `subprocess.run(args, shell=False)` was still flagged
  (`safe-cmdi-01`) — Bandit's B603 check warns on subprocess calls
  generically even without `shell=True`, a documented Bandit quirk, not a
  bug in this project.

The real next step for a credible number is running against a proper
labeled corpus (a Python-relevant slice of the Juliet Test Suite, or a
larger self-built set covering more CWE categories and edge cases) — listed
below.

## HF classifier finding, and the redesign that followed

**v1 (rejected):** wired `HFZeroShotClassifier` (`app/agents/hf_classifier.py`,
real `facebook/bart-large-mnli`) as an independent second opinion — if the
classifier was confident (score ≥ 0.5) about *any* candidate CWE label on a
snippet Bandit missed, that snippet got flagged too. Ran it for real:
**precision dropped from 0.900 to 0.714 while recall rose to 1.000** (F1:
0.900 → 0.833, net worse). It caught the one real gap it was meant to
(`secret-01`, a hardcoded key Bandit's heuristic missed), but also
confidently mislabeled a trivial `Cache` class as **SSRF at 84%
confidence**, plus three more false positives.

The root cause was visible in the raw scores: the true catch (`secret-01`,
`idor(0.62)`) and a false positive (`safe-sqli-01`, correctly-parameterized
SQL, `idor(0.61)`) are separated by **0.01** — same label, nearly identical
confidence, opposite ground truth. `bart-large-mnli` is a general
sentence-pair NLI model trained on natural language, not code; short
snippets are out-of-distribution for it, and taking the argmax across 11
unrelated candidate labels amplifies that noise into a confident wrong
answer, as the SSRF case shows.

**v2 (current, both in the eval harness and in `graph.py`'s
`classification_node`):** the classifier can no longer independently
trigger a finding, in production or in eval. It only scores the ONE label
that actually corresponds to a finding Bandit already produced (via an
explicit `CWE_TO_LABEL` mapping — the single source of truth for this, in
`app/agents/graph.py`), and that score adjusts *severity*, never existence.
This was a real bug in the pipeline code too, not just the eval script:
`classification_node` was taking `classifications[0]` (argmax over all 11
labels) before this fix, which only looked correct against
`MockZeroShotClassifier` because its substring-matching mock happens to
usually pick the right label — the same argmax-across-unrelated-labels
mistake would have reproduced the SSRF-on-a-cache-class failure the moment
a real model was plugged in. Caught with a dedicated adversarial test
(`tests/test_classification_corroboration.py`) that scores an irrelevant
label at 0.95 and the correct one at 0.05, asserting severity is NOT driven
up by the irrelevant score.

With v2, `python3 evaluation/run_eval.py --use-hf` reports
precision/recall/F1 **identical to Bandit-alone by construction** (the
classifier can't move those numbers anymore) — **confirmed on a real run**:
0.900/0.900/0.900 both with and without `--use-hf`. It also reports a
`classifier_diagnostics` block that measures the classifier honestly
instead of using it for decisions: **real separation of 0.085** between
average confidence on the correct label for genuinely vulnerable code vs.
safe lookalikes (essentially no discriminative signal), and a **real 42.9%
reconstructed false-positive rate** for the rejected v1 design — the number
that actually justifies rejecting it, not just the one anecdote about a
misclassified cache class.

Real next steps, in order of expected payoff: (1) a model actually
fine-tuned for code or vulnerability classification instead of a general
NLI model; (2) if sticking with zero-shot NLI, reformulate each label as a
full hypothesis sentence ("this code contains a SQL injection
vulnerability") rather than a bare category name, closer to how these
models are meant to be prompted; (3) expand the benchmark past 17 cases so
the diagnostic averages are less noisy.

## Why it's structured this way

- **Every ML model client is a `Protocol`** (`app/agents/model_clients.py`).
  Where this environment could produce something real (static analysis,
  classical retrieval, GitHub API auth), it does. Where it honestly
  couldn't (neural classification, LLM generation — both need APIs this
  sandbox can't reach), the interface is real and tested, the
  implementation behind it is mocked, and that's stated plainly rather than
  hidden behind a good-looking demo.
- **State is a single typed Pydantic model** threaded through the graph.
- **Guardrails are enforced at the graph layer**, not just the prompt layer.
- **Diffs are parsed into real, syntactically-valid source** before hitting
  an analyzer (`app/agents/diff_utils.py`) — an earlier version of this
  pipeline fed raw diff markup (`+`/`-`/`@@` prefixes) straight to Bandit,
  which silently failed to parse it and produced zero findings on
  obviously-vulnerable code. Caught by tests, fixed, now covered by 5
  dedicated unit tests including a `compile()` syntax check.

## Immediate next milestones (in priority order)

1. ~~Pull real GHSA advisories~~ — **done**: 150 real advisories (pip + npm)
   ingested via `app/knowledge/ingest_cli.py`, verified duplicate-free
   against live data (`UniqueConstraint` + within-batch dedup + correct
   `Link`-header pagination — three real bugs found and fixed in this
   process, see git history / conversation log).
2. ~~Wire a real classification model~~ — **done**: `HFZeroShotClassifier`
   works correctly as built (6/6 unit tests, real model run against real
   data). First integration design (independent second opinion) was a
   documented negative result (precision 0.900 → 0.714); redesigned into a
   corroboration-only role instead — see "HF classifier finding" above for
   the full story including the specific bug this caught in `graph.py`
   itself, not just the eval script.
3. ~~Redesign the classifier's role~~ — **done**: `classification_node` and
   the eval harness both now use a targeted `CWE_TO_LABEL` lookup instead of
   taking the argmax across all 11 candidate labels, backed by an
   adversarial regression test (`tests/test_classification_corroboration.py`)
   that would have caught the original bug. Detection decisions (Bandit)
   and confidence calibration (classifier) are now cleanly separated.
4. ~~Resolve the Semgrep/PyJWT dependency conflict and add it as a second
   analyzer~~ — **done**: real root cause found (apt vs pip package
   management, not a fundamental incompatibility), fixed, integrated,
   merged with Bandit, and measured: recall 0.900 → 1.000 at a real 16x
   latency cost. See "Semgrep" row above.
5. ~~Fix Semgrep's per-file latency~~ — **done, with a real correction along
   the way**: added `analyze_files()` (batch API) to both `BanditAnalyzer`
   and `SemgrepAnalyzer` — one subprocess call per PR instead of one per
   file, wired into `static_analysis_node` via `merge_analyzer_findings`.
   A first hasty single-trial measurement showed Bandit batching as a
   *regression* and Semgrep batching as barely helping at all — both wrong,
   caused by not controlling for a one-time ~15-99s Semgrep environment
   warmup (a network call to `semgrep.dev` timing out on first run, cached
   afterward) contaminating whichever measurement happened to run first.
   Re-tested properly (warm-up call + 3 repeated trials each): **real,
   consistent speedup of ~4.6-5x for both analyzers** (Semgrep: 2.8s vs
   13.5-14s for 5 files; Bandit: 0.21s vs 1.0s). Also fixed a real bug this
   surfaced: `classification_node` was clobbering multi-analyzer agreement
   info (`"bandit+semgrep"`) with a hardcoded `"combined"` string, throwing
   away a genuine confidence signal. 8 new tests
   (`tests/test_analyzer_merge.py`) cover the merge logic; 8 more
   (`tests/test_static_analyzers.py`) cover both analyzers' batch APIs
   directly, consolidated into as few real subprocess calls as possible
   after discovering that many rapid Semgrep invocations degrade badly
   under single-core CPU contention (a real sandbox-specific constraint,
   confirmed via `nproc` — not expected on a normal multi-core machine).
   Full suite: 61 tests, 15.8s. Applied the same batching to
   `evaluation/run_eval.py` itself (17 separate per-case calls → 1 batched
   call per analyzer): full eval harness run dropped to ~4s from what would
   have been 45-50s+ unbatched, with byte-identical precision/recall/F1
   (0.909/1.000/0.952) confirming correctness wasn't traded for speed. That
   change briefly broke everything first, though — batch dict keys need a
   `.py` extension for the analyzers' language detection to recognize them
   as Python at all (`case.id` alone, e.g. `"sqli-01"`, silently scans as
   nothing); caught immediately since precision/recall/F1 dropped to
   0.0/0.0/0.0 on the very next run, not silently.
6. ~~GitHub App webhook → DB → auth chain → real RQ background job~~ —
   **done**: see the table above. What's genuinely left is registering a
   real GitHub App and pointing its webhook URL at a tunnel (ngrok or
   similar) into a running instance of this backend — that's the one thing
   in this entire project that fundamentally cannot be verified without
   your GitHub account and a machine that can receive inbound webhooks,
   which this sandbox can't. See the runbook above for the exact steps.
7. Expand the eval benchmark past 17 hand-written cases.
8. A model actually fine-tuned for code/vulnerability classification, to
   see whether the classifier's diagnostic separation score (0.066-0.085
   with `bart-large-mnli`, near-zero) improves with a better-suited model.
9. ~~React dashboard~~ — **done, 5 pages (including Login)**: Dashboard is now protected with full GitHub OAuth flow.
10. ~~Patch suggestion / Verification Persistence~~ — **done**: Patch Suggestions and Verification Outcomes are fully persisted to the database via `pipeline_runner.py` and displayed on the review detail dashboard view.

## What I genuinely can't test from here

- ~~The dashboard rendered in a real browser~~ — **confirmed**, with real
  screenshots: Reviews list, Review detail, and Evaluation pages all
  render correctly against real backend data (severity gauge, Space
  Grotesk headings, and the color system all work as designed). One real
  bug found this way and fixed: seed data had an internally inconsistent
  severity/classifier-score pairing (see `scripts/seed_dashboard_data.py`
  history) — a screenshot caught it, no automated test did.

- **A live GitHub App webhook delivery** — still genuinely untested, and
  still needs your GitHub account, not more code from me. Everything up to
  the actual live delivery is built, tested, and — as of this session —
  end-to-end including a real Redis/RQ worker actually processing a queued
  review (`tests/test_queue_integration.py`: real Redis, real
  `Queue.enqueue()`, a real `SimpleWorker` popping and executing the job,
  confirmed `COMPLETED` with real findings in a real database — not a
  mock). The exact remaining steps:

  1. **Register the App**: GitHub → Settings → Developer settings → GitHub
     Apps → New GitHub App.
     - Webhook URL: your tunnel's HTTPS URL + `/webhooks/github` (step 3 below)
     - Webhook secret: generate one (`openssl rand -hex 32`), save it —
       you'll need it in step 4
     - Permissions: Repository → Pull requests (Read & write), Contents
       (Read-only) — the "write" on pull requests is for eventually posting
       review comments (not built yet, see milestone list)
     - Subscribe to events: Pull request, Installation
     - Generate a private key on the App's settings page after creating it
       — downloads a `.pem` file
  2. **Install the App** on a real repository from the App's public page
     (or via "Install App" in its settings).
  3. **Tunnel your local stack**: `ngrok http 8010` (8010, not 8000 — see
     the Quickstart port remapping above). Copy the `https://...ngrok...`
     URL ngrok gives you.
  4. **Configure `.env`** (create it in the project root if it doesn't
     exist) with the App ID (shown on the App's settings page), the
     private key (paste the full `.pem` contents), and the webhook secret
     from step 1:
     ```
     GITHUB_APP_ID=123456
     GITHUB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
     GITHUB_WEBHOOK_SECRET=<the secret from step 1>
     ```
  5. **Bring up the full stack**: `docker compose up --build` (now
     includes a real `worker` service processing the queue — see
     `docker/docker-compose.yml`).
  6. **Open a PR** on the repo you installed the App on. Watch
     `docker compose logs -f worker` — you should see the job picked up,
     and the Reviews dashboard (`localhost:5183`) should show a new row
     transition from Running to Completed with real findings, if the PR
     touches any `.py` files with something Bandit/Semgrep would catch.

  If step 6 doesn't work, the webhook payload GitHub actually sends is the
  first thing to check against `_pr_payload()`/`_INSTALLATION_PAYLOAD` in
  `tests/test_webhooks.py` — those were written from GitHub's documented
  schema, not a captured real payload, so a real delivery is exactly the
  kind of thing that could reveal a field I got subtly wrong.

## Local development without Docker

For the Docker path (recommended, one command for everything), see
**Quickstart** at the top of this file. This is the alternative for faster
iteration without container rebuilds, or if Docker isn't available:

Backend, against SQLite instead of Postgres:
```bash
DATABASE_URL="sqlite:///./dev.db" PYTHONPATH=backend uvicorn app.main:app --reload
```

Seed sample data so the dashboard has something to show:
```bash
DATABASE_URL="sqlite:///./dev.db" PYTHONPATH=backend python3 scripts/seed_dashboard_data.py
```

Frontend (in a second terminal, backend must be running on :8000 first):
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

**Running the test suite without Docker requires a real local Redis** for
one test (`tests/test_queue_integration.py`) — it deliberately fails
loudly rather than silently skipping if it can't connect (see that file's
docstring for why). Start one with `redis-server --daemonize yes`, or skip
just that file: `pytest tests/ --ignore=tests/test_queue_integration.py`.

## Run the eval harness

```bash
PYTHONPATH=backend python3 evaluation/run_eval.py
```

## Project layout

```
backend/app/
  core/        # settings
  db/          # SQLAlchemy models + session
  agents/      # LangGraph pipeline, state, diff parsing, model client interfaces
  auth/        # GitHub App JWT auth + installation token exchange
  knowledge/   # TF-IDF retrieval index, seed corpus, GHSA ingestion
  security/    # prompt-injection guardrails, tool allowlisting
  sandbox/     # real Bandit + Semgrep analyzers, sandboxed execution runner
  services/    # pipeline_runner: observability (real AgentRun DB writes)
  routers/     # FastAPI: health, GitHub webhooks, reviews, evaluation
frontend/      # React dashboard (Vite + TypeScript + Tailwind v4)
  src/api/     # typed API client + data-fetching hook
  src/components/  # Layout, severity gauge/badge (the design system)
  src/pages/   # Reviews list, Review detail, Evaluation
scripts/       # seed_dashboard_data.py: realistic sample data for local dev
tests/         # 77 passing backend tests
evaluation/    # labeled benchmark fixtures + real eval harness
docker/        # Dockerfile + docker-compose (Postgres+pgvector, Redis)
.github/workflows/ci.yml
```