# SentinelReview

<div align="center">
  <p><strong>Agentic security code review for GitHub Pull Requests.</strong></p>
  <p>
    <a href="https://github.com/akarshjain05/sentinelreview/actions"><img src="https://github.com/akarshjain05/sentinelreview/workflows/CI/badge.svg" alt="CI Status"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  </p>
</div>

## About

SentinelReview is a powerful, autonomous security code review tool designed to catch vulnerabilities directly in your GitHub Pull Requests. 

It combines robust static analysis with retrieval-augmented generation (RAG) over authoritative sources (CWE, OWASP, GHSA) and a 7-agent LangGraph pipeline. SentinelReview doesn't just flag issues—it grounds every claim in an authoritative source, generates a patch, verifies the patch in a secure sandbox, and posts a structured PR review.

### Topics
`security` `code-review` `artificial-intelligence` `langgraph` `rag` `static-analysis` `github-actions` `devsecops` `python` `react` `fastapi`

---

## Architecture Overview

SentinelReview operates on a multi-agent architecture powered by **LangGraph**:
1. **Static Analysis**: Scans code with tools like Bandit and Semgrep.
2. **RAG Integration**: Grounds findings in authoritative databases (OWASP, CWE).
3. **Patch Generation**: Autonomously writes fixes for detected vulnerabilities.
4. **Sandbox Verification**: Tests the generated patches to ensure they don't break existing functionality.
5. **Review Posting**: Delivers actionable insights directly to GitHub PRs.

## Quickstart: Docker Compose

The easiest way to run SentinelReview is using Docker. One command brings up Postgres (with pgvector), Redis, the FastAPI backend, the RQ worker, and the React dashboard.

```bash
git clone https://github.com/akarshjain05/sentinelreview.git
cd sentinelreview/docker
docker compose up --build -d
```

### Services
| Service | URL / Port |
|---|---|
| **Dashboard** | http://localhost:5183 |
| **API** | http://localhost:8010 (docs at `/docs`) |
| **Postgres** | `localhost:5435` |
| **Redis** | `localhost:6382` |

> *Note: Host ports have been deliberately remapped from defaults (e.g., 5435 instead of 5432) to prevent collisions with your existing local services.*

### Populating Sample Data
To populate the dashboard with sample reviews and evaluation metrics, run the following seed scripts against the running backend container:

```bash
docker compose exec backend python3 scripts/seed_dashboard_data.py
docker compose exec backend python3 evaluation/run_eval.py
```

## GitHub App Configuration

To enable live PR scanning, you must configure a GitHub App and connect it to your SentinelReview instance.

1. **Register the App**: Go to GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
   - **Webhook URL**: Your tunnel's HTTPS URL (e.g., via `ngrok http 8010`) + `/webhooks/github`
   - **Permissions**: Repository → Pull requests (Read & write), Contents (Read-only)
   - **Events**: Pull request, Installation
2. **Generate Secrets**: Create a Webhook secret (`openssl rand -hex 32`) and generate a private key (`.pem`).
3. **Configure Environment**: Create a `.env` file in the project root:
   ```env
   GITHUB_APP_ID=your_app_id
   GITHUB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
   GITHUB_WEBHOOK_SECRET=your_webhook_secret
   ```
4. **Restart Services**: `docker compose up -d` to inject the new environment variables into the worker and backend.

## Local Development (Without Docker)

If you prefer to run services natively on your machine:

**1. Backend (FastAPI)**
```bash
DATABASE_URL="sqlite:///./dev.db" PYTHONPATH=backend uvicorn app.main:app --reload
```

**2. Frontend (React + Vite)**
```bash
cd frontend
npm install
npm run dev
```

**3. Run the Evaluation Harness**
```bash
PYTHONPATH=backend python3 evaluation/run_eval.py
```

**4. Run Tests**
```bash
# Note: Requires a local Redis server running on port 6379 for integration tests
PYTHONPATH=backend pytest tests/ -v
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
