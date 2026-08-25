# 🛡️ SentinelReview

<div align="center">
  <p><strong>Agentic security code review for GitHub Pull Requests.</strong></p>
  <p>
    <a href="https://github.com/akarshjain05/sentinelreview/actions"><img src="https://github.com/akarshjain05/sentinelreview/workflows/CI/badge.svg" alt="CI Status"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  </p>
</div>

---

## 📖 About

**SentinelReview** is a powerful, autonomous security code review tool designed to catch vulnerabilities directly in your GitHub Pull Requests before they ever reach production. 

Rather than just throwing noisy static analysis alerts at developers, SentinelReview uses a multi-agent AI pipeline to investigate findings, ground its claims in authoritative sources (like OWASP and CWE), autonomously generate a fix, and verify the patch in a secure sandbox. It then posts a high-signal, actionable review directly to your GitHub PR.

### 🌟 Key Features
- **Multi-Agent Pipeline**: Powered by a 7-agent **LangGraph** architecture.
- **RAG-Backed Analysis**: Grounds every vulnerability claim in authoritative databases (CWE, OWASP, GHSA).
- **Auto-Patching & Verification**: Generates secure code patches and tests them in a containerized sandbox to ensure they don't break functionality.
- **Developer Dashboard**: A beautiful, real-time React/Vite dashboard to monitor system health, view security analytics, and manage active repositories.
- **Secure by Default**: Built with strict CORS, strong JWT validation, and secure GitHub webhook signature verification.

---

## 🏗️ Architecture

SentinelReview relies on several integrated services:
1. **FastAPI Backend**: Handles GitHub Webhooks, API routing, and authentication.
2. **React/Vite Dashboard**: The frontend UI for monitoring and analytics.
3. **Redis & RQ Worker**: Asynchronous queue processing for deep code analysis without timing out GitHub webhooks.
4. **PostgreSQL (pgvector)**: Stores PR metadata, findings, and vector embeddings for RAG.
5. **LangGraph Pipeline**: The "brain" that coordinates LLM models, static analyzers (Bandit, Semgrep), and sandbox patching.

---

## 🛠️ Prerequisites

Before you start, ensure you have the following installed:
- **Docker** and **Docker Compose**
- **Git**
- A **GitHub Account** (to create a GitHub App and OAuth App)
- An **LLM API Key** (e.g., Anthropic, OpenAI, NVIDIA NIM, Groq, or Gemini). SentinelReview is model-agnostic via LiteLLM.

---

## 🚀 Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/akarshjain05/sentinelreview.git
cd sentinelreview
```

### 2. Configure Environment Variables
Create a `.env` file in the root of the project:
```bash
touch .env
```

Populate it with the required configuration. *Generate a random 32+ character string for `SESSION_SECRET_KEY`.*

```env
# Security
SESSION_SECRET_KEY="your-super-secret-random-32-byte-string"

# LLM Provider (Provide AT LEAST ONE of these)
ANTHROPIC_API_KEY="sk-ant-..."
# OPENAI_API_KEY="sk-..."
# NVIDIA_API_KEY="nvapi-..."
# GEMINI_API_KEY="AIza..."

# GitHub App Integration (See step 3 below)
GITHUB_APP_ID="your_app_id"
GITHUB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET="your_webhook_secret"

# GitHub OAuth for Dashboard Login
GITHUB_CLIENT_ID="your_oauth_client_id"
GITHUB_CLIENT_SECRET="your_oauth_client_secret"
```

### 3. Setup GitHub App & Webhooks
To allow SentinelReview to listen to PRs and post reviews:
1. Go to **Settings → Developer settings → GitHub Apps → New GitHub App**.
2. **Webhook URL**: You need a publicly accessible URL forwarding to `http://localhost:8010/webhooks/github` (e.g., using `ngrok http 8010` or `smee.io`).
3. **Webhook Secret**: Generate a random secret and put it in your `.env`.
4. **Permissions**: 
   - Repository: `Pull requests` (Read & write), `Contents` (Read-only)
5. **Events**: Subscribe to `Pull request` and `Installation`.
6. Generate a **Private Key** and download the `.pem` file. Paste its contents exactly into your `.env`.
7. Install the App on your repositories.

### 4. Setup GitHub OAuth (For the Dashboard)
1. Go to **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. **Authorization callback URL**: `http://localhost:8010/auth/github/callback`
3. Copy the Client ID and Secret into your `.env`.

---

## 🏃‍♂️ Running the Stack

With your `.env` configured, launch the entire application stack using Docker Compose:

```bash
cd docker
docker compose up --build -d
```

This spins up the Database, Redis, Backend, Background Worker, and Frontend Dashboard.

### Services Overview
| Service | Local URL |
|---|---|
| **Dashboard UI** | [http://localhost:5183](http://localhost:5183) |
| **Backend API** | [http://localhost:8010](http://localhost:8010) (Docs at `/docs`) |
| **Postgres** | `localhost:5435` |
| **Redis** | `localhost:6382` |

> *Note: Host ports are deliberately remapped to prevent collisions with your local services.*

### Populating Sample Data (Optional)
If you want to test the dashboard UI without triggering a real GitHub PR, you can seed fake review data and run the evaluation benchmark:

```bash
# Generate fake PRs and vulnerabilities
docker compose exec backend python3 scripts/seed_dashboard_data.py

# Run the evaluation harness to populate analytics
docker compose exec backend python3 evaluation/run_eval.py
```

---

## 👨‍💻 Using SentinelReview

1. **Login**: Go to `http://localhost:5183` and log in via GitHub OAuth.
2. **Open a PR**: Make a pull request with intentionally vulnerable Python code (e.g., a SQL injection) in a repository where your GitHub App is installed.
3. **Watch the Magic**: 
   - The GitHub App fires a webhook.
   - The RQ Worker picks up the job.
   - LangGraph spawns agents to run static analysis, verify it against RAG, sandbox a patch, and write a review.
   - SentinelReview posts a highly-detailed comment on your PR with the patched code.
4. **View Analytics**: Check the Dashboard to view the live status of the run, the generated patch, and historical security trends.

---

## 🛠️ Local Development (Without Docker)

If you wish to develop without Docker containers:

**1. Backend**
```bash
# Uses SQLite for local dev
DATABASE_URL="sqlite:///./dev.db" PYTHONPATH=backend uvicorn app.main:app --reload
```

**2. Frontend**
```bash
cd frontend
npm install
npm run dev
```

**3. Run Tests**
```bash
# Requires a local Redis instance on port 6379
PYTHONPATH=backend pytest tests/ -v
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
