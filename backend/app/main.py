from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.routers import auth, evaluation, health, observability, repositories, reviews, webhooks
from app.routers import settings as settings_router

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="Agentic security code review for GitHub Pull Requests.",
    version="0.1.0",
)

# Dashboard (Vite dev server) runs on a different origin during development.
# Restricted to localhost dev ports, not a wildcard -- this API also handles
# GitHub webhooks and should not send permissive CORS headers by default.
# Two port sets: 5173 is Vite's own default (non-Docker `npm run dev`);
# 5183 is this project's Docker Compose host-port mapping (docker/docker-compose.yml),
# remapped off 5173 specifically because 5173 is common enough to collide
# with other projects' dev servers running at the same time.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(webhooks.router)
app.include_router(settings_router.router)
app.include_router(auth.router)
app.include_router(repositories.router)
app.include_router(reviews.router)
app.include_router(evaluation.router)
app.include_router(observability.router)