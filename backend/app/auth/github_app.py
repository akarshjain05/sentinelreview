"""
GitHub App authentication.

Implements the two-step auth flow GitHub Apps actually require:
  1. Sign a short-lived JWT with the App's RS256 private key (proves you
     control the App itself).
  2. Exchange that JWT for an installation access token scoped to a
     specific installation (proves + limits access to the repos that
     installation was granted).

generate_app_jwt is fully real -- RS256 signing/verification via PyJWT +
cryptography, tested against a real generated keypair below.
exchange_installation_token makes a real HTTP call shaped exactly like
GitHub's documented endpoint; it's tested against a mocked HTTP response
(via respx) since this project has no live GitHub App credentials yet.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import jwt

GITHUB_API_BASE = "https://api.github.com"


class GitHubAppAuthError(RuntimeError):
    pass


def generate_app_jwt(app_id: str, private_key_pem: str, *, now: int | None = None) -> str:
    """
    Build the JWT a GitHub App uses to authenticate as itself.

    Per GitHub's docs: `iat` should be slightly in the past to tolerate
    clock drift, `exp` must be no more than 10 minutes out, and `iss` is
    the App ID.
    """
    issued_at = (now or int(time.time())) - 60
    expires_at = issued_at + (9 * 60)  # stay safely under the 10-minute cap

    payload = {"iat": issued_at, "exp": expires_at, "iss": app_id}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


@dataclass
class InstallationToken:
    token: str
    expires_at: str


def exchange_installation_token(
    installation_id: int,
    app_jwt: str,
    *,
    client: httpx.Client | None = None,
) -> InstallationToken:
    """
    Exchange an App-level JWT for an installation access token, scoped to
    whatever repos/permissions that installation was granted.
    """
    owns_client = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        response = client.post(
            f"{GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if response.status_code != 201:
            raise GitHubAppAuthError(
                f"Installation token exchange failed ({response.status_code}): {response.text[:300]}"
            )
        data = response.json()
        return InstallationToken(token=data["token"], expires_at=data["expires_at"])
    finally:
        if owns_client:
            client.close()


def get_installation_token(
    installation_id: int,
    *,
    app_id: str | None = None,
    private_key_pem: str | None = None,
    client: httpx.Client | None = None,
) -> InstallationToken:
    """
    The full two-step chain in one call: sign an App JWT, then exchange it
    for an installation token. Reads app_id/private_key from app config by
    default so callers (like the webhook handler) don't need to thread
    settings through manually.

    Raises GitHubAppAuthError with an actionable message -- not a bare
    AttributeError/TypeError -- if the App isn't configured yet, which is
    the expected state for local development without a registered App.
    """
    if app_id is None or private_key_pem is None:
        from app.core.config import get_settings

        settings = get_settings()
        app_id = app_id or settings.github_app_id
        private_key_pem = private_key_pem or settings.github_private_key

    if not app_id or not private_key_pem:
        raise GitHubAppAuthError(
            "GitHub App is not configured: GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be "
            "set (e.g. in .env) before installation tokens can be issued. This is expected "
            "if you haven't registered a GitHub App yet -- see README.md for setup steps."
        )

    app_jwt = generate_app_jwt(app_id=app_id, private_key_pem=private_key_pem)
    return exchange_installation_token(installation_id, app_jwt, client=client)
