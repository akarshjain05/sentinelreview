import time

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.github_app import (
    GitHubAppAuthError,
    exchange_installation_token,
    generate_app_jwt,
)


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate a real RSA keypair -- same primitive GitHub Apps actually use."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def test_generate_app_jwt_is_valid_and_verifiable(rsa_keypair):
    private_pem, public_pem = rsa_keypair

    token = generate_app_jwt(app_id="123456", private_key_pem=private_pem)

    # Verify with the PUBLIC key only -- proves the JWT was actually signed
    # by the private key, not just base64-shaped.
    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
    assert decoded["iss"] == "123456"
    assert decoded["exp"] - decoded["iat"] <= 600  # GitHub's 10-minute cap
    assert decoded["iat"] <= int(time.time())


def test_generate_app_jwt_rejects_verification_with_wrong_key(rsa_keypair):
    private_pem, _ = rsa_keypair
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_public_pem = other_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    token = generate_app_jwt(app_id="123456", private_key_pem=private_pem)

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, wrong_public_pem, algorithms=["RS256"])


@respx.mock
def test_exchange_installation_token_success(rsa_keypair):
    private_pem, _ = rsa_keypair
    app_jwt = generate_app_jwt(app_id="123456", private_key_pem=private_pem)

    respx.post("https://api.github.com/app/installations/999/access_tokens").mock(
        return_value=httpx.Response(
            201, json={"token": "ghs_mocked_installation_token", "expires_at": "2026-07-07T12:00:00Z"}
        )
    )

    result = exchange_installation_token(999, app_jwt)
    assert result.token == "ghs_mocked_installation_token"
    assert result.expires_at == "2026-07-07T12:00:00Z"


@respx.mock
def test_exchange_installation_token_failure_raises(rsa_keypair):
    private_pem, _ = rsa_keypair
    app_jwt = generate_app_jwt(app_id="123456", private_key_pem=private_pem)

    respx.post("https://api.github.com/app/installations/999/access_tokens").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )

    with pytest.raises(GitHubAppAuthError):
        exchange_installation_token(999, app_jwt)


# ---- get_installation_token: the combined convenience function -------------

def test_get_installation_token_raises_clear_error_when_unconfigured(monkeypatch):
    from app.auth.github_app import GitHubAppAuthError, get_installation_token
    from app.core.config import Settings, get_settings

    # Provide a completely clean Settings object without loading .env
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_PRIVATE_KEY", raising=False)
    monkeypatch.setattr("app.core.config.get_settings", lambda: Settings(_env_file=None))

    with pytest.raises(GitHubAppAuthError, match="not configured"):
        get_installation_token(9001)

    get_settings.cache_clear()


@respx.mock
def test_get_installation_token_full_chain_with_explicit_args(rsa_keypair):
    """The combined function, called with explicit app_id/key rather than reading from settings."""
    from app.auth.github_app import get_installation_token

    private_pem, _ = rsa_keypair
    respx.post("https://api.github.com/app/installations/9001/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": "ghs_direct", "expires_at": "2026-08-01T00:00:00Z"})
    )

    result = get_installation_token(9001, app_id="123456", private_key_pem=private_pem)
    assert result.token == "ghs_direct"
    assert result.expires_at == "2026-08-01T00:00:00Z"


@respx.mock
def test_get_installation_token_full_chain_reads_from_settings(rsa_keypair, monkeypatch):
    """The combined function, reading app_id/key from settings -- the actual path the webhook handler uses."""
    from app.auth.github_app import get_installation_token
    from app.core.config import get_settings

    private_pem, _ = rsa_keypair
    monkeypatch.setenv("GITHUB_APP_ID", "999999")
    monkeypatch.setenv("GITHUB_PRIVATE_KEY", private_pem)
    get_settings.cache_clear()

    respx.post("https://api.github.com/app/installations/9002/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": "ghs_from_settings", "expires_at": "2026-08-02T00:00:00Z"})
    )

    result = get_installation_token(9002)
    assert result.token == "ghs_from_settings"

    get_settings.cache_clear()
