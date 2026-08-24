import uuid  # noqa: I001

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from redis import Redis

from app.auth.oauth import (
    COOKIE_NAME,
    create_access_token,
    get_current_user,
    get_user_installations,
)
from app.core.config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])

@router.get("/login/github")
def login_github():
    """Redirect to GitHub's OAuth authorization page."""
    import secrets
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=500, detail="GitHub Client ID not configured")
    
    
    is_secure = settings.environment != "development"
    state = secrets.token_urlsafe(32)
    url = f"https://github.com/login/oauth/authorize?client_id={settings.github_client_id}&state={state}"
    
    # Cryptographically sign the CSRF state to prevent cookie-forcing attacks
    import time

    import jwt
    signed_state = jwt.encode(
        {"state": state, "exp": time.time() + 600}, 
        settings.session_secret_key, 
        algorithm="HS256"
    )
    
    response = RedirectResponse(url)
    response.set_cookie(
        key="oauth_state",
        value=signed_state,
        httponly=True,
        secure=is_secure,
        max_age=600,
        samesite="lax",
        path="/",
    )
    return response




@router.get("/login/github/callback")
def login_github_callback(request: Request, code: str, state: str | None = None):  # noqa: RUF013  # type: ignore
    """Exchange the code for a token and set the session cookie."""
    settings = get_settings()
    cookie_state_token = request.cookies.get("oauth_state")
    cookie_state = None
    
    if cookie_state_token:
        import jwt
        try:
            payload = jwt.decode(cookie_state_token, settings.session_secret_key, algorithms=["HS256"])
            cookie_state = payload.get("state")
        except jwt.PyJWTError:
            pass

    if not cookie_state or not state or cookie_state != state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state (CSRF protection)")

    if not settings.github_client_id or not settings.github_client_secret:

        raise HTTPException(status_code=500, detail="GitHub OAuth not fully configured")
        
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": settings.github_client_id,
        "client_secret": settings.github_client_secret,
        "code": code,
    }
    
    with httpx.Client() as client:
        resp = client.post(token_url, json=data, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to authenticate with GitHub")
            
        token_data = resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Invalid token response from GitHub")
            
        # Fetch user info to store in session
        user_resp = client.get(
            "https://api.github.com/user", 
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"}
        )
        if user_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user info")
            
        user_info = user_resp.json()
        
    # We will fetch and cache the installations they can access right now.
    # Note: A real app might cache this with an expiration in Redis, but for now we'll put it in the JWT
    # to avoid hitting GitHub API on every dashboard load.
    installations = get_user_installations(access_token)
    
    
    settings = get_settings()
    session_id = str(uuid.uuid4())
    
    # Store GitHub token in Redis
    redis_client = Redis.from_url(settings.redis_url)
    redis_client.setex(
        f"session:{session_id}:github_token",
        86400, # 1 day
        access_token
    )
    
    jwt_payload = {
        "session_id": session_id,
        "login": user_info["login"],
        "id": user_info["id"],
        "avatar_url": user_info["avatar_url"],
        "installations": installations,
    }

    
    session_token = create_access_token(jwt_payload)
    
    # Redirect back to the frontend
    redirect_url = settings.frontend_url
    is_secure = settings.environment != "development"
    
    redirect_resp = RedirectResponse(url=redirect_url)
    redirect_resp.delete_cookie("oauth_state", path="/", secure=is_secure, httponly=True, samesite="lax")
    redirect_resp.set_cookie(
        key=COOKIE_NAME,
        value=session_token,
        httponly=True,
        secure=is_secure,
        max_age=3600,
        samesite="lax",
        path="/",
    )
    return redirect_resp


@router.post("/logout")
def logout():
    """Clear the session cookie."""
    settings = get_settings()
    is_secure = settings.environment != "development"
    # Redirect back to the frontend root (Landing Page)
    redirect_url = settings.frontend_url
    resp = RedirectResponse(url=redirect_url, status_code=303)
    resp.delete_cookie(COOKIE_NAME, path="/", secure=is_secure, httponly=True, samesite="lax")
    return resp


@router.get("/me")
def get_me(user: dict = Depends(get_current_user)):  # noqa: B008
    """Return the current user's info for the frontend to render the UI."""
    return {
        "login": user["login"],
        "avatar_url": user["avatar_url"],
    }
