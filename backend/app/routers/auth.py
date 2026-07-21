from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
import httpx

from app.core.config import get_settings
from app.auth.oauth import create_access_token, get_current_user, get_user_installations, COOKIE_NAME

router = APIRouter(prefix="/auth", tags=["auth"])

@router.get("/login/github")
def login_github():
    """Redirect to GitHub's OAuth authorization page."""
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=500, detail="GitHub Client ID not configured")
    
    # We request the minimum scopes needed. For GitHub Apps, user-to-server tokens 
    # just need to know who the user is to check their installations.
    # Actually, we don't need any special scopes, just the default identity.
    url = f"https://github.com/login/oauth/authorize?client_id={settings.github_client_id}"
    return RedirectResponse(url)


@router.get("/login/github/callback")
def login_github_callback(code: str, response: Response):
    """Exchange the code for a token and set the session cookie."""
    settings = get_settings()
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
    
    jwt_payload = {
        "login": user_info["login"],
        "id": user_info["id"],
        "avatar_url": user_info["avatar_url"],
        "installations": installations,
        "github_access_token": access_token, # Needed if we ever need to make more user-to-server calls
    }
    
    session_token = create_access_token(jwt_payload)
    
    # Redirect back to the frontend
    # Normally this would be dynamic or configured, but we know our frontend runs on 5173
    redirect_url = "http://localhost:5173/"
    
    redirect_resp = RedirectResponse(url=redirect_url)
    redirect_resp.set_cookie(
        key=COOKIE_NAME,
        value=session_token,
        httponly=True,
        max_age=86400,
        samesite="lax",
    )
    return redirect_resp


@router.post("/logout")
def logout():
    """Clear the session cookie."""
    resp = RedirectResponse(url="http://localhost:5173/login")
    resp.delete_cookie(COOKIE_NAME)
    return resp


@router.get("/me")
def get_me(user: dict = Depends(get_current_user)):
    """Return the current user's info for the frontend to render the UI."""
    return {
        "login": user["login"],
        "avatar_url": user["avatar_url"],
    }
