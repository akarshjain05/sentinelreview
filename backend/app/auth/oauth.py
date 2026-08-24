import time
import httpx
import jwt
from fastapi import Request, HTTPException
from fastapi.security import APIKeyCookie
from app.core.config import get_settings

ALGORITHM = "HS256"
COOKIE_NAME = "session_token"

cookie_sec = APIKeyCookie(name=COOKIE_NAME, auto_error=False)

def create_access_token(data: dict) -> str:
    settings = get_settings()
    to_encode = data.copy()
    to_encode.update({"exp": time.time() + 3600}) # 1 day expiration
    encoded_jwt = jwt.encode(to_encode, settings.session_secret_key, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.session_secret_key, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def get_current_user(request: Request) -> dict:
    """Dependency to get the current logged-in user from the session cookie."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return payload

def get_user_installations(token: str) -> list[int]:
    """Fetch the GitHub App installations the user has access to."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = "https://api.github.com/user/installations"
    installations = []
    
    with httpx.Client() as client:
        while url:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail="Failed to fetch installations from GitHub")
            data = resp.json()
            for inst in data.get("installations", []):
                installations.append(inst["id"])
            
            # Check for pagination
            link_header = resp.headers.get("Link")
            url = None
            if link_header:
                for link in link_header.split(","):
                    if 'rel="next"' in link:
                        url = link[link.index("<") + 1 : link.index(">")]
                        break
                        
    return installations
