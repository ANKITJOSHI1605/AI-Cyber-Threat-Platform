import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .database import get_user_by_id

TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "28800"))
_TOKEN_SECRET = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)
_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), expected)
    except (TypeError, ValueError):
        return False


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_access_token(user: dict) -> str:
    payload = {"sub": user["id"], "role": user["role"], "exp": int(time.time()) + TOKEN_TTL_SECONDS}
    body = _encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = _encode(hmac.new(_TOKEN_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}"


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Sign in to continue", headers={"WWW-Authenticate": "Bearer"})
    try:
        body, provided = credentials.credentials.split(".", 1)
        expected = _encode(hmac.new(_TOKEN_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(provided, expected):
            raise ValueError
        payload = json.loads(_decode(body))
        if payload["exp"] < time.time():
            raise ValueError
        user = get_user_by_id(int(payload["sub"]))
        if not user:
            raise ValueError
        return user
    except (ValueError, KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Invalid or expired access token", headers={"WWW-Authenticate": "Bearer"})


def require_roles(*roles: str):
    def dependency(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Your role does not permit this action")
        return user
    return dependency
