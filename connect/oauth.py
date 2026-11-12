"""OAuth 2.0 device authorization grant (RFC 8628) for delegated access.

Used for Microsoft 365: a person runs the `connect` action, gets a short code
and a sign-in address, signs in with their own account and consents to the
scopes the server needs. Tokens never leave the app: they are kept encrypted
in the store and turned into an Authorization header just before a call.

Standard library only. The authority defaults to the Microsoft identity
platform; OMEGA_CONNECT_OAUTH_AUTHORITY overrides it (tests use a local fake).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

DEFAULT_AUTHORITY = "https://login.microsoftonline.com"


class OAuthError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


def authority() -> str:
    return os.environ.get("OMEGA_CONNECT_OAUTH_AUTHORITY", DEFAULT_AUTHORITY).rstrip("/")


def _post(url: str, form: dict) -> dict:
    body = urllib.parse.urlencode(form).encode("ascii")
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception:
            raise OAuthError("http", f"identity provider answered HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise OAuthError("unreachable", f"identity provider unreachable: {exc.reason}")


@dataclass
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    interval: int
    expires_at: float
    message: str


def start_device_flow(tenant: str, client_id: str, scopes: list[str]) -> DeviceCode:
    data = _post(f"{authority()}/{tenant}/oauth2/v2.0/devicecode",
                 {"client_id": client_id, "scope": " ".join(scopes)})
    if "device_code" not in data:
        raise OAuthError("device_code", data.get("error_description") or data.get("error") or "no device code")
    return DeviceCode(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_uri=data.get("verification_uri") or data.get("verification_url", ""),
        interval=int(data.get("interval", 5)),
        expires_at=time.time() + int(data.get("expires_in", 900)),
        message=str(data.get("message", "")),
    )


def poll_device_flow(tenant: str, client_id: str, code: DeviceCode, sleep=time.sleep) -> dict:
    """Blocks until the person signs in, declines, or the code expires."""
    interval = max(code.interval, 1)
    while time.time() < code.expires_at:
        data = _post(f"{authority()}/{tenant}/oauth2/v2.0/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": code.device_code,
        })
        if "access_token" in data:
            return _token_record(data)
        error = data.get("error")
        if error == "authorization_pending":
            sleep(interval)
            continue
        if error == "slow_down":
            interval += 5
            sleep(interval)
            continue
        raise OAuthError(error or "token", data.get("error_description") or "sign-in failed")
    raise OAuthError("expired_token", "the sign-in code expired before it was used")


def refresh(tenant: str, client_id: str, scopes: list[str], record: dict) -> dict:
    if not record.get("refresh_token"):
        raise OAuthError("no_refresh_token", "sign-in expired; a person must run connect again")
    data = _post(f"{authority()}/{tenant}/oauth2/v2.0/token", {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": record["refresh_token"],
        "scope": " ".join(scopes),
    })
    if "access_token" not in data:
        raise OAuthError(data.get("error") or "refresh", "sign-in expired; a person must run connect again")
    new = _token_record(data)
    if not new.get("refresh_token"):
        new["refresh_token"] = record["refresh_token"]
    return new


def _token_record(data: dict) -> dict:
    return {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token"),
        "expires_at": time.time() + int(data.get("expires_in", 3600)),
        "scope": data.get("scope", ""),
    }


def needs_refresh(record: dict, margin: float = 120.0) -> bool:
    return float(record.get("expires_at", 0)) - margin < time.time()
