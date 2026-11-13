"""The app's own store: per-swarm server list, encrypted credentials, call traces.

Layout under OMEGA_CONNECT_DATA_DIR (default ~/.omega-connect), one folder per
swarm (named by a digest of the swarm id):

    servers.json   server records, no secrets; each keeps the tools a person
                   accepted as read, with the digest of the definition accepted
    secrets.bin    OAuth tokens, encrypted with Fernet (AES-128-CBC + HMAC)
    trace.jsonl    one line per tool call: digests only, never content
    intents.json   app-level idempotency records for use-tool

The encryption key comes from OMEGA_CONNECT_SECRET_KEY (a Fernet key). Without
it the store refuses to keep credentials: it fails closed rather than writing
tokens in clear. Files are created with mode 0600.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

SERVER_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
CRED_VARIABLE = re.compile(r"^OMEGA_CONNECT_CRED_[A-Z0-9_]{1,60}$")
TRACE_KEEP = 2000


class StoreError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


def digest(value: Any) -> str:
    """sha256 of canonical JSON (or of the text itself for strings)."""
    if isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _base_dir() -> Path:
    return Path(os.environ.get("OMEGA_CONNECT_DATA_DIR") or Path.home() / ".omega-connect")


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)


def _fernet():
    key = os.environ.get("OMEGA_CONNECT_SECRET_KEY", "").strip()
    if not key:
        raise StoreError("no_secret_key",
                         "the operator has not set OMEGA_CONNECT_SECRET_KEY, so credentials cannot be stored")
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise StoreError("no_crypto", "the 'cryptography' package is required to store credentials")
    try:
        return Fernet(key.encode("ascii"))
    except Exception:
        raise StoreError("bad_secret_key", "OMEGA_CONNECT_SECRET_KEY is not a valid Fernet key")


class SwarmStore:
    _locks: dict[str, threading.Lock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, swarm_id: str):
        if not swarm_id:
            raise StoreError("no_swarm", "every call must be scoped to a swarm")
        self.swarm_id = str(swarm_id)
        folder = hashlib.sha256(self.swarm_id.encode("utf-8")).hexdigest()[:24]
        self.dir = _base_dir() / folder
        with SwarmStore._locks_guard:
            self.lock = SwarmStore._locks.setdefault(folder, threading.Lock())

    # ---------------------------------------------------------- servers
    def servers(self) -> dict[str, dict]:
        path = self.dir / "servers.json"
        if not path.exists():
            return {}
        return json.loads(path.read_text("utf-8")).get("servers", {})

    def _save_servers(self, servers: dict[str, dict]) -> None:
        payload = {"swarm": digest(self.swarm_id), "servers": servers}
        _write_private(self.dir / "servers.json", json.dumps(payload, indent=2, sort_keys=True).encode())

    def put_server(self, record: dict) -> None:
        with self.lock:
            servers = self.servers()
            servers[record["name"]] = record
            self._save_servers(servers)

    def remove_server(self, name: str) -> bool:
        with self.lock:
            servers = self.servers()
            if servers.pop(name, None) is None:
                return False
            self._save_servers(servers)
        self.delete_credentials(name)
        return True

    def set_tool_class(self, server: str, tool: str, cls: str | None) -> None:
        with self.lock:
            servers = self.servers()
            record = servers.get(server)
            if record is None:
                raise StoreError("unknown_server", f"no server named '{server}'")
            reclass = record.setdefault("reclass", {})
            if cls is None:
                reclass.pop(tool, None)
            else:
                reclass[tool] = cls
            self._save_servers(servers)

    def accept_reads(self, server: str, digests: dict[str, str], by: str, whole_server: bool) -> None:
        """Record that a person accepted these tools as read: {tool: digest of its definition}.
        For the whole server the list replaces the earlier one."""
        with self.lock:
            servers = self.servers()
            record = servers.get(server)
            if record is None:
                raise StoreError("unknown_server", f"no server named '{server}'")
            reviewed = {} if whole_server else record.get("reviewed", {})
            at = int(time.time())
            reviewed.update({tool: {"digest": value, "by": by, "at": at} for tool, value in digests.items()})
            record["reviewed"] = reviewed
            self._save_servers(servers)

    # ---------------------------------------------------------- credentials
    def _secrets(self) -> dict:
        path = self.dir / "secrets.bin"
        if not path.exists():
            return {}
        return json.loads(_fernet().decrypt(path.read_bytes()).decode("utf-8"))

    def _save_secrets(self, secrets: dict) -> None:
        token = _fernet().encrypt(json.dumps(secrets).encode("utf-8"))
        _write_private(self.dir / "secrets.bin", token)

    def credentials(self, server: str) -> dict | None:
        with self.lock:
            return self._secrets().get(server)

    def put_credentials(self, server: str, value: dict) -> None:
        with self.lock:
            secrets = self._secrets()
            secrets[server] = value
            self._save_secrets(secrets)

    def replace_credentials(self, server: str, old: dict, new: dict) -> bool:
        """Store `new` only if the stored credentials are still `old`, so a renewal that finishes
        after a revoke or a new sign-in never writes over them."""
        with self.lock:
            secrets = self._secrets()
            if secrets.get(server) != old:
                return False
            secrets[server] = new
            self._save_secrets(secrets)
            return True

    def delete_credentials(self, server: str) -> bool:
        with self.lock:
            path = self.dir / "secrets.bin"
            if not path.exists():
                return False
            secrets = self._secrets()
            removed = secrets.pop(server, None) is not None
            self._save_secrets(secrets)
            return removed

    def has_credentials(self, server: str) -> bool:
        try:
            return self.credentials(server) is not None
        except StoreError:
            return False

    # ---------------------------------------------------------- traces
    def trace(self, entry: dict) -> None:
        entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **entry}
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
        with self.lock:
            path = self.dir / "trace.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(line)

    def traces(self, limit: int = 30) -> list[dict]:
        path = self.dir / "trace.jsonl"
        if not path.exists():
            return []
        lines = path.read_text("utf-8").splitlines()[-max(limit, 0):]
        return [json.loads(line) for line in lines if line.strip()]

    def trace_count(self) -> int:
        path = self.dir / "trace.jsonl"
        if not path.exists():
            return 0
        with path.open("rb") as handle:
            return sum(1 for _ in handle)

    # ---------------------------------------------------------- intents
    def intent(self, key: str) -> dict | None:
        path = self.dir / "intents.json"
        if not path.exists():
            return None
        return json.loads(path.read_text("utf-8")).get(key)

    def put_intent(self, key: str, record: dict) -> None:
        with self.lock:
            path = self.dir / "intents.json"
            data = json.loads(path.read_text("utf-8")) if path.exists() else {}
            data[key] = record
            if len(data) > TRACE_KEEP:
                for old in sorted(data, key=lambda k: data[k].get("at", ""))[: len(data) - TRACE_KEEP]:
                    data.pop(old, None)
            _write_private(path, json.dumps(data, sort_keys=True).encode())

    def drop_intent(self, key: str) -> None:
        with self.lock:
            path = self.dir / "intents.json"
            data = json.loads(path.read_text("utf-8")) if path.exists() else {}
            if data.pop(key, None) is not None:
                _write_private(path, json.dumps(data, sort_keys=True).encode())
