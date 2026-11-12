import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "tests" / "fixtures" / "demo_server.py"
sys.path.insert(0, str(ROOT / "tests"))

# Everything stays on this machine.
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


@pytest.fixture(scope="session")
def program():
    spec = importlib.util.spec_from_file_location("omega_connect_program", ROOT / "program.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    module.ENGINE.shutdown()


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_CONNECT_DATA_DIR", str(tmp_path / "store"))
    monkeypatch.setenv("OMEGA_CONNECT_LOG_DIR", str(tmp_path / "logs"))
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OMEGA_CONNECT_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("OMEGA_CONNECT_ALLOW_STDIO", raising=False)
    yield


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_demo(env_extra: dict) -> tuple[subprocess.Popen, str]:
    port = free_port()
    env = {**os.environ, **env_extra}
    proc = subprocess.Popen([sys.executable, str(DEMO), "http", str(port)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return proc, f"http://127.0.0.1:{port}/mcp"
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError("demo server did not start")


@pytest.fixture
def demo_url():
    proc, url = _start_demo({})
    yield url
    proc.terminate()
    proc.wait(timeout=10)


SECRET = "tok-9f2c4b7e51d0a8"


@pytest.fixture
def guarded_url():
    """Demo server that answers only with `Authorization: Bearer SECRET`."""
    proc, url = _start_demo({"DEMO_REQUIRE_TOKEN": SECRET})
    yield url
    proc.terminate()
    proc.wait(timeout=10)


class _FakeAuthority(BaseHTTPRequestHandler):
    """Microsoft identity platform stand-in: device code then token."""
    access_token = SECRET
    pending_polls = 1

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        if self.path.endswith("/devicecode"):
            body = {"device_code": "dev-1", "user_code": "ABCD-1234",
                    "verification_uri": "https://microsoft.com/devicelogin",
                    "expires_in": 60, "interval": 1, "message": "sign in"}
        elif form.get("grant_type", "").endswith("device_code"):
            cls = type(self)
            if cls.pending_polls > 0:
                cls.pending_polls -= 1
                body = {"error": "authorization_pending"}
            else:
                body = {"access_token": cls.access_token, "refresh_token": "rt-55aa66bb",
                        "expires_in": 3600, "scope": form.get("scope", "")}
        elif form.get("grant_type") == "refresh_token":
            body = {"access_token": type(self).access_token, "expires_in": 3600}
        else:
            body = {"error": "unsupported"}
        data = json.dumps(body).encode()
        status = 400 if "error" in body else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def fake_authority(monkeypatch):
    _FakeAuthority.pending_polls = 1
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeAuthority)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OMEGA_CONNECT_OAUTH_AUTHORITY", f"http://127.0.0.1:{server.server_port}")
    yield server
    server.shutdown()
