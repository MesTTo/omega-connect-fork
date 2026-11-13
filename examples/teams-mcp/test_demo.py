"""demo.py as a person runs it, with Microsoft Graph and the identity platform simulated.

Each test starts demo.py in its own process and answers its prompts through its
standard input. demo.py starts this file in place of server.py: teams-mcp with
the FakeGraph of test_server.py, which writes each Graph request it gets to a
file the test reads. The sign-in goes to a fake identity platform in the test's
process. Nothing leaves this machine.

    python -m pytest -q examples/teams-mcp
"""

import base64
import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest

HERE = Path(__file__).resolve().parent
DEMO = HERE / "demo.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


graph_tests = _load(HERE / "test_server.py", "teams_mcp_graph_tests")  # FakeGraph and its data
TOKEN, REFRESH, TEAM, CHANNEL = graph_tests.TOKEN, graph_tests.REFRESH, graph_tests.TEAM, graph_tests.CHANNEL
TENANT, CLIENT_ID, SCOPES = graph_tests.TENANT, graph_tests.CLIENT_ID, graph_tests.SCOPES
ACCOUNT = "ada@omegademo.example"
ID_TOKEN = "eyJhbGciOiJSUzI1NiJ9." + base64.urlsafe_b64encode(
    json.dumps({"preferred_username": ACCOUNT}).encode()).decode().rstrip("=") + ".c2ln"
DEVICE_CODE = "dev-code-5c1e9a"
SHELL_KEY = "the-operators-own-key"  # set in the shell that runs the demo; not a Fernet key, so using it fails
OTHER_TEAM = "0e0e0e0e-1111-4222-8333-444444444444"
PRIVATE, QUIET = "19:5e1f0a7b@thread.tacv2", "19:0c2d3e4f@thread.tacv2"
HOSTILE = "line one\nline \x9b31mtwo"  # 8-bit CSI: some terminals take it for an escape sequence


def serve_with_fake_graph(argv: list[str]) -> None:
    """teams-mcp as demo.py starts it, with FakeGraph in place of Microsoft Graph and a second team,
    whose private channel holds a message with terminal controls in it. The first line of
    $FAKE_GRAPH_LOG gives this process's id and the OMEGA_CONNECT_ settings it got, then each Graph
    request follows as "METHOD path"."""
    teams = _load(HERE / "server.py", "teams_mcp_server")
    graph = graph_tests.FakeGraph(teams.GRAPH)
    graph.teams.append({"id": OTHER_TEAM, "displayName": "Other team"})
    graph.channels[OTHER_TEAM] = [{"id": PRIVATE, "displayName": "Private", "membershipType": "private"},
                                  {"id": QUIET, "displayName": "Quiet", "membershipType": "standard"}]
    graph.messages[(OTHER_TEAM, PRIVATE)] = [
        {"id": "9", "messageType": "message", "createdDateTime": "2026-11-13T08:00:00Z",
         "from": {"user": {"displayName": "Eve \u202eevil"}}, "body": {"contentType": "text", "content": HOSTILE}}]
    graph.messages[(OTHER_TEAM, QUIET)] = []
    log = Path(os.environ["FAKE_GRAPH_LOG"])
    log.write_text(json.dumps({"pid": os.getpid(), "settings": sorted(
        name for name in os.environ if name.startswith("OMEGA_CONNECT_"))}) + "\n")

    def send(method, url, headers, body):
        with log.open("a") as out:
            out.write(f"{method} {url[len(teams.GRAPH):].split('?')[0]}\n")
        return graph.send(method, url, headers, body)

    teams.graph_send = send
    teams.main(argv)


class _IdentityPlatform(BaseHTTPRequestHandler):
    """The Microsoft identity platform for the demo's sign-in: a device code, `pending` answers
    "authorization_pending", then a token. A step named in `refuse` gets that error instead."""
    state = None  # set by the platform fixture

    def log_message(self, *args):
        pass

    def do_POST(self):
        state = type(self).state
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        step = "devicecode" if self.path.endswith("/devicecode") else "token"
        state.requests.append((self.path, form))
        if step in state.refuse:
            body = state.refuse[step]
        elif step == "devicecode":
            body = {"device_code": DEVICE_CODE, "user_code": "ABCD-1234", "expires_in": 60, "interval": 1,
                    "verification_uri": "https://microsoft.com/devicelogin"}
        elif state.pending > 0:
            state.pending -= 1
            body = {"error": "authorization_pending"}
        else:
            body = {"access_token": TOKEN, "refresh_token": REFRESH, "expires_in": 3600, "id_token": ID_TOKEN,
                    "scope": " ".join(SCOPES)}
        data = json.dumps(body).encode()
        self.send_response(400 if "error" in body else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# Runs demo.py with this file in place of server.py. argv: demo.py, this file.
RUNNER = """\
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("teams_demo", sys.argv[1])
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
demo.SERVER = pathlib.Path(sys.argv[2])
sys.exit(demo.main())
"""


class DemoRun:
    """demo.py in its own process, answered line by line as a person at the terminal would."""

    def __init__(self, platform, tmp_path: Path):
        self.graph_log = tmp_path / "graph.log"
        self.temp = tmp_path / "tmp"  # the demo's temporary folder goes here
        self.temp.mkdir()
        self.operator_store = tmp_path / "operator-store"
        env = {name: value for name, value in os.environ.items() if not name.startswith("OMEGA_CONNECT_")}
        env.update(PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8", TMPDIR=str(self.temp),
                   FAKE_GRAPH_LOG=str(self.graph_log), OMEGA_CONNECT_OAUTH_AUTHORITY=platform.url,
                   # what an operator's shell may hold; the demo must use neither
                   OMEGA_CONNECT_DATA_DIR=str(self.operator_store), OMEGA_CONNECT_SECRET_KEY=SHELL_KEY)
        self.proc = subprocess.Popen([sys.executable, "-c", RUNNER, str(DEMO), __file__], env=env, cwd=tmp_path,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self._out = b""
        self._seen = 0
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        for chunk in iter(lambda: os.read(self.proc.stdout.fileno(), 65536), b""):
            self._out += chunk

    @property
    def output(self) -> str:
        return self._out.decode("utf-8", errors="replace")

    def expect(self, text: str, timeout: float = 60) -> None:
        """Waits until demo.py prints `text` after what the last expect found."""
        deadline = time.monotonic() + timeout
        while True:
            ended = not self._reader.is_alive()  # then the output is complete
            found = self.output.find(text, self._seen)
            if found >= 0:
                self._seen = found + len(text)
                return
            assert not ended and time.monotonic() < deadline, f"demo.py did not print {text!r}:\n{self.output}"
            time.sleep(0.05)

    def send(self, *lines: str) -> None:
        self.proc.stdin.write("".join(line + "\n" for line in lines).encode())
        self.proc.stdin.flush()

    def finish(self, timeout: float = 60) -> int:
        """Closes the input, waits for the demo to end and returns its exit code."""
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        code = self.proc.wait(timeout=timeout)
        self._reader.join(timeout=10)
        return code

    def stop(self) -> None:
        """After each test: a demo still running gets Ctrl-C, so that it stops its server too."""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self._reader.join(timeout=10)
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                stream.close()
            except OSError:
                pass

    def server(self) -> dict | None:
        """The server's process id and the OMEGA_CONNECT_ settings it got; None if it never started."""
        lines = self.graph_log.read_text().splitlines() if self.graph_log.exists() else []
        return json.loads(lines[0]) if lines else None

    def graph(self) -> list[str]:
        """The Graph requests so far, as "METHOD path"."""
        return self.graph_log.read_text().splitlines()[1:] if self.graph_log.exists() else []

    def leftovers(self) -> list[str]:
        """What the demo left behind: its temporary folder, or anything in the operator's store."""
        left = [path.name for path in self.temp.iterdir() if path.name.startswith("omega-connect-demo-")]
        return left + (["the operator's store"] if self.operator_store.exists() else [])


@pytest.fixture
def platform():
    _IdentityPlatform.state = state = SimpleNamespace(pending=1, refuse={}, requests=[])
    server = ThreadingHTTPServer(("127.0.0.1", 0), _IdentityPlatform)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state.url = f"http://127.0.0.1:{server.server_port}"
    yield state
    server.shutdown()
    server.server_close()


@pytest.fixture
def start(platform, tmp_path):
    """Starts demo.py and sends it the given lines; after the test, stops it if it still runs."""
    runs = []

    def start(*lines: str) -> DemoRun:
        runs.append(DemoRun(platform, tmp_path))
        if lines:
            runs[-1].send(*lines)
        return runs[-1]

    yield start
    for run in runs:
        run.stop()


# ------------------------------------------------------------------ the demo

def test_the_demo_reads_the_channel_and_posts_only_after_a_yes(start, platform):
    run = start()
    run.expect("Tenant ID (Directory ID): ")
    run.send("organizations")  # a single-tenant app needs its tenant id
    run.expect("does not accept 'organizations'")
    run.send(TENANT, "not-a-guid", CLIENT_ID)
    run.expect("Give the Application (client) ID")
    run.expect("Code    ABCD-1234")
    run.expect("Which team? [1-2]: ")
    run.send("1")
    run.expect("the only channel: General")
    run.expect("  > ")
    run.send("")  # the default text
    run.expect("Approve the post? (y/n): ")
    reads = ["GET /me/joinedTeams", f"GET /teams/{TEAM}/channels", f"GET /teams/{TEAM}/channels/{CHANNEL}/messages"]
    assert run.graph() == reads  # the mind waits, and nothing is posted
    run.send("maybe", "y")  # anything but y or n asks again
    assert run.finish() == 0
    assert run.graph() == reads + [f"POST /teams/{TEAM}/channels/{CHANNEL}/messages"]

    out = run.output
    for shown in ("Open    https://microsoft.com/devicelogin", f"Sign-in: oauth-device (signed in as {ACCOUNT})",
                  "read:  list_channels, list_teams, read_channel_messages", "write: post_channel_message",
                  "Hi Bob, the demo is at 3pm", "The host answers approval_required: request apr-1",
                  "text     Test message from omega-connect", "with the same key and approval_id apr-1",
                  f"Posted in Teams as {ACCOUNT}", "approved by user:operator", "✓ No token", "Demo complete."):
        assert shown in out, shown
    for hidden in (TOKEN, REFRESH, ID_TOKEN, DEVICE_CODE, TENANT, CLIENT_ID, SHELL_KEY):
        assert hidden not in out
    assert not re.search(r"[A-Za-z0-9_-]{43}=", out)  # nor the Fernet key of the run
    path, form = platform.requests[0]
    assert (path, form["client_id"], form["scope"]) == (
        f"/{TENANT}/oauth2/v2.0/devicecode", CLIENT_ID, " ".join(SCOPES + ["openid", "profile", "offline_access"]))
    assert run.server()["settings"] == []  # not even the key in the operator's shell
    assert run.leftovers() == []


def test_a_no_posts_nothing_and_message_text_cannot_drive_the_terminal(start):
    run = start(TENANT, CLIENT_ID, "2", "1", "Hello", "n")
    assert run.finish() == 0
    out = run.output
    assert "Eve evil" in out and "line 31mtwo" in out  # the text stays, without its controls
    assert "\x9b" not in out and "\u202e" not in out
    assert "Not approved" in out and "No use-tool call in the trace" in out
    assert run.graph()[-1] == f"GET /teams/{OTHER_TEAM}/channels/{PRIVATE}/messages"
    assert not [request for request in run.graph() if request.startswith("POST")]
    assert run.leftovers() == []


@pytest.mark.parametrize("refuse, says", [
    ({"devicecode": {"error": "invalid_client", "error_description": "AADSTS7000218: The request body must "
                     "contain the following parameter: 'client_assertion' or 'client_secret'."}},
     "✗ connect: error. AADSTS7000218"),
    ({"token": {"error": "authorization_declined", "error_description": "The end user declined the sign-in."}},
     "✗ Sign-in failed: The end user declined the sign-in."),
], ids=["public-client-flows-off", "declined"])
def test_a_failed_sign_in_stops_the_demo_and_cleans_up(start, platform, refuse, says):
    platform.refuse = refuse
    run = start(TENANT, CLIENT_ID)
    assert run.finish() == 1
    assert says in run.output and "If something fails" in run.output
    assert run.output.rstrip().endswith("Server stopped; temporary store, token and key deleted.")
    assert run.graph() == [] and run.leftovers() == []


def test_ctrl_c_stops_the_server_and_deletes_the_store(start, platform):
    platform.pending = 10 ** 6  # nobody signs in
    run = start(TENANT, CLIENT_ID)
    run.expect("the demo goes on by itself.")
    run.proc.send_signal(signal.SIGINT)
    assert run.finish() == 130
    assert "Interrupted." in run.output
    with pytest.raises(ProcessLookupError):
        os.kill(run.server()["pid"], 0)
    assert run.leftovers() == []


def test_closing_the_input_stops_the_demo(start):
    run = start(TENANT)  # the input ends before the client ID
    assert run.finish() == 1
    assert run.output.rstrip().endswith("Demo stopped.")
    assert run.server() is None and run.leftovers() == []


if __name__ == "__main__":  # demo.py starts this file in place of server.py (see RUNNER)
    serve_with_fake_graph(sys.argv[1:])
