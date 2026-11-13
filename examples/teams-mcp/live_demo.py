"""The live Teams demo on a scratch hive: a person adds the Teams server and signs in through the browser,
a mind reads a channel and asks to post, and the person approves the post.

Needs a tenant set up as README.md says (Before the demo), with the browser sign-in's redirect address
registered. Run it where the hive runs, from this repository:

    python examples/teams-mcp/live_demo.py --tenant TENANT_ID --client-id CLIENT_ID --team "Demo team" \\
        --channel General --workdir DIR --hive-checkout OMEGAHIVE --hive-python PY --petta PETTA \\
        --swipl-bin DIR [--app-pythonpath DIR] [--answers DIR]

The hive's Python needs this app's requirements: installed, or in --app-pythonpath. The person is asked twice:
for the address their browser lands on after they sign in, and whether to approve the mind's post. Each answer
comes from the terminal, or with --answers from a file of that name in DIR (redirect_url, then approve), so
someone can relay it; the question is written beside it as <name>.question. The script never signs in itself.
It prints one VERDICT line and writes a report to the workdir.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import time

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = "omega-connect"
SCOPES = ["https://graph.microsoft.com/Team.ReadBasic.All", "https://graph.microsoft.com/Channel.ReadBasic.All",
          "https://graph.microsoft.com/ChannelMessage.Read.All", "https://graph.microsoft.com/ChannelMessage.Send"]
TEXT = "Hello from an Omega mind. A person approved this post before it was sent."
STEPS = 13


def tail(path: pathlib.Path, lines: int = 40) -> str:
    return "\n".join(path.read_text(errors="replace").splitlines()[-lines:]) if path.exists() else ""


def wait_until(proc: subprocess.Popen, check, what: str, log: pathlib.Path) -> None:
    """Poll check() until it holds; a process that exits ends the wait with its log."""
    while True:
        if proc.poll() is not None:
            raise SystemExit(f"{what} exited with {proc.returncode}:\n{tail(log)}")
        try:
            if check():
                return
        except (httpx.HTTPError, OSError):
            pass
        time.sleep(0.5)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Processes:
    """The hive, with this app in HIVE_PLUGIN_DIRS, and the Teams server beside it, both on 127.0.0.1."""

    def __init__(self, args, work: pathlib.Path):
        from cryptography.fernet import Fernet

        self.work, self.procs = work, []
        self.base, self.password = f"http://127.0.0.1:{args.hive_port}", secrets.token_urlsafe(18)
        self.teams_port = free_port()
        for folder in ("hive-data", "home", "tmp", "oc-data", "oc-logs"):
            (work / folder).mkdir(parents=True, exist_ok=True)
        path = [str(args.hive_checkout)] + ([str(args.app_pythonpath)] if args.app_pythonpath else [])
        self.env = {"HOME": str(work / "home"), "TMPDIR": str(work / "tmp"), "TZ": "UTC", "LANG": "en_US.UTF-8",
                    "PATH": f"{args.swipl_bin}:{pathlib.Path(args.hive_python).parent}:/usr/bin:/bin",
                    "PYTHONPATH": ":".join(path), "PETTA_PATH": str(args.petta),
                    "HIVE_DATA_DIR": str(work / "hive-data"), "HIVE_ADMIN_PASSWORD": self.password,
                    "HIVE_PLUGIN_DIRS": str(ROOT), "HIVE_HOST": "127.0.0.1", "HIVE_PORT": str(args.hive_port),
                    "OMEGA_CONNECT_DATA_DIR": str(work / "oc-data"), "OMEGA_CONNECT_LOG_DIR": str(work / "oc-logs"),
                    "OMEGA_CONNECT_SECRET_KEY": Fernet.generate_key().decode()}
        if os.environ.get("OMEGA_CONNECT_OAUTH_AUTHORITY"):  # a stand-in identity platform, for a rehearsal
            self.env["OMEGA_CONNECT_OAUTH_AUTHORITY"] = os.environ["OMEGA_CONNECT_OAUTH_AUTHORITY"]
        self.args = args

    def __enter__(self):
        teams_log, hive_log = self.work / "teams-mcp.log", self.work / "hive.log"
        teams = subprocess.Popen([str(self.args.hive_python), str(self.args.teams_server),
                                  "--port", str(self.teams_port)], env=self.env, cwd=str(ROOT),
                                 stdout=teams_log.open("wb"), stderr=subprocess.STDOUT)
        self.procs.append(teams)
        wait_until(teams, lambda: socket.create_connection(("127.0.0.1", self.teams_port), timeout=2).close() or True,
                   "the Teams server", teams_log)
        hive = subprocess.Popen([str(self.args.hive_python), "-m", "hive"], env=self.env,
                                cwd=str(self.args.hive_checkout), stdout=hive_log.open("wb"),
                                stderr=subprocess.STDOUT)
        self.procs.append(hive)
        # /api/health needs a session (401 without one), so any answer below 500 means the hive is serving.
        wait_until(hive, lambda: httpx.get(f"{self.base}/api/health", timeout=5).status_code < 500, "the hive",
                   hive_log)
        return self

    def __exit__(self, *exc):
        for proc in reversed(self.procs):
            proc.terminate()
            proc.wait()

    def traces(self) -> list[dict]:
        return [json.loads(line) for path in (self.work / "oc-data").rglob("trace.jsonl")
                for line in path.read_text().splitlines()]


class Session:
    """The operator acting as a person (with the host's confirm token, PROGRAMS.md 9d), and a mind acting
    through the agent route."""

    def __init__(self, procs: Processes):
        self.http = httpx.Client(base_url=procs.base, timeout=120)
        token = self.http.post("/api/auth/login", json={"password": procs.password}).json()["token"]
        self.headers = {"Authorization": f"Bearer {token}"}
        self.swarm = None
        self.actions = {}

    def app(self) -> dict | None:
        found = next((p for p in self.http.get("/api/programs", headers=self.headers).json() if p["id"] == APP), None)
        if found and found.get("enabled"):
            described = self.http.get(f"/api/programs/{APP}", headers=self.headers).json()["describe"]
            self.actions = {a["id"]: a for a in described["actions"]}
        return found

    def setup(self, swarm_name: str, mind_name: str, rules: dict) -> dict:
        """A swarm, one external member (a mind that starts no process) and its rules for the app."""
        self.swarm = self.http.post("/api/swarms", headers=self.headers, json={"name": swarm_name}).json()
        mind = self.http.post("/api/agents", headers=self.headers,
                              json={"name": mind_name, "kind": "module", "swarm_id": self.swarm["id"]}).json()
        for action, mode in rules.items():
            self.http.post("/api/policy", headers=self.headers,
                           json={"scope": f"agent:{mind['id']}", "skill": f"program:{APP}:{action}", "mode": mode})
        return mind

    def person(self, action: str, items=(), **params) -> dict:
        body = {"swarm_id": self.swarm["id"], "action": action, "items": list(items), "params": params}
        if self.actions[action].get("confirm"):
            payload = {"items": list(items), "params": params, "base_revision": None}
            text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            body["confirm_token"] = self.http.post(f"/api/programs/{APP}/confirm", headers=self.headers, json={
                "swarm_id": self.swarm["id"], "action": action, "payload": payload,
                "payload_digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest()}).json()["confirm_token"]
        return self.http.post(f"/api/programs/{APP}/act", headers=self.headers, json=body).json()

    def mind(self, mind: dict, action: str, key: str, approval_id: str | None = None, **params) -> dict:
        body = {"action": action, "items": [], "params": params, "idempotency_key": key,
                **({"approval_id": approval_id} if approval_id else {})}
        return self.http.post(f"/api/agent/programs/{APP}/act", headers={"Authorization": f"Bearer {mind['token']}"},
                              json=body).json()

    def approve(self, approval_id: str) -> int:
        return self.http.post(f"/api/approvals/{approval_id}/approve", headers=self.headers, json={}).status_code


class Steps:
    def __init__(self):
        self.rows = []

    def check(self, name: str, ok: bool, detail=None) -> bool:
        self.rows.append({"step": name, "ok": bool(ok), **({"detail": detail} if detail is not None else {})})
        print(f"{'ok  ' if ok else 'FAIL'} {name}", flush=True)
        return bool(ok)

    def verdict(self, report: pathlib.Path, **extra) -> int:
        passed = len(self.rows) == STEPS and all(row["ok"] for row in self.rows)
        report.write_text(json.dumps({"passed": passed, "steps": self.rows, **extra}, indent=1))
        print(f"VERDICT teams-live-demo {'PASS' if passed else 'FAIL'} "
              f"({sum(r['ok'] for r in self.rows)}/{STEPS} steps; report {report})", flush=True)
        return 0 if passed else 1


def ask(name: str, prompt: str, answers: pathlib.Path | None) -> str:
    print(prompt, flush=True)
    if answers is None:
        return input("> ").strip()
    question, answer = answers / f"{name}.question", answers / name
    question.write_text(prompt + "\n")
    while not answer.exists():
        time.sleep(1)
    value = answer.read_text().strip()
    answer.unlink()
    question.unlink(missing_ok=True)
    return value


def result(out: dict) -> dict:
    """The JSON a Teams tool returned, from omega-connect's untrusted text."""
    try:
        return json.loads(((out.get("detail") or {}).get("result") or {}).get("text") or "{}")
    except ValueError:
        return {}


def named(entries: list, wanted: str | None) -> dict | None:
    if wanted is None:
        return entries[0] if entries else None
    return next((e for e in entries if str(e.get("name", "")).lower() == wanted.lower()), None)


def drive(procs: Processes, args, steps: Steps, answers: pathlib.Path | None) -> None:
    s = Session(procs)
    app = s.app()
    steps.check("the hive loaded omega-connect from HIVE_PLUGIN_DIRS", app and app.get("enabled") and not app.get("error"),
                app)
    dot = s.setup("Teams demo", "Dot", {"list-servers": "allow", "list-tools": "allow", "read-tool": "allow",
                                        "use-tool": "ask"})
    signin = {"kind": "oauth-device", "tenant": args.tenant, "client_id": args.client_id, "scopes": SCOPES}
    added = s.person("add-server", name="teams", url=f"http://127.0.0.1:{procs.teams_port}/mcp", signin=signin)
    steps.check("a person adds the Teams server", added.get("status") == "done", added.get("message"))
    start = s.person("connect", ["server:teams"], flow="browser")
    if not steps.check("connect gives the person a Microsoft sign-in address", start.get("status") == "needs_input",
                       start.get("message")):
        return
    landing = ask("redirect_url", "Open this address, sign in and accept:\n\n  " + start["detail"]["authorization_url"]
                  + "\n\nThen paste the whole address your browser lands on (it starts "
                  + start["detail"]["redirect_uri"] + ").", answers)
    done = s.person("connect", ["server:teams"], redirect_url=landing)
    if not steps.check("the sign-in finishes for the person who started it", done.get("status") == "done",
                       done.get("message")):
        return
    listed = s.mind(dot, "list-tools", "demo-tools", server="teams")
    classes = {t["name"]: t["class"] for t in ((listed.get("detail") or {}).get("tools") or {}).get("teams", [])}
    steps.check("the mind lists the tools, all write until a person accepts the reads",
                classes and set(classes.values()) == {"write"}, classes)
    accepted = s.person("accept-reads", ["server:teams"])
    steps.check("the person accepts the server's reads", accepted.get("status") == "done", accepted.get("detail"))
    teams = result(s.mind(dot, "read-tool", "demo-teams", server="teams", tool="list_teams")).get("teams", [])
    team = named(teams, args.team)
    channels = result(s.mind(dot, "read-tool", "demo-channels", server="teams", tool="list_channels",
                             arguments={"team_id": team["id"]})).get("channels", []) if team else []
    channel = named(channels, args.channel)
    if not steps.check("the mind finds the team and the channel", team is not None and channel is not None,
                       {"teams": [t.get("name") for t in teams], "channels": [c.get("name") for c in channels]}):
        return
    where = {"team_id": team["id"], "channel_id": channel["id"]}
    read = s.mind(dot, "read-tool", "demo-read", server="teams", tool="read_channel_messages",
                  arguments={**where, "top": 5})
    steps.check("the mind reads the channel", read.get("status") == "done", read.get("message"))
    for message in result(read).get("messages", []):
        print(f"  {message.get('from', 'someone')}: {str(message.get('text', ''))[:200]}", flush=True)
    body = {"server": "teams", "tool": "post_channel_message", "arguments": {**where, "text": args.text}}
    waiting = s.mind(dot, "use-tool", "demo-post", **body)
    if not steps.check("the mind asks to post and waits for a person", waiting.get("status") == "approval_required",
                       waiting):
        return
    decision = ask("approve", f"\nThe mind asks to post to {team.get('name')} / {channel.get('name')}:\n\n"
                              f"  {args.text}\n\nApprove it? (yes or no)", answers)
    if not steps.check("the person approves the post", decision.lower() in ("yes", "y") and
                       s.approve(waiting["approval_id"]) == 200, decision):
        return
    posted = s.mind(dot, "use-tool", "demo-post", waiting["approval_id"], **body)
    steps.check("the post runs once, with the approval", posted.get("status") == "done" and
                "posted" in result(posted), posted.get("message"))
    again = s.mind(dot, "use-tool", "demo-post", waiting["approval_id"], **body)
    steps.check("the identical retry returns the recorded result and posts nothing more", again == posted)
    write = next((t for t in procs.traces() if t.get("action") == "use-tool" and t.get("status") == "done"), {})
    steps.check("the trace records the post and who approved it",
                write.get("tool") == "post_channel_message" and bool(write.get("approved_by")), write)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("--workdir", "--hive-checkout", "--hive-python", "--petta", "--swipl-bin", "--tenant", "--client-id"):
        parser.add_argument(name, required=True)
    parser.add_argument("--hive-port", type=int, default=8947)
    parser.add_argument("--teams-server", default=str(ROOT / "examples/teams-mcp/server.py"),
                        help="the Teams server script (default: the one beside this file)")
    parser.add_argument("--app-pythonpath", help="a folder holding this app's requirements, if the hive's Python lacks them")
    parser.add_argument("--team", help="the team's name (default: the first team you belong to)")
    parser.add_argument("--channel", default="General", help="the channel's name (default: General)")
    parser.add_argument("--text", default=TEXT, help="what the mind asks to post")
    parser.add_argument("--answers", help="a folder to read the person's answers from instead of the terminal")
    args = parser.parse_args()
    work = pathlib.Path(args.workdir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    answers = pathlib.Path(args.answers).resolve() if args.answers else None
    if answers:
        answers.mkdir(parents=True, exist_ok=True)
    steps = Steps()
    with Processes(args, work) as procs:
        try:
            drive(procs, args, steps, answers)
        except Exception as exc:  # a step that broke is a failed step, reported with the rest
            steps.check("the demo went through every step", False, f"{type(exc).__name__}: {exc}")
    sys.exit(steps.verdict(work / "teams-live-demo-report.json", tenant=args.tenant))


if __name__ == "__main__":
    main()
