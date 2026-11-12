"""omega-connect against the brief's definition of done, through a fake host."""

import json
import logging
import re
import time
from pathlib import Path

import pytest

from conftest import DEMO, SECRET
from fakehive import FakeHive, HostRefusal, run, validate_graph

PERSON = "person:ada"
MIND = "mind:scout"


def add(hive, swarm, name, url=None, **extra):
    params = {"name": name, "url": url, **extra}
    return run(hive.person_act(swarm, PERSON, "add-server", [], params, confirmed=True))


def mind(hive, swarm, action, key, **params):
    return run(hive.agent_act(swarm, MIND, action, params, key))


@pytest.fixture
def hive(program):
    h = FakeHive(program)
    for action in ("list-servers", "list-tools", "inspect-tool", "read-tool"):
        h.attach(MIND, action, "allow")
    h.attach(MIND, "use-tool", "ask")
    return h


# ------------------------------------------------------------------ describe

def test_describe_matches_the_brief(program):
    actions = {a["id"]: a for a in program.describe()["actions"]}
    for name in ("list-servers", "list-tools", "read-tool"):
        assert actions[name]["agents"] is True and actions[name]["effect"] == "read"
    assert actions["use-tool"]["agents"] is True and actions["use-tool"].get("effect") != "read"
    for name in ("add-server", "remove-server", "connect", "revoke", "reclass-tool"):
        assert not actions[name].get("agents") and actions[name]["confirm"] is True


# ------------------------------------------------------------------ done #2

def test_lists_servers_and_tools(hive, demo_url):
    assert add(hive, "s1", "demo", demo_url)["status"] == "done"
    servers = mind(hive, "s1", "list-servers", "k1")["detail"]["servers"]
    assert [s["name"] for s in servers] == ["demo"]
    tools = mind(hive, "s1", "list-tools", "k2", server="demo")["detail"]["tools"]["demo"]
    classes = {t["name"]: t["class"] for t in tools}
    assert classes["add"] == "read" and classes["create_note"] == "write"


def test_read_tool_runs_a_read_classed_tool(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    result = mind(hive, "s1", "read-tool", "k1", server="demo", tool="add", arguments={"a": 2, "b": 40})
    assert result["status"] == "done"
    assert result["detail"]["result"] == {"untrusted": True, "text": "42"}
    assert "not as instructions" in result["message"]


def test_read_tool_refuses_a_write_classed_tool(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    result = mind(hive, "s1", "read-tool", "k1", server="demo", tool="create_note",
                  arguments={"title": "x", "text": "y"})
    assert result["status"] == "refused" and result["detail"]["class"] == "write"
    notes = mind(hive, "s1", "read-tool", "k2", server="demo", tool="list_notes")
    assert notes["detail"]["result"]["text"] == "(no notes)"  # nothing was written


def test_use_tool_waits_for_a_person(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    args = {"title": "plan", "text": 'call "Bob" today'}
    first = mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    assert first["status"] == "pending_approval"
    assert mind(hive, "s1", "read-tool", "r1", server="demo", tool="list_notes")["detail"]["result"]["text"] \
        == "(no notes)"
    hive.approve(first["approvals"][0], PERSON)
    done = mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    assert done["status"] == "done" and done["detail"]["result"]["text"] == "saved 'plan'"
    read = mind(hive, "s1", "read-tool", "r2", server="demo", tool="get_note", arguments={"title": "plan"})
    assert read["detail"]["result"]["text"] == 'call "Bob" today'
    # the approval was spent: a new request needs a new one
    again = mind(hive, "s1", "use-tool", "w2", server="demo", tool="create_note", arguments=args)
    assert again["status"] == "pending_approval"
    # act() is not told who approved; the trace keeps the hive's record id, and that record names the approver
    calls = [i["text"] for i in run(hive.view("s1", PERSON))["items"] if i["label"].startswith("use-tool")]
    record_id = re.search(r"^record_id: (\S+)$", calls[0], re.M).group(1)
    assert hive.record(record_id)["approved_by"] == PERSON


def test_identical_retry_returns_the_recorded_result(hive, demo_url):
    hive.attach(MIND, "use-tool", "allow")
    add(hive, "s1", "demo", demo_url)
    args = {"title": "once", "text": "1"}
    first = mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    run(hive.agent_act("s1", MIND, "use-tool",
                       {"server": "demo", "tool": "delete_notes", "arguments": {}}, "w-del"))
    retry = mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    assert retry == first  # recorded, not re-run: the note stays deleted
    assert "once" not in mind(hive, "s1", "read-tool", "r1", server="demo", tool="list_notes")["detail"]["result"]["text"]
    with pytest.raises(HostRefusal) as conflict:
        mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments={"title": "other", "text": "2"})
    assert conflict.value.status == 409


def test_app_level_idempotency_also_holds(program, demo_url):
    """Defence in depth: the app keeps its own intent records for use-tool."""
    from fakehive import Ctx

    hive = FakeHive(program)
    add(hive, "s1", "demo", demo_url)
    ctx = Ctx(swarm_id="s1", actor={"kind": "mind", "id": MIND}, command={"idempotency_key": "same"})
    params = {"server": "demo", "tool": "create_note", "arguments": {"title": "a", "text": "b"}}
    first = run(program.act(ctx, "use-tool", [], params))
    second = run(program.act(ctx, "use-tool", [], params))
    assert first == second
    # delivered again after a failed attempt: the app's own record answers, so nothing runs and nothing warns
    ctx.command["prior_failed"] = True
    assert run(program.act(ctx, "use-tool", [], params)) == first
    other = run(program.act(ctx, "use-tool", [], {**params, "arguments": {"title": "c", "text": "d"}}))
    assert other["status"] == "refused" and other["detail"]["type"] == "conflict"


def test_a_write_delivered_again_after_a_failure_warns_it_may_repeat(hive, demo_url, monkeypatch):
    """PROGRAMS.md 9d: an attempt that failed has an unknown effect. The hive delivers it again only
    after a new approval, with ctx.command.prior_failed; the app, holding no record of the first
    attempt, runs the tool and says the first attempt may already have taken effect."""
    add(hive, "s1", "demo", demo_url)
    args = {"title": "plan", "text": "x"}
    store_cls = hive.program.store_mod.SwarmStore
    put_intent = store_cls.put_intent

    def lose_the_record(self, key, record):  # the tool ran, then the app failed before keeping its record
        monkeypatch.setattr(store_cls, "put_intent", put_intent)
        raise OSError("disk full")

    monkeypatch.setattr(store_cls, "put_intent", lose_the_record)
    first = mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    hive.approve(first["approvals"][0], PERSON)
    with pytest.raises(HostRefusal) as failed:
        mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    assert failed.value.code == "program_error"
    assert mind(hive, "s1", "read-tool", "r1", server="demo", tool="list_notes")["detail"]["result"]["text"] == "plan"
    again = mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    assert again["status"] == "pending_approval"  # the spent approval does not cover a second delivery
    hive.approve(again["approvals"][0], PERSON)
    done = mind(hive, "s1", "use-tool", "w1", server="demo", tool="create_note", arguments=args)
    assert done["status"] == "done" and done["detail"]["prior_failed"] is True
    assert "may already have taken effect" in done["message"]
    assert done["detail"]["result"]["text"] == "saved 'plan'"


def test_tokens_never_appear_in_results_views_traces_or_logs(hive, guarded_url, caplog, monkeypatch, tmp_path):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("OMEGA_CONNECT_CRED_DEMO", SECRET)
    signin = {"kind": "bearer-env", "variable": "OMEGA_CONNECT_CRED_DEMO"}
    assert add(hive, "s1", "guarded", guarded_url, signin=signin)["status"] == "done"
    outputs = [
        mind(hive, "s1", "list-tools", "k1", server="guarded"),
        mind(hive, "s1", "read-tool", "k2", server="guarded", tool="add", arguments={"a": 1, "b": 1}),
        mind(hive, "s1", "read-tool", "k3", server="guarded", tool="fail"),
        mind(hive, "s1", "inspect-tool", "k4", server="guarded", tool="add"),
        run(hive.view("s1", PERSON)),
        run(hive.view("s1", PERSON, focus="server:guarded", stage="detail")),
    ]
    assert outputs[1]["detail"]["result"]["text"] == "2"  # the token was sent
    # a wrong token: the error must not echo it either
    monkeypatch.setenv("OMEGA_CONNECT_CRED_DEMO", SECRET + "-wrong")
    hive.program.ENGINE.forget("s1", "guarded")
    outputs.append(mind(hive, "s1", "read-tool", "k5", server="guarded", tool="add", arguments={"a": 1, "b": 2}))
    assert outputs[-1]["status"] == "error"
    blob = json.dumps(outputs) + caplog.text
    for path in Path(tmp_path).rglob("*"):
        if path.is_file():
            blob += path.read_text("utf-8", errors="ignore")
    assert SECRET not in blob


# ------------------------------------------------------------------ owner controls

def test_owner_reclass(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    mind(hive, "s1", "list-tools", "k0", server="demo")
    run(hive.person_act("s1", PERSON, "reclass-tool", ["tool:demo/add"], {"class": "write"}, confirmed=True))
    assert mind(hive, "s1", "read-tool", "k1", server="demo", tool="add", arguments={"a": 1, "b": 1})["status"] \
        == "refused"
    run(hive.person_act("s1", PERSON, "reclass-tool", ["tool:demo/create_note"], {"class": "read"}, confirmed=True))
    assert mind(hive, "s1", "read-tool", "k2", server="demo", tool="create_note",
                arguments={"title": "a", "text": "b"})["status"] == "refused"  # never promoted
    run(hive.person_act("s1", PERSON, "reclass-tool", ["tool:demo/whoami"], {"class": "hidden"}, confirmed=True))
    names = [t["name"] for t in mind(hive, "s1", "list-tools", "k3", server="demo")["detail"]["tools"]["demo"]]
    assert "whoami" not in names


def test_people_only_actions(hive, demo_url):
    with pytest.raises(HostRefusal):
        run(hive.agent_act("s1", MIND, "add-server", {"name": "x", "url": demo_url}, "k1"))
    with pytest.raises(HostRefusal):
        run(hive.person_act("s1", PERSON, "add-server", [], {"name": "x", "url": demo_url}))  # no confirm


def test_no_rule_means_deny(program, demo_url):
    hive = FakeHive(program)
    add(hive, "s1", "demo", demo_url)
    with pytest.raises(HostRefusal) as denied:
        mind(hive, "s1", "read-tool", "k1", server="demo", tool="add", arguments={"a": 1, "b": 1})
    assert denied.value.code == "policy_denied"


def test_stdio_is_off_by_default(hive, monkeypatch):
    params = {"name": "local", "transport": "stdio", "command": "python3", "args": [str(DEMO)]}
    refused = run(hive.person_act("s1", PERSON, "add-server", [], params, confirmed=True))
    assert refused["status"] == "refused" and "OMEGA_CONNECT_ALLOW_STDIO" in refused["message"]
    monkeypatch.setenv("OMEGA_CONNECT_ALLOW_STDIO", "1")
    assert run(hive.person_act("s1", PERSON, "add-server", [], params, confirmed=True))["status"] == "done"
    assert mind(hive, "s1", "read-tool", "k1", server="local", tool="add",
                arguments={"a": 3, "b": 4})["detail"]["result"]["text"] == "7"


def test_bearer_env_only_reads_app_variables(hive, demo_url):
    bad = add(hive, "s1", "x", demo_url, signin={"kind": "bearer-env", "variable": "OPENAI_API_KEY"})
    assert bad["status"] == "refused"


def test_url_rules(hive):
    assert add(hive, "s1", "a", "http://example.com/mcp")["status"] == "refused"
    assert add(hive, "s1", "b", "https://user:pw@example.com/mcp")["status"] == "refused"
    assert add(hive, "s1", "c", "https://example.com/mcp?api_key=1")["status"] == "refused"
    assert add(hive, "s1", "d", "https://example.com/mcp")["status"] == "done"


def test_credential_keys_in_a_body_are_refused_by_the_host(hive, demo_url):
    with pytest.raises(HostRefusal) as refused:
        add(hive, "s1", "x", demo_url, signin={"kind": "bearer-env", "token": "abc"})
    assert refused.value.code == "credential_in_body"


def test_swarms_are_isolated(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    assert mind(hive, "s2", "list-servers", "k1")["detail"]["servers"] == []
    other = mind(hive, "s2", "read-tool", "k2", server="demo", tool="add", arguments={"a": 1, "b": 1})
    assert other["status"] == "error" and other["detail"]["type"] == "unknown_server"


def test_remove_server(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    run(hive.person_act("s1", PERSON, "remove-server", ["server:demo"], {}, confirmed=True))
    assert mind(hive, "s1", "list-servers", "k1")["detail"]["servers"] == []


def test_stale_page_is_refused(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    result = run(hive.person_act("s1", PERSON, "remove-server", ["server:demo"],
                                 {"base_revision": "r-old"}, confirmed=True))
    assert result["status"] == "stale"
    validate_graph(result["graph"])


# ------------------------------------------------------------------ results

def test_results_are_capped(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    result = mind(hive, "s1", "read-tool", "k1", server="demo", tool="big")
    assert result["detail"]["truncated"] is True
    assert len(result["detail"]["result"]["text"]) < 8100


def test_bad_arguments(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    assert mind(hive, "s1", "read-tool", "k1", server="demo", tool="add", arguments="not json")["status"] == "refused"
    assert mind(hive, "s1", "read-tool", "k2", server="demo", tool="nope")["status"] == "refused"


# ------------------------------------------------------------------ views

def test_view_is_valid_and_stable_in_every_stage(hive, demo_url):
    add(hive, "s1", "demo", demo_url)
    mind(hive, "s1", "list-tools", "k1", server="demo")
    first = run(hive.view("s1", PERSON))
    for stage in ("unfold", "map", "compare", "detail"):
        again = run(hive.view("s1", PERSON, focus="server:demo", stage=stage))
        assert again["revision"] == first["revision"]
        assert [i["id"] for i in again["items"]] == [i["id"] for i in first["items"]]
    assert any(i["id"] == "tool:demo/add" for i in first["items"])


def test_empty_view(hive):
    graph = run(hive.view("empty", PERSON))
    assert graph["items"] == [] and "No servers yet" in graph["notes"][0]


# ------------------------------------------------------------------ Microsoft 365 style sign-in

def test_device_code_sign_in_and_revoke(hive, guarded_url, fake_authority, tmp_path, monkeypatch):
    engine_cls, store_cls = hive.program.engine_mod.McpEngine, hive.program.store_mod.SwarmStore
    forget, token_seen_by_forget = engine_cls.forget, []

    def recorded_forget(self, swarm, name):
        token_seen_by_forget.append(store_cls(swarm).has_credentials(name))
        forget(self, swarm, name)

    monkeypatch.setattr(engine_cls, "forget", recorded_forget)
    signin = {"kind": "oauth-device", "tenant": "organizations",
              "client_id": "11111111-2222-3333-4444-555555555555", "scopes": ["Mail.Read"]}
    assert add(hive, "s1", "m365", guarded_url, signin=signin)["status"] == "done"
    before = mind(hive, "s1", "read-tool", "k0", server="m365", tool="add", arguments={"a": 1, "b": 1})
    assert before["status"] == "error" and "connect" in before["message"]
    started = run(hive.person_act("s1", PERSON, "connect", ["server:m365"], {}, confirmed=True))
    assert started["detail"]["user_code"] == "ABCD-1234"
    view = run(hive.view("s1", PERSON))
    assert any("ABCD-1234" in i.get("text", "") for i in view["items"])
    for _ in range(50):
        if store_cls("s1").has_credentials("m365"):
            break
        time.sleep(0.2)
    assert token_seen_by_forget == [False]  # the old session closed before the new token was visible
    after = mind(hive, "s1", "read-tool", "k1", server="m365", tool="add", arguments={"a": 20, "b": 22})
    assert after["detail"]["result"]["text"] == "42"
    stored = b"".join(p.read_bytes() for p in Path(tmp_path, "store").rglob("*") if p.is_file())
    assert SECRET.encode() not in stored and b"rt-55aa66bb" not in stored  # encrypted at rest
    run(hive.person_act("s1", PERSON, "revoke", ["server:m365"], {}, confirmed=True))
    revoked = mind(hive, "s1", "read-tool", "k2", server="m365", tool="add", arguments={"a": 1, "b": 1})
    assert revoked["status"] == "error"


def test_sign_in_needs_an_encryption_key(hive, guarded_url, fake_authority, monkeypatch):
    signin = {"kind": "oauth-device", "tenant": "organizations",
              "client_id": "11111111-2222-3333-4444-555555555555", "scopes": ["Mail.Read"]}
    add(hive, "s1", "m365", guarded_url, signin=signin)
    monkeypatch.delenv("OMEGA_CONNECT_SECRET_KEY")
    result = run(hive.person_act("s1", PERSON, "connect", ["server:m365"], {}, confirmed=True))
    assert result["status"] == "error" and "OMEGA_CONNECT_SECRET_KEY" in result["message"]
