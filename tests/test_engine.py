"""The MCP engine on its own: transports, reconnection, timeouts."""

import asyncio
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import DEMO, ROOT, free_port


@pytest.fixture
def engine(program):
    eng = program.engine_mod.McpEngine()
    yield eng
    eng.shutdown()


def spec(program, **kw):
    base = {"name": "demo", "transport": "stdio", "command": sys.executable, "args": [str(DEMO)]}
    base.update(kw)
    return program.engine_mod.ServerSpec(**base)


def call(engine, s, tool, args=None, retry=True):
    return asyncio.run(engine.call("sw", s, tool, args or {}, retry_on_drop=retry))


def test_stdio_and_tool_discovery(program, engine):
    s = spec(program)
    worker = asyncio.run(engine.connect("sw", s))
    assert worker.tools["add"].read_only_hint is True
    assert worker.tools["create_note"].read_only_hint is False
    assert call(engine, s, "add", {"a": 2, "b": 3}).text == "5"


def test_http_transport(program, engine, demo_url):
    s = spec(program, transport="http", url=demo_url, command=None, args=[])
    assert call(engine, s, "add", {"a": 20, "b": 22}).text == "42"


def test_reconnects_after_the_server_dies(program, engine):
    s = spec(program)
    try:
        call(engine, s, "crash", retry=False)
    except Exception:
        pass
    for _ in range(20):
        worker = engine.peek("sw", "demo")
        if worker is None or not worker.connected:
            break
        time.sleep(0.2)
    assert call(engine, s, "add", {"a": 1, "b": 1}).text == "2"


def test_forget_while_a_call_is_running(program, engine):
    """The call in flight finishes on the old session; a call that reaches the old worker after
    forget fails at once instead of waiting for its timeout; the next call opens a new session."""
    s = spec(program)
    old = asyncio.run(engine.connect("sw", s))
    with ThreadPoolExecutor(1) as pool:
        running = pool.submit(call, engine, s, "slow", {"seconds": 2})
        time.sleep(0.5)  # the slow call is out
        engine.forget("sw", "demo")

        async def add(session):
            return await session.call_tool("add", {"a": 1, "b": 2})

        started = time.monotonic()
        with pytest.raises(program.engine_mod.NotSent) as closed:  # it never went out
            asyncio.run(engine.run_async(old.submit(add), 10))
        assert closed.value.kind == "connection" and time.monotonic() - started < 2
        assert not old.connected
        assert running.result(timeout=10).text == "done"
    assert call(engine, s, "add", {"a": 1, "b": 2}).text == "3"
    assert engine.peek("sw", "demo") is not old


def test_a_call_running_past_the_stop_grace_fails_at_once(program, engine, monkeypatch):
    """When the session is cut, the call it was running fails right away, saying it may
    already have taken effect, instead of waiting for its own timeout."""
    monkeypatch.setattr(program.engine_mod, "STOP_GRACE", 0.5)
    s = spec(program, timeout=20)
    asyncio.run(engine.connect("sw", s))
    with ThreadPoolExecutor(1) as pool:
        running = pool.submit(call, engine, s, "slow", {"seconds": 10})
        time.sleep(0.5)  # the slow call is out
        started = time.monotonic()
        engine.forget("sw", "demo")
        with pytest.raises(program.engine_mod.OutcomeUnknown) as cut:
            running.result(timeout=15)
        elapsed = time.monotonic() - started
    assert elapsed < 5
    assert cut.value.kind == "connection" and "may already have taken effect" in cut.value.message


def test_a_call_that_finds_no_server_is_not_sent(program, engine, restartable_demo):
    """A refused connection proves the call never went out, when a session opens and also when the
    server goes away while a session is open: both SDKs then cancel the session, and only the
    transport's own error tells the two apart from a call cut once it was out."""
    eng = program.engine_mod
    nobody = spec(program, name="nobody", transport="http", url=f"http://127.0.0.1:{free_port()}/mcp",
                  command=None, args=[], timeout=5)
    with pytest.raises(eng.NotSent):
        asyncio.run(engine.connect("sw", nobody))
    with pytest.raises(eng.NotSent):
        call(engine, nobody, "add", {"a": 1, "b": 2}, retry=False)
    s = spec(program, transport="http", url=restartable_demo.url, command=None, args=[], timeout=5)
    assert call(engine, s, "add", {"a": 1, "b": 2}, retry=False).text == "3"
    restartable_demo.proc.terminate()
    restartable_demo.proc.wait(timeout=10)
    with pytest.raises(eng.NotSent) as refused:
        call(engine, s, "add", {"a": 1, "b": 2}, retry=False)
    assert "could not be reached" in refused.value.message and "did not go out" in refused.value.message
    restartable_demo.restart()
    assert call(engine, s, "add", {"a": 2, "b": 2}, retry=False).text == "4"  # a new session


def test_a_call_cut_once_it_was_out_has_an_unknown_outcome(program, engine, demo_url):
    """The server takes the call and dies before it answers: the call may have taken effect. SDK 2.x says
    the stream ended without a response; 1.x says nothing, and the call runs out of time."""
    s = spec(program, transport="http", url=demo_url, command=None, args=[], timeout=2)
    assert call(engine, s, "add", {"a": 1, "b": 2}, retry=False).text == "3"
    with pytest.raises(program.engine_mod.OutcomeUnknown) as cut:
        call(engine, s, "crash", retry=False)
    assert cut.value.kind in ("connection", "timeout")


def test_a_call_goes_out_only_on_the_definition_it_was_checked_against(program, engine):
    """With `expect`, nothing is sent unless the session still has that definition of the tool."""
    s = spec(program)
    worker = asyncio.run(engine.connect("sw", s))
    with pytest.raises(program.engine_mod.EngineError) as changed:
        asyncio.run(engine.call("sw", s, "create_note", {"title": "a", "text": "b"}, retry_on_drop=False,
                                expect="sha256:" + "0" * 64))
    assert changed.value.kind == "tool_changed"
    assert call(engine, s, "list_notes").text == "(no notes)"
    digest = worker.tools["create_note"].digest
    assert digest.startswith("sha256:") and digest != worker.tools["delete_notes"].digest
    assert asyncio.run(engine.call("sw", s, "create_note", {"title": "a", "text": "b"}, retry_on_drop=False,
                                   expect=digest)).text == "saved 'a'"


def test_call_timeout(program, engine):
    s = spec(program, timeout=1)
    with pytest.raises(program.engine_mod.OutcomeUnknown) as late:
        call(engine, s, "slow", {"seconds": 5})
    assert late.value.kind == "timeout" and "within 1 s" in late.value.message


def test_tool_error_is_not_a_crash(program, engine):
    outcome = call(engine, spec(program), "fail")
    assert outcome.ok is False


def test_slow_start_reports_then_recovers(program, engine, tmp_path):
    slow = tmp_path / "slow.py"
    slow.write_text(f"import time, runpy\ntime.sleep(3)\nrunpy.run_path({str(DEMO)!r}, run_name='__main__')\n")
    s = spec(program, name="slow", args=[str(slow)], connect_timeout=1)
    with pytest.raises(program.engine_mod.EngineError) as starting:
        asyncio.run(engine.connect("sw", s))
    assert "still starting" in starting.value.message
    time.sleep(4)
    assert call(engine, s, "add", {"a": 1, "b": 2}).text == "3"


def test_secrets_are_redacted_from_errors(program):
    eng = program.engine_mod
    s = eng.ServerSpec(name="x", auth_headers={"Authorization": "Bearer abcdef123"})
    text = eng.redact("failed with Bearer abcdef123 (token abcdef123)", s.secrets())
    assert "abcdef123" not in text and "[redacted]" in text
