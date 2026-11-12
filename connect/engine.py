"""MCP connection engine for omega-connect.

Holds one live MCP session per (swarm, server) and lets synchronous or async
callers use it. No knowledge of the hive: program.py decides who may do what,
the store keeps configuration and secrets, this module only talks MCP.

Threading model. The hive calls act() on its own event loop, and the checker
may call it on a fresh one. MCP transports use anyio cancel scopes, which must
be entered and exited by the same task, so sessions cannot be shared across
those loops. The engine therefore runs one private event loop in a daemon
thread. Each server gets a long-lived task there that owns its transport and
ClientSession; callers hand work to it through a queue. A dropped connection is
noticed on the next call and reopened.

Classification. A tool is "read" only when the server marks it with the
readOnlyHint annotation and the owner has not reclassed it; everything else is
"write". The owner can also hide a tool.

Works with the MCP Python SDK 1.x (camelCase fields, streamablehttp_client)
and 2.x (snake_case fields, streamable_http_client).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
import threading
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

logger = logging.getLogger("omega_connect.engine")

DEFAULT_TIMEOUT = 60.0
CONNECT_TIMEOUT = 30.0
STOP_GRACE = 10.0  # seconds a closing session gets to finish the call it is running
MAX_RESULT_CHARS = 8000
MAX_DESCRIPTION_CHARS = 300
_CONNECTION_CLOSED = -32000  # JSON-RPC code the SDK uses for a dropped connection
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class EngineError(RuntimeError):
    """A failure that is safe to show: never carries credentials."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


# ----------------------------------------------------------------- helpers

def attr(obj: Any, *names: str, default: Any = None) -> Any:
    """Read a field that is snake_case in SDK 2.x and camelCase in 1.x."""
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


def clean_text(text: Any, limit: int) -> str:
    text = _CONTROL_CHARS.sub("", str(text or "")).strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def describe_exception(exc: BaseException, secrets: tuple[str, ...] = ()) -> str:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    text = clean_text(f"{exc.__class__.__name__}: {exc or ''}", 300)
    return redact(text, secrets)


def redact(text: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "[redacted]")
    return text


def is_connection_lost(exc: BaseException) -> bool:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    if getattr(getattr(exc, "error", None), "code", None) == _CONNECTION_CLOSED:
        return True
    return exc.__class__.__name__ in ("ClosedResourceError", "BrokenResourceError", "EndOfStream") \
        or isinstance(exc, (ConnectionError, EOFError))


# ----------------------------------------------------------------- data

@dataclass
class ServerSpec:
    """How to reach one server. Secrets are not stored here: `auth_headers`
    is filled in by the caller just before connecting and never persisted."""

    name: str
    transport: str = "http"
    url: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    connect_timeout: float = CONNECT_TIMEOUT
    auth_headers: dict[str, str] = field(default_factory=dict, repr=False)

    def secrets(self) -> tuple[str, ...]:
        values = []
        for value in self.auth_headers.values():
            values.append(value)
            if " " in value:  # "Bearer abc" -> also "abc"
                values.append(value.split(" ", 1)[1])
        return tuple(values)


@dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict
    read_only_hint: bool
    destructive_hint: bool


# ----------------------------------------------------------------- transports

def _open_transport(spec: ServerSpec, stderr_dir: str | None):
    if spec.transport == "stdio":
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(command=spec.command, args=list(spec.args))
        return stdio_client(params, errlog=_stderr_file(spec.name, stderr_dir))

    from mcp.client import streamable_http as sh

    headers = dict(spec.auth_headers)
    if hasattr(sh, "streamable_http_client"):
        fn = sh.streamable_http_client
        if "headers" in inspect.signature(fn).parameters:  # late 1.x
            return fn(spec.url, headers=headers)
        from mcp.shared._httpx_utils import create_mcp_http_client

        return fn(spec.url, http_client=create_mcp_http_client(headers=headers))
    return sh.streamablehttp_client(spec.url, headers=headers)  # 1.x


_STDERR: dict[str, Any] = {}


def _stderr_file(name: str, directory: str | None):
    handle = _STDERR.get(name)
    if handle is None or handle.closed:
        import tempfile

        directory = directory or os.path.join(tempfile.gettempdir(), "omega-connect")
        os.makedirs(directory, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        handle = open(os.path.join(directory, f"{safe}.stderr.log"), "a", encoding="utf-8")
        _STDERR[name] = handle
    return handle


async def _list_all_tools(session) -> list:
    tools: list = []
    cursor = None
    params = inspect.signature(session.list_tools).parameters
    for _ in range(50):
        if cursor is None:
            result = await session.list_tools()
        elif "params" in params:
            from mcp import types

            result = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor))
        else:
            result = await session.list_tools(cursor=cursor)
        tools.extend(attr(result, "tools", default=[]) or [])
        cursor = attr(result, "next_cursor", "nextCursor")
        if not cursor:
            break
    return tools


# ----------------------------------------------------------------- worker

class _Worker:
    def __init__(self, spec: ServerSpec, stderr_dir: str | None):
        self.spec = spec
        self.stderr_dir = stderr_dir
        self.tools: dict[str, ToolInfo] = {}
        self.server_info = ""
        self.last_error: str | None = None
        self._queue: asyncio.Queue | None = None
        self._task: asyncio.Task | None = None
        self._ready: asyncio.Future | None = None
        self._stopping = False  # set by stop(): this worker takes no more calls and never reconnects

    @property
    def connected(self) -> bool:
        return (not self._stopping and self._task is not None and not self._task.done()
                and self._ready is not None and self._ready.done() and self._ready.exception() is None)

    async def ensure_connected(self) -> None:
        if self._stopping:
            raise EngineError("connection", self._closed_message())
        if self.connected:
            return
        if self._task is None or self._task.done():
            loop = asyncio.get_running_loop()
            self._queue = asyncio.Queue()
            self._ready = loop.create_future()
            self._task = loop.create_task(self._run())
        try:
            await asyncio.wait_for(asyncio.shield(self._ready), timeout=self.spec.connect_timeout)
        except asyncio.TimeoutError:
            raise EngineError("connection", f"server '{self.spec.name}' is still starting "
                                            f"(no answer within {int(self.spec.connect_timeout)} s)")

    async def submit(self, fn: Callable[[Any], Awaitable[Any]]) -> Any:
        await self.ensure_connected()
        if self._stopping:  # stop() came while this call waited for the session
            raise EngineError("connection", self._closed_message())
        future = asyncio.get_running_loop().create_future()
        await self._queue.put((fn, future))
        return await future

    async def stop(self) -> None:
        self._stopping = True
        if self._task and not self._task.done():
            await self._queue.put(None)
            try:
                await asyncio.wait_for(self._task, timeout=STOP_GRACE)
            except Exception:
                self._task.cancel()

    async def _run(self) -> None:
        from mcp import ClientSession

        secrets = self.spec.secrets()
        try:
            async with _open_transport(self.spec, self.stderr_dir) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    init = await session.initialize()
                    info = attr(init, "server_info", "serverInfo")
                    self.server_info = clean_text(
                        f"{attr(info, 'name', default='?')} {attr(info, 'version', default='')}", 120)
                    await self._refresh_tools(session)
                    self.last_error = None
                    if not self._ready.done():
                        self._ready.set_result(True)
                    while True:
                        item = await self._queue.get()
                        if item is None:
                            self._fail_queued(self._closed_message())  # now, not after the session closes
                            break
                        fn, future = item
                        if future.cancelled():
                            continue
                        try:
                            future.set_result(await fn(session))
                        except asyncio.CancelledError:
                            # The session is being cut (stop ran out of grace): this call may
                            # already have reached the server, so its caller hears it now.
                            if not future.done():
                                future.set_exception(EngineError(
                                    "connection", f"the session with '{self.spec.name}' closed while this call "
                                                  "was running; it may already have taken effect"))
                            raise
                        except Exception as exc:
                            if not future.done():
                                future.set_exception(exc)
                            if is_connection_lost(exc):
                                raise
        except BaseException as exc:  # noqa: BLE001
            message = describe_exception(exc, secrets)
            self.last_error = message
            logger.warning("MCP server '%s' stopped: %s", self.spec.name, message)
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(EngineError("connection", message))
            self._fail_queued(message)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise

    def _fail_queued(self, message: str) -> None:
        """Fail every call still waiting in the queue; none of them went out."""
        while self._queue is not None and not self._queue.empty():
            pending = self._queue.get_nowait()
            if pending and not pending[1].done():
                pending[1].set_exception(EngineError("connection", message))

    def _closed_message(self) -> str:
        return f"the session with '{self.spec.name}' closed before this call went out; try again"

    async def _refresh_tools(self, session) -> None:
        tools = {}
        for tool in await _list_all_tools(session):
            name = str(attr(tool, "name", default=""))
            if not name:
                continue
            ann = attr(tool, "annotations")
            schema = attr(tool, "input_schema", "inputSchema", default={}) or {}
            if hasattr(schema, "model_dump"):
                schema = schema.model_dump()
            tools[name] = ToolInfo(
                name=name,
                description=clean_text(attr(tool, "description", default=""), MAX_DESCRIPTION_CHARS),
                input_schema=dict(schema),
                read_only_hint=bool(attr(ann, "read_only_hint", "readOnlyHint", default=False)) if ann else False,
                destructive_hint=bool(attr(ann, "destructive_hint", "destructiveHint", default=False)) if ann else False,
            )
        self.tools = tools


# ----------------------------------------------------------------- engine

@dataclass
class CallOutcome:
    ok: bool
    text: str
    truncated: bool
    structured: Any = None


class McpEngine:
    """One instance per process. Keys are (swarm_id, server_name)."""

    def __init__(self, stderr_dir: str | None = None):
        self.stderr_dir = stderr_dir
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._workers: dict[tuple[str, str], _Worker] = {}
        self._lock = threading.Lock()

    # -- loop plumbing
    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is None:
                loop = asyncio.new_event_loop()
                thread = threading.Thread(target=loop.run_forever, name="omega-connect-mcp", daemon=True)
                thread.start()
                self._loop, self._thread = loop, thread
            return self._loop

    def _future(self, coro: Awaitable[Any]):
        return asyncio.run_coroutine_threadsafe(coro, self._ensure_loop())

    def run_sync(self, coro: Awaitable[Any], timeout: float) -> Any:
        future = self._future(coro)
        try:
            return future.result(timeout=timeout)
        except FutureTimeout:
            future.cancel()
            raise EngineError("timeout", f"no answer within {int(timeout)} s")

    async def run_async(self, coro: Awaitable[Any], timeout: float) -> Any:
        try:
            return await asyncio.wait_for(asyncio.wrap_future(self._future(coro)), timeout=timeout)
        except asyncio.TimeoutError:
            raise EngineError("timeout", f"no answer within {int(timeout)} s")

    # -- workers
    def worker(self, swarm: str, spec: ServerSpec) -> _Worker:
        key = (swarm, spec.name)
        with self._lock:
            worker = self._workers.get(key)
            if worker is None or _spec_changed(worker.spec, spec):
                old = worker
                worker = _Worker(spec, self.stderr_dir)
                self._workers[key] = worker
            else:
                old = None
                worker.spec.auth_headers = spec.auth_headers  # refreshed credentials
        if old is not None:
            self._future(old.stop())
        return worker

    def peek(self, swarm: str, name: str) -> _Worker | None:
        return self._workers.get((swarm, name))

    def forget(self, swarm: str, name: str) -> None:
        with self._lock:
            worker = self._workers.pop((swarm, name), None)
        if worker is not None:
            self._future(worker.stop())

    async def connect(self, swarm: str, spec: ServerSpec) -> _Worker:
        worker = self.worker(swarm, spec)
        await self.run_async(worker.ensure_connected(), spec.connect_timeout + 5)
        return worker

    async def call(self, swarm: str, spec: ServerSpec, tool: str, arguments: dict,
                   retry_on_drop: bool) -> CallOutcome:
        worker = await self.connect(swarm, spec)
        timeout = spec.timeout

        async def invoke(session):
            return await asyncio.wait_for(session.call_tool(tool, arguments), timeout=timeout)

        try:
            result = await self.run_async(worker.submit(invoke), timeout + 5)
        except Exception as exc:
            if not (retry_on_drop and is_connection_lost(exc)):
                raise
            worker = await self.connect(swarm, spec)
            result = await self.run_async(worker.submit(invoke), timeout + 5)
        return render_result(result)

    def shutdown(self) -> None:
        with self._lock:
            workers = list(self._workers.values())
            self._workers.clear()
            loop = self._loop
            self._loop = None
        if loop is None:
            return
        for worker in workers:
            try:
                asyncio.run_coroutine_threadsafe(worker.stop(), loop).result(timeout=15)
            except Exception:
                pass
        loop.call_soon_threadsafe(loop.stop)


def _spec_changed(old: ServerSpec, new: ServerSpec) -> bool:
    return (old.transport, old.url, old.command, tuple(old.args)) != \
        (new.transport, new.url, new.command, tuple(new.args))


def render_result(result: Any) -> CallOutcome:
    parts: list[str] = []
    for block in attr(result, "content", default=[]) or []:
        kind = attr(block, "type", default="")
        if kind == "text":
            parts.append(str(attr(block, "text", default="")))
        elif kind in ("image", "audio"):
            parts.append(f"[{kind} {attr(block, 'mime_type', 'mimeType', default='')} omitted]")
        elif kind == "resource":
            resource = attr(block, "resource")
            text = attr(resource, "text")
            parts.append(str(text) if text is not None else f"[resource {attr(resource, 'uri', default='')}]")
        elif kind == "resource_link":
            parts.append(f"[link {attr(block, 'uri', default='')}]")
        else:
            parts.append(f"[{kind or 'unknown'} content omitted]")
    structured = attr(result, "structured_content", "structuredContent")
    if not parts and structured is not None:
        parts.append(json.dumps(structured, ensure_ascii=False, default=str))
    text = _CONTROL_CHARS.sub("", "\n".join(parts))
    truncated = len(text) > MAX_RESULT_CHARS
    if truncated:
        text = text[:MAX_RESULT_CHARS] + "\n...[truncated]"
    is_error = bool(attr(result, "is_error", "isError", default=False))
    return CallOutcome(ok=not is_error, text=text, truncated=truncated)
