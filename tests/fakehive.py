"""A small stand-in for the OmegaHive host, for offline tests.

It follows program contract 0.2 as described publicly (omegahive-schematics,
06-apps/01-programs-contract.md) and in hive/PROGRAMS.md (omegahive 04fc3f2):

- describe() is called synchronously; view() and act() may be async.
- Minds act only through actions marked "agents": true, and only under an
  explicit rule for program:<id>:<action>. No rule means deny.
- On "ask" the host files an approval bound to the exact request and redeems
  it once, just before calling act(). act() is not told who approved: it gets
  the host's record of the act (ctx.command.record_id), and that record knows.
- A mind sends an idempotency key: an identical retry returns the recorded
  result, a different request under the same key is refused (409).
- If act() raises, the effect is unknown. A retry under the same key is
  delivered again, after a new approval on "ask", with the same record_id and
  ctx.command.prior_failed.
- "effect": "read" actions store only a digest, never the content, and re-run
  on a repeat.
- People's "confirm": true actions need a host confirmation.
- Bodies naming an identity or carrying credential-like keys are refused.

Views and results are checked with validate_graph and validate_result below;
test_contract.py passes the hive's own (hive/core/programs.py) instead when the
contract copy sits next to this repository.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from dataclasses import dataclass, field
from typing import Any

APP_ID = "omega-connect"
FORBIDDEN_KEYS = {"principal", "actor", "swarm_id", "agent_id", "member_id"}
CREDENTIAL_LIKE = re.compile(r"(token|secret|password|api[_-]?key|credential|authorization)", re.I)


def canonical(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class Ctx:
    swarm_id: str
    actor: dict
    command: dict = field(default_factory=dict)
    read_only: bool = False


class HostRefusal(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


def _check_body(params: dict) -> None:
    def walk(value, top=True):
        if isinstance(value, dict):
            for key, inner in value.items():
                if top and key in FORBIDDEN_KEYS:
                    raise HostRefusal(400, "identity_in_body")
                if CREDENTIAL_LIKE.search(str(key)):
                    raise HostRefusal(400, "credential_in_body")
                walk(inner, False)
        elif isinstance(value, list):
            for inner in value:
                walk(inner, False)
    walk(params)


class FakeHive:
    def __init__(self, program, checks=None):
        self.program = program
        self.descriptor = program.describe()
        assert not inspect.iscoroutine(self.descriptor), "describe() must be synchronous"
        self.actions = {a["id"]: a for a in self.descriptor["actions"]}
        # (graph check, result check): this file's own unless a test passes the hive's
        self.check_graph, self.check_result = checks or (validate_graph, validate_result)
        self.rules: dict[tuple[str, str], str] = {}
        self.approvals: dict[str, dict] = {}
        self.records: dict[tuple[str, str], dict] = {}
        self._approval_seq = 0

    # ---------------------------------------------------------------- policy
    def attach(self, mind: str, action: str, mode: str) -> None:
        assert mode in ("allow", "ask", "deny")
        self.rules[(mind, f"program:{APP_ID}:{action}")] = mode

    def approve(self, approval_id: str, person: str) -> None:
        self.approvals[approval_id]["state"] = "approved"
        self.approvals[approval_id]["by"] = person

    def pending(self) -> list[dict]:
        return [a for a in self.approvals.values() if a["state"] == "pending"]

    def record(self, record_id: str) -> dict:
        """The host's own record of a mind's act, including who approved it."""
        return next(r for r in self.records.values() if r["id"] == record_id)

    # ---------------------------------------------------------------- routes
    async def view(self, swarm: str, person: str, focus=None, stage="unfold") -> dict:
        ctx = Ctx(swarm_id=swarm, actor={"kind": "person", "id": person})
        graph = await _maybe_await(self.program.view(ctx, focus, stage))
        self.check_graph(graph)
        return graph

    async def agent_act(self, swarm: str, mind: str, action: str, params: dict, key: str) -> dict:
        _check_body(params)
        spec = self.actions.get(action)
        if spec is None or not spec.get("agents"):
            raise HostRefusal(403, "not_for_agents")
        mode = self.rules.get((mind, f"program:{APP_ID}:{action}"))
        if mode in (None, "deny"):
            raise HostRefusal(403, "policy_denied")
        request = canonical({"action": action, "params": params})
        record = self.records.get((mind, key))
        if record is not None:
            if record["request"] != request:
                raise HostRefusal(409, "idempotency_conflict")
            if record["status"] == "done" and record["effect"] != "read":
                return record["result"]
        approval_by = None
        if mode == "ask":
            approval = next((a for a in self.approvals.values()
                             if a["mind"] == mind and a["request"] == request and a["state"] == "approved"), None)
            if approval is None:
                if not any(a["mind"] == mind and a["request"] == request and a["state"] == "pending"
                           for a in self.approvals.values()):
                    self._approval_seq += 1
                    aid = f"apr-{self._approval_seq}"
                    self.approvals[aid] = {"id": aid, "mind": mind, "action": action, "params": params,
                                           "request": request, "state": "pending"}
                return {"status": "pending_approval", "approvals": [a["id"] for a in self.pending()]}
            approval["state"] = "redeemed"  # once
            approval_by = approval["by"]
        if record is None:
            record = self.records[(mind, key)] = {"id": f"rec-{len(self.records) + 1}", "request": request,
                                                   "effect": spec.get("effect"), "status": None}
        command = {"idempotency_key": key, "record_id": record["id"]}
        if record["status"] == "failed":
            command["prior_failed"] = True
        record["approved_by"] = approval_by
        ctx = Ctx(swarm_id=swarm, actor={"kind": "mind", "id": mind}, command=command,
                  read_only=spec.get("effect") == "read")
        try:
            result = await _maybe_await(self.program.act(ctx, action, [], params))
        except Exception as exc:
            record["status"] = "failed"  # the effect is unknown
            raise HostRefusal(500, "program_error") from exc
        self.check_result(result)
        record["status"] = "done"
        record["result"] = {"redacted": True, "digest": canonical(result), "status": result["status"]} \
            if spec.get("effect") == "read" else result
        return result

    async def person_act(self, swarm: str, person: str, action: str, items: list, params: dict,
                         confirmed: bool = False) -> dict:
        _check_body(params)
        spec = self.actions.get(action)
        if spec is None:
            raise HostRefusal(404, "unknown_action")
        if spec.get("confirm") and not confirmed:
            raise HostRefusal(403, "confirm_required")
        ctx = Ctx(swarm_id=swarm, actor={"kind": "person", "id": person})
        result = await _maybe_await(self.program.act(ctx, action, items, params))
        self.check_result(result)
        return result


STATUSES = {"done", "started", "needs_input", "stale", "refused", "error"}


def validate_result(result: dict) -> None:
    assert isinstance(result, dict), result
    assert result.get("status") in STATUSES, result
    if result["status"] == "started":
        assert result.get("task", {}).get("id"), result
    if "graph" in result:
        validate_graph(result["graph"])
    json.dumps(result)  # must be plain JSON


def validate_graph(graph: dict) -> None:
    assert graph.get("revision"), "revision is required"
    items = graph.get("items", [])
    assert len(items) <= 400, "at most 400 items"
    ids = [item["id"] for item in items]
    assert len(ids) == len(set(ids)), "item ids must be unique"
    known = set(ids)
    assert len(graph.get("links", [])) <= 1200
    for link in graph.get("links", []):
        assert link["from"] in known and link["to"] in known, link
    for group in graph.get("groups", []):
        assert set(group["items"]) <= known, group
    focus = graph.get("focus")
    assert focus is None or focus in known
    json.dumps(graph)


def run(coro):
    return asyncio.run(coro)
