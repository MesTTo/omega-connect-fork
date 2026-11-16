"""A small stand-in for the OmegaHive host, for offline tests.

It follows program contract 0.2 as described publicly (omegahive-schematics,
06-apps/01-programs-contract.md) and in hive/PROGRAMS.md (omegahive 04fc3f2),
and runs actions as hive/core/program_actions.py does at omegahive main
832b36e (a private repository until it opens; the file is unchanged since
04fc3f2). Not modelled: app attachments, template policy ceilings and
person-owned swarm setups, which can only narrow what a mind may do; host
confirm tokens, for which `confirmed` stands in; and the records the person
route keeps for actions that declare person_activity, which this app's do not.

- describe() is called synchronously; view() and act() may be async.
- A request that names who acts (principal, actor, swarm_id, agent_id,
  member_id), or carries a credential-like key (a token, secret, password, api
  key and the like, or any *_key other than the hive's own retry keys such as
  idempotency_key), at the top level of its body or of params, is refused: 400
  identity_in_request or credential_in_request. Nested keys are not looked at.
  The person route here checks the same.
- Minds act only through actions marked "agents": true (else 403
  not_for_minds), only under an explicit rule for program:<id>:<action> (none,
  or deny: 403 policy_refused), and with an idempotency key of 1 to 120
  characters (else 400 bad_request).
- On "ask" the host files an approval bound to the exact request, its
  idempotency key included, and answers approval_required with its
  approval_id. Once a person approves, the mind sends the same request again
  with that approval_id. The host redeems it once, just before calling act(),
  and passes it as ctx.actor.approval = {id, binding_digest, approved_by},
  approved_by being the approver's principal. For an action that declares
  approver "person", an approval decided with the local operator password
  (user:operator) is refused: 409 person_approval_required.
- Every act of a mind is recorded under its idempotency key; a different
  request under the same key is refused (409 idempotency_conflict). An
  identical retry of an act recorded as done gets the recorded result back,
  without act() being called, unless the action declares revalidate: true.
  Then it is a recovery: act() gets the approval the act first ran under,
  ctx.actor.recovery = True and ctx.command with revalidation_supported and
  recorded_result, and is to deliver nothing again; no new approval is asked
  for. Whatever status act() answered, the act counts as done.
- If act() raises, the act is failed and its effect unknown. An identical retry
  runs act() again, after a new approval on "ask", with the same record_id and
  no ctx.command.prior_failed.
- "effect": "read" actions store only a digest, never the content, and re-run
  on a repeat.
- The person route refuses an action that declares approver "person" to the
  local operator password (403 person_required), and a "confirm": true action
  that the person did not confirm (403 confirm_required). ctx.command carries
  their idempotency key, if any, and no record_id: nothing is recorded, so a
  person's retry calls act() again.
- ctx.actor has the hive's shape (mind_actor, person_actor); view() gets none.
- act() gets params with base_revision added, as the host sends it at the top
  level of the request (None when the caller sends none).

Views and results are checked with validate_graph and validate_result below;
test_contract.py passes the hive's own (hive/core/programs.py) instead when the
contract copy sits next to this repository.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import itertools
import json
import re
from dataclasses import dataclass, field
from typing import Any

APP_ID = "omega-connect"
IDENTITY_KEYS = {"principal", "actor", "swarm_id", "agent_id", "member_id"}
RETRY_KEYS = {"idempotency_key", "client_key", "intent_key", "receipt_key"}
CREDENTIAL_WORD = re.compile(r"token|secret|password|credential|authorization|api_?key|private_key")


def digest(value: Any) -> str:
    """sha256 of canonical JSON."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def named_person(principal: Any) -> bool:
    """A signed-in person's principal: user:<id>, but never the local operator password's user:operator."""
    return isinstance(principal, str) and principal.startswith("user:") and principal != "user:operator"


@dataclass
class Ctx:
    swarm_id: str
    actor: dict | None = None
    command: dict = field(default_factory=dict)
    read_only: bool = False


def mind_actor(swarm: str, mind: str, approval: dict | None = None) -> dict:
    """ctx.actor for a mind, as the hive's ProgramActions.mind_actor builds it."""
    return {"principal": f"agent:{mind}", "kind": "mind", "id": mind, "name": mind, "role": None,
            "local_operator": False, "member_id": mind, "swarm_id": swarm, "route": "agent", "approval": approval}


def person_actor(swarm: str, person: str) -> dict:
    """ctx.actor for a person, as the hive's ProgramActions.person_actor builds it. "operator" stands for
    the local operator password, user:operator."""
    return {"principal": f"user:{person}", "kind": "person", "id": person, "name": person, "role": "owner",
            "local_operator": person == "operator", "member_id": None, "swarm_id": swarm, "route": "operator",
            "approval": None}


class HostRefusal(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


def _credential_like(key: str) -> bool:
    name = key.lower()
    if name in RETRY_KEYS:
        return False
    return name == "key" or name.endswith("_key") or bool(CREDENTIAL_WORD.search(name))


def _check_request(body: dict, params: dict) -> None:
    """The keys of a request, as the hive checks them: the top level of the body (params aside) and of
    params."""
    keys = [key for key in (*body, *params) if isinstance(key, str)]
    if IDENTITY_KEYS.intersection(keys):
        raise HostRefusal(400, "identity_in_request")
    if any(_credential_like(key) for key in keys):
        raise HostRefusal(400, "credential_in_request")


def _check_key(key: Any, required: bool) -> None:
    if (key is not None or required) and not (isinstance(key, str) and 1 <= len(key) <= 120):
        raise HostRefusal(400, "bad_request")


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
        self.records: dict[tuple[str, str], dict] = {}  # (mind, idempotency key) -> the hive's record of the act
        self._approval_seq = 0
        self._record_ids = itertools.count(1)  # tests act on several threads at once

    # ---------------------------------------------------------------- policy
    def attach(self, mind: str, action: str, mode: str) -> None:
        assert mode in ("allow", "ask", "deny")
        self.rules[(mind, f"program:{APP_ID}:{action}")] = mode

    def approve(self, approval_id: str, person: str) -> None:
        """A person approves; the hive keeps their principal as the approver (decided_by)."""
        self.approvals[approval_id].update(state="approved", by=f"user:{person}")

    def pending(self) -> list[dict]:
        return [a for a in self.approvals.values() if a["state"] == "pending"]

    def record(self, record_id: str) -> dict:
        """The host's own record of a mind's act, including who approved it."""
        return next(r for r in self.records.values() if r["id"] == record_id)

    # ---------------------------------------------------------------- routes
    async def view(self, swarm: str, person: str, focus=None, stage="unfold") -> dict:
        ctx = Ctx(swarm_id=swarm)
        graph = await _maybe_await(self.program.view(ctx, focus, stage))
        self.check_graph(graph)
        return graph

    async def agent_act(self, swarm: str, mind: str, action: str, params: dict, key: str,
                        approval_id: str | None = None, base_revision: str | None = None,
                        items: list | None = None) -> dict:
        items = list(items or [])
        _check_request({"action": action, "items": items, "idempotency_key": key, "base_revision": base_revision,
                        "approval_id": approval_id}, params)
        _check_key(key, required=True)
        spec = self.actions.get(action)
        if spec is None:
            raise HostRefusal(400, "bad_request")
        if spec.get("agents") is not True:
            raise HostRefusal(403, "not_for_minds")
        mode = self.rules.get((mind, f"program:{APP_ID}:{action}"), "deny")
        request = digest({"action": action, "items": items, "params": params, "base_revision": base_revision})
        record = self.records.get((mind, key))
        if record is not None:
            if record["request"] != request:
                raise HostRefusal(409, "idempotency_conflict")
            if record["status"] == "running":
                raise HostRefusal(409, "in_progress")
        if mode == "deny":
            raise HostRefusal(403, "policy_refused")
        read = spec.get("effect") == "read"
        command = {"idempotency_key": key, "route": "agent", "action": action, "items": items,
                   "params_digest": request, "base_revision": base_revision}
        if record is not None and record["status"] == "done" and not read:
            recorded = json.loads(record["result"])
            if spec.get("revalidate") is not True:
                return recorded  # act() is not called again
            # A recovery: no new approval, the approval the act first ran under, and the record left as it is.
            ctx = Ctx(swarm_id=swarm, actor={**mind_actor(swarm, mind, record["approval"]), "recovery": True},
                      command={**command, "record_id": record["id"], "revalidation_supported": True,
                               "recorded_result": recorded})
            result = await self._run_app(ctx, action, items, params, base_revision)
            self.check_result(result)
            return result
        approval = None
        if mode == "ask":
            binding = {"principal": f"agent:{mind}", "actor": mind, "swarm_id": swarm, "program": APP_ID,
                       "action": action, "items": items,
                       "binding_params": {name: params.get(name) for name in spec.get("binding_params", [])},
                       "payload_digest": digest(params), "base_revision": base_revision, "idempotency_key": key}
            approval = self._approval(mind, action, binding, approval_id, spec.get("approver") == "person")
            if approval.get("pending"):
                return {"status": "approval_required", "approval_id": approval["id"],
                        "message": f"a person must approve program:{APP_ID}:{action}; "
                                   "repeat the same request with this approval_id"}
        if record is None:
            record = self.records[(mind, key)] = {"id": f"rec-{next(self._record_ids)}", "request": request}
        # A run again records who it ran as now, with its new approval: what a recovery of it gets.
        record.update(status="running", approval=approval, approved_by=approval and approval["approved_by"])
        ctx = Ctx(swarm_id=swarm, actor=mind_actor(swarm, mind, approval),
                  command={**command, "record_id": record["id"], "revalidation_supported": spec.get("revalidate") is True},
                  read_only=read)
        try:
            result = await self._run_app(ctx, action, items, params, base_revision)
        except Exception as exc:
            record["status"] = "failed"  # the effect is unknown
            raise HostRefusal(500, "program_error") from exc
        self.check_result(result)
        stored = {"redacted": "read", "digest": digest(result), "status": result.get("status")} if read else result
        record.update(status="done", result=json.dumps(stored))
        return result

    def _approval(self, mind: str, action: str, binding: dict, approval_id: str | None, person_only: bool) -> dict:
        """The open approval for this exact request (filed if there is none) while no approval_id comes;
        with one, that approval redeemed, once."""
        if approval_id is None:
            filed = next((a for a in self.approvals.values() if a["mind"] == mind and a["binding"] == binding
                          and a["state"] in ("pending", "approved")), None)
            if filed is None:
                self._approval_seq += 1
                filed = {"id": f"apr-{self._approval_seq}", "mind": mind, "action": action,
                         "params": binding["binding_params"], "binding": binding, "state": "pending", "by": None}
                self.approvals[filed["id"]] = filed
            return {"id": filed["id"], "pending": True}
        found = self.approvals.get(approval_id)
        if found is None or found["mind"] != mind or found["action"] != action:
            raise HostRefusal(409, "binding_mismatch")
        if found["state"] != "approved":
            raise HostRefusal(409, "not_approved")
        if found["binding"] != binding:
            raise HostRefusal(409, "binding_mismatch")
        if person_only and not named_person(found["by"]):
            raise HostRefusal(409, "person_approval_required")
        found["state"] = "used"
        return {"id": found["id"], "binding_digest": digest(binding), "approved_by": found["by"]}

    async def person_act(self, swarm: str, person: str, action: str, items: list, params: dict,
                         confirmed: bool = False, base_revision: str | None = None, key: str | None = None) -> dict:
        items = list(items)
        _check_request({"action": action, "items": items, "idempotency_key": key, "base_revision": base_revision},
                       params)
        actor = person_actor(swarm, person)
        spec = self.actions.get(action, {})
        if spec.get("approver") == "person" and not named_person(actor["principal"]):
            raise HostRefusal(403, "person_required")
        _check_key(key, required=False)
        if spec.get("confirm") is True and not confirmed:
            raise HostRefusal(403, "confirm_required")
        if action not in self.actions:
            raise HostRefusal(400, "bad_request")
        command = {"idempotency_key": key, "record_id": None, "route": "operator", "action": action, "items": items,
                   "params_digest": digest({"action": action, "items": items, "params": params,
                                            "base_revision": base_revision}),
                   "base_revision": base_revision}
        result = await self._run_app(Ctx(swarm_id=swarm, actor=actor, command=command), action, items, params,
                                     base_revision)
        self.check_result(result)
        return result

    async def _run_app(self, ctx: Ctx, action: str, items: list, params: dict, base_revision: str | None) -> dict:
        return await _maybe_await(self.program.act(ctx, action, items, {**params, "base_revision": base_revision}))


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
