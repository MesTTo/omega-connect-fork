# CLAUDE.md: working on omega-connect

## What this is

An OmegaHive app (program contract 0.2) that lets minds use outside tools via
MCP. Requested by Jon Grove (SingularityNET / Omega flagship) in the "Omega
tool connections: starter brief", 12 Nov 2026. Kabir and the flagship team
decide what ships. Apache-2.0. Share the repository early.

The brief, in short:
- App in its own repo, mounted through `HIVE_PLUGIN_DIRS`. Never edit the hive.
- Actions: list-servers, list-tools, read-tool (read), use-tool (write, owner
  keeps it on "ask"), and people-only confirm actions: add-server,
  remove-server, connect (OAuth inside the app).
- Streamable HTTP first; stdio off by default. One swarm per call.
  Credentials encrypted at rest, never in results / view() / logs / errors.
  Tool results are untrusted data, capped. Trace every call with digests and
  the approver. Microsoft 365: delegated OAuth, least privilege, consent per
  person, a revoke action.
- Done = programs_check passes; offline tests with a mock MCP server covering
  listing, read-tool on read, read-tool refusing write, use-tool waiting for
  approval, idempotent retry, no token leaks; live demo on a scratch hive
  (mind reads a Teams channel, asks to post, a person approves).

## Contract facts to respect

- `describe()` must be synchronous; `view()` and `act()` may be async.
- `view()` returns a full WorkGraph: `revision` (change it whenever content
  changes), items with stable unique ids, links inside the graph, at most 400
  items and 1,200 links. Stages: unfold, map, compare, detail.
- `act()` returns `{status: done|started|needs_input|stale|refused|error,
  message, detail?, graph?, task?}`. `started` needs `task.id`.
- Return `stale` (with the current graph) when `params.base_revision` is old.
- The host refuses bodies with `principal`, `actor`, `swarm_id`, `agent_id`,
  `member_id` or credential-like keys. That is why add-server takes `signin`,
  not `auth`.
- Confirm payloads are canonical JSON, integers only: no floats in params of
  confirm actions.
- Raise `PermissionError` in `view()` to refuse a swarm.
- Capabilities are not a sandbox; the app runs in the hive process.

Reference: https://github.com/omega-flagship/omegahive-schematics (06-apps),
https://github.com/omega-flagship/omega-tools (template app). The omegahive
repo (with `hive/PROGRAMS.md` and `hive.programs_check`) opens ~19–20 Nov.

## Layout and design

- `program.py`: describe / view / act. Loads `connect/*.py` by file path
  (`importlib`), because the host imports program.py by path, not as a package.
- `connect/engine.py`: MCP client. One private asyncio loop in a daemon
  thread; one long-lived task per (swarm, server) owns transport and
  ClientSession (anyio cancel scopes must stay in one task). Callers submit
  work through a queue. Dropped connections, and sessions the server forgot
  (HTTP 404 after a restart), reconnect on the next call; only read-classed
  calls are retried. Each session loads the tool list when it opens and on
  `notifications/tools/list_changed` (the reload runs in the worker's task:
  SDK 1.x calls the message handler inside its receive loop). Every tool keeps
  a digest of its definition; `call(expect=digest)` sends nothing if the
  definition changed. New auth headers mean a new session; the old one
  finishes its calls (grace = call timeout). Supports MCP SDK 1.x and 2.x:
  `mcp>=1.30,<3`, 1.30 being the lowest version tested.
- `connect/store.py`: per-swarm folder under `OMEGA_CONNECT_DATA_DIR`:
  servers.json (no secrets; the tools a person accepted as read, with the
  digest of each definition), secrets.bin (Fernet), trace.jsonl (digests),
  intents.json (app-level idempotency for use-tool). Files mode 0600.
- `connect/oauth.py`: RFC 8628 device flow, standard library only; authority
  overridable with `OMEGA_CONNECT_OAUTH_AUTHORITY` (tests use a fake). Keeps
  only `preferred_username` from the id_token, to show who signed in.
  Renewal runs in a thread under a lock per (swarm, server), in program.py.
- `examples/teams-mcp/`: MCP server over Microsoft Graph for the Teams demo,
  separate from the app. 127.0.0.1 only; each call uses the token in its own
  request's Authorization header, never stored or logged. README = demo steps.
  `demo.py` runs them on a real tenant in FakeHive (temporary store, Fernet key
  per run, the approval asked in the terminal, output filtered of tokens);
  `test_demo.py` drives it as a person would, with Graph and sign-in simulated.

Classification rule: read only if the server says `readOnlyHint`, a person
accepted that tool with `accept-reads` (people only, confirm), and its
definition digest still matches the accepted one; every tool of a new server
is write until then. The owner can demote (write, hidden, back to default),
never promote. The digest catches definition changes, not behaviour changes.
The device code goes only into the `connect` result, never into `view()`.

## Commands

```sh
pip install -r requirements-dev.txt
python -m pytest -q tests            # 52 tests, ~60 s, localhost only
python -m pytest -q examples/teams-mcp   # 30 tests, ~13 s, Graph simulated in memory
```

Contract checker, from the pre-release copy next to this repo (until omegahive
is public); `tests/test_contract.py` also uses its validators when it is there:
```sh
cd ../omegahive-app-contract-04fc3f2 && python -m hive.programs_check ../omega-connect
```

## Rules for changes

- Never put a credential in a result, view, trace, log line or error. New
  outputs that can carry server text go through `_scrub` / `engine.redact`.
- Never store tool content; traces hold digests only.
- Keep `describe()` sync and cheap. Keep `view()` deterministic: no network,
  no connecting (the checker compares two views).
- New behaviour needs a test in `tests/test_app.py` through `FakeHive`.
- Keep the brief's action names; open points are listed in README.md.

## Next steps

1. Done (12 Nov 2026): `PROGRAMS.md` and `programs_check` came as a pre-release
   copy (`../omegahive-app-contract-04fc3f2`); the checker reports COMPATIBLE.
   First review (Dot for Jon, on 8051f30) handled on branch `review-1` as
   0.2.0 (13 Nov 2026): reads reviewed by a person, definition digests,
   device code only in the connect result, locked token renewal, new session
   on a new token, `mcp>=1.30,<3`. It settled README open points 1–3 and 5;
   4 and 6 are with the flagship team. Not done from that review: checking
   `mcp`'s dependencies against the hive's pins, and the live demo.
2. Microsoft 365 showcase on a dev tenant (Microsoft 365 Developer Program):
   Entra app registration (public client, device code enabled), delegated
   scopes for reading a Teams channel, then one write (post a message) behind
   use-tool on "ask". Pick the MCP endpoint (Work IQ / Agent 365 tooling
   servers, or a Graph-based server over streamable HTTP). A Graph-based one
   is in `examples/teams-mcp/`; `demo.py` ran it on a real tenant on 13 Nov
   2026 (the channel read, a message posted once approved).
3. Scratch hive demo, recorded.
4. Optional: the mind skill for native Omega minds wrapping
   `POST /api/agent/programs/omega-connect/act` (confirm with the team first).
   A standalone MeTTa plugin that calls MCP directly from Omega core already
   exists in the separate `omega-mcp` folder and was tested end to end in Omega.
