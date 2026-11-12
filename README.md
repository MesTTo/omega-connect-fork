# omega-connect: tool connections for OmegaHive

An OmegaHive app that lets the minds in a hive use outside tools through MCP
servers (Microsoft 365, Dataverse, GitHub, Slack, Notion...). Reads run under
the owner's choice of permission; every write goes through `use-tool`, which
the owner normally keeps on "ask", so a person approves each one.

Built against the "Omega tool connections: starter brief" (12 Nov 2026) and
program contract 0.2 as described in
[omegahive-schematics](https://github.com/omega-flagship/omegahive-schematics)
(`06-apps/`). Apache-2.0.

**Status: 0.1.0, first working version.** All actions work against real MCP
servers over streamable HTTP and stdio, and the offline tests pass.
`hive.programs_check` from a pre-release copy of omegahive (04fc3f2) reports it
compatible. The contract fixture is not in that copy; the omegahive repository
opens around 19–20 November.

## Actions

| Action | Minds | Effect | What it does |
|---|---|---|---|
| `list-servers` | yes | read | Servers in this swarm, their transport and status |
| `list-tools` | yes | read | Tools per server, each classed `read` or `write` |
| `inspect-tool` | yes | read | One tool's description and full input schema |
| `read-tool` | yes | read | Runs a tool only if it is classed `read` |
| `use-tool` | yes | (write) | Runs any visible tool; the owner keeps it on "ask" |
| `add-server`, `remove-server` | no | confirm | People only |
| `reclass-tool` | no | confirm | Make a tool `write` or `hidden` (never promote to `read`) |
| `connect`, `revoke` | no | confirm | OAuth device-code sign-in inside the app, and its removal |

Parameters for the tool actions: `server`, `tool`, `arguments` (a JSON object,
or a string holding one). They are also `binding_params`, so an approval binds
to the exact server, tool and arguments.

A tool is `read` only when the server marks it `readOnlyHint` **and** the owner
has not reclassed it. Everything else is `write`.

## What the app guarantees

- **Credentials stay inside the app.** Bearer tokens come from operator
  variables named `OMEGA_CONNECT_CRED_<NAME>` (a server can never be pointed
  at the hive's own secrets). OAuth tokens are encrypted at rest with Fernet
  and the key in `OMEGA_CONNECT_SECRET_KEY`; without that key the app refuses
  to store them. Tokens never appear in results, `view()`, traces, logs or
  errors: every outgoing text is scrubbed of the values tied to the server.
- **Tool output is untrusted data.** Results are capped at 8,000 characters,
  returned as `{"untrusted": true, "text": ...}` and labelled as data, not
  instructions. Server-provided descriptions are cleaned and capped too.
- **Every call is traced**: server, tool, digest of the arguments, digest of
  the result, status, actor and the hive's record id for the act
  (`ctx.command.record_id`). Content is never stored.
- **Streamable HTTP by default.** `https://` only (plain `http` for localhost),
  no credentials in URLs. stdio servers start processes on the hive's machine
  and are refused unless the operator sets `OMEGA_CONNECT_ALLOW_STDIO=1`.
- **One swarm per call.** Server lists, tokens and traces are kept per swarm.
- **Idempotency twice.** The hive records intents; the app also keeps its own
  record for `use-tool`, so a retried write returns its recorded result. The
  hive promises at most one delivery per confirm, not exactly-once effects
  (PROGRAMS.md 9d): when it delivers again an attempt that failed with an
  unknown effect (`ctx.command.prior_failed`) and the app has no record of it,
  `use-tool` runs the tool again and the result says the first attempt may
  already have taken effect (`detail.prior_failed: true`).

## Mount it in a hive

```sh
pip install -r requirements.txt              # into the hive's Python environment
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
export OMEGA_CONNECT_SECRET_KEY=<that key>    # needed only for OAuth sign-in
export HIVE_PLUGIN_DIRS=/path/to/omega-connect
```

Optional settings: `OMEGA_CONNECT_DATA_DIR` (store, default `~/.omega-connect`),
`OMEGA_CONNECT_LOG_DIR` (stderr of stdio servers), `OMEGA_CONNECT_ALLOW_STDIO=1`,
`OMEGA_CONNECT_CRED_<NAME>` (bearer tokens), `OMEGA_CONNECT_OAUTH_AUTHORITY`
(default `https://login.microsoftonline.com`).

Then attach a mind, for example `read-tool` on allow and `use-tool` on ask.

## Add a server (person, confirmed)

A GitHub-style server with a token the operator provides:

```json
{"name": "github", "url": "https://api.githubcopilot.com/mcp/",
 "signin": {"kind": "bearer-env", "variable": "OMEGA_CONNECT_CRED_GITHUB"}}
```

A Microsoft 365 server with delegated sign-in (Entra app registration,
least-privilege scopes, consent by the person who runs `connect`):

```json
{"name": "m365", "url": "https://<your Microsoft 365 MCP endpoint>",
 "signin": {"kind": "oauth-device", "tenant": "organizations",
            "client_id": "<application id>", "scopes": ["ChannelMessage.Read.All"]}}
```

`connect` returns a code and a sign-in address; the app finishes the sign-in on
its own once the person has signed in. `revoke` deletes the token.

The parameter is `signin` rather than `auth` because the host refuses request
bodies with credential-like keys.

## Tests

```sh
pip install -r requirements-dev.txt
python -m pytest -q tests        # 35 tests, mock MCP servers on localhost, no outside network
```

`tests/fakehive.py` is a small stand-in for the host that follows the public
contract notes and `hive/PROGRAMS.md`: agent flag, no default allow, approvals
bound to the exact request and redeemed once, idempotency keys, the hive's
record id in `ctx.command` (never the approver), failed attempts delivered
again with `prior_failed`, read actions stored as digests only, confirm for
people's actions, refusal of identity and credential keys.

`tests/test_contract.py` runs the app through the same fake host with the
hive's own `validate_graph` and `validate_result` (`hive/core/programs.py`)
when the contract copy `../omegahive-app-contract-04fc3f2` sits next to this
repository; otherwise it is skipped.

Coverage against the brief's definition of done:

| Done item | Tests |
|---|---|
| Listing servers and tools | `test_lists_servers_and_tools` |
| A read-classed tool through `read-tool` | `test_read_tool_runs_a_read_classed_tool` |
| A write-classed tool refused through `read-tool` | `test_read_tool_refuses_a_write_classed_tool` |
| `use-tool` waiting for approval | `test_use_tool_waits_for_a_person` |
| An identical retry returning the recorded result | `test_identical_retry_returns_the_recorded_result`, `test_app_level_idempotency_also_holds` |
| Tokens never in results, views or logs | `test_tokens_never_appear_in_results_views_traces_or_logs`, `test_device_code_sign_in_and_revoke` |
| `programs_check` passes | COMPATIBLE with the pre-release copy: `cd ../omegahive-app-contract-04fc3f2 && python -m hive.programs_check ../omega-connect`. It sees only an empty view, so `test_contract.py` checks fuller views and every result with the hive's validators |
| Live demo: read a Teams channel, then a write a person approves | to do on a scratch hive |

## Open points for the flagship team

Checked against `hive/PROGRAMS.md` in the pre-release copy of omegahive
(04fc3f2): sections 1–5, "Read actions" and 9d.

1. **Settled: `use-tool` declares no effect.** The contract defines only
   `"effect": "read"`, for actions that change nothing and are safe to repeat;
   anything else keeps the ordinary contract, which is what a write needs.
   `USE_TOOL_EFFECT` in `program.py` stays `None`.
2. `applies_to` for actions that do not target an item (`list-servers`,
   `add-server`): currently `["server"]`. The contract shows `applies_to` only
   as a list of kinds and says nothing about actions without an item.
3. **Settled: `act()` is not told who approved.** `ctx.command` carries the
   request identity: `idempotency_key`, `record_id`, and `prior_failed` when a
   failed attempt is delivered again. Traces now keep `record_id`, which ties
   each call to the hive's own record of the act. Still to confirm: that this
   record names the person who approved a mind's act on "ask" (the contract
   does not describe the "ask" flow).
4. Microsoft 365 consent per person: today a server uses the token of the
   person who last ran `connect`. Choosing a token per acting mind needs to
   know which person a mind acts for, and the contract does not say. Section
   9d mentions an action field `approver: "person"` (only a named person may
   confirm, never the local operator password); it may suit `connect`, whose
   token belongs to whoever signs in, but the copy does not define it further.
5. The mind skill for native Omega minds (brief, "a second, smaller piece").
6. Failed writes delivered again: section 9d describes `prior_failed` for acts
   a person confirms in the host. `use-tool` reaches the app through a mind's
   "ask" approval; the app and `tests/fakehive.py` assume the same rules there
   (a failed attempt runs again only after a new approval, with the same
   `record_id` and `prior_failed`). To confirm.

## Layout

| Path | What |
|---|---|
| `plugin.json`, `program.py` | App identity and the host program (`describe` / `view` / `act`) |
| `connect/engine.py` | MCP sessions: one long-lived task per server on a private event loop |
| `connect/store.py` | Per-swarm servers, encrypted credentials, traces, intents |
| `connect/oauth.py` | OAuth 2.0 device authorization grant (standard library only) |
| `tests/` | Fake host, mock MCP server, fake identity provider, tests |
