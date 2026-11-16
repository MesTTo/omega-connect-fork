"""The fake host runs actions as hive/core/program_actions.py (omegahive 832b36e) does.

These tests drive it with a stub app rather than omega-connect, so that they can declare what
omega-connect does not (revalidate, approver "person") and count every call to act().
"""

import pytest

from fakehive import FakeHive, HostRefusal, run

MIND, PERSON = "scout", "ada"


class Stub:
    """An app whose actions are declared by the test; act() records what it gets, and fails on
    {"fail": true}."""

    def __init__(self, **actions):
        self.actions = actions
        self.calls = []

    def describe(self):
        return {"contract": "0.2", "kinds": [{"id": "thing", "label": "Thing", "role": "other"}], "relations": [],
                "actions": [{"id": name, "label": name, "applies_to": ["thing"], **spec}
                            for name, spec in self.actions.items()]}

    def view(self, ctx, focus, stage):
        return {"revision": "r-1", "items": [], "links": []}

    async def act(self, ctx, action, items, params):
        self.calls.append({"action": action, "actor": dict(ctx.actor), "command": dict(ctx.command),
                           "params": dict(params)})
        if params.get("fail"):
            raise RuntimeError("the effect of this act is unknown")
        return {"status": "done", "message": f"run {len(self.calls)}"}


def hive_for(mode="allow", **actions):
    stub = Stub(**actions)
    hive = FakeHive(stub)
    for name in actions:
        hive.attach(MIND, name, mode)
    return hive, stub


def mind(hive, action, key, approval_id=None, **params):
    return run(hive.agent_act("s1", MIND, action, params, key, approval_id))


def refusal(call, *args, **kwargs):
    with pytest.raises(HostRefusal) as refused:
        call(*args, **kwargs)
    return refused.value.status, refused.value.code


def test_an_identical_retry_of_a_done_act_gets_the_recorded_result_without_the_app():
    hive, stub = hive_for(write={"agents": True})
    first = mind(hive, "write", "k1", n=1)
    assert mind(hive, "write", "k1", n=1) == first == {"status": "done", "message": "run 1"}
    assert len(stub.calls) == 1 and stub.calls[0]["command"]["revalidation_supported"] is False
    assert refusal(mind, hive, "write", "k1", n=2) == (409, "idempotency_conflict")


def test_only_an_action_that_revalidates_gets_a_recovery():
    """The recovery reaches act() with the approval the act first ran under and the hive's record of the
    answer; no new approval is asked for, and the record stays as it was."""
    hive, stub = hive_for("ask", write={"agents": True, "revalidate": True})
    asked = mind(hive, "write", "k1", n=1)
    hive.approve(asked["approval_id"], PERSON)
    first = mind(hive, "write", "k1", asked["approval_id"], n=1)
    assert stub.calls[0]["command"]["revalidation_supported"] is True
    again = mind(hive, "write", "k1", n=1)
    assert again == {"status": "done", "message": "run 2"} and hive.pending() == []
    recovery = stub.calls[1]
    assert recovery["actor"]["recovery"] is True and recovery["actor"]["approval"]["id"] == asked["approval_id"]
    assert recovery["command"]["recorded_result"] == first and recovery["command"]["revalidation_supported"] is True
    assert recovery["command"]["record_id"] == stub.calls[0]["command"]["record_id"]
    assert mind(hive, "write", "k1", n=1)["message"] == "run 3"  # still answered from the first run's record
    assert stub.calls[2]["command"]["recorded_result"] == first


def test_a_failed_act_runs_again_after_a_new_approval_with_the_same_record():
    hive, stub = hive_for("ask", write={"agents": True})
    asked = mind(hive, "write", "k1", fail=True)
    hive.approve(asked["approval_id"], PERSON)
    assert refusal(mind, hive, "write", "k1", asked["approval_id"], fail=True) == (500, "program_error")
    assert refusal(mind, hive, "write", "k1", asked["approval_id"], fail=True) == (409, "not_approved")  # spent
    again = mind(hive, "write", "k1", fail=True)
    assert again["status"] == "approval_required" and again["approval_id"] != asked["approval_id"]
    hive.approve(again["approval_id"], PERSON)
    refusal(mind, hive, "write", "k1", again["approval_id"], fail=True)
    first, second = (call["command"] for call in stub.calls)
    assert first["record_id"] == second["record_id"] and "prior_failed" not in second
    assert stub.calls[1]["actor"]["approval"]["id"] == again["approval_id"]


def test_a_read_runs_again_and_its_answer_is_kept_as_a_digest():
    hive, stub = hive_for(look={"agents": True, "effect": "read"})
    assert mind(hive, "look", "k1")["message"] == "run 1"
    assert mind(hive, "look", "k1")["message"] == "run 2"
    [kept] = hive.records.values()
    assert '"redacted": "read"' in kept["result"] and "run" not in kept["result"]


def test_approver_person_refuses_the_local_operator_password():
    """For an action that declares approver "person", user:operator neither approves a mind's request
    (409, and the act does not run) nor acts on the person route (403)."""
    hive, stub = hive_for("ask", write={"agents": True, "approver": "person"}, plain={"agents": True})
    asked = mind(hive, "write", "k1")
    hive.approve(asked["approval_id"], "operator")
    assert refusal(mind, hive, "write", "k1", asked["approval_id"]) == (409, "person_approval_required")
    plain = mind(hive, "plain", "k2")
    hive.approve(plain["approval_id"], "operator")
    assert mind(hive, "plain", "k2", plain["approval_id"])["status"] == "done"  # declares no approver
    named = mind(hive, "write", "k3")
    hive.approve(named["approval_id"], PERSON)
    assert mind(hive, "write", "k3", named["approval_id"])["status"] == "done"
    assert stub.calls[-1]["actor"]["approval"]["approved_by"] == f"user:{PERSON}"
    assert refusal(run, hive.person_act("s1", "operator", "write", [], {})) == (403, "person_required")
    assert run(hive.person_act("s1", "operator", "plain", [], {}))["status"] == "done"
    assert run(hive.person_act("s1", PERSON, "write", [], {}))["status"] == "done"
    assert len(stub.calls) == 4


def test_request_keys_are_checked_as_the_hive_checks_them():
    """Identity and credential-like keys are refused at the top level of params; the hive's own retry keys
    are not credentials, and nested keys are not looked at."""
    hive, stub = hive_for(write={"agents": True})
    for params, code in (({"principal": "user:x"}, "identity_in_request"), ({"swarm_id": "s2"}, "identity_in_request"),
                         ({"token": "x"}, "credential_in_request"), ({"api_key": "x"}, "credential_in_request"),
                         ({"ApiKey": "x"}, "credential_in_request"), ({"key": "x"}, "credential_in_request"),
                         ({"signing_key": "x"}, "credential_in_request"),
                         ({"client_secret_ref": "x"}, "credential_in_request")):
        assert refusal(run, hive.agent_act("s1", MIND, "write", params, "k1")) == (400, code), params
        assert refusal(run, hive.person_act("s1", PERSON, "write", [], params)) == (400, code), params
    assert mind(hive, "write", "k2", client_key="c", signin={"token": "nested"})["status"] == "done"
    assert refusal(mind, hive, "write", "") == (400, "bad_request")
    assert refusal(mind, hive, "write", "k" * 121) == (400, "bad_request")
    assert refusal(run, hive.person_act("s1", PERSON, "write", [], {}, key="")) == (400, "bad_request")
    assert len(stub.calls) == 1


def test_minds_act_only_through_actions_for_them_and_under_a_rule():
    hive, stub = hive_for(write={"agents": True}, people_only={}, denied={"agents": True}, unattached={"agents": True})
    hive.attach(MIND, "denied", "deny")
    del hive.rules[(MIND, "program:omega-connect:unattached")]
    assert refusal(mind, hive, "nope", "k1") == (400, "bad_request")
    assert refusal(mind, hive, "people_only", "k1") == (403, "not_for_minds")
    assert refusal(mind, hive, "denied", "k1") == (403, "policy_refused")
    assert refusal(mind, hive, "unattached", "k1") == (403, "policy_refused")
    assert stub.calls == []
