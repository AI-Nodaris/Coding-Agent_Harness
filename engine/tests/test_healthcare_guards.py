"""The healthcare_guards setting (Varun, 2026-10-07): the PHI prompt block, the PHI lint, approval to read
PHI-marked files, the healthcare security procedure and the patient, tenant and auth overlays can be turned off
while every other part of the harness keeps working. Every string here is synthetic."""
import json, os, subprocess, sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from nodaris_harness import dispatch, events, gates, hosts, policy, router  # noqa: E402

HOOKS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "packs", "core", "hooks")
sys.path.insert(0, HOOKS)
import done_gate  # noqa: E402

SSN = "-".join(("123", "45", "6789"))
SENSITIVE_ASK = "Add a patient login page with tenant billing and session tokens"


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NODARIS_HARNESS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("NODARIS_HARNESS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("NODARIS_HARNESS_NO_BG", "1")
    monkeypatch.delenv("NODARIS_JEV", raising=False)
    subprocess.run(["git", "init", "-q", str(tmp_path / "repo")], check=True)
    return tmp_path


def settings(**kw):
    os.makedirs(policy.home(), exist_ok=True)
    with open(os.path.join(policy.home(), "settings.json"), "w") as fh:
        json.dump(kw, fh)


def handle(env, **ev):
    base = {"session_id": "s1", "cwd": str(env / "repo"), "permission_mode": "bypassPermissions"}
    return dispatch.handle(events.parse("claude", {**base, **ev}))


def prompt(env, text):
    return handle(env, hook_event_name="UserPromptSubmit", prompt=text)


def read_remit(env):
    return handle(env, hook_event_name="PreToolUse", tool_name="Read",
                  tool_input={"file_path": str(env / "repo" / "era" / "march" / "remit.835")})


def write_code(env):
    return handle(env, hook_event_name="PostToolUse", tool_name="Write",
                  tool_input={"file_path": str(env / "repo" / "app" / "views.py"),
                              "content": "logger.info('patient %s', patient.ssn)\n"})


def sensitive_state():
    return {"events": [{"kind": "edit", "seq": 1, "path": "/repo/app/auth.py", "sensitive": True},
                       {"kind": "check", "seq": 2, "ok": True, "test": True}]}


def test_guards_stay_on_when_the_setting_is_absent(env):
    assert prompt(env, "Look up SSN " + SSN)["decision"] == "block"
    assert read_remit(env)["decision"] == "deny"
    assert "PHI lint" in (write_code(env).get("context") or "")
    assert "attack" in done_gate.verdict(sensitive_state())
    out = prompt(env, SENSITIVE_ASK)
    assert "Risk: high" in out["context"] and "sensitive surface" in out["context"]


def test_off_lets_a_prompt_with_an_identifier_through_unchanged(env):
    settings(healthcare_guards=False)
    out = prompt(env, "Look up SSN " + SSN)
    assert out["decision"] == "allow"
    assert "patient information" not in (out.get("context") or "")


def test_off_drops_the_security_procedure_and_the_gated_overlays(env):
    settings(healthcare_guards=False)
    out = prompt(env, SENSITIVE_ASK)
    ctx = out["context"]
    assert out["decision"] == "allow" and "Harness router" in ctx
    assert "sensitive surface" not in ctx and "Risk: high" not in ctx
    assert not {"phi", "tenant-money", "auth"} & set(out["route"]["overlays"])


def test_off_never_asks_for_a_design_record_on_a_sensitive_feature(env):
    settings(healthcare_guards=False)
    prompt(env, SENSITIVE_ASK)
    assert gates.stop_check({"session_id": "s1", "cwd": str(env / "repo")}) is None


def test_off_reads_a_phi_marked_file_without_approval(env):
    settings(healthcare_guards=False)
    assert read_remit(env)["decision"] == "allow"


def test_off_skips_the_phi_lint(env):
    settings(healthcare_guards=False)
    assert "PHI lint" not in (write_code(env).get("context") or "")


def test_off_skips_the_done_gate_attack_threat_and_scan_checks_but_not_the_test_check(env):
    settings(healthcare_guards=False)
    assert done_gate.verdict(sensitive_state()) == []
    untested = {"events": [{"kind": "edit", "seq": 1, "path": "/repo/app/auth.py", "sensitive": True}]}
    assert done_gate.verdict(untested) == ["tests"]


def test_off_keeps_push_approval(env):
    settings(healthcare_guards=False)
    out = handle(env, hook_event_name="PreToolUse", tool_name="Bash",
                 tool_input={"command": "git push origin feature/x"})
    assert out["decision"] == "deny" and "C-PUSH" in out["rule"]


def test_off_drops_the_redact_step_from_media_work():
    decision = {"playbook": "media", "overlays": []}
    assert "redact --check" in router.brief(decision)
    assert "redact --check" not in router.brief(decision, healthcare=False)
    assert "creative-studio" in router.brief(decision, healthcare=False)


def test_off_removes_the_guard_rules_from_the_installed_rules_text(env):
    on = hosts.rules_text(packs=["core", "healthcare"])
    settings(healthcare_guards=False)
    off = hosts.rules_text(packs=["core", "healthcare"])
    for gone in ("PHI lint", "**Redaction:**", "Healthcare security bar", "Sensitive file, unannounced",
                 "self-attack", "adversarial tests were written"):
        assert gone in on and gone not in off
    for kept in ("## Memory loop", "healthcare-domain", "check passed after the last code", "No AI fingerprint"):
        assert kept in off
    assert "pack:" not in off and "\n\n\n" not in off and "\n\n- **" not in off
