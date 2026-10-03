"""Invented P0 JSON fixtures only; no real provider, account or GUI evidence."""

import json

from codex_preserve.runtime_control import (
    AUTHORIZATION_SCHEMA, BINDING_SCHEMA, RECEIPT_SCHEMA,
    authorization_digest, binding_digest, identity_ref,
)

RUN = "11111111-1111-4111-8111-111111111111"
ATTEMPT = "22222222-2222-4222-8222-222222222222"
THREAD = "01234567-89ab-7cde-8fab-0123456789ab"
TURN = "01234567-89ab-7cde-8fab-0123456789ac"
LAUNCH = "33333333-3333-4333-8333-333333333333"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def authorization():
    return {
        "schema": AUTHORIZATION_SCHEMA, "task_id": "synthetic-task", "run_id": RUN,
        "attempt_id": ATTEMPT, "provider": "codex", "scope_version": "session-preserve-runtime-scope/v1",
        "workspace": "/workspace/project", "authorized_roots": ["/workspace"],
        "worker_writable_roots": ["/workspace/project"],
        "runtime_state_root": "/authority/runtime", "controller_endpoint_root": "/authority/ipc",
        "provider_evidence_store": "/authority/provider-evidence",
        "required_sandbox_posture": {
            "active_worker_sandboxed": True, "runtime_state_not_worker_writable": True,
            "controller_channel_unreachable": True, "policy_not_worker_writable": True,
            "provider_evidence_not_worker_writable": True,
        },
        "nested_start_policy": "FORBIDDEN", "wall_clock_seconds": 300, "idle_seconds": 60,
        "max_corrections": 3, "observe_authorized": True, "steer_authorized": True,
        "calculator": {"observe": False, "mutate": False, "foreground": False, "restore_foreground": False},
    }


def binding(grant=None):
    grant = authorization() if grant is None else grant
    return {
        "schema": BINDING_SCHEMA, "task_id": grant["task_id"], "run_id": grant["run_id"],
        "attempt_id": grant["attempt_id"], "provider": "codex",
        "authorization_sha256": authorization_digest(encoded(grant)),
        "thread_id": THREAD, "turn_id": TURN, "binding_phase": "TURN_BOUND",
        "process_identity": {"pid": 42, "birth_ns": 100, "executable_sha256": "a" * 64, "launch_id": LAUNCH},
        "process_birth_source": "INDEPENDENT_OS_OBSERVATION",
        "runtime_profile": "codex-app-server-calculator-r1", "runtime_version": "0.0.0",
        "capabilities": {"openai_signed": True, "launchservices_hosted": True, "isolated_state": True,
                         "owner_config_unchanged": True, "calculator_catalog_proven": True, "other_capabilities_disabled": True},
        "sandbox_posture": dict(grant["required_sandbox_posture"]),
        "nested_start_enforcement": "UNVERIFIED_PENDING_N6_N11",
    }


def receipt(grant=None, bound=None):
    grant = authorization() if grant is None else grant
    bound = binding(grant) if bound is None else bound
    return {
        "schema": RECEIPT_SCHEMA,
        "identity": {
            "provider": "codex", "task_ref": identity_ref("task", grant["task_id"]),
            "run_ref": identity_ref("run", grant["run_id"]), "attempt_ref": identity_ref("attempt", grant["attempt_id"]),
            "thread_id": bound["thread_id"], "turn_id": bound["turn_id"], "binding_phase": bound["binding_phase"],
            "process_ref": identity_ref("process", bound["process_identity"]),
        },
        "authorization_sha256": authorization_digest(encoded(grant)), "binding_sha256": binding_digest(encoded(bound)),
        "runtime_profile": bound["runtime_profile"], "runtime_version": bound["runtime_version"],
        "state": "RUNNING", "decision": "NONE", "provider_terminal_fact": "NONE",
        "execution_ambiguous": False, "ambiguity_reasons": [], "correction_maximum": grant["max_corrections"],
        "correction_count": 0, "corrections": [],
        "calculator": {
            "authorization": dict(grant["calculator"]), "approval_count": 0, "click_count": 0,
            "session_proof": "UNPROVEN", "click_schema_string": False, "calculator_preexisting": False,
            "target": "com.apple.calculator", "persistent_approval": False,
            "previous_frontmost_captured": False, "maximum_snapshot_age_ms": 1000, "keys": [],
        },
        "cleanup": {"requested": False, "released": 0, "skipped": 0, "errors": 0,
                    "foreground_restored": False, "verified": False, "grace_seconds": 5, "owned_resources": []},
        "provider_calls": [],
    }


def correction(index=1, level="CONSUMED"):
    return {
        "client_id": "44444444-4444-4444-8444-%012d" % index, "level": level,
        "accepted": level in ("ACCEPTED", "PERSISTED", "CONSUMED"),
        "persisted": level in ("PERSISTED", "CONSUMED"), "consumed": level == "CONSUMED",
        "rejected": level == "REJECTED", "settled": level in ("CONSUMED", "REJECTED"),
        "non_delivery_proven": level == "REJECTED", "reservation_released": level == "REJECTED",
    }
