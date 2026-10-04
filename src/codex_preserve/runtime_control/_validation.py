"""Strict, pure JSON validators. No process, network, path resolution or writes."""

import hashlib
import json
import re
import uuid
from pathlib import PurePosixPath

from .._runtime_contract import (
    AUTHORIZATION_SCHEMA, BINDING_SCHEMA, RECEIPT_SCHEMA,
    AUTHORIZATION_MAX_BYTES, BINDING_MAX_BYTES, RECEIPT_MAX_BYTES,
)

CONTRACT_VERSION = "session-preserve-runtime-scope/v1"
PROFILE = "codex-app-server-calculator-r1"
STATES = ("RUNNING", "COMPLETED", "FAILED", "STOPPED", "AMBIGUOUS")
TERMINAL = ("COMPLETED", "FAILED", "STOPPED")
LEVELS = ("ACCEPTED", "PERSISTED", "CONSUMED", "REJECTED", "UNCERTAIN")
KEYS = ("Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven",
        "Eight", "Nine", "Add", "Equals", "Clear")
MIGRATION_CLASSES = ("FILE_STATE_ONLY", "HOST_BINDING", "TCC_PERMISSION",
                     "SIGNING_REGISTRATION", "ACCOUNT_OR_DEVICE_PAIRING", "EPHEMERAL")
SANDBOX_FLAGS = (
    "active_worker_sandboxed", "runtime_state_not_worker_writable",
    "controller_channel_unreachable", "policy_not_worker_writable",
    "provider_evidence_not_worker_writable",
)
CAPABILITIES = ("openai_signed", "launchservices_hosted", "isolated_state",
                "owner_config_unchanged", "calculator_catalog_proven",
                "other_capabilities_disabled")
_TASK = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}(?:[-+][A-Za-z0-9.-]{1,32})?\Z")
_CEILINGS = {AUTHORIZATION_SCHEMA: AUTHORIZATION_MAX_BYTES,
             BINDING_SCHEMA: BINDING_MAX_BYTES, RECEIPT_SCHEMA: RECEIPT_MAX_BYTES}
VERIFY_SEMANTICS = (
    "PASS is local structural/consistency validation only. It does not attest "
    "that the run occurred, that provider/GUI facts are authentic, or that "
    "execution succeeded."
)


class ValidationError(ValueError):
    """A stable code and schema-owned location, never raw input or exception text."""

    def __init__(self, code, location="$"):
        self.code = code
        self.location = location
        super().__init__("%s at %s" % (code, location))


def _fail(code, location="$"):
    raise ValidationError(code, location)


def _object(value, required, optional=(), location="$"):
    if type(value) is not dict:
        _fail("WRONG_TYPE", location)
    if set(value) - set(required) - set(optional):
        _fail("UNKNOWN_FIELD", location)
    if set(required) - set(value):
        _fail("MISSING_FIELD", location)
    return value


def _bool(value, location):
    if type(value) is not bool:
        _fail("WRONG_TYPE", location)


def _int(value, low, high, location):
    if type(value) is not int:
        _fail("WRONG_TYPE", location)
    if not low <= value <= high:
        _fail("OUT_OF_RANGE", location)


def _enum(value, values, location):
    if type(value) is not str:
        _fail("WRONG_TYPE", location)
    if value not in values:
        _fail("INVALID_ENUM", location)


def _pattern(value, pattern, location):
    if type(value) is not str:
        _fail("WRONG_TYPE", location)
    if not pattern.fullmatch(value):
        _fail("MALFORMED_IDENTIFIER", location)


def _uuid(value, location, version=None):
    if type(value) is not str:
        _fail("WRONG_TYPE", location)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        _fail("MALFORMED_UUID", location)
    if str(parsed) != value or parsed.int == 0 or parsed.variant != uuid.RFC_4122 \
            or parsed.version not in range(1, 9) \
            or (version is not None and parsed.version != version):
        _fail("MALFORMED_UUID", location)


def _list(value, maximum, location):
    if type(value) is not list:
        _fail("WRONG_TYPE", location)
    if len(value) > maximum:
        _fail("TOO_MANY_RECORDS", location)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("DUPLICATE_KEY")
        result[key] = value
    return result


def _constant(_value):
    _fail("NON_JSON_NUMBER")


def _decode(payload, ceiling):
    if type(payload) is str:
        try:
            payload = payload.encode("utf-8")
        except UnicodeError:
            _fail("INVALID_UTF8")
    if type(payload) is not bytes:
        _fail("WRONG_PAYLOAD_TYPE")
    if len(payload) > ceiling:
        _fail("PAYLOAD_TOO_LARGE")
    try:
        result = json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs,
                            parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, ValidationError):
            raise
        _fail("INVALID_JSON")
    if type(result) is not dict:
        _fail("WRONG_TYPE")
    return result


def _path(value, location):
    # Lexical constraints only. Actual OS/symlink/sandbox attestation is outside P0.
    if type(value) is not str:
        _fail("WRONG_TYPE", location)
    if not 1 <= len(value.encode("utf-8", errors="replace")) <= 1024 \
            or not value.startswith("/") or str(PurePosixPath(value)) != value \
            or any(p in (".", "..") for p in value.split("/")) \
            or any(ord(c) < 32 or ord(c) > 126 for c in value) \
            or any(c in value for c in ("$", "~", "\\")) or value.startswith("//"):
        _fail("INVALID_SCOPE_PATH", location)


def _under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _roots(value, location):
    _list(value, 16, location)
    if not value:
        _fail("EMPTY_SCOPE", location)
    for path in value:
        _path(path, location)
    if len(set(value)) != len(value):
        _fail("DUPLICATE_SCOPE", location)


def _sandbox(value, location):
    _object(value, SANDBOX_FLAGS, location=location)
    for field in SANDBOX_FLAGS:
        _bool(value[field], location + "." + field)
        if not value[field]:
            _fail("SANDBOX_REQUIRED", location + "." + field)


def _calculator_authority(value, location):
    fields = ("observe", "mutate", "foreground", "restore_foreground")
    _object(value, fields, ("mutate_preexisting",), location)
    value.setdefault("mutate_preexisting", False)
    for name in fields + ("mutate_preexisting",):
        _bool(value[name], location + "." + name)
    if value["mutate"] and not (value["observe"] and value["foreground"]):
        _fail("CALCULATOR_AUTHORITY_REQUIRED", location)
    if value["mutate_preexisting"] and not value["mutate"]:
        _fail("CALCULATOR_AUTHORITY_REQUIRED", location)
    if value["restore_foreground"] and not value["foreground"]:
        _fail("FOREGROUND_AUTHORITY_REQUIRED", location)


def _process(value, location):
    _object(value, ("pid", "birth_ns", "executable_sha256", "launch_id"), location=location)
    _int(value["pid"], 1, 2**31 - 1, location + ".pid")
    _int(value["birth_ns"], 1, 2**63 - 1, location + ".birth_ns")
    _pattern(value["executable_sha256"], _HASH, location + ".executable_sha256")
    _uuid(value["launch_id"], location + ".launch_id")


def _native_identity(value, location):
    _enum(value["provider"], ("codex",), location + ".provider")
    _uuid(value["thread_id"], location + ".thread_id", 7)
    _enum(value["binding_phase"], ("THREAD_BOUND", "TURN_BOUND"), location + ".binding_phase")
    if value["binding_phase"] == "THREAD_BOUND":
        if value["turn_id"] is not None:
            _fail("TURN_NOT_ESTABLISHED", location + ".turn_id")
    else:
        _uuid(value["turn_id"], location + ".turn_id", 7)


def validate_authorization(payload):
    """Validate UTF-8 JSON bytes/text and return a detached, default-normalized dict."""
    value = _decode(payload, AUTHORIZATION_MAX_BYTES)
    fields = ("schema", "task_id", "run_id", "attempt_id", "provider",
              "scope_version", "workspace", "authorized_roots", "worker_writable_roots",
              "runtime_state_root", "controller_endpoint_root", "provider_evidence_store",
              "required_sandbox_posture", "nested_start_policy", "wall_clock_seconds",
              "max_corrections", "observe_authorized", "steer_authorized", "calculator")
    _object(value, fields, ("idle_seconds",))
    _enum(value["schema"], (AUTHORIZATION_SCHEMA,), "$.schema")
    _pattern(value["task_id"], _TASK, "$.task_id")
    for name in ("run_id", "attempt_id"):
        _uuid(value[name], "$." + name)
    _enum(value["provider"], ("codex",), "$.provider")
    _enum(value["scope_version"], (CONTRACT_VERSION,), "$.scope_version")
    _path(value["workspace"], "$.workspace")
    for name in ("authorized_roots", "worker_writable_roots"):
        _roots(value[name], "$." + name)
    for path in [value["workspace"]] + value["worker_writable_roots"]:
        if not any(_under(path, root) for root in value["authorized_roots"]):
            _fail("OUTSIDE_AUTHORIZED_SCOPE")
    for name in ("runtime_state_root", "controller_endpoint_root", "provider_evidence_store"):
        path = value[name]
        _path(path, "$." + name)
        if any(_under(path, root) or _under(root, path) for root in value["worker_writable_roots"]):
            _fail("WORKER_WRITABLE_AUTHORITY", "$." + name)
    _sandbox(value["required_sandbox_posture"], "$.required_sandbox_posture")
    _enum(value["nested_start_policy"], ("FORBIDDEN",), "$.nested_start_policy")
    _int(value["wall_clock_seconds"], 1, 86400, "$.wall_clock_seconds")
    if "idle_seconds" in value:
        _int(value["idle_seconds"], 1, value["wall_clock_seconds"], "$.idle_seconds")
    _int(value["max_corrections"], 0, 3, "$.max_corrections")
    for name in ("observe_authorized", "steer_authorized"):
        _bool(value[name], "$." + name)
    if not value["steer_authorized"] and value["max_corrections"] != 0:
        _fail("STEER_NOT_AUTHORIZED", "$.max_corrections")
    _calculator_authority(value["calculator"], "$.calculator")
    return value


def validate_binding(payload):
    value = _decode(payload, BINDING_MAX_BYTES)
    fields = ("schema", "task_id", "run_id", "attempt_id", "provider", "authorization_sha256",
              "thread_id", "turn_id", "binding_phase", "process_identity", "process_birth_source",
              "runtime_profile", "runtime_version", "capabilities", "sandbox_posture",
              "nested_start_enforcement")
    _object(value, fields)
    _enum(value["schema"], (BINDING_SCHEMA,), "$.schema")
    _pattern(value["task_id"], _TASK, "$.task_id")
    for name in ("run_id", "attempt_id"):
        _uuid(value[name], "$." + name)
    _pattern(value["authorization_sha256"], _HASH, "$.authorization_sha256")
    _native_identity(value, "$")
    _process(value["process_identity"], "$.process_identity")
    _enum(value["process_birth_source"], ("INDEPENDENT_OS_OBSERVATION",), "$.process_birth_source")
    _enum(value["runtime_profile"], (PROFILE,), "$.runtime_profile")
    _pattern(value["runtime_version"], _VERSION, "$.runtime_version")
    _object(value["capabilities"], CAPABILITIES, location="$.capabilities")
    for name in CAPABILITIES:
        _bool(value["capabilities"][name], "$.capabilities." + name)
        if not value["capabilities"][name]:
            _fail("MISSING_ATTESTATION", "$.capabilities." + name)
    _sandbox(value["sandbox_posture"], "$.sandbox_posture")
    # P0 artifacts may retain the explicit unverified residual; active P1 bindings
    # use OWNER_STAGED_GATE_ATTESTED only after the separately reviewed launch gate.
    _enum(value["nested_start_enforcement"],
          ("UNVERIFIED_PENDING_N6_N11", "OWNER_STAGED_GATE_ATTESTED"),
          "$.nested_start_enforcement")
    return value


def _correction(row, location):
    fields = ("client_id", "level", "accepted", "persisted", "consumed", "rejected",
              "settled", "non_delivery_proven", "reservation_released")
    _object(row, fields, location=location)
    _uuid(row["client_id"], location + ".client_id")
    _enum(row["level"], LEVELS, location + ".level")
    for name in fields[2:]:
        _bool(row[name], location + "." + name)
    if row["consumed"] and not row["persisted"] or row["persisted"] and not row["accepted"]:
        _fail("CORRECTION_EVIDENCE_ORDER", location)
    if row["rejected"] and row["accepted"]:
        _fail("CONFLICTING_CORRECTION_EVIDENCE", location)
    expected = {"ACCEPTED": (True, False, False, False),
                "PERSISTED": (True, True, False, False),
                "CONSUMED": (True, True, True, False),
                "REJECTED": (False, False, False, True)}
    if row["level"] in expected and tuple(row[n] for n in fields[2:6]) != expected[row["level"]]:
        _fail("CORRECTION_LEVEL_MISMATCH", location)
    if row["non_delivery_proven"] and not row["rejected"]:
        _fail("NON_DELIVERY_PROOF_REQUIRED", location)
    if row["reservation_released"] != (row["rejected"] and row["non_delivery_proven"]):
        _fail("RESERVATION_RELEASE_INVALID", location)
    if row["settled"] != (row["consumed"] or row["reservation_released"]):
        _fail("CORRECTION_SETTLEMENT_INVALID", location)
    if row["level"] == "UNCERTAIN" and row["settled"]:
        _fail("CORRECTION_SETTLEMENT_INVALID", location)


def _calculator(value):
    location = "$.calculator"
    fields = ("authorization", "approval_count", "click_count", "session_proof",
              "click_schema_string", "calculator_preexisting", "target", "persistent_approval",
              "previous_frontmost_captured", "maximum_snapshot_age_ms", "keys")
    _object(value, fields, location=location)
    _calculator_authority(value["authorization"], location + ".authorization")
    _int(value["approval_count"], 0, 1, location + ".approval_count")
    _int(value["click_count"], 0, 128, location + ".click_count")
    _enum(value["session_proof"], ("UNPROVEN", "HOLD", "CURRENT_SESSION"), location + ".session_proof")
    for name in ("click_schema_string", "calculator_preexisting", "persistent_approval", "previous_frontmost_captured"):
        _bool(value[name], location + "." + name)
    if value["persistent_approval"]:
        _fail("PERSISTENT_APPROVAL_FORBIDDEN", location)
    _enum(value["target"], ("com.apple.calculator",), location + ".target")
    _int(value["maximum_snapshot_age_ms"], 1, 1000, location + ".maximum_snapshot_age_ms")
    _list(value["keys"], 128, location + ".keys")
    for key in value["keys"]:
        _enum(key, KEYS, location + ".keys")
    if len(value["keys"]) != value["click_count"]:
        _fail("CLICK_COUNT_MISMATCH", location)
    grant = value["authorization"]
    if value["session_proof"] == "CURRENT_SESSION" and value["approval_count"] != 1:
        _fail("SESSION_APPROVAL_REQUIRED", location)
    if value["session_proof"] == "HOLD" and value["approval_count"] != 0:
        _fail("SESSION_PROOF_MISMATCH", location)
    if value["approval_count"] or value["previous_frontmost_captured"] or value["session_proof"] == "CURRENT_SESSION":
        if not (grant["observe"] and grant["foreground"]):
            _fail("CALCULATOR_ENTRY_AUTHORITY_REQUIRED", location)
    if value["click_count"]:
        if not (grant["mutate"] and value["click_schema_string"] and value["session_proof"] == "CURRENT_SESSION"):
            _fail("CLICK_AUTHORITY_REQUIRED", location)
        if value["calculator_preexisting"] and not grant["mutate_preexisting"]:
            _fail("PREEXISTING_MUTATION_FORBIDDEN", location)


def _cleanup(value, calculator):
    location = "$.cleanup"
    fields = ("requested", "released", "skipped", "errors", "foreground_restored", "verified",
              "grace_seconds", "owned_resources")
    _object(value, fields, location=location)
    for name in ("requested", "foreground_restored", "verified"):
        _bool(value[name], location + "." + name)
    for name in ("released", "skipped", "errors"):
        _int(value[name], 0, 16, location + "." + name)
    _int(value["grace_seconds"], 0, 5, location + ".grace_seconds")
    _list(value["owned_resources"], 16, location + ".owned_resources")
    refs = set()
    outcomes = {"RELEASED": 0, "SKIPPED": 0, "ERROR": 0, "NOT_REQUESTED": 0}
    for row in value["owned_resources"]:
        _object(row, ("kind", "identity_ref", "outcome", "exact_identity_verified", "absence_verified"), location=location)
        _enum(row["kind"], ("CALCULATOR", "SOCKET", "APP_SERVER", "HELPER"), location)
        _pattern(row["identity_ref"], _HASH, location)
        _enum(row["outcome"], tuple(outcomes), location)
        for name in ("exact_identity_verified", "absence_verified"):
            _bool(row[name], location)
        if row["identity_ref"] in refs:
            _fail("DUPLICATE_RESOURCE", location)
        refs.add(row["identity_ref"])
        outcomes[row["outcome"]] += 1
        if row["kind"] == "CALCULATOR" and calculator["calculator_preexisting"]:
            _fail("PREEXISTING_CLEANUP_FORBIDDEN", location)
        if row["outcome"] == "RELEASED" and not row["exact_identity_verified"]:
            _fail("EXACT_OWNERSHIP_REQUIRED", location)
        if not value["requested"] and row["outcome"] != "NOT_REQUESTED":
            _fail("CLEANUP_NOT_REQUESTED", location)
    if (value["released"], value["skipped"], value["errors"]) != tuple(outcomes[n] for n in ("RELEASED", "SKIPPED", "ERROR")):
        _fail("CLEANUP_COUNT_MISMATCH", location)
    if value["verified"] and (not value["requested"] or value["skipped"] or value["errors"]
                              or any(not r["absence_verified"] or r["outcome"] != "RELEASED" for r in value["owned_resources"])):
        _fail("CLEANUP_UNVERIFIED", location)
    if value["foreground_restored"] and not (value["requested"] and calculator["previous_frontmost_captured"]
                                            and calculator["authorization"]["restore_foreground"]):
        _fail("RESTORE_AUTHORITY_REQUIRED", location)


def validate_receipt(payload):
    value = _decode(payload, RECEIPT_MAX_BYTES)
    fields = ("schema", "identity", "authorization_sha256", "binding_sha256", "runtime_profile",
              "runtime_version", "state", "decision", "provider_terminal_fact", "execution_ambiguous",
              "ambiguity_reasons", "correction_maximum", "correction_count", "corrections", "calculator",
              "cleanup", "provider_calls")
    _object(value, fields)
    _enum(value["schema"], (RECEIPT_SCHEMA,), "$.schema")
    identity = _object(value["identity"], ("provider", "task_ref", "run_ref", "attempt_ref", "thread_id", "turn_id", "binding_phase", "process_ref"), location="$.identity")
    _native_identity(identity, "$.identity")
    for name in ("task_ref", "run_ref", "attempt_ref", "process_ref"):
        _pattern(identity[name], _HASH, "$.identity." + name)
    for name in ("authorization_sha256", "binding_sha256"):
        _pattern(value[name], _HASH, "$." + name)
    _enum(value["runtime_profile"], (PROFILE,), "$.runtime_profile")
    _pattern(value["runtime_version"], _VERSION, "$.runtime_version")
    _enum(value["state"], STATES, "$.state")
    _enum(value["decision"], ("NONE", "PROVIDER_COMPLETED", "PROVIDER_FAILED", "REQUESTED_STOP",
                            "DEADLINE_EXPIRED", "IDLE_EXPIRED", "CORRECTIONS_EXHAUSTED",
                            "CAPABILITY_UNAVAILABLE", "CONTROLLER_LOST", "GUI_EXECUTION_UNCERTAIN", "TRANSPORT_LOST"), "$.decision")
    _enum(value["provider_terminal_fact"], ("NONE",) + TERMINAL, "$.provider_terminal_fact")
    _bool(value["execution_ambiguous"], "$.execution_ambiguous")
    _list(value["ambiguity_reasons"], 6, "$.ambiguity_reasons")
    for reason in value["ambiguity_reasons"]:
        _enum(reason, ("ACCEPTED_NOT_PERSISTED", "UNCERTAIN_CORRECTION", "GUI_EXECUTION", "CONTROLLER_LOSS", "TRANSPORT_LOSS", "RESOURCE_UNVERIFIED"), "$.ambiguity_reasons")
    if len(set(value["ambiguity_reasons"])) != len(value["ambiguity_reasons"]) \
            or value["execution_ambiguous"] != bool(value["ambiguity_reasons"]):
        _fail("AMBIGUITY_MISMATCH")
    if value["state"] == "AMBIGUOUS" and not value["execution_ambiguous"]:
        _fail("AMBIGUITY_REQUIRED")
    expected_decisions = {"RUNNING": ("NONE",), "COMPLETED": ("PROVIDER_COMPLETED",),
                          "FAILED": ("PROVIDER_FAILED",),
                          "AMBIGUOUS": ("CONTROLLER_LOST", "GUI_EXECUTION_UNCERTAIN", "TRANSPORT_LOST"),
                          "STOPPED": ("REQUESTED_STOP", "DEADLINE_EXPIRED", "IDLE_EXPIRED", "CORRECTIONS_EXHAUSTED", "CAPABILITY_UNAVAILABLE", "CONTROLLER_LOST", "GUI_EXECUTION_UNCERTAIN", "TRANSPORT_LOST")}
    _enum(value["decision"], expected_decisions[value["state"]], "$.decision")
    if value["state"] in ("COMPLETED", "FAILED") and value["provider_terminal_fact"] != value["state"]:
        _fail("PROVIDER_TERMINAL_FACT_REQUIRED")
    if value["decision"] in ("CONTROLLER_LOST", "GUI_EXECUTION_UNCERTAIN", "TRANSPORT_LOST"):
        needed = {"CONTROLLER_LOST": "CONTROLLER_LOSS", "GUI_EXECUTION_UNCERTAIN": "GUI_EXECUTION", "TRANSPORT_LOST": "TRANSPORT_LOSS"}[value["decision"]]
        if needed not in value["ambiguity_reasons"]:
            _fail("AMBIGUITY_REQUIRED")
    _int(value["correction_maximum"], 0, 3, "$.correction_maximum")
    _int(value["correction_count"], 0, value["correction_maximum"], "$.correction_count")
    _list(value["corrections"], 32, "$.corrections")
    if identity["turn_id"] is None and value["corrections"]:
        _fail("CORRECTION_REQUIRES_TURN")
    clients = set()
    for row in value["corrections"]:
        _correction(row, "$.corrections")
        if row["client_id"] in clients:
            _fail("DUPLICATE_CORRECTION")
        clients.add(row["client_id"])
        if row["accepted"] and not row["persisted"] and "ACCEPTED_NOT_PERSISTED" not in value["ambiguity_reasons"]:
            _fail("ACCEPTED_NOT_PERSISTED_IS_AMBIGUOUS")
        if row["level"] == "UNCERTAIN" or row["rejected"] and not row["non_delivery_proven"]:
            if "UNCERTAIN_CORRECTION" not in value["ambiguity_reasons"]:
                _fail("UNCERTAIN_CORRECTION_IS_AMBIGUOUS")
    if value["correction_count"] != sum(not row["reservation_released"] for row in value["corrections"]):
        _fail("CORRECTION_COUNT_MISMATCH")
    if value["decision"] == "CORRECTIONS_EXHAUSTED" and value["correction_count"] != value["correction_maximum"]:
        _fail("CORRECTIONS_NOT_EXHAUSTED")
    _calculator(value["calculator"])
    _cleanup(value["cleanup"], value["calculator"])
    _list(value["provider_calls"], 128, "$.provider_calls")
    refs = set()
    for call in value["provider_calls"]:
        _object(call, ("kind", "outcome"), ("correlation_ref",), location="$.provider_calls")
        _enum(call["kind"], ("LAUNCH", "OBSERVE", "RECONCILE", "STEER", "SCHEMA_READ", "CALCULATOR_READ", "CALCULATOR_CLICK", "STOP", "CLEANUP"), "$.provider_calls")
        _enum(call["outcome"], ("ACCEPTED", "REJECTED", "UNCERTAIN", "OBSERVED"), "$.provider_calls")
        if identity["turn_id"] is None and call["kind"] == "STEER":
            _fail("CORRECTION_REQUIRES_TURN")
        if "correlation_ref" in call:
            _pattern(call["correlation_ref"], _HASH, "$.provider_calls")
            if call["correlation_ref"] in refs:
                _fail("DUPLICATE_CALL")
            refs.add(call["correlation_ref"])
    if sum(c["kind"] == "CALCULATOR_CLICK" for c in value["provider_calls"]) != value["calculator"]["click_count"]:
        _fail("CLICK_CALL_COUNT_MISMATCH")
    return value


def validate_artifact(payload):
    value = _decode(payload, RECEIPT_MAX_BYTES)
    schema = value.get("schema")
    if type(schema) is not str or schema not in _CEILINGS:
        _fail("UNSUPPORTED_SCHEMA", "$.schema")
    return {AUTHORIZATION_SCHEMA: validate_authorization, BINDING_SCHEMA: validate_binding,
            RECEIPT_SCHEMA: validate_receipt}[schema](payload)


def authorization_digest(payload):
    value = validate_authorization(payload)
    return _digest("authorization", value)


def binding_digest(payload):
    value = validate_binding(payload)
    return _digest("binding", value)


def _digest(kind, validated_value):
    return hashlib.sha256(b"session-preserve/runtime/" + kind.encode("ascii")
                          + b"/v1\0" + _canonical(validated_value)).hexdigest()


def identity_ref(kind, value):
    """SHA256(domain + kind + NUL + canonical identity), never a path or raw prompt."""
    _enum(kind, ("task", "run", "attempt", "process", "socket", "call"), "$.kind")
    if kind == "task":
        _pattern(value, _TASK, "$.identity")
    elif kind in ("run", "attempt", "call"):
        _uuid(value, "$.identity")
    elif kind == "process":
        _process(value, "$.identity")
    else:
        _object(value, ("run_id", "attempt_id", "handle_nonce", "inode"), location="$.identity")
        for name in ("run_id", "attempt_id", "handle_nonce"):
            _uuid(value[name], "$.identity." + name)
        _int(value["inode"], 1, 2**63 - 1, "$.identity.inode")
    return hashlib.sha256(b"session-preserve/runtime/identity-ref/v1\0" + kind.encode("ascii")
                          + b"\0" + _canonical(value)).hexdigest()


def verify_artifact(payload, *, authorization=None, binding=None):
    """Structural validation with optional explicitly supplied paired JSON payloads."""
    value = validate_artifact(payload)
    grant = validate_authorization(authorization) if authorization is not None else None
    bound = validate_binding(binding) if binding is not None else None
    schema = value["schema"]
    if schema == AUTHORIZATION_SCHEMA:
        if grant is not None:
            _fail("UNEXPECTED_PAIRED_AUTHORIZATION")
        grant = value
    elif schema == BINDING_SCHEMA:
        if bound is not None:
            _fail("UNEXPECTED_PAIRED_BINDING")
        bound = value
    checks = []
    if grant is not None and bound is not None:
        if bound["authorization_sha256"] != _digest("authorization", grant):
            _fail("AUTHORIZATION_DIGEST_MISMATCH")
        if any(grant[n] != bound[n] for n in ("task_id", "run_id", "attempt_id", "provider")):
            _fail("PAIRED_IDENTITY_MISMATCH")
        checks.append("authorization_binding")
    if schema == RECEIPT_SCHEMA:
        if grant is not None:
            if value["authorization_sha256"] != _digest("authorization", grant):
                _fail("AUTHORIZATION_DIGEST_MISMATCH")
            if value["correction_maximum"] != grant["max_corrections"]:
                _fail("CORRECTION_BUDGET_MISMATCH")
            if value["calculator"]["authorization"] != grant["calculator"]:
                _fail("CALCULATOR_GRANT_MISMATCH")
            for kind, name in (("task", "task_id"), ("run", "run_id"), ("attempt", "attempt_id")):
                if value["identity"][kind + "_ref"] != identity_ref(kind, grant[name]):
                    _fail("IDENTITY_REF_MISMATCH")
            checks.append("authorization_receipt")
        if bound is not None:
            if value["binding_sha256"] != _digest("binding", bound):
                _fail("BINDING_DIGEST_MISMATCH")
            for name in ("provider", "thread_id", "turn_id", "binding_phase"):
                if value["identity"][name] != bound[name]:
                    _fail("PAIRED_IDENTITY_MISMATCH")
            for kind, name in (("task", "task_id"), ("run", "run_id"), ("attempt", "attempt_id"), ("process", "process_identity")):
                if value["identity"][kind + "_ref"] != identity_ref(kind, bound[name]):
                    _fail("IDENTITY_REF_MISMATCH")
            if any(value[n] != bound[n] for n in ("runtime_profile", "runtime_version", "authorization_sha256")):
                _fail("BINDING_RECEIPT_MISMATCH")
            checks.append("binding_receipt")
    return {"status": "PASS", "schema": schema, "validation": "LOCAL_STRUCTURAL_ONLY",
            "paired_checks": checks, "unverified_pairs": [n for n, obj in (("authorization", grant), ("binding", bound)) if obj is None],
            "execution_attested": False, "semantics": VERIFY_SEMANTICS}
