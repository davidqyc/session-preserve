"""Pure P0 contract tests using invented JSON, never an active runtime."""

import copy
import hashlib
import json
import unittest

from codex_preserve.runtime_control import (
    AUTHORIZATION_MAX_BYTES, BINDING_MAX_BYTES, RECEIPT_MAX_BYTES, ValidationError,
    validate_authorization, validate_binding, validate_receipt, validate_artifact,
    identity_ref, authorization_digest, verify_artifact,
)
from tests.runtime_fixtures import authorization, binding, receipt, encoded, correction, RUN


class RuntimeSchemas(unittest.TestCase):
    def assert_invalid(self, value, code=None, validator=validate_artifact):
        with self.assertRaises(ValidationError) as caught:
            validator(encoded(value))
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_three_valid_artifacts(self):
        for fixture, validator in ((authorization, validate_authorization), (binding, validate_binding), (receipt, validate_receipt)):
            with self.subTest(schema=fixture()["schema"]):
                value = validator(encoded(fixture()))
                self.assertEqual(value["schema"], fixture()["schema"])
                self.assertEqual(verify_artifact(encoded(fixture()))["status"], "PASS")

    def test_duplicate_keys_at_root_and_nested(self):
        for fixture in (authorization, binding, receipt):
            raw = encoded(fixture())
            for payload in (b'{"schema":"other",' + raw[1:], b'{"hidden":{"x":1,"x":2},' + raw[1:]):
                with self.assertRaises(ValidationError) as caught:
                    validate_artifact(payload)
                self.assertEqual(caught.exception.code, "DUPLICATE_KEY")

    def test_unknown_fields_and_exclusions_are_not_echoed(self):
        excluded = ("AX_tree", "screenshots", "approval_payload", "UI_text", "account_ids", "credentials",
                    "secrets", "private_home_paths", "private_repository_coordinates", "device_ids",
                    "previous_frontmost_bundle", "raw_instruction", "raw_exception", "transcript", "history")
        for fixture in (authorization, binding, receipt):
            for field in excluded:
                value = fixture()
                value[field] = "SYNTHETIC_PRIVATE_PAYLOAD_SENTINEL"
                error = self.assert_invalid(value, "UNKNOWN_FIELD")
                self.assertNotIn(field, str(error))
                self.assertNotIn(value[field], str(error))
        for fixture, name in ((authorization, "calculator"), (binding, "process_identity"), (receipt, "identity")):
            value = fixture()
            value[name]["unknown"] = "sentinel"
            self.assert_invalid(value, "UNKNOWN_FIELD")

    def test_wrong_types_and_missing_fields(self):
        for fixture in (authorization, binding, receipt):
            for field in fixture():
                value = fixture()
                del value[field]
                # idle_seconds is explicitly optional.
                if field != "idle_seconds":
                    self.assert_invalid(value, "UNSUPPORTED_SCHEMA" if field == "schema" else "MISSING_FIELD")
            value = fixture()
            value["schema"] = 1
            self.assert_invalid(value, "UNSUPPORTED_SCHEMA")
        for path, wrong in (("max_corrections", True), ("wall_clock_seconds", 1.0), ("steer_authorized", 1), ("authorized_roots", "/workspace")):
            value = authorization()
            value[path] = wrong
            self.assert_invalid(value, "WRONG_TYPE")
        for wrong in (True, 1.0, "42", None):
            value = binding()
            value["process_identity"]["pid"] = wrong
            self.assert_invalid(value, "WRONG_TYPE")

    def test_malformed_uuid_task_hash_process_and_provider_identity(self):
        for fixture in (authorization, binding):
            for field in ("run_id", "attempt_id"):
                for bad in (RUN.upper(), RUN.replace("-", ""), "00000000-0000-0000-0000-000000000000", "latest"):
                    # RUN contains only digits; use a UUID with uppercase hex instead.
                    bad = "aaaaaaaa-AAAA-4aaa-8aaa-aaaaaaaaaaaa" if bad == RUN.upper() else bad
                    value = fixture()
                    value[field] = bad
                    self.assert_invalid(value, "MALFORMED_UUID")
            for bad in ("", "a" * 65, "task with spaces", "path/to/task"):
                value = fixture()
                value["task_id"] = bad
                self.assert_invalid(value, "MALFORMED_IDENTIFIER")
        for field, bad in (("pid", 0), ("birth_ns", 0), ("executable_sha256", "A" * 64), ("launch_id", "latest")):
            value = binding()
            value["process_identity"][field] = bad
            self.assert_invalid(value)
        value = binding()
        value["process_identity"] = {"pid": 42}
        self.assert_invalid(value, "MISSING_FIELD")
        for field in ("thread_id", "turn_id"):
            value = binding()
            value[field] = RUN
            self.assert_invalid(value, "MALFORMED_UUID")
        for fixture in (authorization, binding):
            value = fixture()
            value["provider"] = "other"
            self.assert_invalid(value, "INVALID_ENUM")

    def test_payload_byte_ceilings_exact_and_over(self):
        for fixture, validator, ceiling in ((authorization, validate_authorization, AUTHORIZATION_MAX_BYTES),
                                            (binding, validate_binding, BINDING_MAX_BYTES),
                                            (receipt, validate_receipt, RECEIPT_MAX_BYTES)):
            raw = encoded(fixture())
            exact = raw + b" " * (ceiling - len(raw))
            self.assertTrue(validator(exact))
            with self.assertRaises(ValidationError) as caught:
                validator(exact + b" ")
            self.assertEqual(caught.exception.code, "PAYLOAD_TOO_LARGE")
        self.assertEqual(RECEIPT_MAX_BYTES, 16384)

    def test_json_errors_never_coerce_or_echo(self):
        for raw in (b"[]", b"null", b"\xff", b'{"secret":NaN}', b'{"secret":Infinity}', b'{"secret":', b'{"a":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"):
            with self.assertRaises(ValidationError):
                validate_artifact(raw)
        with self.assertRaises(ValidationError) as caught:
            validate_authorization(authorization())
        self.assertEqual(caught.exception.code, "WRONG_PAYLOAD_TYPE")

    def test_grant_bounds_defaults_and_steer(self):
        original = authorization()
        normalized = validate_authorization(encoded(original))
        self.assertFalse(normalized["calculator"]["mutate_preexisting"])
        self.assertNotIn("mutate_preexisting", original["calculator"])
        value = authorization()
        value["calculator"]["mutate_preexisting"] = False
        self.assertEqual(authorization_digest(encoded(original)), authorization_digest(encoded(value)))
        for field, bad in (("idle_seconds", 301), ("idle_seconds", 0), ("wall_clock_seconds", 0),
                           ("max_corrections", -1), ("max_corrections", 4)):
            value = authorization()
            value[field] = bad
            self.assert_invalid(value, "OUT_OF_RANGE")
        value = authorization()
        value["steer_authorized"] = False
        self.assert_invalid(value, "STEER_NOT_AUTHORIZED")
        value["max_corrections"] = 0
        self.assertTrue(validate_authorization(encoded(value)))
        del value["idle_seconds"]
        self.assertTrue(validate_authorization(encoded(value)))

    def test_paired_digest_normalization_near_input_ceiling(self):
        value = authorization()
        # A valid dense grant can grow when the false default is materialized.
        # Digest checking must not reapply the input byte ceiling to that view.
        target = AUTHORIZATION_MAX_BYTES - 2
        while len(encoded(value)) < target:
            index = len(value["worker_writable_roots"])
            needed = target - len(encoded(value)) - 3
            prefix = "/workspace/r%d/" % index
            path_size = min(1024, needed)
            self.assertGreaterEqual(path_size, len(prefix) + 1)
            value["worker_writable_roots"].append(prefix + "x" * (path_size - len(prefix)))
        self.assertEqual(len(encoded(value)), target)
        normalized = validate_authorization(encoded(value))
        self.assertGreater(len(encoded(normalized)), AUTHORIZATION_MAX_BYTES)
        bound = binding(value)
        self.assertEqual(verify_artifact(encoded(bound), authorization=encoded(value))["status"], "PASS")

    def test_scope_and_sandbox_are_explicit_lexical_policy(self):
        for path in ("/workspace/project/evidence", "/workspace", "/workspace/project"):
            value = authorization()
            value["provider_evidence_store"] = path
            self.assert_invalid(value, "WORKER_WRITABLE_AUTHORITY")
        for field in ("runtime_state_root", "controller_endpoint_root"):
            value = authorization()
            value[field] = "/workspace/project/control"
            self.assert_invalid(value, "WORKER_WRITABLE_AUTHORITY")
        for path in ("relative", "/workspace/../escape", "/workspace//project", "/workspace/project/", "/workspace/$ROOT"):
            value = authorization()
            value["workspace"] = path
            self.assert_invalid(value, "INVALID_SCOPE_PATH")
        value = authorization()
        value["worker_writable_roots"] = ["/ungranted"]
        self.assert_invalid(value, "OUTSIDE_AUTHORIZED_SCOPE")
        for fixture, name in ((authorization, "required_sandbox_posture"), (binding, "sandbox_posture")):
            for field in fixture()[name]:
                value = fixture()
                value[name][field] = False
                self.assert_invalid(value, "SANDBOX_REQUIRED")
        for enforcement in ("UNVERIFIED_PENDING_N6_N11", "OWNER_STAGED_GATE_ATTESTED"):
            value = binding()
            value["nested_start_enforcement"] = enforcement
            self.assertTrue(validate_binding(encoded(value)))
        for invalid in ("ASSUMED_SAFE", "ATTESTED", "OWNER_STAGED_GATE_UNVERIFIED"):
            value = binding()
            value["nested_start_enforcement"] = invalid
            self.assert_invalid(value, "INVALID_ENUM")

    def test_binding_phase_and_six_attestations(self):
        value = binding()
        value["turn_id"] = None
        self.assert_invalid(value, "WRONG_TYPE")
        value["binding_phase"] = "THREAD_BOUND"
        self.assertTrue(validate_binding(encoded(value)))
        value["turn_id"] = receipt()["identity"]["turn_id"]
        self.assert_invalid(value, "TURN_NOT_ESTABLISHED")
        for name in binding()["capabilities"]:
            value = binding()
            value["capabilities"][name] = False
            self.assert_invalid(value, "MISSING_ATTESTATION")

    def test_domain_separated_identity_refs(self):
        expected = hashlib.sha256(b"session-preserve/runtime/identity-ref/v1\0run\0" + encoded(RUN)).hexdigest()
        self.assertEqual(identity_ref("run", RUN), expected)
        self.assertNotEqual(identity_ref("run", RUN), identity_ref("attempt", RUN))
        process = binding()["process_identity"]
        reordered = dict(reversed(list(process.items())))
        self.assertEqual(identity_ref("process", process), identity_ref("process", reordered))
        changed = dict(process, birth_ns=101)
        self.assertNotEqual(identity_ref("process", process), identity_ref("process", changed))
        with self.assertRaises(ValidationError):
            identity_ref("unknown", RUN)

    def test_socket_and_call_refs_have_typed_separate_domains(self):
        socket_identity = {"run_id": RUN, "attempt_id": authorization()["attempt_id"], "handle_nonce": RUN, "inode": 123}
        expected = hashlib.sha256(b"session-preserve/runtime/identity-ref/v1\0socket\0" + encoded(socket_identity)).hexdigest()
        self.assertEqual(identity_ref("socket", socket_identity), expected)
        self.assertNotEqual(identity_ref("socket", socket_identity), identity_ref("socket", dict(socket_identity, inode=124)))
        self.assertNotEqual(identity_ref("call", RUN), identity_ref("run", RUN))
        with self.assertRaises(ValidationError):
            identity_ref("socket", dict(socket_identity, inode=True))
        with self.assertRaises(ValidationError):
            identity_ref("socket", dict(socket_identity, path="/authority/socket"))

    def test_correction_requires_established_turn(self):
        value = receipt()
        value["identity"].update(binding_phase="THREAD_BOUND", turn_id=None)
        self.assertTrue(validate_receipt(encoded(value)))
        value.update(corrections=[correction()], correction_count=1)
        self.assert_invalid(value, "CORRECTION_REQUIRES_TURN")

    def test_correction_resource_and_call_bounds(self):
        value = receipt()
        value["corrections"] = [correction(i, "REJECTED") for i in range(1, 33)]
        self.assertTrue(validate_receipt(encoded(value)))
        value["corrections"].append(correction(33, "REJECTED"))
        self.assert_invalid(value, "TOO_MANY_RECORDS")
        value = receipt()
        value["cleanup"]["owned_resources"] = [
            {"kind": "HELPER", "identity_ref": "%064x" % i, "outcome": "NOT_REQUESTED",
             "exact_identity_verified": False, "absence_verified": False} for i in range(16)]
        self.assertTrue(validate_receipt(encoded(value)))
        value["cleanup"]["owned_resources"].append(copy.deepcopy(value["cleanup"]["owned_resources"][0]))
        self.assert_invalid(value, "TOO_MANY_RECORDS")
        value = receipt()
        value["provider_calls"] = [{"kind": "SCHEMA_READ", "outcome": "OBSERVED"} for _ in range(128)]
        self.assertTrue(validate_receipt(encoded(value)))
        value["provider_calls"].append(dict(value["provider_calls"][0]))
        self.assert_invalid(value, "TOO_MANY_RECORDS")

    def test_correction_evidence_levels_and_relative_exhaustion(self):
        for level in ("ACCEPTED", "PERSISTED", "CONSUMED", "REJECTED", "UNCERTAIN"):
            value = receipt()
            value["corrections"] = [correction(level=level)]
            value["correction_count"] = int(level != "REJECTED")
            if level in ("ACCEPTED", "UNCERTAIN"):
                value["execution_ambiguous"] = True
                value["ambiguity_reasons"] = ["ACCEPTED_NOT_PERSISTED" if level == "ACCEPTED" else "UNCERTAIN_CORRECTION"]
            self.assertTrue(validate_receipt(encoded(value)))
        for maximum in range(4):
            value = receipt()
            value.update(state="STOPPED", decision="CORRECTIONS_EXHAUSTED", correction_maximum=maximum,
                         correction_count=maximum, corrections=[correction(i) for i in range(1, maximum + 1)])
            self.assertTrue(validate_receipt(encoded(value)))
        value["correction_count"] = 2
        value["corrections"] = value["corrections"][:2]
        self.assert_invalid(value, "CORRECTIONS_NOT_EXHAUSTED")

    def test_accepted_without_persistence_even_at_terminal_is_ambiguous(self):
        value = receipt()
        value.update(state="COMPLETED", decision="PROVIDER_COMPLETED", provider_terminal_fact="COMPLETED",
                     corrections=[correction(level="ACCEPTED")], correction_count=1)
        self.assert_invalid(value, "ACCEPTED_NOT_PERSISTED_IS_AMBIGUOUS")
        value.update(execution_ambiguous=True, ambiguity_reasons=["ACCEPTED_NOT_PERSISTED"])
        self.assertTrue(validate_receipt(encoded(value)))

    def test_stopped_decision_is_separate_from_late_provider_fact(self):
        value = receipt()
        value.update(state="STOPPED", decision="REQUESTED_STOP", provider_terminal_fact="COMPLETED")
        self.assertTrue(validate_receipt(encoded(value)))
        value["decision"] = "PROVIDER_COMPLETED"
        self.assert_invalid(value, "INVALID_ENUM")
        value = receipt()
        value.update(state="AMBIGUOUS", decision="CONTROLLER_LOST")
        self.assert_invalid(value, "AMBIGUITY_REQUIRED")
        value.update(execution_ambiguous=True, ambiguity_reasons=["CONTROLLER_LOSS"])
        self.assertTrue(validate_receipt(encoded(value)))

    def test_uncertainty_retains_positive_facts_and_rejection_release_needs_proof(self):
        value = receipt()
        row = correction(level="ACCEPTED")
        row["level"] = "UNCERTAIN"
        value.update(corrections=[row], correction_count=1, execution_ambiguous=True,
                     ambiguity_reasons=["ACCEPTED_NOT_PERSISTED", "UNCERTAIN_CORRECTION"])
        self.assertTrue(validate_receipt(encoded(value)))
        row["reservation_released"] = True
        self.assert_invalid(value, "RESERVATION_RELEASE_INVALID")
        value = receipt()
        value["corrections"] = [correction(level="REJECTED")]
        value["corrections"][0]["non_delivery_proven"] = False
        self.assert_invalid(value, "RESERVATION_RELEASE_INVALID")

    def test_duplicate_logical_ids_and_evidence_order(self):
        value = receipt()
        value.update(corrections=[correction(), correction()], correction_count=2)
        self.assert_invalid(value, "DUPLICATE_CORRECTION")
        value = receipt()
        value.update(corrections=[correction()], correction_count=1)
        value["corrections"][0]["persisted"] = False
        self.assert_invalid(value, "CORRECTION_EVIDENCE_ORDER")

    def test_calculator_authority_session_approval_fixed_keys_and_snapshot_bound(self):
        value = receipt()
        calc = value["calculator"]
        calc["authorization"].update(observe=True, mutate=True, foreground=True)
        calc.update(approval_count=1, click_count=1, click_schema_string=True, keys=["One"])
        value["provider_calls"] = [{"kind": "CALCULATOR_CLICK", "outcome": "ACCEPTED"}]
        self.assert_invalid(value, "CLICK_AUTHORITY_REQUIRED")
        calc["session_proof"] = "CURRENT_SESSION"
        self.assertTrue(validate_receipt(encoded(value)))
        for field, bad, code in (("approval_count", 0, "SESSION_APPROVAL_REQUIRED"), ("approval_count", 2, "OUT_OF_RANGE"),
                                 ("persistent_approval", True, "PERSISTENT_APPROVAL_FORBIDDEN"),
                                 ("maximum_snapshot_age_ms", 1001, "OUT_OF_RANGE"), ("keys", ["Browser"], "INVALID_ENUM")):
            trial = copy.deepcopy(value)
            trial["calculator"][field] = bad
            self.assert_invalid(trial, code)
        for key in ("Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Add", "Equals", "Clear"):
            calc["keys"] = [key]
            self.assertTrue(validate_receipt(encoded(value)))
        calc["calculator_preexisting"] = True
        self.assert_invalid(value, "PREEXISTING_MUTATION_FORBIDDEN")
        calc["authorization"]["mutate_preexisting"] = True
        self.assertTrue(validate_receipt(encoded(value)))
        calc["authorization"]["foreground"] = False
        self.assert_invalid(value, "CALCULATOR_AUTHORITY_REQUIRED")

    def test_cleanup_grace_counts_preexisting_and_restoration(self):
        value = receipt()
        value["cleanup"]["grace_seconds"] = 6
        self.assert_invalid(value, "OUT_OF_RANGE")
        value["cleanup"]["grace_seconds"] = 5
        value["cleanup"].update(requested=True, released=1, verified=True, owned_resources=[
            {"kind": "CALCULATOR", "identity_ref": "a" * 64, "outcome": "RELEASED", "exact_identity_verified": True, "absence_verified": True}])
        self.assertTrue(validate_receipt(encoded(value)))
        value["calculator"]["calculator_preexisting"] = True
        self.assert_invalid(value, "PREEXISTING_CLEANUP_FORBIDDEN")
        value = receipt()
        value["cleanup"]["foreground_restored"] = True
        self.assert_invalid(value, "RESTORE_AUTHORITY_REQUIRED")

    def test_explicit_pairs_check_digests_all_refs_and_grant(self):
        grant, bound = authorization(), binding()
        rec = receipt(grant, bound)
        verified = verify_artifact(encoded(rec), authorization=encoded(grant), binding=encoded(bound))
        self.assertEqual(verified["paired_checks"], ["authorization_binding", "authorization_receipt", "binding_receipt"])
        for field in ("task_ref", "run_ref", "attempt_ref", "process_ref"):
            trial = copy.deepcopy(rec)
            trial["identity"][field] = "b" * 64
            with self.assertRaises(ValidationError) as caught:
                verify_artifact(encoded(trial), authorization=encoded(grant), binding=encoded(bound))
            self.assertEqual(caught.exception.code, "IDENTITY_REF_MISMATCH")
        for field, code in (("authorization_sha256", "AUTHORIZATION_DIGEST_MISMATCH"), ("binding_sha256", "BINDING_DIGEST_MISMATCH")):
            trial = copy.deepcopy(rec)
            trial[field] = "b" * 64
            with self.assertRaises(ValidationError) as caught:
                verify_artifact(encoded(trial), authorization=encoded(grant), binding=encoded(bound))
            self.assertEqual(caught.exception.code, code)
        changed = dict(grant, max_corrections=2)
        with self.assertRaises(ValidationError):
            verify_artifact(encoded(bound), authorization=encoded(changed))

    def test_pass_explicitly_does_not_attest_execution(self):
        value = verify_artifact(encoded(receipt()))
        self.assertFalse(value["execution_attested"])
        for wording in ("does not attest", "run occurred", "provider/GUI facts are authentic", "execution succeeded"):
            self.assertIn(wording, value["semantics"])
        self.assertEqual(value["unverified_pairs"], ["authorization", "binding"])


if __name__ == "__main__":
    unittest.main()
