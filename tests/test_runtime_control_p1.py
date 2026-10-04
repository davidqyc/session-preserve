"""P1 evidence uses only invented RTCA/protocol fixtures, never a provider turn."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

from codex_preserve.runtime_control import ValidationError, validate_receipt, verify_artifact
from codex_preserve.runtime_control._rtca import (SUPPORTED_RUNTIME_SET, validate_rtca, load_supported,
    digest, SealedAdmission, bytes_digest, materialize_pinned, CATEGORIES)
from codex_preserve.runtime_control._canary import ConfinementCanary
from codex_preserve.runtime_control._engine import P1Controller
from codex_preserve.runtime_control._proof import CompositeProof, ActiveFreeze, inventory
from codex_preserve.runtime_control._state import (canonical_roots, trusted_read, publish_once,
    exclusive, resolved_scope, RunStore)
from codex_preserve.runtime_control import _commands
from tests.runtime_fixtures import encoded, THREAD, TURN
from tests.runtime_p1_fixtures import rtca, review, sealed, Fixture, SyntheticDriver, SyntheticRoute


class RTCAContract(unittest.TestCase):
    def check(self, value):
        payload = encoded(value)
        return validate_rtca(payload, review(payload, value))

    def assertCode(self, code, fn):
        with self.assertRaises(ValidationError) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def test_registry_is_empty_and_fixture_not_discoverable(self):
        self.assertEqual(SUPPORTED_RUNTIME_SET, ())
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "supported-rtca.json").write_bytes(encoded(rtca()))
            with mock.patch.dict(os.environ, {"SESSION_PRESERVE_RTCA": temp, "SUPPORTED_RUNTIME_SET": temp,
                                             "CODEX_RUNTIME_DIGEST": "a" * 64}):
                self.assertCode("RUNTIME_DIGEST_UNSUPPORTED", lambda: load_supported("codex-app-server-r1", sys.platform, "a" * 64))

    def test_valid_fixture_and_conditional_null_inventory(self):
        for unified in (True, False):
            self.assertEqual(self.check(rtca(unified=unified)), rtca(unified=unified))

    def test_exact_bytes_and_receipt_identity(self):
        value = rtca(); payload = encoded(value); receipt = review(payload, value)
        self.assertCode("RTCA_INVALID", lambda: validate_rtca(payload + b" ", receipt))
        for field, replacement in (("rtca_sha256", "f" * 64), ("reviewer", value["author"]),
                                   ("independence", "I1"), ("derivations", []), ("review_id", "other-review")):
            changed = json.loads(receipt); changed[field] = replacement
            with self.subTest(field=field):
                self.assertCode("RTCA_INVALID", lambda: validate_rtca(payload, encoded(changed)))
        admission = sealed(value, SyntheticDriver)
        admission.review_payload += b" "
        self.assertCode("RTCA_INVALID", admission.load_verified)

    def test_strict_bounds_and_duplicate_json(self):
        for payload in (b"x" * (256 * 1024 + 1), b'{"schema":1,"schema":2}', b'{"schema":NaN}', b"[]"):
            self.assertCode("RTCA_INVALID", lambda: validate_rtca(payload, b"{}"))
        value = rtca(); value["unknown"] = True
        self.assertCode("RTCA_INVALID", lambda: self.check(value))

    def test_source_correspondence_is_required(self):
        for replacement in ("VERSION_STRING", "SIGNATURE_ONLY", "SYMBOLS_ONLY"):
            value = rtca(); value["source"]["correspondence"]["kind"] = replacement
            self.assertCode("SOURCE_CORRESPONDENCE_NOT_ATTESTED", lambda: self.check(value))
        value = rtca(); value["source"]["correspondence"]["executable_sha256"] = "f" * 64
        self.assertCode("SOURCE_CORRESPONDENCE_NOT_ATTESTED", lambda: self.check(value))
        value = rtca(); del value["source"]["correspondence"]
        self.assertCode("RTCA_INVALID", lambda: self.check(value))

    def test_surface_count_digest_method_and_inventory_reclassification(self):
        for field, replacement in (("count", 1), ("digest", "0" * 64)):
            value = rtca(); value["method_surface"][field] = replacement
            self.assertCode("METHOD_SURFACE_MISMATCH", lambda: self.check(value))
        value = rtca(); value["exact_thread_tool_inventory_method"] = None
        self.assertCode("UNIFIED_INVENTORY_REQUIRED", lambda: self.check(value))
        value = rtca(); value["method_surface"]["methods"] = [m for m in value["method_surface"]["methods"] if m["name"] != "turn/start"]
        value["method_surface"]["count"] -= 1
        value["method_surface"]["digest"] = digest("rtca-method-surface/v1", value["method_surface"]["methods"])
        self.assertCode("METHOD_NOT_ATTESTED", lambda: self.check(value))

    def test_construction_categories_closure_and_gates(self):
        value = rtca(); value["dispatch_closure"]["unknown_dispatch"] = True
        self.assertCode("DISPATCH_CLOSURE_NOT_ATTESTED", lambda: self.check(value))
        value = rtca(); del value["capability_gates"]["managed_requirements"]
        self.assertCode("CAPABILITY_GATE_NOT_CLOSED", lambda: self.check(value))
        for category in CATEGORIES:
            value = rtca(); value["capability_gates"][category]["basis"] = "UNOBSERVABLE"
            self.assertCode("CAPABILITY_GATE_NOT_CLOSED", lambda: self.check(value))
        value = rtca(); value["attested_tools"][0]["category"] = "computer_use"
        self.assertCode("RTCA_INVALID", lambda: self.check(value))

    def test_fallback_requires_exact_policy_and_digest_equivalence(self):
        value = rtca(); route = value["confinement"]; route["route"] = "EQUIVALENT_FALLBACK"
        self.assertCode("RTCA_INVALID", lambda: self.check(value))
        route["equivalence"] = {"executable_sha256": value["executable_sha256"], "policy_digest": route["policy_digest"],
                                "evidence": copy.deepcopy(route["evidence"])}
        self.check(value)
        route["equivalence"]["policy_digest"] = "f" * 64
        self.assertCode("CONFINEMENT_ROUTE_NOT_ATTESTED", lambda: self.check(value))


class P1FixtureCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sp-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name)
        self.controller = None

    def create(self, production=False):
        self.f.stage()
        self.controller = P1Controller(self.f.store, self.f.observer) if production else P1Controller(self.f.store, self.f.observer, self.f.loader)
        self.addCleanup(self.close)
        return self.controller

    def close(self):
        c = self.controller
        if c is not None and c.run is not None:
            if c.run._lock is not None:
                if not c.run.terminal and c.bound:
                    c.stop()
                else:
                    c.run.release_lock()
            if c.endpoint and c.endpoint.socket:
                c.endpoint.close()

    def assertCode(self, code, fn):
        with self.assertRaises(ValidationError) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def start(self):
        c = self.create()
        c.start(self.f.grant["run_id"], self.f.executable)
        return c

    def direct(self):
        run = self.f.state / self.f.grant["run_id"]
        run.mkdir(mode=0o700, exist_ok=True); (run / "provider-state").mkdir(mode=0o700, exist_ok=True)
        driver = SyntheticDriver(executable=self.f.executable, launch_id=str(uuid.uuid4()),
                    authorization=self.f.grant, rtca=self.f.record, observer=self.f.observer)
        driver.launch()
        return CompositeProof(self.f.record, driver, self.f.grant, ConfinementCanary()), driver


class CompositeContract(P1FixtureCase):
    def test_all_eleven_components_before_binding(self):
        proof, driver = self.direct()
        thread, identity, freeze = proof.establish()
        self.assertEqual(thread, THREAD)
        self.assertEqual(len(proof.components), 11)
        self.assertTrue(freeze.armed); self.assertFalse(freeze.bound)
        self.assertFalse(any(method == "turn/start" for method, _ in driver.calls))
        self.assertEqual(len(driver.canary_specs), 1)
        self.assertCode("PROOF_REUSE_FORBIDDEN", proof.establish)

    def test_each_pinned_field_drift_including_reasoning(self):
        proof, driver = self.direct()
        original = driver.pinned_inputs
        for field in original():
            with self.subTest(field=field):
                value = original(); value[field] = "DRIFT"
                driver.pinned_inputs = lambda: value
                p = CompositeProof(self.f.record, driver, self.f.grant, ConfinementCanary())
                self.assertCode("RTCA_NOT_APPLICABLE", p.establish)
        driver.pinned_inputs = original

    def test_runtime_version_digest_and_surface_drift(self):
        proof, d = self.direct()
        d.process["executable_sha256"] = "f" * 64
        self.assertCode("RUNTIME_IDENTITY_MISMATCH", proof.establish)
        d.process["executable_sha256"] = self.f.record["executable_sha256"]
        d.method_surface = lambda: []
        self.assertCode("METHOD_SURFACE_MISMATCH", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())
        d.method_surface = lambda: self.f.record["method_surface"]["methods"]
        d.hook = lambda method, params: {"runtimeVersion": "0.0.1"} if method == "initialize" else None
        self.assertCode("RUNTIME_VERSION_MISMATCH", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())

    def test_instance_isolation_each_dimension(self):
        proof, d = self.direct()
        original = d.observe_instance
        for field, bad in (("fresh", False), ("transport", "unix"), ("sole_client", False),
                           ("state_root", "/other"), ("thread_ids", [THREAD]), ("instance_id", "other")):
            d.observe_instance = lambda: dict(original(), **{field: bad})
            self.assertCode("INSTANCE_ISOLATION_NOT_ATTESTED", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())
        d.observe_instance = original
        d.hook = lambda method, params: {"data": [{"id": THREAD}, {"id": TURN}], "nextCursor": None} if method == "thread/loaded/list" else None
        self.assertCode("INSTANCE_ISOLATION_NOT_ATTESTED", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())

    def test_thread_response_each_load_bearing_field(self):
        proof, d = self.direct()
        original = d.request
        for field in ("cwd", "model", "modelProvider", "reasoningEffort", "sandbox", "approvalPolicy", "approvalsReviewer",
                      "activePermissionProfile", "runtimeWorkspaceRoots"):
            d.thread_ids = []
            def request(method, params):
                v = original(method, params)
                if method == "thread/start":
                    v[field] = "DRIFT"
                return v
            d.request = request
            with self.subTest(field=field):
                self.assertCode("THREAD_POSTURE_MISMATCH", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())
        self.assertEqual(d.canary_specs, [])

    def test_every_capability_gate_missing_or_open(self):
        proof, d = self.direct()
        original = d.capability_observations
        for category in CATEGORIES:
            for mode in ("missing", "open"):
                d.thread_ids = []
                value = original(THREAD)
                if mode == "missing": del value[category]
                else: value[category] = "OPEN"
                d.capability_observations = lambda _: value
                self.assertCode("CAPABILITY_GATE_NOT_CLOSED", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())

    def test_mcp_fully_paginated_and_any_entry_refused(self):
        proof, d = self.direct()
        d.hook = lambda method, params: ({"data": [], "nextCursor": "page2" if params["cursor"] is None else None}
                                       if method == "mcpServerStatus/list" else None)
        proof.establish()
        calls = [p for m, p in d.calls if m == "mcpServerStatus/list"]
        self.assertEqual([p["cursor"] for p in calls], [None, "page2"])
        self.assertTrue(all(p["threadId"] == THREAD and p["detail"] == "Full" for p in calls))
        proof, d = self.direct()
        d.hook = lambda method, params: {"data": [{"name": "synthetic-server"}], "nextCursor": None} if method == "mcpServerStatus/list" else None
        self.assertCode("MCP_INVENTORY_NOT_CLOSED", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())

    def test_inventory_repeated_cursor_missing_cursor_error_and_bound(self):
        for page in ({"data": [], "nextCursor": "same"}, {"data": []}, {"error": {}},
                     {"data": [0] * 65, "nextCursor": None}, {"data": [], "nextCursor": ""}):
            self.assertCode("MCP_INVENTORY_NOT_CLOSED", lambda: inventory(lambda m, p: page, "mcpServerStatus/list", {}, "MCP_INVENTORY_NOT_CLOSED"))
        count = [0]
        def pages(m, p):
            count[0] += 1
            return {"data": [], "nextCursor": str(count[0])}
        self.assertCode("MCP_INVENTORY_NOT_CLOSED", lambda: inventory(pages, "mcpServerStatus/list", {}, "MCP_INVENTORY_NOT_CLOSED"))
        self.assertEqual(count[0], 64)

    def test_unified_inventory_mandatory_full_pagination(self):
        proof, d = self.direct()
        def hook(method, params):
            if method == "thread/testToolInventory":
                first = params["cursor"] is None
                t = self.f.record["attested_tools"][0 if first else 1]
                return {"data": [{"name": t["name"], "category": t["category"]}], "nextCursor": "next" if first else None}
        d.hook = hook; proof.establish()
        self.assertEqual(len([m for m, p in d.calls if m == "thread/testToolInventory"]), 2)
        self.assertTrue(all(p["threadId"] == THREAD for m, p in d.calls if m == "thread/testToolInventory"))

    def test_unified_inventory_incomplete_forbidden_and_unattested(self):
        proof, d = self.direct()
        for tools in ([], [{"name": "exec_command", "category": "shell"}],
                      [{"name": "screen", "category": "computer_use"}], [{"name": "unknown", "category": "shell"}]):
            d.thread_ids = []
            d.hook = lambda method, params: {"data": tools, "nextCursor": None} if method == "thread/testToolInventory" else None
            self.assertCode("UNIFIED_INVENTORY_NOT_CLOSED", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())
        self.assertEqual(d.canary_specs, [])

    def test_null_unified_inventory_only_when_surface_classifies_absent(self):
        proof, d = self.direct()
        self.f.record = rtca(self.f.record["executable_sha256"], unified=False); d.rtca = self.f.record
        CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish()
        self.assertFalse(any(m == "thread/testToolInventory" for m, p in d.calls))

    def test_plugin_stability_empty_contribution_and_uncloseable(self):
        proof, d = self.direct()
        d.before_plugins = {"data": [{"id": "synthetic-text-only", "tools": [], "skills": [], "hooks": []}]}
        proof.establish()
        proof, d = self.direct()
        for plugin in ({"tools": ["shell"], "skills": [], "hooks": []}, {"tools": [], "skills": [], "hooks": ["hook"]}, {}):
            d.thread_ids = []; d.before_plugins = {"data": [plugin]}
            self.assertCode("PLUGIN_CAPABILITY_PRESENT", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())
        d.thread_ids = []; d.before_plugins = {"data": []}
        d.hook = lambda method, params: {"data": [1]} if method == "plugin/installed" and d.thread_ids else None
        self.assertCode("PLUGIN_STATE_DRIFT", lambda: CompositeProof(self.f.record, d, self.f.grant, ConfinementCanary()).establish())

    def test_tripwire_missing_blocks_binding(self):
        proof, d = self.direct()
        d.tripwire_armed = lambda _: False
        self.assertCode("TRIPWIRE_NOT_ARMED", proof.establish)


class CanaryContract(P1FixtureCase):
    def setup_canary(self):
        proof, driver = self.direct()
        route = driver.canary_route(THREAD)
        return driver, route

    def canary(self, route):
        return ConfinementCanary().run(rtca=self.f.record, authorization=self.f.grant, thread_id=THREAD,
                                       instance_id=route.instance_id, route=route)

    def assertClean(self):
        self.assertEqual(list(self.f.root.rglob("canary-*")), [])
        self.assertEqual(list(self.f.endpoint.iterdir()), [])

    def test_four_denials_positive_control_and_no_reuse(self):
        driver, route = self.setup_canary()
        canary = ConfinementCanary()
        results = [canary.run(rtca=self.f.record, authorization=self.f.grant, thread_id=THREAD,
                             instance_id=route.instance_id, route=route) for _ in range(2)]
        self.assertEqual([r["check"] for r in results], ["PASS", "PASS"])
        self.assertNotEqual(results[0]["nonce_ref"], results[1]["nonce_ref"])
        self.assertEqual(len(driver.canary_specs), 2)
        self.assertClean()

    def test_each_errno_denial_failure_is_deterministic(self):
        d, route = self.setup_canary(); original = route.execute_probe
        for operation in ("append", "create", "unix", "tcp"):
            def execute(program, spec, timeout):
                response = original(program, spec, timeout); value = json.loads(response["stdout"])
                next(r for r in value["denials"] if r["operation"] == operation)["errno"] = 13
                response["stdout"] = encoded(value); return response
            route.execute_probe = execute
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: self.canary(route))
            self.assertEqual(error.reason, "ERRNO_" + operation.upper()); self.assertClean()

    def test_route_each_attribution_field(self):
        d, route = self.setup_canary()
        for field in ("thread_id", "executable_sha256", "policy_digest", "method", "backend", "route_kind"):
            old = getattr(route, field); setattr(route, field, "wrong")
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: self.canary(route))
            self.assertEqual(error.reason, "ROUTE_ATTRIBUTION"); setattr(route, field, old)
        self.assertEqual(d.canary_specs, []); self.assertClean()

    def test_timeout_helper_positive_shape_and_nonce_failures(self):
        d, route = self.setup_canary(); original = route.execute_probe
        for mode, reason in (("timeout", "TIMEOUT"), ("helper", "HELPER_ABSENCE"), ("nonce", "RESULT_IDENTITY"),
                             ("shape", "RESULT_SHAPE"), ("positive", "POSITIVE_CONTROL"), ("bytes", "POSITIVE_BYTES")):
            def execute(program, spec, timeout):
                if mode == "timeout": raise TimeoutError()
                response = original(program, spec, timeout); value = json.loads(response["stdout"])
                if mode == "helper": response["helper_absent"] = False
                elif mode == "nonce": value["nonce"] = "wrong"
                elif mode == "shape": value["denials"] = []
                elif mode == "positive": value["positive_errno"] = 1
                elif mode == "bytes": Path(json.loads(spec)["positive"]).write_bytes(b"wrong")
                response["stdout"] = encoded(value); return response
            route.execute_probe = execute
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: self.canary(route))
            self.assertEqual(error.reason, reason); self.assertClean()

    def test_digest_target_and_listener_postchecks(self):
        d, route = self.setup_canary(); original = route.execute_probe
        for mode, reason in (("digest", "PROTECTED_DIGEST"), ("target", "PROTECTED_TARGET"),
                             ("unix", "LISTENER_CONNECTION"), ("tcp", "LISTENER_CONNECTION")):
            def execute(program, spec_bytes, timeout):
                result = original(program, spec_bytes, timeout); spec = json.loads(spec_bytes)
                if mode == "digest": Path(spec["protected"][0]["file"]).write_bytes(b"mutated")
                elif mode == "target": Path(spec["protected"][0]["target"]).write_bytes(b"mutated")
                else:
                    family = socket.AF_UNIX if mode == "unix" else socket.AF_INET
                    address = spec["unix"] if mode == "unix" else ("127.0.0.1", spec["port"])
                    with socket.socket(family, socket.SOCK_STREAM) as connection: connection.connect(address)
                return result
            route.execute_probe = execute
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: self.canary(route))
            self.assertEqual(error.reason, reason); self.assertClean()

    def test_setup_dac_and_cleanup_failures(self):
        d, route = self.setup_canary()
        with mock.patch("codex_preserve.runtime_control._canary._drain", return_value=0):
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: self.canary(route))
            self.assertEqual(error.reason, "DAC_ATTRIBUTION")
        self.assertClean()
        original = Path.unlink
        def refuse_positive(path, *a, **kw):
            if path.parent == self.f.workspace: raise OSError()
            return original(path, *a, **kw)
        with mock.patch.object(Path, "unlink", refuse_positive):
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: self.canary(route))
            self.assertEqual(error.reason, "CLEANUP")
        # Test-only removal of failed probe residue; production start is blocked.
        for p in self.f.root.rglob("canary-*"):
            if p.is_file(): p.unlink()
        for p in sorted(self.f.root.rglob("canary-*"), reverse=True):
            if p.is_dir():
                for child in p.iterdir(): child.unlink()
                p.rmdir()
        self.assertClean()

    def test_unsandboxed_command_route_is_rejected_without_model(self):
        d, route = self.setup_canary()
        def execute(program, spec, timeout):
            response = subprocess.run([sys.executable, "-B", "-c", program, spec.decode()],
                                      capture_output=True, timeout=timeout)
            return {"stdout": response.stdout, "helper_absent": response.returncode is not None}
        route.execute_probe = execute
        error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: self.canary(route))
        self.assertEqual(error.reason, "ERRNO_APPEND"); self.assertClean()


class ControllerContract(P1FixtureCase):
    def test_unknown_real_digest_burns_without_turn_or_binding(self):
        c = self.create(production=True)
        self.assertCode("RUNTIME_DIGEST_UNSUPPORTED", lambda: c.start(self.f.grant["run_id"], self.f.executable))
        self.assertEqual(c.run.terminal["state"], "START_FAILED_BEFORE_BINDING")
        self.assertEqual(c.run.resources(), [])
        self.assertFalse((c.run.directory / "receipt.json").exists())
        self.assertFalse((c.run.directory / "binding.json").exists())
        self.assertEqual(self.f.drivers, [])
        self.f.stage()
        self.assertCode("RUN_ALREADY_EXISTS", lambda: P1Controller(self.f.store, self.f.observer).start(self.f.grant["run_id"], self.f.executable))

    def test_binding_publication_follows_all_proof_and_freeze(self):
        c = self.start()
        self.assertTrue(c.freeze.armed); self.assertTrue(c.freeze.bound)
        self.assertTrue(c.driver.tripwire); self.assertEqual(len(c.driver.canary_specs), 1)
        records = c.run.records()
        self.assertEqual([v["event"] for v in records].count("BINDING_FLUSHED"), 1)
        self.assertFalse(any(m == "turn/start" for m, p in c.driver.calls))
        verify_artifact((c.run.directory / "binding.json").read_bytes(), authorization=encoded(self.f.grant))

    def test_calculator_all_grant_bits_precede_reservation(self):
        for bit in ("observe", "mutate", "mutate_preexisting", "foreground", "restore_foreground"):
            grant = copy.deepcopy(self.f.grant)
            if bit == "mutate_preexisting": grant["calculator"].update(observe=True, foreground=True, mutate=True)
            if bit == "mutate": grant["calculator"].update(observe=True, foreground=True)
            if bit == "restore_foreground": grant["calculator"]["foreground"] = True
            grant["calculator"][bit] = True
            self.f.grant = grant; self.f.stage()
            self.assertCode("CALCULATOR_NOT_AUTHORIZED_P1", lambda: self.f.store.authorization(grant["run_id"]))
            self.assertFalse((self.f.state / grant["run_id"]).exists())
            self.f.grant["calculator"] = {k: False for k in grant["calculator"]}

    def test_local_only_freeze_all_mutations_and_overrides(self):
        c = self.start(); d = c.driver; before = copy.deepcopy(d.calls)
        denied = ("thread/settings/update", "turn/steer", "config/value/write", "config/batchWrite", "config/mcpServer/reload",
                  "experimentalFeature/enablement/set", "plugin/install", "plugin/enable", "thread/start", "thread/resume", "thread/fork")
        for method in denied:
            self.assertCode("ACTIVE_METHOD_REFUSED", lambda: c.freeze.request(method, {"threadId": THREAD}))
        for field in ("sandbox", "sandboxPolicy", "cwd", "approvalPolicy", "approvalsReviewer", "disabledPluginIds", "model",
                      "modelProvider", "reasoningEffort", "config", "features", "tools"):
            self.assertCode("ACTIVE_METHOD_REFUSED", lambda: c.freeze.request("turn/start", {"threadId": THREAD, "input": [], field: "override"}))
        self.assertEqual(d.calls, before)

    def test_tripwire_interrupt_then_stop_suspend_and_no_repeat_release(self):
        c = self.start(); c.freeze.turn_id = TURN
        result = c.tool_event({"name": "screen", "category": "computer_use", "thread_id": THREAD, "turn_id": TURN})
        self.assertEqual(result["code"], "ATTESTED_TOOL_SET_VIOLATION_OBSERVED")
        self.assertEqual(c.driver.calls[-1][0], "turn/interrupt")
        self.assertTrue(c.store.suspended(c.admission.rtca_sha256, c.rtca["review_id"]))
        self.assertEqual(len(self.f.observer.releases), 1)
        records = c.run.records(); terminal = next(i for i, v in enumerate(records) if v["event"] == "TERMINAL")
        self.assertTrue(all(i > terminal for i, v in enumerate(records) if v["event"] == "RELEASE_INTENT"))
        c.stop(); self.assertEqual(len(self.f.observer.releases), 1)
        receipt = validate_receipt((c.run.directory / "receipt.json").read_bytes())
        self.assertEqual(receipt["decision"], "CAPABILITY_UNAVAILABLE")
        self.f.grant["run_id"] = str(uuid.uuid4()); self.f.grant["attempt_id"] = str(uuid.uuid4())
        self.f.grant["provider_evidence_store"] = str(self.f.state / self.f.grant["run_id"] / "provider-state")
        self.f.stage(); other = P1Controller(self.f.store, self.f.observer, self.f.loader)
        self.assertCode("RTCA_SUSPENDED", lambda: other.start(self.f.grant["run_id"], self.f.executable))
        self.assertEqual(len(self.f.drivers), 1)

    def test_every_violation_category_trips_and_exact_allowed_tool_passes(self):
        c = self.start(); c.freeze.turn_id = TURN
        allowed = {"name": "exec_command", "category": "shell", "thread_id": THREAD, "turn_id": TURN}
        c.tool_event(allowed); self.assertFalse(c.run.terminal)
        # Category/name/identity spoofing cannot turn dynamic/meta into shell.
        c.tool_event(dict(allowed, category="dynamic")); self.assertTrue(c.run.terminal)

    def test_controller_provider_client_loss_are_distinct_and_sticky(self):
        c = self.start()
        self.assertEqual(c.loss("COORDINATOR_OR_CLIENT_LOSS")["status"], "RUNNING")
        c.loss("PROVIDER_CONNECTION_LOSS")
        self.assertEqual(c.state, "AMBIGUOUS"); self.assertEqual(c.decision, "TRANSPORT_LOST")
        self.assertIn("TRANSPORT_LOSS", c.reasons)
        self.assertEqual(c.reconcile()["status"], "AMBIGUOUS")
        c.loss("CONTROLLER_LOSS")
        self.assertEqual(c.decision, "CONTROLLER_LOST"); self.assertIn("CONTROLLER_LOSS", c.reasons)
        self.assertCode("SIDE_EFFECTS_FROZEN", lambda: c.send_initial_input("synthetic text"))

    def test_no_blind_retry_even_after_send_reply_loss(self):
        c = self.start()
        c.send_initial_input("synthetic text only")
        self.assertCode("BLIND_RETRY_FORBIDDEN", lambda: c.freeze.request("turn/start", {"threadId": THREAD, "input": []}))
        calls = [m for m, p in c.driver.calls if m == "turn/start"]
        self.assertEqual(calls, ["turn/start"])

    def test_exact_native_evidence_and_wrong_process_refusal(self):
        c = self.start()
        c.driver.process["birth_ns"] += 1
        self.assertCode("EXACT_IDENTITY_REQUIRED", c.observe)
        c.driver.process["birth_ns"] -= 1
        c.driver.read_native_evidence = lambda t, u: {"thread_id": TURN, "turn_id": u, "state_root": self.f.grant["provider_evidence_store"], "terminal_fact": "NONE"}
        self.assertCode("EXACT_IDENTITY_REQUIRED", c.reconcile)

    def test_read_only_observe_reconcile_do_not_advance_generation(self):
        c = self.start(); before = (c.run.directory / "preaction.log").read_bytes()
        c.observe(); c.reconcile()
        self.assertEqual(before, (c.run.directory / "preaction.log").read_bytes())
        self.assertEqual(c.run.generation, 1)

    def test_release_wrong_identity_and_intent_gap_never_signals(self):
        c = self.start()
        identity = c.bound["process_identity"]
        self.f.observer.alive[identity["pid"]] = "UNVERIFIED"
        c.stop(); self.assertEqual(self.f.observer.releases, [])
        self.assertIn("RESOURCE_UNVERIFIED", c.reasons)

    def test_release_intent_gap_is_verification_only_across_generation(self):
        c = self.start()
        ref = digest("runtime-owned-resource/v1", c.bound["process_identity"])
        c.run.append("RELEASE_INTENT", resource_ref=ref)
        c.stop(); self.assertEqual(self.f.observer.releases, [])

    def test_canary_failure_is_prebinding_terminal_without_receipt(self):
        self.f.configure_driver = lambda d: setattr(d, "canary_route", lambda t: mock.Mock(thread_id="wrong"))
        c = self.create()
        self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: c.start(self.f.grant["run_id"], self.f.executable))
        self.assertEqual(c.run.terminal["state"], "START_FAILED_BEFORE_BINDING")
        self.assertFalse((c.run.directory / "receipt.json").exists())
        self.assertFalse((c.run.directory / "binding.json").exists())
        self.assertFalse(any(m == "turn/start" for m, p in c.driver.calls))


class StateContract(P1FixtureCase):
    def test_canonical_roots_ignore_all_worker_environment(self):
        roots = canonical_roots()
        with mock.patch.dict(os.environ, {"HOME": "/worker", "XDG_STATE_HOME": "/worker", "CODEX_HOME": "/worker", "TMPDIR": "/worker"}):
            self.assertEqual(canonical_roots(), roots)

    def test_authorization_roots_provider_state_and_symlinks(self):
        for field in ("runtime_state_root", "controller_endpoint_root", "provider_evidence_store"):
            old = self.f.grant[field]; self.f.grant[field] = "/other"
            self.f.stage()
            expected = "PROVIDER_STATE_ROOT_MISMATCH" if field == "provider_evidence_store" else "CANONICAL_ROOT_MISMATCH"
            self.assertCode(expected, lambda: self.f.store.authorization(self.f.grant["run_id"]))
            self.f.grant[field] = old
        link = self.f.root / "link"; link.symlink_to(self.f.workspace)
        grant = copy.deepcopy(self.f.grant); grant["workspace"] = str(link)
        self.assertCode("RESOLVED_SCOPE_MISMATCH", lambda: resolved_scope(grant, self.f.state, self.f.endpoint))

    def test_file_trust_hardlinks_mode_and_no_follow(self):
        self.f.stage(); path = self.f.state / "authorization-inbox" / (self.f.grant["run_id"] + ".json")
        path.chmod(0o644)
        self.assertCode("UNTRUSTED_OWNER_FILE", lambda: trusted_read(path, 8192))
        path.chmod(0o600); link = path.with_name("link"); os.link(path, link)
        self.assertCode("UNTRUSTED_OWNER_FILE", lambda: trusted_read(path, 8192))
        link.unlink(); link.symlink_to(path)
        with self.assertRaises(OSError): trusted_read(link, 8192)

    def test_ipc_path_bound_before_reservation(self):
        endpoint = self.f.root / ("e" * 80); endpoint.mkdir(mode=0o700)
        self.f.store.endpoint = endpoint; self.f.grant["controller_endpoint_root"] = str(endpoint)
        c = self.create()
        self.assertCode("IPC_PATH_TOO_LONG", lambda: c.start(self.f.grant["run_id"], self.f.executable))
        self.assertFalse((self.f.state / self.f.grant["run_id"]).exists())

    def test_consumption_single_attempt_and_overlap_alive_resource(self):
        c = self.start()
        self.assertFalse((self.f.state / "authorization-inbox" / (self.f.grant["run_id"] + ".json")).exists())
        self.f.grant["run_id"] = str(uuid.uuid4()); self.f.grant["attempt_id"] = str(uuid.uuid4())
        self.f.grant["provider_evidence_store"] = str(self.f.state / self.f.grant["run_id"] / "provider-state")
        self.f.stage(); other = P1Controller(self.f.store, self.f.observer, self.f.loader)
        self.assertCode("OVERLAPPING_ACTIVE_RUN", lambda: other.start(self.f.grant["run_id"], self.f.executable))
        c.run.append("TERMINAL", state="STOPPED", code="REQUESTED_STOP", stage="BOUND")
        self.assertCode("OVERLAPPING_ACTIVE_RUN", lambda: other.start(self.f.grant["run_id"], self.f.executable))

    def test_fenced_closer_requires_lock_plus_absence_and_boot(self):
        c = self.start(); another = self.f.store.load(c.run.grant["run_id"])
        self.assertCode("CONTROLLER_STILL_ALIVE", lambda: another.fence_closer(self.f.observer))
        c.run.release_lock()
        self.assertCode("CONTROLLER_ABSENCE_NOT_ATTESTED", lambda: another.fence_closer(self.f.observer))
        self.f.observer.alive[self.f.observer.controller["pid"]] = "ABSENT"
        self.f.observer.controller = dict(self.f.observer.controller, pid=124, birth_ns=2000)
        another.fence_closer(self.f.observer)
        self.assertEqual(another.generation, 2); another.release_lock()

    def test_atomic_no_replace_and_durable_terminal_precedes_cleanup(self):
        path = self.f.root / "published.json"; publish_once(path, {"v": 1})
        with self.assertRaises(FileExistsError): publish_once(path, {"v": 2})
        self.assertEqual(json.loads(path.read_bytes()), {"v": 1})
        self.assertEqual(path.stat().st_nlink, 1)
        c = self.start(); c.stop()
        records = c.run.records()
        events = [v["event"] for v in records]
        self.assertLess(events.index("TERMINAL"), events.index("RELEASE_INTENT"))

    def test_prebinding_verbs_are_typed_read_only_and_stale_fenced(self):
        c = self.create(production=True)
        self.assertCode("RUNTIME_DIGEST_UNSUPPORTED", lambda: c.start(self.f.grant["run_id"], self.f.executable))
        with mock.patch.object(_commands, "store_for_owner", return_value=self.f.store), mock.patch.object(_commands, "OSObserver", return_value=self.f.observer):
            before = (c.run.directory / "preaction.log").read_bytes()
            for verb in ("observe", "reconcile", "stop"):
                result = _commands.inspect_run(verb, self.f.grant["run_id"], self.f.grant["attempt_id"], 1)
                self.assertEqual(result["status"], "START_FAILED_BEFORE_BINDING")
            self.assertEqual(before, (c.run.directory / "preaction.log").read_bytes())
            self.assertCode("STALE_CONTROLLER_CLIENT", lambda: _commands.inspect_run("observe", self.f.grant["run_id"], str(uuid.uuid4()), 1))
            self.assertCode("STALE_CONTROLLER_CLIENT", lambda: _commands.inspect_run("stop", self.f.grant["run_id"], self.f.grant["attempt_id"], 2))



class AdditionalP1Evidence(P1FixtureCase):
    def test_canary_setup_postcheck_nonce_reuse_and_cleanup_absence(self):
        proof, d = self.direct(); route = d.canary_route(THREAD)
        canary = ConfinementCanary()
        kwargs = dict(rtca=self.f.record, authorization=self.f.grant, thread_id=THREAD, instance_id=route.instance_id, route=route)
        with mock.patch("codex_preserve.runtime_control._canary.secrets.token_hex", return_value="1" * 32):
            canary.run(**kwargs)
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: canary.run(**kwargs))
            self.assertEqual(error.reason, "NONCE_REUSE")
        with mock.patch("codex_preserve.runtime_control._canary._sync_write", side_effect=OSError()):
            error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: ConfinementCanary().run(**kwargs))
            self.assertEqual(error.reason, "SETUP_OR_POSTCHECK")
        grant = copy.deepcopy(self.f.grant); grant["runtime_state_root"] = str(self.f.executable)
        kwargs["authorization"] = grant
        error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: ConfinementCanary().run(**kwargs))
        self.assertEqual(error.reason, "SETUP")

    def test_raw_driver_requests_and_dynamic_input_are_locally_refused(self):
        c = self.start(); before = copy.deepcopy(c.driver.calls)
        self.assertCode("ACTIVE_METHOD_REFUSED", lambda: c.driver.request("thread/start", {}))
        self.assertCode("ACTIVE_METHOD_REFUSED", lambda: c.freeze.request("turn/start", {"threadId": THREAD,
                                                "input": [{"type": "tool_output", "text": "unattested"}]}))
        self.assertEqual(c.driver.calls, before)

    def test_boot_and_deadline_are_exact_read_only_evidence(self):
        c = self.start()
        anchor = next(r for r in c.run.records() if r["event"] == "START_RESERVED")
        self.f.observer.clock = anchor["deadline_ns"]
        self.assertTrue(c.observe()["deadline_expired"])
        self.f.observer.boot = "different-boot"
        self.assertEqual(c.observe()["exact_evidence"], "BOOT_MISMATCH")
        c.stop()
        self.assertEqual(self.f.observer.releases, [])

    def test_terminal_provider_facts_are_absorbing_and_receipts_strict(self):
        c = self.start(); c.freeze.turn_id = TURN
        c.driver.read_native_evidence = lambda t, u: {"thread_id": t, "turn_id": u,
                    "state_root": self.f.grant["provider_evidence_store"], "terminal_fact": "COMPLETED"}
        c.driver.events = [{"kind": "terminal", "thread_id": THREAD, "turn_id": TURN, "fact": "COMPLETED"}]
        c.serve()
        self.assertEqual(c.run.terminal["state"], "COMPLETED")
        c.loss("CONTROLLER_LOSS"); c.stop()
        self.assertEqual(c.run.terminal["state"], "COMPLETED")
        receipt = validate_receipt((c.run.directory / "receipt.json").read_bytes())
        self.assertEqual(receipt["decision"], "PROVIDER_COMPLETED")

    def test_fenced_closer_adopts_terminal_before_receipt_publication(self):
        c = self.start()
        c.run.append("TERMINAL", state="COMPLETED", code="PROVIDER_TERMINAL_OBSERVED", stage="BOUND")
        c.run.release_lock()
        self.f.observer.alive[self.f.observer.controller["pid"]] = "ABSENT"
        self.f.observer.controller = dict(self.f.observer.controller, pid=124, birth_ns=2000)
        # Closer doesn't bind/reconnect, and adopts the completed decision.
        with mock.patch.object(_commands, "store_for_owner", return_value=self.f.store), \
             mock.patch.object(_commands, "OSObserver", return_value=self.f.observer), \
             mock.patch("codex_preserve.runtime_control._engine.ControllerEndpoint.bind", side_effect=AssertionError("closer binds")), \
             mock.patch("codex_preserve.runtime_control._rtca.load_supported", side_effect=self.f.loader):
            result = _commands.inspect_run("stop", self.f.grant["run_id"], self.f.grant["attempt_id"], 1)
        self.assertEqual(result["status"], "COMPLETED")
        receipt = validate_receipt((c.run.directory / "receipt.json").read_bytes())
        self.assertEqual(receipt["decision"], "PROVIDER_COMPLETED")
        self.assertIn("CONTROLLER_LOSS", receipt["ambiguity_reasons"])
        self.assertEqual(self.f.store.load(self.f.grant["run_id"]).generation, 2)
        self.assertEqual(len(self.f.drivers), 1)

    def test_prebinding_spawn_gap_is_sticky_until_fenced_stop(self):
        self.f.configure_driver = lambda d: setattr(d, "launch", mock.Mock(side_effect=OSError()))
        c = self.create()
        self.assertCode("START_PROOF_FAILED", lambda: c.start(self.f.grant["run_id"], self.f.executable))
        self.assertIsNone(c.run.terminal)
        self.assertIn("RESOURCE_UNVERIFIED", [r["reason"] for r in c.run.records() if r["event"] == "LOSS"])
        self.assertFalse((c.run.directory / "receipt.json").exists())
        self.f.observer.alive[self.f.observer.controller["pid"]] = "ABSENT"
        self.f.observer.controller = dict(self.f.observer.controller, pid=124, birth_ns=2000)
        with mock.patch.object(_commands, "store_for_owner", return_value=self.f.store), mock.patch.object(_commands, "OSObserver", return_value=self.f.observer):
            result = _commands.inspect_run("stop", self.f.grant["run_id"], self.f.grant["attempt_id"], 1)
        self.assertEqual(result["status"], "START_FAILED_BEFORE_BINDING")
        self.assertFalse((c.run.directory / "receipt.json").exists())

    def test_active_tripwire_each_forbidden_tool_category(self):
        for category in ("mcp", "dynamic", "plugin", "computer_use", "delegation", "meta", "network"):
            with tempfile.TemporaryDirectory(prefix="sp-", dir="/tmp") as temp:
                f = Fixture(temp); f.stage(); c = P1Controller(f.store, f.observer, f.loader)
                c.start(f.grant["run_id"], f.executable); c.freeze.turn_id = TURN
                result = c.tool_event({"name": "exec_command", "category": category, "thread_id": THREAD, "turn_id": TURN})
                self.assertEqual(result["code"], "ATTESTED_TOOL_SET_VIOLATION_OBSERVED")
                self.assertEqual(c.driver.calls[-1][0], "turn/interrupt")
                self.assertTrue(f.store.suspended(c.admission.rtca_sha256, c.rtca["review_id"]))

    def test_ledger_excludes_raw_and_bounded_bad_identity(self):
        c = self.start()
        with self.assertRaises(ValidationError):
            c.run.append("RESOURCE_OBSERVED", kind="APP_SERVER", identity=dict(c.bound["process_identity"], raw_prompt="PRIVATE_BODY_SENTINEL"))
        self.assertCode("LEDGER_WRITE_REFUSED", lambda: c.run.append("RAW", text="PRIVATE_BODY_SENTINEL"))
        self.assertNotIn(b"PRIVATE_BODY_SENTINEL", (c.run.directory / "preaction.log").read_bytes())

    def test_cli_no_override_surface_and_exact_generation(self):
        from tests.test_runtime_control_cli import invoke
        from codex_preserve import cli
        for args in (["runtime", "start", "--rtca", "fixture"], ["runtime", "start", "--state-root", "fixture"],
                     ["runtime", "observe", "--latest"]):
            with self.assertRaises(SystemExit) as caught:
                invoke(args)
            self.assertEqual(caught.exception.code, 2)
        with mock.patch.object(_commands, "store_for_owner", return_value=self.f.store), mock.patch.object(_commands, "OSObserver", return_value=self.f.observer):
            self.f.stage()
            code, out, err = invoke(["runtime", "launch", "--run-id", self.f.grant["run_id"], "--executable", str(self.f.executable)])
            self.assertEqual(code, 2); self.assertEqual(json.loads(err)["code"], "RUNTIME_DIGEST_UNSUPPORTED")
            self.assertEqual(self.f.drivers, [])


class StdioContract(unittest.TestCase):
    def transport(self, frames):
        from codex_preserve.runtime_control._transport import StdioTransport
        read_fd, server_write = os.pipe(); server_read, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd); self.addCleanup(os.close, write_fd)
        self.addCleanup(os.close, server_write); self.addCleanup(os.close, server_read)
        events = []
        wire = StdioTransport(read_fd, write_fd, lambda m, p: events.append(m))
        self.addCleanup(wire.close)
        os.write(server_write, b"".join(encoded(f) + b"\n" for f in frames))
        return wire, server_read, events

    def test_stdio_serialization_and_notification_before_result(self):
        wire, server_read, events = self.transport([{"method": "synthetic/tool", "params": {}}, {"id": 1, "result": {"ok": True}}])
        self.assertEqual(wire.request("initialize", {}), {"ok": True})
        self.assertEqual(events, ["synthetic/tool"])
        self.assertEqual(json.loads(os.read(server_read, 4096)), {"id": 1, "method": "initialize", "params": {}})

    def test_wrong_reply_identity_and_server_requests_sticky_no_retry(self):
        for frame, code in (({"id": 2, "result": {}}, "PROVIDER_REPLY_IDENTITY_MISMATCH"),
                            ({"id": 1, "method": "approval", "params": {}}, "UNATTESTED_SERVER_REQUEST")):
            wire, server_read, events = self.transport([frame])
            with self.assertRaises(ValidationError) as caught: wire.request("initialize", {})
            self.assertEqual(caught.exception.code, code)
            with self.assertRaises(ValidationError) as caught: wire.request("initialize", {})
            self.assertEqual(caught.exception.code, "PROVIDER_CONNECTION_LOSS")

    def test_policy_refusal_sends_no_bytes_and_turn_loss_no_resume(self):
        wire, server_read, events = self.transport([])
        wire.arm_policy(lambda m, p: (_ for _ in ()).throw(ValidationError("ACTIVE_METHOD_REFUSED")))
        with self.assertRaises(ValidationError): wire.request("thread/settings/update", {})
        os.set_blocking(server_read, False)
        with self.assertRaises(BlockingIOError): os.read(server_read, 4096)


class FinalBoundaryEvidence(P1FixtureCase):
    def test_helper_group_identity_is_durable_and_released_exactly_once(self):
        c = self.start()
        process = {"pid": 43, "birth_ns": 200, "executable_sha256": "f" * 64, "launch_id": str(uuid.uuid4())}
        identity = {"process": process, "group": {"pgid": 43, "sid": 43, "leader_birth_ns": 200, "boot_id": self.f.observer.boot}}
        c.run.append("RESOURCE_OBSERVED", kind="HELPER", identity=identity)
        self.f.observer.alive[43] = "EXACT"
        c.stop(); c.stop()
        self.assertEqual(self.f.observer.releases.count(identity), 1)
        self.assertEqual(len(c.run.resources()), 3)

    def test_canary_cannot_leave_second_thread(self):
        proof, driver = self.direct()
        original = driver.canary_route
        def route(thread_id):
            value = original(thread_id)
            execute = value.execute_probe
            def execute_probe(program, spec, timeout):
                result = execute(program, spec, timeout)
                driver.thread_ids.append(TURN)
                return result
            value.execute_probe = execute_probe
            return value
        driver.canary_route = route
        self.assertCode("INSTANCE_ISOLATION_NOT_ATTESTED", proof.establish)
        self.assertFalse(any(m == "turn/start" for m, p in driver.calls))

    def test_malformed_canary_encoding_stays_typed_confinement_failure(self):
        proof, driver = self.direct(); route = driver.canary_route(THREAD)
        route.execute_probe = lambda *args: {"stdout": b"invalid JSON", "helper_absent": True}
        error = self.assertCode("SANDBOX_CONFINEMENT_NOT_ATTESTED", lambda: ConfinementCanary().run(
            rtca=self.f.record, authorization=self.f.grant, thread_id=THREAD, instance_id=route.instance_id, route=route))
        self.assertEqual(error.reason, "SETUP_OR_POSTCHECK")

    def test_transport_bypass_and_active_notifications_send_nothing(self):
        c = self.start(); before = copy.deepcopy(c.driver.calls)
        self.assertCode("ACTIVE_METHOD_REFUSED", lambda: c.driver.outbound_guard("thread/settings/update", {}))
        self.assertCode("ACTIVE_METHOD_REFUSED", lambda: c.driver.notify("initialized", {}))
        self.assertEqual(c.driver.calls, before)

    def test_suspension_marker_gap_remains_closed_by_durable_ledger(self):
        c = self.start(); c.freeze.turn_id = TURN
        with mock.patch.object(c.store, "suspend", side_effect=OSError()):
            self.assertCode("RTCA_SUSPENSION_DURABILITY_FAILED", lambda: c.tool_event({}))
        self.assertTrue(c.store.suspended(c.admission.rtca_sha256, c.rtca["review_id"]))
        self.assertEqual(c.driver.calls[-1][0], "turn/interrupt")
        self.assertEqual(c.run.terminal["code"], "ATTESTED_TOOL_SET_VIOLATION_OBSERVED")

    def test_unclassified_tool_payload_still_suspends_and_stops(self):
        c = self.start(); c.freeze.turn_id = TURN
        result = c.tool_event({"name": [], "category": {}, "thread_id": THREAD, "turn_id": TURN})
        self.assertEqual(result["code"], "ATTESTED_TOOL_SET_VIOLATION_OBSERVED")
        self.assertTrue(c.store.suspended(c.admission.rtca_sha256, c.rtca["review_id"]))


class NativeControllerEvidence(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"), "native P1 POSIX observer")
    def test_os_executed_controller_binary_and_sleep_including_clock(self):
        from codex_preserve.runtime_control._platform import OSObserver, process_executable, executable_digest
        observer = OSObserver()
        identity = observer.controller_identity()
        self.assertEqual(identity["executable_sha256"], executable_digest(process_executable(os.getpid())))
        self.assertEqual(observer.observe(identity), "EXACT")
        self.assertGreater(identity["birth_ns"], 0)
        self.assertGreater(observer.now_ns(), 0)
        self.assertTrue(observer.boot_id())


class NativeIPCEvidence(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"), "native owner Unix IPC")
    def test_exact_owner_peer_and_generation_handshake(self):
        import threading
        from codex_preserve.runtime_control._ipc import ControllerEndpoint, request_controller
        from codex_preserve.runtime_control._platform import OSObserver
        with tempfile.TemporaryDirectory(prefix="sp-", dir="/tmp") as temp:
            root = Path(temp).resolve(); root.chmod(0o700)
            run_id, attempt_id = str(uuid.uuid4()), str(uuid.uuid4())
            endpoint = ControllerEndpoint(root / "controller.sock", run_id, attempt_id, 1)
            identity = endpoint.bind()
            errors = []
            def serve():
                try:
                    endpoint.serve_once(lambda verb: {"status": "RUNNING", "verb": verb})
                except Exception as error:
                    errors.append(type(error).__name__)
            server = threading.Thread(target=serve)
            server.start()
            try:
                result = request_controller(endpoint.path, run_id, attempt_id, 1, identity, "observe",
                                            OSObserver().controller_identity())
                self.assertEqual(result, {"status": "RUNNING", "verb": "observe"})
                self.assertEqual(endpoint.path.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(ValidationError) as caught:
                    request_controller(endpoint.path, run_id, attempt_id, 1, dict(identity, inode=identity["inode"] + 1),
                                       "observe", OSObserver().controller_identity())
                self.assertEqual(caught.exception.code, "STALE_CONTROLLER_CLIENT")
            finally:
                server.join(timeout=2)
                endpoint.close()
            self.assertFalse(server.is_alive()); self.assertEqual(errors, [])
            self.assertFalse(endpoint.path.exists())


if __name__ == "__main__":
    unittest.main()
