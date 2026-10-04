"""P1 controller framework. Production is closed until a reviewed RTCA exists."""
import copy
import sys
import uuid

from ._canary import ConfinementCanary
from ._ipc import ControllerEndpoint
from ._platform import executable_digest
from ._proof import CompositeProof
from ._rtca import (FORBIDDEN, digest, fail, load_supported, materialize_pinned)
from ._state import publish_once, trusted_read
from ._validation import (PROFILE_GENERIC, BINDING_SCHEMA, RECEIPT_SCHEMA,
                          BINDING_MAX_BYTES, _canonical, _uuid,
                          authorization_digest, binding_digest, identity_ref,
                          validate_binding, validate_receipt, verify_artifact,
                          ValidationError)


class P1Controller:
    def __init__(self, store, observer, admission_loader=load_supported):
        self.store, self.observer, self.admission_loader = store, observer, admission_loader
        self.run, self.driver, self.freeze, self.endpoint = None, None, None, None
        self.bound, self.rtca, self.admission = None, None, None
        self.binding_durable = False
        self.state, self.decision, self.provider_fact = "RUNNING", "NONE", "NONE"
        self.reasons = set()
        self.last_activity_ns = observer.now_ns()

    def start(self, run_id, executable):
        grant, payload, inbox_identity = self.store.authorization(run_id)
        self.run = self.store.reserve(grant, payload, inbox_identity, self.observer.controller_identity(),
                                      self.observer.boot_id(), self.observer.now_ns(), self.observer)
        try:
            self.run.append("STAGE", stage="PREFLIGHT")
            executable_sha256 = executable_digest(executable)
            self.admission, self.rtca = self.admission_loader(PROFILE_GENERIC, sys.platform, executable_sha256)
            if self.store.suspended(self.admission.rtca_sha256, self.rtca["review_id"]):
                fail("RTCA_SUSPENDED")
            self.observer = self.admission.resource_observer_factory(base=self.observer,
                            authorization=copy.deepcopy(grant), rtca=copy.deepcopy(self.rtca))
            if self.observer.boot_id() != self.run.boot_id or self.observer.controller_identity() != self.run.controller:
                fail("CONTROLLER_IDENTITY_MISMATCH")
            launch_id = str(uuid.uuid4())
            self.run.append("LAUNCH_INTENT", launch_id=launch_id, executable_sha256=executable_sha256)
            self.run.append("STAGE", stage="LAUNCH_INTENT")
            # The digest-specific reviewed realization must pin executable bytes,
            # stdio and state roots before spawning. No PATH/helper fallback.
            self.driver = self.admission.realization(executable=executable, launch_id=launch_id,
                          authorization=copy.deepcopy(grant), rtca=copy.deepcopy(self.rtca),
                          observer=self.observer)
            self.driver.launch()
            observed = self.driver.observe_identity()
            process = observed["process"]
            if process["launch_id"] != launch_id or process["executable_sha256"] != executable_sha256:
                fail("RUNTIME_IDENTITY_MISMATCH")
            self.run.append("RESOURCE_OBSERVED", kind="APP_SERVER", identity=process)
            self.run.append("STAGE", stage="PROCESS_OBSERVED")
            self.driver.before_thread_request = lambda: self.run.append("STAGE", stage="THREAD_REQUESTED")
            proof = CompositeProof(self.rtca, self.driver, grant, ConfinementCanary())
            thread_id, observed, self.freeze = proof.establish()
            self.run.append("PROOF_ESTABLISHED", rtca_sha256=self.admission.rtca_sha256,
                            review_sha256=self.admission.review_sha256,
                            components_digest=digest("runtime-composite-proof/v1", proof.components),
                            pinned_inputs_digest=digest("runtime-effective-inputs/v1", materialize_pinned(self.rtca, grant)),
                            canary_nonce_ref=proof.canary_result["nonce_ref"])
            self.bound = {
                "schema": BINDING_SCHEMA, "task_id": grant["task_id"], "run_id": run_id,
                "attempt_id": grant["attempt_id"], "provider": "codex",
                "authorization_sha256": authorization_digest(payload), "thread_id": thread_id,
                "turn_id": None, "binding_phase": "THREAD_BOUND", "process_identity": observed["process"],
                "process_birth_source": "INDEPENDENT_OS_OBSERVATION", "runtime_profile": PROFILE_GENERIC,
                "runtime_version": self.rtca["runtime_version"], "capabilities": self.driver.binding_capabilities(),
                "sandbox_posture": dict(grant["required_sandbox_posture"]),
                "nested_start_enforcement": "OWNER_STAGED_GATE_ATTESTED",
            }
            self.bound = validate_binding(_canonical(self.bound))
            verify_artifact(_canonical(self.bound), authorization=payload)
            self.endpoint = ControllerEndpoint(self.store.endpoint_path(run_id, self.run.generation),
                           run_id, grant["attempt_id"], self.run.generation)
            identity = self.endpoint.bind()
            self.run.append("RESOURCE_OBSERVED", kind="SOCKET", identity=identity)
            # Freeze/tripwire already armed; publication is no-replace + synced.
            publish_once(self.run.directory / "binding.json", self.bound)
            self.run.append("BINDING_FLUSHED", binding_sha256=binding_digest(_canonical(self.bound)))
            self.binding_durable = True
            self.run.append("STAGE", stage="BOUND")
            self.freeze.mark_bound()
            return self.snapshot()
        except Exception as error:
            code = error.code if isinstance(error, ValidationError) else "START_PROOF_FAILED"
            stage = self.run.stage
            unknown = stage in ("LAUNCH_INTENT", "PROCESS_OBSERVED", "THREAD_REQUESTED", "BOUND")
            if self.binding_durable:
                self.stop(code, decision="CAPABILITY_UNAVAILABLE")
            elif stage == "LAUNCH_INTENT" and not self.run.resources():
                # A spawn/reply gap cannot fabricate a clean pre-binding failure.
                self.run.append("LOSS", reason="RESOURCE_UNVERIFIED")
                self.state, self.decision = "AMBIGUOUS", "CONTROLLER_LOST"
                self.reasons.add("RESOURCE_UNVERIFIED")
            else:
                self.bound = None
                self.run.append("TERMINAL", state="START_FAILED_BEFORE_BINDING", code=code, stage=stage)
                if unknown:
                    self.run.release_resources(self.observer)
            if self.endpoint and self.endpoint.socket:
                self._close_endpoint_once()
            self.run.release_lock()
            if isinstance(error, ValidationError):
                raise
            fail(code)

    def snapshot(self):
        terminal = self.run.terminal
        return {"status": terminal["state"] if terminal else self.state,
                "code": terminal["code"] if terminal else self.decision,
                "binding_established": self.bound is not None and (self.run.directory / "binding.json").exists(),
                "generation": self.run.generation, "execution_ambiguous": bool(self.reasons),
                "ambiguity_reasons": sorted(self.reasons)}

    def send_initial_input(self, text):
        if self.state != "RUNNING" or self.run.terminal or self.freeze is None:
            fail("SIDE_EFFECTS_FROZEN")
        if type(text) is not str or not text or len(_canonical([{"type": "text", "text": text}])) > 65536:
            fail("TASK_INPUT_INVALID")
        self.run.append("TURN_SEND_INTENT", thread_id=self.bound["thread_id"])
        try:
            response = self.freeze.request("turn/start", {"threadId": self.bound["thread_id"],
                                "input": [{"type": "text", "text": text}]})
            turn_id = response["turn"]["id"]
            _uuid(turn_id, "$.turn_id", 7)
            self.run.append("TURN_OBSERVED", thread_id=self.bound["thread_id"], turn_id=turn_id)
            self.freeze.turn_id = turn_id
            self.last_activity_ns = self.observer.now_ns()
        except Exception:
            self.loss("PROVIDER_CONNECTION_LOSS")
            fail("PROVIDER_CONNECTION_LOSS")

    def loss(self, loss_class):
        if loss_class == "COORDINATOR_OR_CLIENT_LOSS":
            return self.snapshot()
        reason = {"CONTROLLER_LOSS": "CONTROLLER_LOSS",
                  "PROVIDER_CONNECTION_LOSS": "TRANSPORT_LOSS"}.get(loss_class)
        if reason is None:
            fail("LOSS_CLASS_INVALID")
        if not self.run.terminal:
            self.run.append("LOSS", reason=reason)
            self.reasons.add(reason)
            self.state = "AMBIGUOUS"
            self.decision = "CONTROLLER_LOST" if reason == "CONTROLLER_LOSS" else "TRANSPORT_LOST"
            if self.freeze:
                self.freeze.close()
        return self.snapshot()

    def observe(self):
        """No lifecycle reclassification and no provider reconnect/resume."""
        result = self.snapshot()
        if self.observer.boot_id() != self.run.boot_id:
            result["exact_evidence"] = "BOOT_MISMATCH"
            return result
        if self.driver and self.bound:
            identity = self.driver.observe_identity()["process"]
            if identity != self.bound["process_identity"] or self.observer.observe(identity) != "EXACT":
                fail("EXACT_IDENTITY_REQUIRED")
            evidence = self.driver.read_native_evidence(self.bound["thread_id"], self.freeze.turn_id)
            if evidence["thread_id"] != self.bound["thread_id"] or evidence["turn_id"] != self.freeze.turn_id \
                    or evidence["state_root"] != self.run.grant["provider_evidence_store"]:
                fail("EXACT_IDENTITY_REQUIRED")
            result["provider_fact"] = evidence["terminal_fact"]
        anchor = next(v for v in self.run.records() if v["event"] == "START_RESERVED")
        result["deadline_expired"] = self.observer.now_ns() >= anchor["deadline_ns"]
        return result

    def reconcile(self):
        # Read-only facts improve knowledge; sticky loss never restores control.
        return self.observe()

    def _close_endpoint_once(self):
        ref = digest("runtime-owned-resource/v1", self.endpoint.identity)
        if not any(v["event"] == "RELEASE_INTENT" and v["resource_ref"] == ref for v in self.run.records()):
            self.run.append("RELEASE_INTENT", resource_ref=ref)
            try:
                self.endpoint.close()
                outcome = "ABSENT"
            except Exception:
                outcome = "RESOURCE_UNVERIFIED"
            self.run.append("RELEASE_OUTCOME", resource_ref=ref, outcome=outcome)

    def stop(self, code="REQUESTED_STOP", decision=None, terminal_state="STOPPED"):
        if self.run.terminal:
            return self.snapshot()
        state = terminal_state if self.binding_durable else "START_FAILED_BEFORE_BINDING"
        decision = decision or (self.decision if self.reasons else "REQUESTED_STOP")
        self.run.append("TERMINAL", state=state, code=code, stage=self.run.stage,
                        decision=decision if self.binding_durable else "NONE")
        self.state, self.decision = terminal_state, decision
        if self.freeze:
            self.freeze.close()
        if self.endpoint:
            self._close_endpoint_once()
        outcomes = self.run.release_resources(self.observer)
        try:
            if self.binding_durable:
                self._publish_receipt(outcomes)
            return self.snapshot()
        finally:
            self.run.release_lock()

    def tool_event(self, tool):
        if self.run.terminal:
            return self.snapshot()
        expected = {t["name"]: t["category"] for t in self.rtca["attested_tools"]}
        violation = type(tool) is not dict or set(tool) != {"name", "category", "thread_id", "turn_id"} \
                    or any(type(tool[k]) is not str for k in ("name", "category", "thread_id", "turn_id")) \
                    or tool["thread_id"] != self.bound["thread_id"] or tool["turn_id"] != self.freeze.turn_id \
                    or tool["category"] in FORBIDDEN or expected.get(tool["name"]) != tool["category"]
        if not violation:
            return self.snapshot()
        suspension_error = None
        try:
            self.run.append("RTCA_SUSPENDED", rtca_sha256=self.admission.rtca_sha256, review_id=self.rtca["review_id"])
            self.store.suspend(self.admission.rtca_sha256, self.rtca["review_id"])
        except Exception as error:
            suspension_error = error
            self.reasons.add("RESOURCE_UNVERIFIED")
        try:
            if self.freeze.turn_id is not None:
                self.freeze.request("turn/interrupt", {"threadId": self.bound["thread_id"], "turnId": self.freeze.turn_id})
        except Exception:
            self.reasons.add("TRANSPORT_LOSS")
        result = self.stop("ATTESTED_TOOL_SET_VIOLATION_OBSERVED", decision="CAPABILITY_UNAVAILABLE")
        if suspension_error:
            fail("RTCA_SUSPENSION_DURABILITY_FAILED")
        return result

    def _publish_receipt(self, outcomes):
        grant, bound = self.run.grant, self.bound
        rows = [{"kind": row["kind"], "identity_ref": row["identity_ref"],
                 "outcome": "RELEASED" if row["outcome"] == "ABSENT" else "ERROR",
                 "exact_identity_verified": row["outcome"] == "ABSENT",
                 "absence_verified": row["outcome"] == "ABSENT"} for row in outcomes]
        if any(row["outcome"] == "ERROR" for row in rows):
            self.reasons.add("RESOURCE_UNVERIFIED")
        value = {
            "schema": RECEIPT_SCHEMA,
            "identity": {"provider": "codex", "task_ref": identity_ref("task", grant["task_id"]),
                         "run_ref": identity_ref("run", grant["run_id"]),
                         "attempt_ref": identity_ref("attempt", grant["attempt_id"]),
                         "thread_id": bound["thread_id"], "turn_id": None, "binding_phase": "THREAD_BOUND",
                         "process_ref": identity_ref("process", bound["process_identity"])},
            "authorization_sha256": bound["authorization_sha256"], "binding_sha256": binding_digest(_canonical(bound)),
            "runtime_profile": PROFILE_GENERIC, "runtime_version": bound["runtime_version"],
            "state": self.state, "decision": self.decision, "provider_terminal_fact": self.provider_fact,
            "execution_ambiguous": bool(self.reasons), "ambiguity_reasons": sorted(self.reasons),
            "correction_maximum": 0, "correction_count": 0, "corrections": [],
            "calculator": {"authorization": grant["calculator"], "approval_count": 0, "click_count": 0,
                           "session_proof": "UNPROVEN", "click_schema_string": False, "calculator_preexisting": False,
                           "target": "com.apple.calculator", "persistent_approval": False,
                           "previous_frontmost_captured": False, "maximum_snapshot_age_ms": 1000, "keys": []},
            "cleanup": {"requested": True, "released": sum(r["outcome"] == "RELEASED" for r in rows),
                        "skipped": 0, "errors": sum(r["outcome"] == "ERROR" for r in rows),
                        "foreground_restored": False, "verified": all(r["absence_verified"] for r in rows),
                        "grace_seconds": 5, "owned_resources": rows}, "provider_calls": [],
        }
        validate_receipt(_canonical(value))
        verify_artifact(_canonical(value), authorization=_canonical(grant), binding=_canonical(bound))
        publish_once(self.run.directory / "receipt.json", value)

    def serve(self):
        """Run-scoped foreground controller; never a machine-global daemon."""
        while not self.run.terminal:
            if self.observe().get("deadline_expired"):
                return self.stop("DEADLINE_EXPIRED", decision="DEADLINE_EXPIRED")
            idle_seconds = self.run.grant.get("idle_seconds")
            if idle_seconds and self.observer.now_ns() - self.last_activity_ns >= idle_seconds * 10**9:
                return self.stop("IDLE_EXPIRED", decision="IDLE_EXPIRED")
            event = self.driver.next_event(timeout=0)
            if event is not None:
                if type(event) is not dict or type(event.get("kind")) is not str:
                    return self.tool_event({})
                if event["kind"] == "tool":
                    self.tool_event(event["tool"])
                elif event["kind"] == "provider_connection_loss":
                    self.loss("PROVIDER_CONNECTION_LOSS")
                elif event["kind"] == "activity":
                    if event["thread_id"] != self.bound["thread_id"] or event["turn_id"] != self.freeze.turn_id:
                        fail("EXACT_IDENTITY_REQUIRED")
                    self.last_activity_ns = self.observer.now_ns()
                elif event["kind"] == "resource":
                    if not self.driver.verify_owned_resource(event["resource"]):
                        self.reasons.add("RESOURCE_UNVERIFIED")
                        return self.stop("RESOURCE_UNVERIFIED", decision="CAPABILITY_UNAVAILABLE")
                    self.run.append("RESOURCE_OBSERVED", kind="HELPER", identity=event["resource"])
                elif event["kind"] == "terminal":
                    # Normalized terminal facts are exact thread/turn scoped.
                    evidence = self.observe()
                    if event["thread_id"] != self.bound["thread_id"] or event["turn_id"] != self.freeze.turn_id:
                        fail("EXACT_IDENTITY_REQUIRED")
                    if event["fact"] not in ("COMPLETED", "FAILED", "STOPPED") or evidence.get("provider_fact") != event["fact"]:
                        fail("PROVIDER_TERMINAL_NOT_ATTESTED")
                    self.provider_fact = event["fact"]
                    decision = {"COMPLETED": "PROVIDER_COMPLETED", "FAILED": "PROVIDER_FAILED", "STOPPED": "REQUESTED_STOP"}[event["fact"]]
                    return self.stop("PROVIDER_TERMINAL_OBSERVED", decision=decision, terminal_state=event["fact"])
                else:
                    return self.tool_event({})
            self.endpoint.serve_once(lambda verb: getattr(self, verb)())
        return self.snapshot()
