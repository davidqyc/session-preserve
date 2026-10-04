"""Explicit P1 CLI commands. No state-root, registry or realization overrides."""
from ._engine import P1Controller
from ._ipc import request_controller
from ._platform import OSObserver
from ._rtca import fail
from ._state import RunStore, canonical_roots
from ._validation import _uuid, _int


def store_for_owner():
    return RunStore(*canonical_roots())


def start(run_id, executable, input_file=None):
    controller = P1Controller(store_for_owner(), OSObserver())
    controller.start(run_id, executable)
    try:
        if input_file is not None:
            # Read task bytes only after binding, never into launch parameters.
            from ._local import read_regular_file
            payload = read_regular_file(input_file, 65536)
            try:
                text = payload.decode("utf-8")
            except UnicodeError:
                fail("TASK_INPUT_INVALID")
            controller.send_initial_input(text)
        return controller.serve()
    except Exception as error:
        from ._validation import ValidationError
        code = error.code if isinstance(error, ValidationError) else "ACTIVE_RUNTIME_EVIDENCE_FAILED"
        if not controller.run.terminal:
            controller.stop(code, decision="CAPABILITY_UNAVAILABLE")
        if isinstance(error, ValidationError):
            raise
        fail(code)


def inspect_run(verb, run_id, attempt_id, generation):
    _uuid(run_id, "$.run_id"); _uuid(attempt_id, "$.attempt_id")
    _int(generation, 1, 2**63 - 1, "$.generation")
    store, observer = store_for_owner(), OSObserver()
    run = store.load(run_id)
    if run.grant["attempt_id"] != attempt_id or run.generation != generation:
        fail("STALE_CONTROLLER_CLIENT")
    if verb != "stop" and not run.grant["observe_authorized"]:
        fail("OBSERVE_NOT_AUTHORIZED")
    terminal = run.terminal
    binding_flushed = any(v["event"] == "BINDING_FLUSHED" for v in run.records())
    receipt_path = run.directory / "receipt.json"
    if terminal and (not binding_flushed or receipt_path.exists()):
        if binding_flushed:
            from ._state import trusted_read
            from ._validation import RECEIPT_MAX_BYTES, BINDING_MAX_BYTES, verify_artifact
            verify_artifact(trusted_read(receipt_path, RECEIPT_MAX_BYTES)[0],
                            authorization=trusted_read(run.directory / "authorization.json", 8192)[0],
                            binding=trusted_read(run.directory / "binding.json", BINDING_MAX_BYTES)[0])
        return {"status": terminal["state"], "code": terminal["code"],
                "generation": run.generation, "binding_established": binding_flushed}
    if terminal and verb != "stop":
        return {"status": terminal["state"], "code": "TERMINAL_RECEIPT_PENDING_CLOSURE",
                "generation": run.generation, "binding_established": binding_flushed}
    if observer.boot_id() != run.boot_id:
        return {"status": "AMBIGUOUS", "code": "BOOT_MISMATCH", "generation": run.generation}
    presence = observer.observe(run.controller)
    if presence == "EXACT":
        sockets = [r for r in run.resources() if r["kind"] == "SOCKET"]
        if len(sockets) != 1:
            return {"status": "AMBIGUOUS", "code": "CONTROLLER_UNRESPONSIVE", "generation": run.generation}
        try:
            return request_controller(store.endpoint_path(run_id, generation), run_id, attempt_id,
                                      generation, sockets[0]["identity"], verb, run.controller)
        except (OSError, TimeoutError):
            return {"status": "AMBIGUOUS", "code": "CONTROLLER_UNRESPONSIVE", "generation": generation}
    if verb != "stop":
        # Observation never acquires a lock, writes LOSS or advances a fence.
        code = "CONTROLLER_LOSS" if presence == "ABSENT" else "CONTROLLER_IDENTITY_UNVERIFIED"
        return {"status": "AMBIGUOUS", "code": code, "generation": run.generation,
                "last_durable_stage": run.stage}
    if binding_flushed:
        from ._state import trusted_read
        from ._validation import BINDING_MAX_BYTES, validate_binding
        from ._rtca import load_supported
        import sys
        bound_value = validate_binding(trusted_read(run.directory / "binding.json", BINDING_MAX_BYTES)[0])
        admission, rtca = load_supported(bound_value["runtime_profile"], sys.platform,
                                       bound_value["process_identity"]["executable_sha256"])
        # A reviewed read-only ownership observer; never recreates a provider
        # driver, connection or endpoint in a fenced closer.
        observer = admission.resource_observer_factory(base=observer, authorization=run.grant, rtca=rtca)
    run.fence_closer(observer)  # lock acquisition + exact absence + same boot
    try:
        bound_path = run.directory / "binding.json"
        bound = binding_flushed
        run.append("LOSS", reason="CONTROLLER_LOSS")
        if run.terminal is None:
            run.append("TERMINAL", state="STOPPED" if bound else "START_FAILED_BEFORE_BINDING",
                       code="CONTROLLER_LOST", stage=run.stage, decision="CONTROLLER_LOST" if bound else "NONE")
        outcomes = run.release_resources(observer)
        if bound:
            from ._state import trusted_read
            from ._validation import BINDING_MAX_BYTES, validate_binding
            from ._engine import P1Controller
            controller = P1Controller(store, observer)
            controller.run = run
            controller.bound = validate_binding(trusted_read(bound_path, BINDING_MAX_BYTES)[0])
            controller.binding_durable = True
            controller.reasons = {v["reason"] for v in run.records() if v["event"] == "LOSS"}
            controller.reasons.add("CONTROLLER_LOSS")
            controller.state, controller.decision = run.terminal["state"], run.terminal["decision"]
            controller.provider_fact = controller.state if controller.state in ("COMPLETED", "FAILED") else "NONE"
            controller._publish_receipt(outcomes)
        return {"status": run.terminal["state"], "code": run.terminal["code"], "generation": run.generation}
    finally:
        run.release_lock()
