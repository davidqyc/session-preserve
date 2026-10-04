"""Synthetic/test-only RTCA and protocol realization. Never production admission."""
import copy
import json
import os
from pathlib import Path
import sys
import uuid

from codex_preserve.runtime_control._rtca import (RTCA_SCHEMA, REVIEW_SCHEMA, CATEGORIES,
    REVIEW_DERIVATIONS, digest, bytes_digest, SealedAdmission, validate_rtca, materialize_pinned)
from codex_preserve.runtime_control._platform import executable_digest
from codex_preserve.runtime_control._state import RunStore
from tests.runtime_fixtures import authorization, THREAD, TURN, encoded

EVIDENCE = {"url": "https://example.org/synthetic-proof", "sha256": "b" * 64}
TOOLS = [{"name": "exec_command", "category": "shell", "construction_site": "shell/create"},
         {"name": "apply_patch", "category": "filesystem", "construction_site": "fs/create"}]


def rtca(executable_sha256="a" * 64, unified=True):
    names = ["initialize", "thread/start", "thread/loaded/list", "thread/read", "turn/start",
             "turn/interrupt", "mcpServerStatus/list", "plugin/installed", "thread/testSandbox"]
    if unified:
        names.append("thread/testToolInventory")
    methods = [{"name": name, "exact_thread_complete_inventory": name == "thread/testToolInventory"} for name in names]
    pinned = {"cwd": "@workspace", "model": "synthetic-model", "modelProvider": "synthetic",
              "reasoningEffort": "high", "permissionProfile": ":workspace", "approvalsReviewer": "user",
              "sandbox": {"type": "workspaceWrite", "writableRoots": "@writable_roots",
                          "networkAccess": False, "excludeTmpdirEnvVar": True, "excludeSlashTmp": True},
              "approvalPolicy": "never", "config": {}, "features": {}, "tools": [], "disabledPluginIds": []}
    return {
        "schema": RTCA_SCHEMA, "runtime_profile": "codex-app-server-r1", "platform": sys.platform,
        "executable_sha256": executable_sha256, "runtime_version": "0.0.0-synthetic", "author": "synthetic-author",
        "source": {"repository": EVIDENCE, "commit": "c" * 40, "tree_sha256": "d" * 64,
                   "correspondence": {"kind": "REPRODUCIBLE_BYTE_IDENTICAL_BUILD", "executable_sha256": executable_sha256,
                                      "evidence": EVIDENCE}},
        "method_surface": {"methods": methods, "count": len(methods),
                           "digest": digest("rtca-method-surface/v1", methods), "evidence": EVIDENCE},
        "exact_thread_tool_inventory_method": "thread/testToolInventory" if unified else None,
        "pinned_inputs": pinned, "thread_start_digest": digest("rtca-thread-start/v1", pinned),
        "construction_sites": [{"site": "shell/create", "category": "shell", "tools": ["exec_command"],
                                "reachable": True, "evidence": EVIDENCE},
                               {"site": "fs/create", "category": "filesystem", "tools": ["apply_patch"],
                                "reachable": True, "evidence": EVIDENCE}],
        "capability_gates": {category: {"basis": "OBSERVED", "input": category,
                            "expected": "P1_ONLY" if category in ("shell", "filesystem") else "CLOSED",
                            "evidence": EVIDENCE} for category in CATEGORIES},
        "attested_tools": copy.deepcopy(TOOLS), "dispatch_closure": {"tools": ["apply_patch", "exec_command"],
                                "unknown_dispatch": False, "evidence": EVIDENCE},
        "hot_reload_inputs": [{"input": field, "gate": "FROZEN", "evidence": EVIDENCE}
                              for field in ("config", "features", "tools", "model", "reasoningEffort")],
        "plugin_relation": {"method": "plugin/installed", "capability_fields": ["tools", "skills", "hooks"], "evidence": EVIDENCE},
        "confinement": {"method": "thread/testSandbox", "route": "EXACT_THREAD", "backend": "synthetic",
                        "expected_errno": {"append": 1, "create": 1, "unix": 1, "tcp": 1},
                        "policy_digest": digest("rtca-sandbox-policy/v1", pinned["sandbox"]), "equivalence": None,
                        "evidence": EVIDENCE}, "review_id": "synthetic-independent-review",
    }


def review(payload, value):
    return encoded({"schema": REVIEW_SCHEMA, "review_id": value["review_id"], "reviewer": "synthetic-reviewer",
                    "author": value["author"], "independence": "I2", "rtca_sha256": bytes_digest(payload),
                    "derivations": list(REVIEW_DERIVATIONS), "verdict": "PASS", "evidence": EVIDENCE})


def sealed(value, realization):
    payload = encoded(value)
    receipt = review(payload, value)
    return SealedAdmission((value["runtime_profile"], value["platform"], value["executable_sha256"]),
                           payload, receipt, bytes_digest(payload), bytes_digest(receipt), realization,
                           lambda **kw: kw["base"])


class FakeObserver:
    def __init__(self):
        self.alive = {}
        self.releases = []
        self.controller = {"pid": 123, "birth_ns": 1000, "executable_sha256": "e" * 64, "launch_id": str(uuid.uuid4())}
        self.boot = "synthetic-boot"
        self.clock = 10**9

    def controller_identity(self):
        return copy.deepcopy(self.controller)

    def boot_id(self):
        return self.boot

    def now_ns(self):
        return self.clock

    def observe(self, identity):
        if "group" in identity:
            return self.observe(identity["process"])
        if "inode" in identity:
            p = Path(identity["path"])
            if not p.exists():
                return "ABSENT"
            s = p.lstat()
            return "EXACT" if (s.st_dev, s.st_ino) == (identity["device"], identity["inode"]) else "UNVERIFIED"
        return self.alive.get(identity["pid"], "EXACT" if identity == self.controller else "ABSENT")

    def all_absent(self, resources, boot_id):
        return boot_id == self.boot and all(self.observe(r["identity"]) == "ABSENT" for r in resources)

    def release_once(self, identity, timeout):
        self.releases.append(copy.deepcopy(identity))
        self.alive[identity.get("process", identity)["pid"]] = "ABSENT"


class SyntheticRoute:
    def __init__(self, driver, thread_id):
        self.driver = driver
        self.thread_id, self.instance_id = thread_id, driver.instance_id
        self.executable_sha256 = driver.rtca["executable_sha256"]
        self.policy_digest = digest("canary-effective-policy/v1", materialize_pinned(driver.rtca, driver.authorization)["sandbox"])
        self.method = driver.rtca["confinement"]["method"]
        self.backend, self.route_kind = "synthetic", "EXACT_THREAD"

    def execute_probe(self, program, spec_bytes, timeout):
        spec = json.loads(spec_bytes)
        self.driver.canary_specs.append(copy.deepcopy(spec))
        fd = os.open(spec["positive"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, spec["nonce"].encode()); os.fsync(fd)
        finally:
            os.close(fd)
        denials = [{"operation": name, "errno": 1} for _ in spec["protected"] for name in ("append", "create")]
        denials += [{"operation": "unix", "errno": 1}, {"operation": "tcp", "errno": 1}]
        return {"stdout": encoded({"nonce": spec["nonce"], "denials": denials, "positive_errno": 0}), "helper_absent": True}


class SyntheticDriver:
    def __init__(self, *, executable, launch_id, authorization, rtca, observer):
        self.authorization, self.rtca, self.observer = authorization, rtca, observer
        self.process = {"pid": 42, "birth_ns": 100, "executable_sha256": rtca["executable_sha256"], "launch_id": launch_id}
        self.instance_id, self.thread_ids = str(uuid.uuid4()), []
        self.calls, self.canary_specs, self.events = [], [], []
        self.tripwire = False
        self.outbound_guard = None
        self.hook = None
        self.before_thread_request = lambda: None
        self.before_plugins = {"data": []}

    def launch(self):
        self.observer.alive[42] = "EXACT"

    def observe_identity(self):
        return {"process": copy.deepcopy(self.process), "platform": sys.platform,
                "runtime_profile": self.rtca["runtime_profile"], "instance_id": self.instance_id}

    def verify_source_correspondence(self, source):
        assert source == self.rtca["source"]

    def method_surface(self):
        return copy.deepcopy(self.rtca["method_surface"]["methods"])

    def pinned_inputs(self):
        return materialize_pinned(self.rtca, self.authorization)

    def observe_instance(self):
        return {"fresh": True, "transport": "stdio", "sole_client": True,
                "state_root": self.authorization["provider_evidence_store"],
                "thread_ids": list(self.thread_ids), "instance_id": self.instance_id}

    def request(self, method, params):
        if self.outbound_guard is not None:
            self.outbound_guard(method, params)
        self.calls.append((method, copy.deepcopy(params)))
        if self.hook:
            result = self.hook(method, params)
            if result is not None:
                return result
        if method == "initialize":
            return {"runtimeVersion": self.rtca["runtime_version"]}
        if method == "plugin/installed":
            return copy.deepcopy(self.before_plugins)
        if method == "thread/start":
            self.thread_ids.append(THREAD)
            pinned = self.pinned_inputs()
            return dict({k: pinned[k] for k in ("cwd", "model", "modelProvider", "reasoningEffort", "sandbox",
                                              "approvalPolicy", "approvalsReviewer")},
                        thread={"id": THREAD}, activePermissionProfile=pinned["permissionProfile"],
                        runtimeWorkspaceRoots=self.authorization["worker_writable_roots"])
        if method == "thread/loaded/list":
            return {"data": [{"id": t} for t in self.thread_ids], "nextCursor": None}
        if method == "mcpServerStatus/list":
            return {"data": [], "nextCursor": None}
        if method == "thread/testToolInventory":
            return {"data": [{"name": t["name"], "category": t["category"]} for t in TOOLS], "nextCursor": None}
        if method == "turn/start":
            return {"turn": {"id": TURN}}
        if method == "turn/interrupt":
            return {}
        raise AssertionError(method)

    def notify(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))

    def capability_observations(self, thread_id):
        return {k: v["expected"] for k, v in self.rtca["capability_gates"].items()}

    def canary_route(self, thread_id):
        return SyntheticRoute(self, thread_id)

    def arm_outbound_guard(self, guard):
        self.outbound_guard = guard

    def outbound_guard_armed(self):
        return self.outbound_guard is not None

    def arm_tripwire(self, thread_id, tools):
        self.tripwire = True

    def tripwire_armed(self, thread_id):
        return self.tripwire

    def binding_capabilities(self):
        return {"openai_signed": True, "launchservices_hosted": True, "isolated_state": True,
                "owner_config_unchanged": True, "calculator_catalog_proven": False, "other_capabilities_disabled": True}

    def read_native_evidence(self, thread_id, turn_id):
        return {"thread_id": thread_id, "turn_id": turn_id, "state_root": self.authorization["provider_evidence_store"],
                "terminal_fact": "NONE"}

    def next_event(self, timeout):
        return self.events.pop(0) if self.events else None


class Fixture:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.state, self.endpoint, self.workspace = [self.root / n for n in ("state", "ipc", "work")]
        for path in (self.state, self.endpoint, self.workspace, self.state / "authorization-inbox"):
            path.mkdir(mode=0o700)
        self.grant = authorization()
        self.grant.update(workspace=str(self.workspace), authorized_roots=[str(self.workspace)],
                          worker_writable_roots=[str(self.workspace)], runtime_state_root=str(self.state),
                          controller_endpoint_root=str(self.endpoint),
                          provider_evidence_store=str(self.state / self.grant["run_id"] / "provider-state"),
                          max_corrections=0, steer_authorized=False)
        self.executable = self.root / "synthetic-runtime"
        self.executable.write_bytes(b"TEST ONLY: not a real runtime")
        self.record = rtca(executable_digest(self.executable))
        self.observer = FakeObserver()
        self.store = RunStore(self.state, self.endpoint)
        self.drivers = []
        self.configure_driver = lambda d: None

    def driver_factory(self, **kwargs):
        d = SyntheticDriver(**kwargs)
        self.configure_driver(d)
        self.drivers.append(d)
        return d

    def loader(self, profile, platform, sha256):
        admission = sealed(self.record, self.driver_factory)
        assert admission.key == (profile, platform, sha256)
        return admission.load_verified()

    def stage(self):
        path = self.state / "authorization-inbox" / (self.grant["run_id"] + ".json")
        path.write_bytes(encoded(self.grant)); path.chmod(0o600)
