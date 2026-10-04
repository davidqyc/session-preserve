"""Conjunctive pre-binding proof and local-only active outbound freeze."""
import copy

from ._rtca import (CATEGORIES, FORBIDDEN, digest, fail, materialize_pinned, exact)
from ._validation import _uuid, _canonical

MAX_PAGES = 64
MAX_ITEMS = 4096


def inventory(request, method, params, code):
    """Full, bounded pagination; missing final cursor never means complete."""
    cursor, seen, items = None, set(), []
    for _ in range(MAX_PAGES):
        page = request(method, dict(params, cursor=cursor, limit=64))
        if type(page) is not dict or set(page) != {"data", "nextCursor"} \
                or type(page["data"]) is not list or len(page["data"]) > 64:
            fail(code)
        items.extend(page["data"])
        if len(items) > MAX_ITEMS:
            fail(code)
        cursor = page["nextCursor"]
        if cursor is None:
            return items
        if type(cursor) is not str or not 1 <= len(cursor) <= 1024 or cursor in seen:
            fail(code)
        seen.add(cursor)
    fail(code)


class ActiveFreeze:
    """Only one initial turn; all other mutation/refusal is before wire send."""
    def __init__(self, wire, thread_id):
        self._wire, self.thread_id = wire, thread_id
        self._send = wire.request
        self.armed = False
        self.bound = False
        self.turn_id = None
        self._turn_sent = False
        self._closed = False
        self._authorized_send = None

    def arm(self):
        if self.armed:
            fail("FREEZE_ALREADY_ARMED")
        self.armed = True
        # All later controller requests through this realization share the same
        # guard, including accidental calls that bypass the convenience handle.
        self._wire.request = self.request
        self._wire.notify = lambda *args, **kwargs: fail("ACTIVE_METHOD_REFUSED")
        self._wire.arm_outbound_guard(self.authorize_transport)
        if not self._wire.outbound_guard_armed():
            fail("OUTBOUND_FREEZE_NOT_ARMED")

    def authorize_transport(self, method, params):
        token = (method, _canonical(params))
        if not self.armed or not self.bound or self._closed or self._authorized_send != token:
            fail("ACTIVE_METHOD_REFUSED")
        self._authorized_send = None

    def mark_bound(self):
        if not self.armed:
            fail("FREEZE_NOT_ARMED")
        self.bound = True

    def request(self, method, params):
        if not self.armed or not self.bound or self._closed or type(params) is not dict:
            fail("ACTIVE_METHOD_REFUSED")
        allowed = {
            "thread/read": {"threadId", "includeTurns"},
            "turn/interrupt": {"threadId", "turnId"},
            "turn/start": {"threadId", "input"},
        }
        if method not in allowed or set(params) != allowed[method] or params["threadId"] != self.thread_id:
            fail("ACTIVE_METHOD_REFUSED")
        if method == "turn/start":
            if self._turn_sent:
                fail("BLIND_RETRY_FORBIDDEN")
            if type(params["input"]) is not list or not params["input"] or len(_canonical(params["input"])) > 65536:
                fail("ACTIVE_METHOD_REFUSED")
            for item in params["input"]:
                if type(item) is not dict or set(item) != {"type", "text"} or item["type"] != "text" or type(item["text"]) is not str:
                    fail("ACTIVE_METHOD_REFUSED")
            # Consume before send, even if the connection loses its reply.
            self._turn_sent = True
        if method == "turn/interrupt" and (self.turn_id is None or params["turnId"] != self.turn_id):
            fail("EXACT_IDENTITY_REQUIRED")
        if method == "thread/read" and params["includeTurns"] is not True:
            fail("ACTIVE_METHOD_REFUSED")
        self._authorized_send = (method, _canonical(params))
        try:
            return self._send(method, copy.deepcopy(params))
        finally:
            self._authorized_send = None

    def close(self):
        self._closed = True


class CompositeProof:
    def __init__(self, rtca, driver, authorization, canary):
        self.rtca, self.driver, self.authorization, self.canary = rtca, driver, authorization, canary
        self.components = {}
        self._used = False

    def _component(self, key):
        self.components[key] = "PASS"

    def establish(self):
        if self._used:
            fail("PROOF_REUSE_FORBIDDEN")
        self._used = True
        r, d, a = self.rtca, self.driver, self.authorization
        identity = d.observe_identity()
        if identity["process"]["executable_sha256"] != r["executable_sha256"] \
                or identity["platform"] != r["platform"] \
                or identity["runtime_profile"] != r["runtime_profile"]:
            fail("RUNTIME_IDENTITY_MISMATCH")
        self._component("K1")
        d.verify_source_correspondence(r["source"])
        self._component("K2")
        actual = d.method_surface()
        if not exact(actual, r["method_surface"]["methods"]):
            fail("METHOD_SURFACE_MISMATCH")
        pinned = materialize_pinned(r, a)
        if not exact(d.pinned_inputs(), pinned):
            fail("RTCA_NOT_APPLICABLE")
        self._component("K3")
        instance = d.observe_instance()
        expected = {"fresh": True, "transport": "stdio", "sole_client": True,
                    "state_root": a["provider_evidence_store"], "thread_ids": [],
                    "instance_id": identity["instance_id"]}
        if not exact(instance, expected):
            fail("INSTANCE_ISOLATION_NOT_ATTESTED")
        self._component("K4")
        init = d.request("initialize", {"clientInfo": {"name": "session-preserve",
                          "title": "Session Preserve Runtime Control", "version": "0.2.0"}})
        if type(init) is not dict or init.get("runtimeVersion") != r["runtime_version"]:
            fail("RUNTIME_VERSION_MISMATCH")
        d.notify("initialized", {})
        before = d.request("plugin/installed", {"cwds": [a["workspace"]]})
        d.before_thread_request()
        response = d.request("thread/start", pinned)
        if type(response) is not dict or type(response.get("thread")) is not dict:
            fail("THREAD_POSTURE_MISMATCH")
        thread_id = response["thread"].get("id")
        _uuid(thread_id, "$.thread_id", 7)
        # Strict posture comparison includes all load-bearing fields. Runtime
        # response decoding is part of the digest-specific reviewed realization.
        fields = ("cwd", "model", "modelProvider", "reasoningEffort", "sandbox",
                  "approvalPolicy", "approvalsReviewer")
        if any(not exact(response.get(f), pinned[f]) for f in fields) \
                or response.get("activePermissionProfile") != pinned["permissionProfile"] \
                or not exact(response.get("runtimeWorkspaceRoots"), a["worker_writable_roots"]):
            fail("THREAD_POSTURE_MISMATCH")
        self._component("K5")
        loaded = inventory(d.request, "thread/loaded/list", {}, "INSTANCE_ISOLATION_NOT_ATTESTED")
        if loaded != [{"id": thread_id}] or not exact(d.observe_instance(), dict(expected, thread_ids=[thread_id])):
            fail("INSTANCE_ISOLATION_NOT_ATTESTED")
        observations = d.capability_observations(thread_id)
        if type(observations) is not dict:
            fail("CAPABILITY_GATE_NOT_CLOSED")
        for category in CATEGORIES:
            gate = r["capability_gates"][category]
            if gate["basis"] == "OBSERVED" and observations.get(category) != gate["expected"]:
                fail("CAPABILITY_GATE_NOT_CLOSED")
            if gate["basis"] == "PINNED" and not exact(pinned[gate["input"]], gate["expected"]):
                fail("CAPABILITY_GATE_NOT_CLOSED")
        self._component("K6")
        mcp = inventory(d.request, "mcpServerStatus/list", {"threadId": thread_id, "detail": "Full"},
                        "MCP_INVENTORY_NOT_CLOSED")
        if mcp:
            fail("MCP_INVENTORY_NOT_CLOSED")
        self._component("K7")
        after = d.request("plugin/installed", {"cwds": [a["workspace"]]})
        if not exact(before, after) or type(before) is not dict or set(before) != {"data"} \
                or type(before["data"]) is not list or len(before["data"]) > 128:
            fail("PLUGIN_STATE_DRIFT")
        for plugin in before["data"]:
            if type(plugin) is not dict:
                fail("PLUGIN_RELATION_NOT_CLOSED")
            for field in r["plugin_relation"]["capability_fields"]:
                if field not in plugin or plugin[field] != []:
                    fail("PLUGIN_CAPABILITY_PRESENT")
        self._component("K8")
        unified = r["exact_thread_tool_inventory_method"]
        if unified is not None:
            tools = inventory(d.request, unified, {"threadId": thread_id}, "UNIFIED_INVENTORY_NOT_CLOSED")
            expected_tools = {t["name"]: t["category"] for t in r["attested_tools"]}
            found = set()
            for tool in tools:
                if type(tool) is not dict or set(tool) != {"name", "category"} \
                        or type(tool["category"]) is not str or type(tool["name"]) is not str \
                        or tool["category"] in FORBIDDEN or tool["name"] in found \
                        or expected_tools.get(tool["name"]) != tool["category"]:
                    fail("UNIFIED_INVENTORY_NOT_CLOSED")
                found.add(tool["name"])
            if found != set(expected_tools):
                fail("UNIFIED_INVENTORY_NOT_CLOSED")
        self._component("K9")
        self.canary_result = self.canary.run(rtca=r, authorization=a, thread_id=thread_id,
                        instance_id=identity["instance_id"], route=d.canary_route(thread_id))
        self._component("K10")
        # Canary execution cannot leave an extra thread/client or a changed
        # capability-producing plugin state at the binding boundary.
        if not exact(d.observe_instance(), dict(expected, thread_ids=[thread_id])):
            fail("INSTANCE_ISOLATION_NOT_ATTESTED")
        if not exact(d.request("plugin/installed", {"cwds": [a["workspace"]]}), after):
            fail("PLUGIN_STATE_DRIFT")
        final_observations = d.capability_observations(thread_id)
        for category, gate in r["capability_gates"].items():
            if gate["basis"] == "OBSERVED" and final_observations.get(category) != gate["expected"]:
                fail("CAPABILITY_GATE_NOT_CLOSED")
        freeze = ActiveFreeze(d, thread_id)
        freeze.arm()
        d.arm_tripwire(thread_id, r["attested_tools"])
        if not d.tripwire_armed(thread_id):
            fail("TRIPWIRE_NOT_ARMED")
        self._component("K11")
        if set(self.components) != {"K%d" % n for n in range(1, 12)}:
            fail("COMPOSITE_PROOF_INCOMPLETE")
        # Re-observe the incarnation at the final binding boundary.
        if not exact(d.observe_identity(), identity):
            fail("RUNTIME_IDENTITY_MISMATCH")
        return thread_id, identity, freeze
