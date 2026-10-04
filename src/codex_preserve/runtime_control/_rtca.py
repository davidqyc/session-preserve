"""Public RTCA contract and sealed production admission. No runtime discovery.

A review receipt is not self-authenticating: only byte identities explicitly
shipped in the supported registry may reach the production launcher.
"""
import hashlib
import re
from urllib.parse import urlparse

from ._validation import (_decode, _object, _canonical, _pattern, _HASH, _VERSION,
                          ValidationError, PROFILE_GENERIC)

RTCA_SCHEMA = "session-preserve-runtime-tool-catalog-attestation/v1"
REVIEW_SCHEMA = "session-preserve-runtime-tool-catalog-review/v1"
RTCA_MAX_BYTES = 256 * 1024
CATEGORIES = ("shell", "filesystem", "mcp", "dynamic", "plugin", "computer_use",
              "delegation", "meta", "network", "managed_requirements")
FORBIDDEN = frozenset(CATEGORIES) - {"shell", "filesystem"}
# An admission needs tracked RTCA + receipt bytes, their independently reviewed
# identities, and an exact platform realization. No scan/env/CLI override exists.
SUPPORTED_RUNTIME_SET = ()
REVIEW_DERIVATIONS = ("source", "method_surface", "construction_sites", "categories",
                      "dispatch_closure", "plugin_relation", "canary_route")
PINNED_FIELDS = ("cwd", "model", "modelProvider", "reasoningEffort",
                 "permissionProfile", "sandbox", "approvalPolicy", "approvalsReviewer",
                 "config", "features", "tools", "disabledPluginIds")
_OPERATION = re.compile(r"[A-Za-z:][A-Za-z0-9_./:-]{0,127}\Z")


def fail(code):
    raise ValidationError(code)


def digest(domain, value):
    return hashlib.sha256(domain.encode() + b"\0" + _canonical(value)).hexdigest()


def exact(value, expected):
    """JSON type identity, including bool/int distinctions, matters to proof."""
    try:
        return _canonical(value) == _canonical(expected)
    except (TypeError, ValueError, RecursionError):
        return False


def bytes_digest(payload):
    return hashlib.sha256(payload).hexdigest()


def bounded_names(value, maximum=2048):
    if type(value) is not list or not value or len(value) > maximum:
        fail("RTCA_INVALID")
    for name in value:
        _pattern(name, _OPERATION, "$")
    if len(set(value)) != len(value):
        fail("RTCA_INVALID")


def public_evidence(value):
    _object(value, ("url", "sha256"))
    if type(value["url"]) is not str or len(value["url"]) > 2048:
        fail("RTCA_INVALID")
    url = urlparse(value["url"])
    if url.scheme != "https" or not url.netloc or url.username or url.password:
        fail("RTCA_INVALID")
    _pattern(value["sha256"], _HASH, "$")


def validate_rtca(payload, review_payload):
    """Pure bounded validator. Review admission still requires a sealed registry."""
    try:
        v = _decode(payload, RTCA_MAX_BYTES)
        _object(v, ("schema", "runtime_profile", "platform", "executable_sha256",
                    "runtime_version", "author", "source", "method_surface",
                    "exact_thread_tool_inventory_method", "pinned_inputs",
                    "thread_start_digest", "construction_sites", "capability_gates",
                    "attested_tools", "dispatch_closure", "hot_reload_inputs",
                    "plugin_relation", "confinement", "review_id"))
        if v["schema"] != RTCA_SCHEMA or v["runtime_profile"] != PROFILE_GENERIC:
            fail("RTCA_INVALID")
        bounded_names([v["platform"], v["author"], v["review_id"]])
        _pattern(v["executable_sha256"], _HASH, "$")
        _pattern(v["runtime_version"], _VERSION, "$")
        source = v["source"]
        _object(source, ("repository", "commit", "tree_sha256", "correspondence"))
        public_evidence(source["repository"])
        _pattern(source["commit"], re.compile(r"[0-9a-f]{40,64}\Z"), "$")
        _pattern(source["tree_sha256"], _HASH, "$")
        corr = source["correspondence"]
        _object(corr, ("kind", "executable_sha256", "evidence"))
        if corr["kind"] not in ("VENDOR_PROVENANCE", "REPRODUCIBLE_BYTE_IDENTICAL_BUILD") \
                or corr["executable_sha256"] != v["executable_sha256"]:
            fail("SOURCE_CORRESPONDENCE_NOT_ATTESTED")
        public_evidence(corr["evidence"])
        surface = v["method_surface"]
        _object(surface, ("methods", "count", "digest", "evidence"))
        if type(surface["methods"]) is not list or not 1 <= len(surface["methods"]) <= 2048:
            fail("RTCA_INVALID")
        names, inventories = [], []
        for entry in surface["methods"]:
            _object(entry, ("name", "exact_thread_complete_inventory"))
            if type(entry["exact_thread_complete_inventory"]) is not bool:
                fail("RTCA_INVALID")
            names.append(entry["name"])
            if entry["exact_thread_complete_inventory"]:
                inventories.append(entry["name"])
        bounded_names(names)
        if type(surface["count"]) is not int or surface["count"] != len(names) \
                or surface["digest"] != digest("rtca-method-surface/v1", surface["methods"]):
            fail("METHOD_SURFACE_MISMATCH")
        public_evidence(surface["evidence"])
        mandatory = v["exact_thread_tool_inventory_method"]
        if (inventories and mandatory not in inventories) or (not inventories and mandatory is not None):
            fail("UNIFIED_INVENTORY_REQUIRED")
        pinned = v["pinned_inputs"]
        _object(pinned, PINNED_FIELDS)
        _object(pinned["sandbox"], ("type", "writableRoots", "networkAccess",
                                     "excludeTmpdirEnvVar", "excludeSlashTmp"))
        if pinned["cwd"] != "@workspace" or not exact(pinned["sandbox"], {
                "type": "workspaceWrite", "writableRoots": "@writable_roots",
                "networkAccess": False, "excludeTmpdirEnvVar": True, "excludeSlashTmp": True}) \
                or pinned["approvalPolicy"] != "never" or pinned["tools"] != [] \
                or pinned["disabledPluginIds"] != []:
            fail("RTCA_INVALID")
        for field in ("model", "modelProvider", "reasoningEffort", "permissionProfile", "approvalsReviewer"):
            bounded_names([pinned[field]])
        for field in ("config", "features"):
            if type(pinned[field]) is not dict or len(pinned[field]) > 128:
                fail("RTCA_INVALID")
        if v["thread_start_digest"] != digest("rtca-thread-start/v1", pinned):
            fail("RTCA_INVALID")
        gates = v["capability_gates"]
        if type(gates) is not dict or set(gates) != set(CATEGORIES):
            fail("CAPABILITY_GATE_NOT_CLOSED")
        for category, gate in gates.items():
            _object(gate, ("basis", "input", "expected", "evidence"))
            if gate["basis"] not in ("PINNED", "OBSERVED", "ABSENT_IN_DIGEST"):
                fail("CAPABILITY_GATE_NOT_CLOSED")
            public_evidence(gate["evidence"])
            if gate["basis"] == "PINNED" and gate["input"] not in pinned:
                fail("CAPABILITY_GATE_NOT_CLOSED")
            if category in FORBIDDEN and gate["expected"] != "CLOSED":
                fail("CAPABILITY_GATE_NOT_CLOSED")
        sites = v["construction_sites"]
        if type(sites) is not list or not 1 <= len(sites) <= 1024:
            fail("RTCA_INVALID")
        seen = set()
        for site in sites:
            _object(site, ("site", "category", "tools", "reachable", "evidence"))
            bounded_names([site["site"]])
            if site["site"] in seen or site["category"] not in CATEGORIES or type(site["reachable"]) is not bool:
                fail("RTCA_INVALID")
            seen.add(site["site"])
            if site["tools"]:
                bounded_names(site["tools"], 128)
            elif type(site["tools"]) is not list:
                fail("RTCA_INVALID")
            if site["category"] in FORBIDDEN and site["reachable"]:
                fail("CAPABILITY_GATE_NOT_CLOSED")
            public_evidence(site["evidence"])
        tools = v["attested_tools"]
        if type(tools) is not list or not 1 <= len(tools) <= 128:
            fail("RTCA_INVALID")
        tool_names = []
        for tool in tools:
            _object(tool, ("name", "category", "construction_site"))
            tool_names.append(tool["name"])
            matches = [s for s in sites if s["site"] == tool["construction_site"]]
            if tool["category"] in FORBIDDEN or tool["category"] not in CATEGORIES \
                    or len(matches) != 1 or not matches[0]["reachable"] \
                    or matches[0]["category"] != tool["category"] or tool["name"] not in matches[0]["tools"]:
                fail("RTCA_INVALID")
        bounded_names(tool_names, 128)
        reachable = {name for site in sites if site["reachable"] for name in site["tools"]}
        if reachable != set(tool_names):
            fail("DISPATCH_CLOSURE_NOT_ATTESTED")
        closure = v["dispatch_closure"]
        _object(closure, ("tools", "unknown_dispatch", "evidence"))
        if closure["tools"] != sorted(tool_names) or closure["unknown_dispatch"] is not False:
            fail("DISPATCH_CLOSURE_NOT_ATTESTED")
        public_evidence(closure["evidence"])
        reloads = v["hot_reload_inputs"]
        if type(reloads) is not list or len(reloads) > 128:
            fail("RTCA_INVALID")
        for entry in reloads:
            _object(entry, ("input", "gate", "evidence"))
            if entry["gate"] != "FROZEN" or entry["input"] not in pinned:
                fail("CAPABILITY_GATE_NOT_CLOSED")
            public_evidence(entry["evidence"])
        relation = v["plugin_relation"]
        _object(relation, ("method", "capability_fields", "evidence"))
        if relation["method"] != "plugin/installed":
            fail("PLUGIN_RELATION_NOT_CLOSED")
        bounded_names(relation["capability_fields"], 32)
        public_evidence(relation["evidence"])
        route = v["confinement"]
        _object(route, ("method", "route", "backend", "expected_errno", "policy_digest",
                        "equivalence", "evidence"))
        if route["method"] not in names or route["route"] not in ("EXACT_THREAD", "EQUIVALENT_FALLBACK"):
            fail("CONFINEMENT_ROUTE_NOT_ATTESTED")
        bounded_names([route["backend"]])
        _pattern(route["policy_digest"], _HASH, "$")
        if route["policy_digest"] != digest("rtca-sandbox-policy/v1", pinned["sandbox"]):
            fail("CONFINEMENT_ROUTE_NOT_ATTESTED")
        if type(route["expected_errno"]) is not dict or set(route["expected_errno"]) != {"append", "create", "unix", "tcp"}:
            fail("RTCA_INVALID")
        if any(type(e) is not int or not 1 <= e <= 255 for e in route["expected_errno"].values()):
            fail("RTCA_INVALID")
        public_evidence(route["evidence"])
        if route["route"] == "EQUIVALENT_FALLBACK":
            eq = route["equivalence"]
            _object(eq, ("executable_sha256", "policy_digest", "evidence"))
            if eq["executable_sha256"] != v["executable_sha256"] or eq["policy_digest"] != route["policy_digest"]:
                fail("CONFINEMENT_ROUTE_NOT_ATTESTED")
            public_evidence(eq["evidence"])
        elif route["equivalence"] is not None:
            fail("RTCA_INVALID")
        required = {"initialize", "thread/start", "thread/loaded/list", "thread/read", "turn/start",
                    "turn/interrupt", "mcpServerStatus/list", "plugin/installed"}
        if not required <= set(names):
            fail("METHOD_NOT_ATTESTED")
        review = _decode(review_payload, 16384)
        _object(review, ("schema", "review_id", "reviewer", "author", "independence",
                         "rtca_sha256", "derivations", "verdict", "evidence"))
        if review["schema"] != REVIEW_SCHEMA or review["review_id"] != v["review_id"] \
                or review["author"] != v["author"] or review["reviewer"] == v["author"] \
                or review["independence"] not in ("I2", "I3") or review["verdict"] != "PASS" \
                or review["rtca_sha256"] != bytes_digest(payload) \
                or review["derivations"] != list(REVIEW_DERIVATIONS):
            fail("RTCA_INVALID")
        bounded_names([review["reviewer"]])
        public_evidence(review["evidence"])
        return v
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        if isinstance(error, ValidationError) and error.code in {
                "SOURCE_CORRESPONDENCE_NOT_ATTESTED", "METHOD_SURFACE_MISMATCH",
                "UNIFIED_INVENTORY_REQUIRED", "CAPABILITY_GATE_NOT_CLOSED",
                "DISPATCH_CLOSURE_NOT_ATTESTED", "PLUGIN_RELATION_NOT_CLOSED",
                "CONFINEMENT_ROUTE_NOT_ATTESTED", "METHOD_NOT_ATTESTED"}:
            raise
        fail("RTCA_INVALID")


def materialize_pinned(rtca, authorization):
    value = _decode(_canonical(rtca["pinned_inputs"]), RTCA_MAX_BYTES)
    value["cwd"] = authorization["workspace"]
    value["sandbox"]["writableRoots"] = authorization["worker_writable_roots"]
    return value


def load_supported(runtime_profile, platform, executable_sha256):
    """Only code-reviewed sealed public entries; never searches filesystem/env."""
    key = (runtime_profile, platform, executable_sha256)
    for entry in SUPPORTED_RUNTIME_SET:
        if entry.key == key:
            return entry.load_verified()
    fail("RUNTIME_DIGEST_UNSUPPORTED")


class SealedAdmission:
    """A tracked entry pins both documents and its independently reviewed driver.

    Constructing one is not admission; production lookup only admits entries in
    SUPPORTED_RUNTIME_SET. Synthetic test entries never enter that registry.
    """
    def __init__(self, key, payload, review_payload, rtca_sha256, review_sha256, realization, resource_observer_factory):
        self.key, self.payload, self.review_payload = key, payload, review_payload
        self.rtca_sha256, self.review_sha256 = rtca_sha256, review_sha256
        self.realization = realization
        self.resource_observer_factory = resource_observer_factory

    def load_verified(self):
        if bytes_digest(self.payload) != self.rtca_sha256 or bytes_digest(self.review_payload) != self.review_sha256:
            fail("RTCA_INVALID")
        if not callable(self.realization) or not callable(self.resource_observer_factory):
            fail("RTCA_INVALID")
        value = validate_rtca(self.payload, self.review_payload)
        if self.key != (value["runtime_profile"], value["platform"], value["executable_sha256"]):
            fail("RTCA_INVALID")
        return self, value
