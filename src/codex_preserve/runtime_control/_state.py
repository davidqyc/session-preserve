"""Owner-only run reservation, durable typed ledger, fencing and release intents."""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import sys
import time

from ._rtca import digest, fail
from ._validation import (_canonical, _decode, _uuid, _under, validate_authorization,
                          authorization_digest, AUTHORIZATION_MAX_BYTES, _process, _int, _path, _pattern, _HASH)

MAX_LEDGER_BYTES = 256 * 1024
EVENT_FIELDS = {
    "START_RESERVED": {"generation", "controller", "boot_id", "start_ns", "deadline_ns", "authorization_sha256"},
    "STAGE": {"stage"},
    "LAUNCH_INTENT": {"launch_id", "executable_sha256"},
    "RESOURCE_OBSERVED": {"kind", "identity"},
    "BINDING_FLUSHED": {"binding_sha256"},
    "PROOF_ESTABLISHED": {"rtca_sha256", "review_sha256", "components_digest", "pinned_inputs_digest", "canary_nonce_ref"},
    "TURN_SEND_INTENT": {"thread_id"},
    "TURN_OBSERVED": {"thread_id", "turn_id"},
    "LOSS": {"reason"},
    "TERMINAL": {"state", "code", "stage", "decision"},
    "RELEASE_INTENT": {"resource_ref"},
    "RELEASE_OUTCOME": {"resource_ref", "outcome"},
    "GENERATION": {"generation", "controller", "boot_id"},
    "RTCA_SUSPENDED": {"rtca_sha256", "review_id"},
}
STAGES = ("RESERVED", "PREFLIGHT", "LAUNCH_INTENT", "PROCESS_OBSERVED", "THREAD_REQUESTED", "BOUND")


def validate_event(event, fields):
    """No raw strings or unclassified dictionaries can enter the control ledger."""
    if event not in EVENT_FIELDS or set(fields) != EVENT_FIELDS[event]:
        fail("LEDGER_INVALID")
    for name, value in fields.items():
        if name == "controller":
            _process(value, "$.controller")
        elif name == "identity":
            if fields["kind"] == "SOCKET":
                if type(value) is not dict or set(value) != {"device", "inode", "generation", "path"}:
                    fail("LEDGER_INVALID")
                for k in ("device", "inode", "generation"):
                    _int(value[k], 0, 2**64 - 1, "$")
                _path(value["path"], "$")
            elif type(value) is dict and set(value) == {"process", "group"}:
                _process(value["process"], "$.identity.process")
                group = value["group"]
                if type(group) is not dict or set(group) != {"pgid", "sid", "leader_birth_ns", "boot_id"}:
                    fail("LEDGER_INVALID")
                for k in ("pgid", "sid"):
                    _int(group[k], 1, 2**31 - 1, "$")
                _int(group["leader_birth_ns"], 1, 2**63 - 1, "$")
                _pattern(group["boot_id"], re.compile(r"[A-Za-z0-9_-]{1,128}\Z"), "$")
                if group["pgid"] != value["process"]["pid"] or group["leader_birth_ns"] != value["process"]["birth_ns"]:
                    fail("LEDGER_INVALID")
            else:
                _process(value, "$.identity")
        elif name in ("generation", "start_ns", "deadline_ns"):
            _int(value, 1, 2**63 - 1, "$")
        elif name.endswith("sha256") or name.endswith("digest") or name in ("resource_ref", "canary_nonce_ref"):
            _pattern(value, _HASH, "$")
        elif name in ("thread_id", "turn_id"):
            _uuid(value, "$", 7)
        elif name == "launch_id":
            _uuid(value, "$")
        elif name == "boot_id":
            _pattern(value, re.compile(r"[A-Za-z0-9_-]{1,128}\Z"), "$")
        elif name == "review_id":
            _pattern(value, re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z"), "$")
        elif name == "stage":
            if value not in STAGES: fail("LEDGER_INVALID")
        elif name == "kind":
            if value not in ("APP_SERVER", "HELPER", "SOCKET"): fail("LEDGER_INVALID")
        elif name == "reason":
            if value not in ("CONTROLLER_LOSS", "TRANSPORT_LOSS", "GUI_EXECUTION", "RESOURCE_UNVERIFIED"):
                fail("LEDGER_INVALID")
        elif name == "outcome":
            if value not in ("ABSENT", "RESOURCE_UNVERIFIED"): fail("LEDGER_INVALID")
        elif name == "state":
            if value not in ("COMPLETED", "FAILED", "STOPPED", "START_FAILED_BEFORE_BINDING"):
                fail("LEDGER_INVALID")
        elif name == "decision":
            if value not in ("NONE", "PROVIDER_COMPLETED", "PROVIDER_FAILED", "REQUESTED_STOP", "DEADLINE_EXPIRED",
                             "IDLE_EXPIRED", "CAPABILITY_UNAVAILABLE", "CONTROLLER_LOST", "TRANSPORT_LOST", "GUI_EXECUTION_UNCERTAIN"):
                fail("LEDGER_INVALID")
        elif name == "code":
            _pattern(value, re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z"), "$")
        else:
            fail("LEDGER_INVALID")


def canonical_roots():
    """OS account record of real UID; never HOME/XDG/argv/grant/provider env."""
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    if sys.platform == "darwin":
        state = home / "Library" / "Application Support" / "session-preserve" / "runtime"
    else:
        state = home / ".local" / "state" / "session-preserve" / "runtime"
    return state, home / ".sp-rt-ipc"


def sync(fd):
    os.fsync(fd)
    if sys.platform == "darwin" and stat.S_ISREG(os.fstat(fd).st_mode):
        fcntl.fcntl(fd, 51)  # F_FULLFSYNC: don't silently degrade durability.


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        sync(fd)
    finally:
        os.close(fd)


def trusted_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        fail("UNTRUSTED_STATE_ROOT")
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
            fail("UNTRUSTED_STATE_ROOT")
    finally:
        os.close(fd)


def trusted_read(path, maximum):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() \
                or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) & 0o177:
            fail("UNTRUSTED_OWNER_FILE")
        with os.fdopen(os.dup(fd), "rb") as stream:
            payload = stream.read(maximum + 1)
        after = os.fstat(fd)
        if len(payload) > maximum or (s.st_size, s.st_mtime_ns, s.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            fail("UNTRUSTED_OWNER_FILE")
        return payload, (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    finally:
        os.close(fd)


def publish_once(path, value):
    """Durable no-replace publication, without a partially readable final file."""
    path = Path(path)
    temporary = path.parent / (".publish-" + secrets.token_hex(16))
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        data = value if type(value) is bytes else _canonical(value)
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data); stream.flush()
        sync(fd)
        os.link(str(temporary), str(path), follow_symlinks=False)
    finally:
        os.close(fd)
        temporary.unlink()
        sync_directory(path.parent)


@contextmanager
def exclusive(path, blocking=True):
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != 0o600:
            fail("UNTRUSTED_OWNER_FILE")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            fail("CONTROLLER_STILL_ALIVE")
        yield fd
    finally:
        os.close(fd)


def resolved_scope(grant, state, endpoint):
    if grant["runtime_state_root"] != str(state) or grant["controller_endpoint_root"] != str(endpoint):
        fail("CANONICAL_ROOT_MISMATCH")
    if grant["provider_evidence_store"] != str(state / grant["run_id"] / "provider-state"):
        fail("PROVIDER_STATE_ROOT_MISMATCH")
    roots = [grant["workspace"]] + grant["authorized_roots"] + grant["worker_writable_roots"]
    for root in roots:
        path = Path(root)
        if path.resolve(strict=True) != path or not path.is_dir():
            fail("RESOLVED_SCOPE_MISMATCH")
    for root in grant["worker_writable_roots"]:
        if any(_under(root.casefold(), str(p).casefold()) or _under(str(p).casefold(), root.casefold())
               for p in (state, endpoint)):
            fail("WORKER_WRITABLE_AUTHORITY")


class RunStore:
    """Internal store; production callers use canonical_roots exclusively."""
    def __init__(self, state, endpoint):
        self.state, self.endpoint = Path(state), Path(endpoint)

    def authorization(self, run_id):
        _uuid(run_id, "$.run_id")
        if (self.state / run_id).exists() or (self.state / run_id).is_symlink():
            fail("RUN_ALREADY_EXISTS")
        for path in (self.state, self.endpoint, self.state / "authorization-inbox"):
            trusted_directory(path)
        payload, identity = trusted_read(self.state / "authorization-inbox" / (run_id + ".json"), AUTHORIZATION_MAX_BYTES)
        grant = validate_authorization(payload)
        if grant["run_id"] != run_id:
            fail("EXACT_IDENTITY_REQUIRED")
        # Deny phase escalation before reservation/burn or executable launch.
        if any(grant["calculator"].values()):
            fail("CALCULATOR_NOT_AUTHORIZED_P1")
        if grant["steer_authorized"] or grant["max_corrections"]:
            fail("STEER_NOT_AUTHORIZED_P1")
        resolved_scope(grant, self.state, self.endpoint)
        return grant, payload, identity

    def endpoint_path(self, run_id, generation):
        locator = digest("runtime-controller-locator/v1", [run_id, generation])[:24]
        path = self.endpoint / (locator + ".sock")
        if len(os.fsencode(path)) >= 90:
            fail("IPC_PATH_TOO_LONG")
        return path

    def reserve(self, grant, payload, inbox_identity, controller, boot_id, now_ns, resources):
        self.endpoint_path(grant["run_id"], 1)  # Must precede RUN_ID burn.
        with exclusive(self.state / "start.lock"):
            directory = self.state / grant["run_id"]
            if directory.exists() or directory.is_symlink():
                fail("RUN_ALREADY_EXISTS")
            for earlier in self.state.iterdir():
                if not earlier.is_dir() or earlier.name == "authorization-inbox":
                    continue
                try:
                    _uuid(earlier.name, "$.run_id")
                except ValueError:
                    continue
                old = self.load(earlier.name)
                prior = old.grant
                overlap = prior["task_id"] == grant["task_id"] or any(
                    _under(x.casefold(), y.casefold()) or _under(y.casefold(), x.casefold())
                    for x in [grant["workspace"]] + grant["authorized_roots"] + grant["worker_writable_roots"]
                    for y in [prior["workspace"]] + prior["authorized_roots"] + prior["worker_writable_roots"])
                if overlap and (not old.terminal or not resources.all_absent(old.resources(), old.boot_id)):
                    fail("OVERLAPPING_ACTIVE_RUN")
            directory.mkdir(mode=0o700)
            sync_directory(self.state)
            run = RunRecord(directory, grant)
            # The reserver owns generation 1 immediately; no launcher handoff.
            run.acquire()
            try:
                source = self.state / "authorization-inbox" / (grant["run_id"] + ".json")
                actual, identity = trusted_read(source, AUTHORIZATION_MAX_BYTES)
                if identity != inbox_identity or actual != payload:
                    fail("AUTHORIZATION_IDENTITY_DRIFT")
                os.rename(str(source), str(directory / "authorization.json"))
                moved, moved_id = trusted_read(directory / "authorization.json", AUTHORIZATION_MAX_BYTES)
                if moved != payload or moved_id != inbox_identity:
                    fail("AUTHORIZATION_IDENTITY_DRIFT")
                sync_directory(source.parent); sync_directory(directory)
                (directory / "provider-state").mkdir(mode=0o700)
                sync_directory(directory)
                run.append("START_RESERVED", generation=1, controller=controller, boot_id=boot_id,
                           start_ns=now_ns, deadline_ns=now_ns + grant["wall_clock_seconds"] * 10**9,
                           authorization_sha256=authorization_digest(payload))
            except Exception:
                # A reservation is burned even if consumption/durability fails.
                # No launch occurred; retain an explicit pre-binding terminal.
                run.append("TERMINAL", state="START_FAILED_BEFORE_BINDING", code="RESERVATION_FAILED", stage="RESERVED")
                run.release_lock()
                raise
            return run

    def load(self, run_id):
        _uuid(run_id, "$.run_id")
        directory = self.state / run_id
        trusted_directory(directory)
        payload, _ = trusted_read(directory / "authorization.json", AUTHORIZATION_MAX_BYTES)
        return RunRecord(directory, validate_authorization(payload))

    def suspended(self, rtca_sha256, review_id):
        path = self.state / ("suspended-" + rtca_sha256 + ".json")
        if not path.exists():
            # The typed pre-action suspension record also closes starts after a
            # crash between recording the violation and publishing the marker.
            for directory in self.state.iterdir():
                if not directory.is_dir() or directory.name == "authorization-inbox":
                    continue
                try:
                    _uuid(directory.name, "$")
                except ValueError:
                    continue
                run = self.load(directory.name)
                for row in run.records():
                    if row["event"] == "RTCA_SUSPENDED" and row["rtca_sha256"] == rtca_sha256:
                        if row["review_id"] != review_id:
                            fail("RTCA_INVALID")
                        return True
            return False
        payload, _ = trusted_read(path, 4096)
        value = _decode(payload, 4096)
        if set(value) != {"rtca_sha256", "review_id"} or value["rtca_sha256"] != rtca_sha256:
            fail("RTCA_INVALID")
        if value["review_id"] != review_id:
            fail("RTCA_INVALID")
        return True

    def suspend(self, rtca_sha256, review_id):
        path = self.state / ("suspended-" + rtca_sha256 + ".json")
        value = {"rtca_sha256": rtca_sha256, "review_id": review_id}
        try:
            publish_once(path, value)
        except FileExistsError:
            if not self.suspended(rtca_sha256, review_id):
                fail("RTCA_INVALID")


class RunRecord:
    def __init__(self, directory, grant):
        self.directory, self.grant = Path(directory), grant
        self._lock = None

    def acquire(self):
        if self._lock is not None:
            fail("CONTROLLER_STILL_ALIVE")
        lock = exclusive(self.directory / "controller.lock", blocking=False)
        lock.__enter__()
        self._lock = lock

    def release_lock(self):
        if self._lock is not None:
            self._lock.__exit__(None, None, None)
            self._lock = None

    def records(self):
        path = self.directory / "preaction.log"
        if not path.exists():
            return []
        payload, _ = trusted_read(path, MAX_LEDGER_BYTES)
        values = []
        for line in payload.splitlines():
            value = _decode(line, 16384)
            if value.get("event") not in EVENT_FIELDS or set(value) != EVENT_FIELDS[value["event"]] | {"event", "sequence"}:
                fail("LEDGER_INVALID")
            if type(value["sequence"]) is not int or value["sequence"] != len(values) + 1:
                fail("LEDGER_INVALID")
            validate_event(value["event"], {k: v for k, v in value.items() if k not in ("event", "sequence")})
            values.append(value)
        if payload and not payload.endswith(b"\n"):
            fail("LEDGER_INVALID")
        return values

    def append(self, event, **fields):
        if event == "TERMINAL" and "decision" not in fields:
            fields["decision"] = {"COMPLETED": "PROVIDER_COMPLETED", "FAILED": "PROVIDER_FAILED",
                                  "START_FAILED_BEFORE_BINDING": "NONE"}.get(fields.get("state"), "REQUESTED_STOP")
        if self._lock is None or event not in EVENT_FIELDS or set(fields) != EVENT_FIELDS[event]:
            fail("LEDGER_WRITE_REFUSED")
        validate_event(event, fields)
        prior = self.records()
        if event == "TERMINAL" and any(v["event"] == "TERMINAL" for v in prior):
            fail("TERMINAL_ALREADY_RECORDED")
        if event == "RESOURCE_OBSERVED":
            resources = [v for v in prior if v["event"] == event]
            if len(resources) >= 16 or any(v["identity"] == fields["identity"] for v in resources):
                fail("OWNED_RESOURCE_BOUND_OR_DUPLICATE")
        if event == "RELEASE_INTENT" and any(v["event"] == event and v["resource_ref"] == fields["resource_ref"] for v in prior):
            fail("RELEASE_ALREADY_ATTEMPTED")
        data = _canonical(dict(fields, event=event, sequence=len(self.records()) + 1)) + b"\n"
        if len(data) > 16384:
            fail("LEDGER_BOUND_EXCEEDED")
        fd = os.open(str(self.directory / "preaction.log"), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            if os.fstat(fd).st_size + len(data) > MAX_LEDGER_BYTES:
                fail("LEDGER_BOUND_EXCEEDED")
            if os.write(fd, data) != len(data):
                fail("LEDGER_WRITE_FAILED")
            sync(fd); sync_directory(self.directory)
        finally:
            os.close(fd)

    @property
    def terminal(self):
        return next((v for v in self.records() if v["event"] == "TERMINAL"), None)

    @property
    def generation(self):
        return next((v["generation"] for v in reversed(self.records()) if v["event"] in ("GENERATION", "START_RESERVED")), 0)

    @property
    def controller(self):
        return next((v["controller"] for v in reversed(self.records()) if v["event"] in ("GENERATION", "START_RESERVED")), None)

    @property
    def boot_id(self):
        return next((v["boot_id"] for v in self.records() if v["event"] == "START_RESERVED"), None)

    @property
    def stage(self):
        return next((v["stage"] for v in reversed(self.records()) if v["event"] == "STAGE"), "RESERVED")

    def resources(self):
        return [v for v in self.records() if v["event"] == "RESOURCE_OBSERVED"]

    def fence_closer(self, observer):
        self.acquire()
        try:
            if observer.boot_id() != self.boot_id or observer.observe(self.controller) != "ABSENT":
                fail("CONTROLLER_ABSENCE_NOT_ATTESTED")
            self.append("GENERATION", generation=self.generation + 1,
                        controller=observer.controller_identity(), boot_id=observer.boot_id())
        except Exception:
            self.release_lock()
            raise

    def release_resources(self, observer):
        if not self.terminal:
            fail("TERMINAL_LEDGER_REQUIRED")
        outcomes = []
        for resource in self.resources():
            ref = digest("runtime-owned-resource/v1", resource["identity"])
            previous = any(v["event"] == "RELEASE_INTENT" and v["resource_ref"] == ref for v in self.records())
            if observer.boot_id() != self.boot_id:
                outcome = "RESOURCE_UNVERIFIED"
            elif observer.observe(resource["identity"]) == "ABSENT":
                outcome = "ABSENT"
            elif previous:
                outcome = "RESOURCE_UNVERIFIED"
            else:
                self.append("RELEASE_INTENT", resource_ref=ref)
                # Re-derive live launch correlation/incarnation AFTER intent sync.
                if observer.observe(resource["identity"]) != "EXACT":
                    outcome = "RESOURCE_UNVERIFIED"
                else:
                    try:
                        observer.release_once(resource["identity"], timeout=5)
                        outcome = "ABSENT" if observer.observe(resource["identity"]) == "ABSENT" else "RESOURCE_UNVERIFIED"
                    except Exception:
                        outcome = "RESOURCE_UNVERIFIED"
            self.append("RELEASE_OUTCOME", resource_ref=ref, outcome=outcome)
            outcomes.append({"kind": resource["kind"], "identity_ref": ref,
                             "outcome": outcome, "release_intent": previous or outcome == "ABSENT"})
        return outcomes
