"""Per-start owner DAC controls and exact-worker sandbox confinement probe.

The route is supplied by the exact digest's reviewed realization. No launcher
sandbox is substituted. This harness never launches a provider/model or GUI.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import time

from ._rtca import digest, materialize_pinned
from ._validation import ValidationError, _canonical, _decode

# Executed by the runtime's thread-bound sandbox command route, not locally.
WORKER_PROBE = r'''
import json, os, socket, sys
v = json.loads(sys.argv[1])
r = {"nonce": v["nonce"], "denials": []}
for p in v["protected"]:
    for name, path, flags in (("append", p["file"], os.O_WRONLY | os.O_APPEND),
                              ("create", p["target"], os.O_WRONLY | os.O_CREAT | os.O_EXCL)):
        try:
            fd = os.open(path, flags, 0o600)
            os.write(fd, b"CANARY_UNEXPECTED_WRITE"); os.fsync(fd); os.close(fd)
            r["denials"].append({"operation": name, "errno": 0})
        except OSError as e:
            r["denials"].append({"operation": name, "errno": e.errno})
for name, family, address in (("unix", socket.AF_UNIX, v["unix"]),
                               ("tcp", socket.AF_INET, ("127.0.0.1", v["port"]))):
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect(address); r["denials"].append({"operation": name, "errno": 0})
        except OSError as e:
            r["denials"].append({"operation": name, "errno": e.errno})
try:
    fd = os.open(v["positive"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, v["nonce"].encode("ascii")); os.fsync(fd); os.close(fd)
    r["positive_errno"] = 0
except OSError as e:
    r["positive_errno"] = e.errno
print(json.dumps(r, separators=(",", ":")))
'''


def confinement_failure(reason):
    error = ValidationError("SANDBOX_CONFINEMENT_NOT_ATTESTED")
    error.reason = reason
    return error


def _sync_write(path, data, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL):
    fd = os.open(str(path), flags | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("short write")
        os.fsync(fd)
    finally:
        os.close(fd)


def _identity(path):
    s = path.lstat()
    return s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode)


def _drain(listener):
    count = 0
    listener.setblocking(False)
    while True:
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            return count
        connection.close()
        count += 1
        if count > 64:
            raise OSError("connection bound")


class ConfinementCanary:
    def __init__(self):
        self._used_nonces = set()

    def run(self, *, rtca, authorization, thread_id, instance_id, route, timeout=5):
        """No result cache. Every invocation builds, executes and removes probes."""
        start = time.monotonic()
        nonce = secrets.token_hex(16)
        if nonce in self._used_nonces:
            raise confinement_failure("NONCE_REUSE")
        self._used_nonces.add(nonce)
        paths, listeners, directories = [], [], []
        identities = {}
        failure, result = None, None
        try:
            effective_policy_digest = digest("canary-effective-policy/v1", materialize_pinned(rtca, authorization)["sandbox"])
            if route.thread_id != thread_id or route.instance_id != instance_id \
                    or route.executable_sha256 != rtca["executable_sha256"] \
                    or route.policy_digest != effective_policy_digest \
                    or route.method != rtca["confinement"]["method"] \
                    or route.backend != rtca["confinement"]["backend"] \
                    or route.route_kind != rtca["confinement"]["route"]:
                raise confinement_failure("ROUTE_ATTRIBUTION")
            protected_roots = list(dict.fromkeys([
                authorization["runtime_state_root"],
                str(Path(authorization["runtime_state_root"]) / "authorization-inbox"),
                str(Path(authorization["runtime_state_root"]) / authorization["run_id"]),
                authorization["provider_evidence_store"], authorization["controller_endpoint_root"]]))
            protected = []
            for root in protected_roots:
                parent = Path(root).resolve(strict=True)
                if not parent.is_dir() or parent.stat().st_uid != os.getuid():
                    raise confinement_failure("SETUP")
                directory = parent / ("canary-" + nonce[:16])
                directory.mkdir(mode=0o700)
                directories.append(directory)
                identities[directory] = _identity(directory)
                file, target = directory / "protected", directory / "created"
                paths.extend([file, target])
                _sync_write(file, b"protected-" + nonce.encode())
                identities[file] = _identity(file)
                # DAC controls: same UID can append and O_EXCL create outside
                # the worker sandbox. Restore bytes before the worker probe.
                _sync_write(file, b"DAC", os.O_WRONLY | os.O_APPEND)
                _sync_write(file, b"protected-" + nonce.encode(), os.O_WRONLY | os.O_TRUNC)
                _sync_write(target, b"DAC"); target.unlink()
                protected.append({"file": str(file), "target": str(target)})
            unix_path = Path(authorization["controller_endpoint_root"]) / ("c-" + nonce[:16])
            if len(os.fsencode(unix_path)) >= 90:
                raise confinement_failure("SETUP")
            paths.append(unix_path)
            unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listeners.append(unix)
            unix.bind(str(unix_path)); os.chmod(unix_path, 0o600); unix.listen(8)
            identities[unix_path] = _identity(unix_path)
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(tcp)
            tcp.bind(("127.0.0.1", 0)); tcp.listen(8)
            port = tcp.getsockname()[1]
            for family, address, listener in ((socket.AF_UNIX, str(unix_path), unix),
                                               (socket.AF_INET, ("127.0.0.1", port), tcp)):
                with socket.socket(family, socket.SOCK_STREAM) as control:
                    control.settimeout(1); control.connect(address)
                if _drain(listener) != 1:
                    raise confinement_failure("DAC_ATTRIBUTION")
            positive = Path(authorization["worker_writable_roots"][0]) / ("canary-" + nonce)
            if positive.exists() or positive.is_symlink():
                raise confinement_failure("SETUP")
            paths.append(positive)
            spec = {"nonce": nonce, "protected": protected, "unix": str(unix_path),
                    "port": port, "positive": str(positive)}
            before = [hashlib.sha256(Path(p["file"]).read_bytes()).hexdigest() for p in protected]
            try:
                # Realizations must return only after exact helper absence is
                # verified, including timeout cancellation. No lingering child.
                response = route.execute_probe(WORKER_PROBE, _canonical(spec), timeout)
            except TimeoutError:
                raise confinement_failure("TIMEOUT") from None
            if time.monotonic() - start > timeout + 2:
                raise confinement_failure("TIMEOUT")
            if response.get("helper_absent") is not True:
                raise confinement_failure("HELPER_ABSENCE")
            value = _decode(response["stdout"], 16384)
            if set(value) != {"nonce", "denials", "positive_errno"} or value["nonce"] != nonce:
                raise confinement_failure("RESULT_IDENTITY")
            expected = [name for _ in protected for name in ("append", "create")] + ["unix", "tcp"]
            rows = value["denials"]
            if type(rows) is not list or len(rows) != len(expected):
                raise confinement_failure("RESULT_SHAPE")
            for name, row in zip(expected, rows):
                if type(row) is not dict or set(row) != {"operation", "errno"} \
                        or row["operation"] != name or type(row["errno"]) is not int \
                        or row["errno"] != rtca["confinement"]["expected_errno"][name]:
                    raise confinement_failure("ERRNO_" + name.upper())
            if type(value["positive_errno"]) is not int or value["positive_errno"] != 0:
                raise confinement_failure("POSITIVE_CONTROL")
            if positive.is_symlink() or positive.read_bytes() != nonce.encode():
                raise confinement_failure("POSITIVE_BYTES")
            identities[positive] = _identity(positive)
            if any(_identity(Path(p["file"])) != identities[Path(p["file"])] for p in protected) \
                    or before != [hashlib.sha256(Path(p["file"]).read_bytes()).hexdigest() for p in protected]:
                raise confinement_failure("PROTECTED_DIGEST")
            if any(Path(p["target"]).exists() or Path(p["target"]).is_symlink() for p in protected):
                raise confinement_failure("PROTECTED_TARGET")
            if any(_drain(listener) != 0 for listener in listeners):
                raise confinement_failure("LISTENER_CONNECTION")
            result = {"check": "PASS", "nonce_ref": digest("canary-nonce/v1", nonce),
                      "thread_id": thread_id, "instance_id": instance_id,
                      "executable_sha256": rtca["executable_sha256"],
                      "policy_digest": effective_policy_digest,
                      "writable_roots_digest": digest("canary-writable-roots/v1", authorization["worker_writable_roots"])}
        except Exception as error:
            failure = error if isinstance(error, ValidationError) else confinement_failure("SETUP_OR_POSTCHECK")
        finally:
            cleanup_errors = []
            for listener in listeners:
                try:
                    listener.close()
                    if listener.fileno() != -1:
                        raise OSError("listener remains")
                except Exception:
                    cleanup_errors.append("listener")
            for path in reversed(paths):
                try:
                    if path.exists() or path.is_symlink():
                        if path in identities and _identity(path) != identities[path]:
                            raise OSError("identity drift")
                        if path.is_dir() or path.is_symlink():
                            raise OSError("unexpected artifact")
                        path.unlink()
                except Exception:
                    cleanup_errors.append("artifact")
            for directory in reversed(directories):
                try:
                    if _identity(directory) != identities[directory]:
                        raise OSError("identity drift")
                    directory.rmdir()
                except Exception:
                    cleanup_errors.append("directory")
            if cleanup_errors or any(p.exists() or p.is_symlink() for p in paths + directories) \
                    or time.monotonic() - start > timeout + 5:
                failure = confinement_failure("CLEANUP")
        if failure:
            raise failure
        return result
