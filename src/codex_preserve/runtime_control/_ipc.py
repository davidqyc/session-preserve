"""Bounded owner-only Unix IPC with exact run/generation/inode fencing."""
import os
import socket
import stat
import struct
import sys

from ._rtca import fail, exact
from ._state import trusted_directory
from ._validation import _canonical, _decode

MAX_IPC_BYTES = 8192


def peer_uid(connection):
    if hasattr(connection, "getpeereid"):
        return connection.getpeereid()[0]
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    fail("IPC_PEER_NOT_ATTESTED")


def peer_pid(connection):
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
    if sys.platform == "darwin":
        return struct.unpack("i", connection.getsockopt(0, 2, 4))[0]  # LOCAL_PEERPID
    fail("IPC_PEER_NOT_ATTESTED")


def read_message(connection):
    data = b""
    while b"\n" not in data:
        block = connection.recv(min(1024, MAX_IPC_BYTES + 1 - len(data)))
        if not block:
            fail("IPC_MESSAGE_INVALID")
        data += block
        if len(data) > MAX_IPC_BYTES:
            fail("IPC_MESSAGE_INVALID")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        fail("IPC_MESSAGE_INVALID")
    return _decode(data[:-1], MAX_IPC_BYTES)


class ControllerEndpoint:
    def __init__(self, path, run_id, attempt_id, generation):
        self.path, self.run_id, self.attempt_id, self.generation = path, run_id, attempt_id, generation
        self.socket = None
        self.identity = None

    def bind(self):
        trusted_directory(self.path.parent)
        if len(os.fsencode(self.path)) >= 90:
            fail("IPC_PATH_TOO_LONG")
        mask = os.umask(0o077)
        try:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.settimeout(0.25)
            # Never unlink a pre-existing locator, even when it looks stale.
            listener.bind(str(self.path))
            os.chmod(self.path, 0o600); listener.listen(8)
        except Exception:
            listener.close()
            raise
        finally:
            os.umask(mask)
        self.socket = listener
        s = self.path.lstat()
        self.identity = {"device": s.st_dev, "inode": s.st_ino, "generation": self.generation, "path": str(self.path)}
        return self.identity

    def serve_once(self, handler):
        try:
            connection, _ = self.socket.accept()
        except socket.timeout:
            return
        with connection:
            connection.settimeout(1)
            if peer_uid(connection) != os.getuid():
                fail("IPC_PEER_NOT_ATTESTED")
            message = read_message(connection)
            if set(message) != {"run_id", "attempt_id", "generation", "endpoint_identity", "verb"} \
                    or message["run_id"] != self.run_id or message["attempt_id"] != self.attempt_id \
                    or type(message["generation"]) is not int or message["generation"] != self.generation \
                    or not exact(message["endpoint_identity"], self.identity) \
                    or message["verb"] not in ("observe", "reconcile", "stop"):
                fail("STALE_CONTROLLER_CLIENT")
            connection.sendall(_canonical(handler(message["verb"])) + b"\n")

    def close(self):
        if self.socket is None:
            return
        s = self.path.lstat()
        if (s.st_dev, s.st_ino) != (self.identity["device"], self.identity["inode"]):
            fail("RESOURCE_UNVERIFIED")
        self.socket.close()
        self.path.unlink()
        self.socket = None


def request_controller(path, run_id, attempt_id, generation, endpoint_identity, verb, controller_identity):
    trusted_directory(path.parent)
    s = path.lstat()
    if not stat.S_ISSOCK(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600 \
            or (s.st_dev, s.st_ino) != (endpoint_identity["device"], endpoint_identity["inode"]) \
            or endpoint_identity["generation"] != generation:
        fail("STALE_CONTROLLER_CLIENT")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1); connection.connect(str(path))
        from ._platform import process_birth
        after = path.lstat()
        if peer_uid(connection) != os.getuid() or peer_pid(connection) != controller_identity["pid"] \
                or process_birth(controller_identity["pid"]) != controller_identity["birth_ns"] \
                or (after.st_dev, after.st_ino) != (s.st_dev, s.st_ino):
            fail("IPC_PEER_NOT_ATTESTED")
        connection.sendall(_canonical({"run_id": run_id, "attempt_id": attempt_id,
                           "generation": generation, "endpoint_identity": endpoint_identity,
                           "verb": verb}) + b"\n")
        return read_message(connection)
