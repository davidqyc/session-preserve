"""Bounded serialized stdio JSON-RPC substrate for reviewed realizations.

No discovery/spawn/retry/resume/logging. Notifications are handled before the
next outbound request. Runtime-specific decoding and exact process ownership
remain part of the sealed RTCA realization.
"""
import os
import selectors
import threading
import time

from ._rtca import fail
from ._validation import _canonical, _decode

MAX_FRAME = 256 * 1024


class StdioTransport:
    def __init__(self, read_fd, write_fd, notification_handler):
        self.read_fd, self.write_fd = read_fd, write_fd
        self.handler = notification_handler
        self._buffer = b""
        self._next_id = 0
        self._lock = threading.Lock()
        self._lost = False
        self._policy = None
        self._selector = selectors.DefaultSelector()
        self._selector.register(read_fd, selectors.EVENT_READ)
        os.set_blocking(read_fd, False)
        os.set_blocking(write_fd, False)

    def arm_policy(self, policy):
        if self._policy is not None:
            fail("FREEZE_ALREADY_ARMED")
        self._policy = policy

    def _send(self, message, deadline):
        data = _canonical(message) + b"\n"
        if len(data) > MAX_FRAME:
            fail("TRANSPORT_FRAME_BOUND")
        # Pipes are nonblocking: provider stalls never hang a controller forever.
        with selectors.DefaultSelector() as writer:
            writer.register(self.write_fd, selectors.EVENT_WRITE)
            offset = 0
            while offset < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not writer.select(remaining):
                    self._lost = True; fail("PROVIDER_CONNECTION_LOSS")
                try:
                    count = os.write(self.write_fd, data[offset:])
                except BlockingIOError:
                    continue
                except OSError:
                    self._lost = True; fail("PROVIDER_CONNECTION_LOSS")
                if not count:
                    self._lost = True; fail("PROVIDER_CONNECTION_LOSS")
                offset += count

    def _read(self, deadline):
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._selector.select(remaining):
                self._lost = True; fail("PROVIDER_CONNECTION_LOSS")
            try:
                block = os.read(self.read_fd, min(65536, MAX_FRAME + 1 - len(self._buffer)))
            except BlockingIOError:
                continue
            if not block:
                self._lost = True; fail("PROVIDER_CONNECTION_LOSS")
            self._buffer += block
            if len(self._buffer) > MAX_FRAME:
                self._lost = True; fail("TRANSPORT_FRAME_BOUND")
        line, self._buffer = self._buffer.split(b"\n", 1)
        try:
            return _decode(line, MAX_FRAME)
        except ValueError:
            self._lost = True
            fail("PROVIDER_REPLY_INVALID")

    def request(self, method, params, timeout=5):
        if self._lost:
            fail("PROVIDER_CONNECTION_LOSS")
        if not self._lock.acquire(blocking=False):
            fail("PROVIDER_CALL_ALREADY_OUTSTANDING")
        try:
            if self._policy:
                self._policy(method, params)
            self._next_id += 1
            request_id = self._next_id
            deadline = time.monotonic() + timeout
            self._send({"id": request_id, "method": method, "params": params}, deadline)
            for _ in range(4096):
                response = self._read(deadline)
                if "method" in response:
                    if set(response) != {"method", "params"}:
                        self._lost = True; fail("UNATTESTED_SERVER_REQUEST")
                    self.handler(response["method"], response["params"])
                    continue
                if type(response.get("id")) is not int or response["id"] != request_id:
                    self._lost = True; fail("PROVIDER_REPLY_IDENTITY_MISMATCH")
                if set(response) == {"id", "error"}:
                    fail("PROVIDER_METHOD_FAILED")
                if set(response) != {"id", "result"} or type(response["result"]) is not dict:
                    self._lost = True; fail("PROVIDER_REPLY_INVALID")
                return response["result"]
            self._lost = True; fail("TRANSPORT_EVENT_BOUND")
        finally:
            self._lock.release()

    def notify(self, method, params):
        if self._lost or self._policy is not None or method != "initialized" or params != {}:
            fail("ACTIVE_METHOD_REFUSED")
        self._send({"method": method, "params": params}, time.monotonic() + 5)

    def close(self):
        # FD ownership/at-most-once release belongs to the controller ledger.
        self._lost = True
        self._selector.close()
