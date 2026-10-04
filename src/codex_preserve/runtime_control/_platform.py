"""Conservative OS evidence. Missing process correlation is never a PID match.

Digest-specific launch, signature/hosting, descendant ownership and sandbox
realizations must be independently reviewed with an RTCA before admission.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import sys
import time
import uuid

from ._rtca import fail


def executable_digest(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            fail("RUNTIME_EXECUTABLE_NOT_REGULAR")
        h = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            fail("RUNTIME_EXECUTABLE_CHANGED")
        return h.hexdigest()
    finally:
        os.close(fd)


def elapsed_ns():
    if hasattr(time, "CLOCK_BOOTTIME"):
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    if sys.platform == "darwin":
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        class Timebase(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
        info = Timebase()
        if lib.mach_timebase_info(ctypes.byref(info)) != 0 or not info.denom:
            fail("DEADLINE_CLOCK_UNAVAILABLE")
        lib.mach_continuous_time.restype = ctypes.c_uint64
        return lib.mach_continuous_time() * info.numer // info.denom
    fail("DEADLINE_CLOCK_UNAVAILABLE")


def boot_identity():
    if sys.platform.startswith("linux"):
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if sys.platform == "darwin":
        class Timeval(ctypes.Structure):
            _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_int)]
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        value, size = Timeval(), ctypes.c_size_t(ctypes.sizeof(Timeval))
        if lib.sysctlbyname(b"kern.boottime", ctypes.byref(value), ctypes.byref(size), None, 0) != 0:
            fail("BOOT_IDENTITY_UNAVAILABLE")
        return hashlib.sha256(("boot:%d:%d" % (value.seconds, value.microseconds)).encode()).hexdigest()
    fail("BOOT_IDENTITY_UNAVAILABLE")


def process_birth(pid):
    if sys.platform.startswith("linux"):
        value = Path("/proc/%d/stat" % pid).read_text()
        fields = value[value.rindex(")") + 2:].split()
        return int(fields[19]) * 10**9 // os.sysconf("SC_CLK_TCK")
    if sys.platform == "darwin":
        class BSDInfo(ctypes.Structure):
            _fields_ = [("header", ctypes.c_uint32 * 12), ("comm", ctypes.c_char * 16),
                        ("name", ctypes.c_char * 32), ("tail", ctypes.c_uint32 * 6),
                        ("start_seconds", ctypes.c_uint64), ("start_microseconds", ctypes.c_uint64)]
        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        info = BSDInfo()
        count = lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        if count != ctypes.sizeof(info):
            raise ProcessLookupError()
        return info.start_seconds * 10**9 + info.start_microseconds * 1000
    fail("PROCESS_IDENTITY_NOT_ATTESTED")


def process_executable(pid):
    if sys.platform.startswith("linux"):
        return Path(os.readlink("/proc/%d/exe" % pid))
    if sys.platform == "darwin":
        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        path = ctypes.create_string_buffer(4096)
        if lib.proc_pidpath(pid, path, len(path)) <= 0:
            raise ProcessLookupError()
        return Path(os.fsdecode(path.value))
    fail("PROCESS_IDENTITY_NOT_ATTESTED")


class OSObserver:
    """Read-only fallback; only reviewed realizations may release provider groups.

No release by PID/name/ps search is implemented here. Darwin provider executable
and launch-correlation proof needs a digest-specific reviewed realization.
"""
    def __init__(self):
        self._launch_id = str(uuid.uuid4())

    def boot_id(self):
        return boot_identity()

    def now_ns(self):
        return elapsed_ns()

    def controller_identity(self):
        return {"pid": os.getpid(), "birth_ns": process_birth(os.getpid()),
                "executable_sha256": executable_digest(process_executable(os.getpid())),
                "launch_id": self._launch_id}

    def observe(self, identity):
        if type(identity) is dict and set(identity) == {"device", "inode", "generation", "path"}:
            try:
                s = Path(identity["path"]).lstat()
            except FileNotFoundError:
                return "ABSENT"
            except OSError:
                return "UNVERIFIED"
            return "EXACT" if stat.S_ISSOCK(s.st_mode) and (s.st_dev, s.st_ino) == (identity["device"], identity["inode"]) else "UNVERIFIED"
        try:
            birth = process_birth(identity["pid"])
        except ProcessLookupError:
            return "ABSENT"
        except FileNotFoundError:
            return "ABSENT"
        except (OSError, ValueError, KeyError):
            return "UNVERIFIED"
        # Birth mismatch proves the old incarnation gone, never authorizes
        # signaling the current PID. Boot mismatch is checked by the caller.
        if birth != identity["birth_ns"]:
            return "ABSENT"
        try:
            if executable_digest(process_executable(identity["pid"])) != identity["executable_sha256"]:
                return "UNVERIFIED"
            # Controller launch correlation is also bound by the exact IPC peer,
            # endpoint inode and generation handshake. Provider correlation and
            # group ownership require the sealed realization's resource observer.
            return "EXACT"
        except (OSError, ValueError):
            return "UNVERIFIED"

    def all_absent(self, resources, boot_id):
        if boot_id != self.boot_id():
            return False
        return all(self.observe(r["identity"]) == "ABSENT" for r in resources)

    def release_once(self, identity, timeout):
        fail("RESOURCE_UNVERIFIED")
