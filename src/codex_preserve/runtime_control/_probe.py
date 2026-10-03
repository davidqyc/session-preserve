"""Passive, advisory inspection of explicit static metadata and path attributes."""

import os
import stat

from ._local import read_regular_file
from ._validation import ValidationError, _decode, _object, _enum, _pattern, _VERSION


def passive_probe(*, metadata=None, executable=None):
    """No automatic discovery. Metadata is a <=4 KiB JSON declaration, not proof."""
    result = {
        "status": "ADVISORY", "provider": "codex", "experimental": True,
        "declared_runtime_version": None, "version_status": "UNKNOWN",
        "executable_status": "UNKNOWN", "live_capabilities": "UNVERIFIED",
        "execution_attested": False,
        "semantics": "Passive static evidence only; not live capability attestation.",
    }
    if metadata is not None:
        try:
            value = _decode(read_regular_file(metadata, 4096), 4096)
            _object(value, ("provider", "declared_runtime_version"))
            _enum(value["provider"], ("codex",), "$.provider")
            _pattern(value["declared_runtime_version"], _VERSION, "$.declared_runtime_version")
        except ValidationError:
            result["version_status"] = "UNVERIFIED"
        else:
            result["declared_runtime_version"] = value["declared_runtime_version"]
            result["version_status"] = "DECLARED"
    if executable is not None:
        try:
            mode = os.stat(executable).st_mode
        except (OSError, ValueError, TypeError):
            result["executable_status"] = "UNVERIFIED"
        else:
            result["executable_status"] = "REGULAR_FILE" if stat.S_ISREG(mode) else "NOT_REGULAR_FILE"
    return result
