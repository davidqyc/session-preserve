"""Bounded reads of explicit local regular files. Never writes or launches."""

import os
import stat

from ._validation import ValidationError


def read_regular_file(path, ceiling):
    try:
        # NONBLOCK avoids hanging on a FIFO; fstat checks the opened object.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValidationError("NOT_REGULAR_FILE")
            payload = stream.read(ceiling + 1)
    except (OSError, ValueError, TypeError) as error:
        if isinstance(error, ValidationError):
            raise
        raise ValidationError("LOCAL_FILE_UNREADABLE") from None
    if len(payload) > ceiling:
        raise ValidationError("PAYLOAD_TOO_LARGE")
    return payload
