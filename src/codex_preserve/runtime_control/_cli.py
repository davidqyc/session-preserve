"""Explicit P1 entries, preserved passive APIs and earliest P2/P3 gates."""

import argparse
import json
import sys

from .._runtime_contract import (
    P1_INACTIVE_VERBS, NOT_IMPLEMENTED_P0_EXIT, p0_unimplemented_result,
    AUTHORIZATION_MAX_BYTES, BINDING_MAX_BYTES, RECEIPT_MAX_BYTES,
)
from ._local import read_regular_file
from ._probe import passive_probe
from ._validation import ValidationError, verify_artifact, VERIFY_SEMANTICS


def main(argv):
    # This gate precedes parser construction and ignores every trailing input.
    if argv and argv[0] in P1_INACTIVE_VERBS:
        print(json.dumps(p0_unimplemented_result(), sort_keys=True), file=sys.stderr)
        return NOT_IMPLEMENTED_P0_EXIT
    parser = argparse.ArgumentParser(
        prog="session-preserve runtime",
        description="EXPERIMENTAL P1 framework; supported runtime registry is empty.",
    )
    verbs = parser.add_subparsers(dest="verb", required=True)
    probe = verbs.add_parser("probe", help="passive advisory static metadata only")
    probe.add_argument("--metadata", help="explicit local JSON version declaration")
    probe.add_argument("--executable", help="explicit candidate path; stat only, never executed")
    verify = verbs.add_parser("verify", help="local structural/consistency validation only")
    verify.add_argument("artifact")
    verify.add_argument("--authorization", help="explicit paired authorization JSON file")
    verify.add_argument("--binding", help="explicit paired binding JSON file")
    for name in P1_INACTIVE_VERBS:
        verbs.add_parser(name, help="NOT_IMPLEMENTED_P0 (exit 3; zero state)")
    start = verbs.add_parser("start", aliases=["launch"], help="owner-staged single-use P1 start")
    start.add_argument("--run-id", required=True)
    start.add_argument("--executable", required=True)
    start.add_argument("--input-file")
    for name in ("observe", "reconcile", "stop"):
        command = verbs.add_parser(name, help="exact run/attempt/controller generation only")
        command.add_argument("--run-id", required=True)
        command.add_argument("--attempt-id", required=True)
        command.add_argument("--generation", required=True, type=int)
    options = parser.parse_args(argv)
    if options.verb in ("start", "launch", "observe", "reconcile", "stop"):
        from . import _commands
        try:
            if options.verb in ("start", "launch"):
                result = _commands.start(options.run_id, options.executable, options.input_file)
            else:
                result = _commands.inspect_run(options.verb, options.run_id, options.attempt_id, options.generation)
        except (ValidationError, OSError) as error:
            code = error.code if isinstance(error, ValidationError) else "OWNER_STATE_UNAVAILABLE"
            print(json.dumps({"status": "FAIL", "code": code}, sort_keys=True), file=sys.stderr)
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    if options.verb == "probe":
        print(json.dumps(passive_probe(metadata=options.metadata, executable=options.executable), sort_keys=True))
        return 0
    try:
        payload = read_regular_file(options.artifact, RECEIPT_MAX_BYTES)
        authorization = read_regular_file(options.authorization, AUTHORIZATION_MAX_BYTES) if options.authorization else None
        binding = read_regular_file(options.binding, BINDING_MAX_BYTES) if options.binding else None
        result = verify_artifact(payload, authorization=authorization, binding=binding)
    except ValidationError as error:
        print(json.dumps({"status": "FAIL", "code": error.code, "location": error.location,
                          "validation": "LOCAL_STRUCTURAL_ONLY", "execution_attested": False,
                          "semantics": VERIFY_SEMANTICS}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0
