"""Pure shared runtime identifiers; imports neither preservation nor runtime plane."""

AUTHORIZATION_SCHEMA = "session-preserve-runtime-authorization/v1"
BINDING_SCHEMA = "session-preserve-runtime-binding/v1"
RECEIPT_SCHEMA = "session-preserve-runtime-control-receipt/v1"
RUNTIME_SCHEMA_IDS = (AUTHORIZATION_SCHEMA, BINDING_SCHEMA, RECEIPT_SCHEMA)

AUTHORIZATION_MAX_BYTES = 8 * 1024
BINDING_MAX_BYTES = 12 * 1024
RECEIPT_MAX_BYTES = 16 * 1024
P0_INACTIVE_VERBS = ("start", "observe", "reconcile", "steer", "calculator", "stop")
NOT_IMPLEMENTED_P0_EXIT = 3


def p0_unimplemented_result():
    return {
        "status": "NOT_IMPLEMENTED_P0",
        "experimental": True,
        "state_created": False,
        "detail": "P0 contract scaffolding does not start or control a runtime.",
    }
