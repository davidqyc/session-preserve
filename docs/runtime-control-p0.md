# Experimental Runtime Control P0 contracts

[简体中文](runtime-control-p0.zh-CN.md) · [P1 conformance matrix](runtime-control-p0-conformance.md)

This is **EXPERIMENTAL contract scaffolding**, outside the stable preservation
compatibility promise. P0 does not start or control Codex, provide live steer,
or perform Computer Use. There is no controller, helper, IPC endpoint, daemon,
server, queue, runtime state directory, provider adapter or active provider code.

The same `session-preserve` distribution contains both namespaces. Version,
empty base dependencies and preservation package schema **3.0** are unchanged.
Preservation `export / verify / pack` retain their read-only source behavior and
compatibility. Runtime Control is not a ProviderAdapter export provider. Runtime
artifacts are separate and are never automatically packed into preservation
packages. There is no second transcript/history database or raw transport log.

## CLI and passive evidence

| Command | P0 behavior |
| --- | --- |
| `session-preserve runtime probe [--metadata FILE] [--executable PATH]` | Passive, advisory inspection only; exit 0, including UNKNOWN/UNVERIFIED evidence |
| `session-preserve runtime verify ARTIFACT [--authorization FILE] [--binding FILE]` | Local strict structure and explicitly paired consistency checks; exit 0 PASS / 2 FAIL |
| `session-preserve runtime start` | NOT_IMPLEMENTED_P0, exit 3, zero state |
| `session-preserve runtime observe` | NOT_IMPLEMENTED_P0, exit 3, zero state |
| `session-preserve runtime reconcile` | NOT_IMPLEMENTED_P0, exit 3, zero state |
| `session-preserve runtime steer` | NOT_IMPLEMENTED_P0, exit 3, zero state |
| `session-preserve runtime calculator` | Parser surface only: NOT_IMPLEMENTED_P0, exit 3, zero state |
| `session-preserve runtime stop` | NOT_IMPLEMENTED_P0, exit 3, zero state |

Inactive verbs return at the earliest entry, before even parsing trailing options
(including `--help`), reading stdin, parsing a grant, resolving/creating a state
root, discovering providers or importing the runtime package. Trailing input is
ignored, never echoed or used. No files or directories are created. Task text,
authorization and future correction/action plans must use stdin/files, not argv;
P0 does not accept or consume any such active-command inputs.

There are no `runtime computer-use / resume / retry / exec / daemon / server /
queue` commands. `runtime --help` lists the experimental surface.

Probe performs no automatic discovery in P0. It reads an explicitly supplied
regular JSON file of at most 4 KiB with exactly `provider: "codex"` and
`declared_runtime_version: "<version>"`. A version is a static declaration, never
obtained by running a binary. The optional executable path is only stat'ed.
No executable, app-server, thread, turn, MCP server, TCC request or foreground
interaction is started. Missing evidence yields UNKNOWN; unreadable, invalid or
insufficient evidence yields UNVERIFIED. Even valid metadata yields only DECLARED,
with live capabilities UNVERIFIED. Output omits input paths.

Verify reads only the named artifact and explicitly supplied paired files; it
does not search siblings or provider state. It rejects nonregular files, limits
reads, writes nothing and reports stable codes and schema-owned locations without
raw values, unknown key names, exception bodies or private paths. PASS does not
attest that a run occurred, that provider/GUI facts are authentic, or that execution
succeeded. `paired_checks` reports what was checked; `unverified_pairs` identifies
missing grant/binding evidence. A self-consistent fabricated artifact can PASS.
Top-level preservation `verify` rejects a runtime JSON artifact with a pointer to
`session-preserve runtime verify` and imports no runtime package.

## Public Python API and import direction

Only these names in `codex_preserve.runtime_control.__all__` are intentionally
public, and all remain experimental:

- `AUTHORIZATION_SCHEMA`, `BINDING_SCHEMA`, `RECEIPT_SCHEMA`;
- `AUTHORIZATION_MAX_BYTES`, `BINDING_MAX_BYTES`, `RECEIPT_MAX_BYTES`;
- `ValidationError` (`code`, `location`);
- `validate_authorization(payload)`, `validate_binding(payload)`, `validate_receipt(payload)`, `validate_artifact(payload)`;
- `authorization_digest(payload)`, `binding_digest(payload)`, `identity_ref(kind, value)`;
- `verify_artifact(payload, *, authorization=None, binding=None)`;
- `passive_probe(*, metadata=None, executable=None)`.

Validators accept UTF-8 JSON bytes or text, never already-parsed mappings. They
return a detached normalized dictionary; they do not mutate any input or authorize
an operation. Digest functions accept the same JSON inputs. Probe path arguments
are explicit local filesystem paths. All other symbols/modules are internal and
carry no compatibility promise. Import itself performs no I/O or discovery.

Preservation paths never import `runtime_control`. Only explicit runtime CLI entry
may lazily import it. Shared pure helpers import neither plane. Schema IDs and P0
gates live in the pure shared `_runtime_contract` module, permitting preservation
rejection without a runtime import. No entry points or dynamic plugin discovery
are added. Fresh-process tests block runtime imports during top-level `--help`,
`export --help`, preservation verify and pack.

## Normative JSON and identity rules

The frozen IDs are `session-preserve-runtime-authorization/v1`,
`session-preserve-runtime-binding/v1`, and
`session-preserve-runtime-control-receipt/v1`. Every object is an exhaustive
allowlist, including nested objects. Duplicate JSON keys, unknown fields, wrong
types, booleans supplied as integers, non-finite numbers, invalid UTF-8, malformed
IDs and oversized encoded input are rejected. No type coercion occurs. Optional
fields are only those explicitly marked below; `null` is not omission.

TASK_ID is a 1–64 character non-secret ASCII token matching
`[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. RUN_ID, ATTEMPT_ID, launch and correction client
IDs are lowercase, hyphenated canonical RFC UUIDs, non-nil, versions 1–8. Selected
Codex native thread/turn IDs use canonical UUIDv7 in the current profile. SHA-256
values are exactly 64 lowercase hexadecimal characters. Versions match three
1–6 digit components with an optional bounded ASCII alphanumeric/dot/hyphen
suffix after `-` or `+`; a version does not establish capability.

Scope paths are canonical absolute POSIX paths, ASCII, at most 1024 encoded bytes,
without `..`, repeated/trailing separators, control characters, expansion tokens
or backslashes. These are conservative P0 lexical policy constraints, not OS or
symlink containment proof. Unicode and other platform path profiles need separate
review. Root arrays have 1–16 unique entries. Workspace and writable roots must be
under authorized roots. State, IPC and provider evidence paths must not overlap
worker-writable roots. These paths never appear in a receipt.

## Exhaustive authorization field table

Authorization input has an independent **8192 byte** ceiling, including whitespace.
This small ceiling limits caller policy material; it is not a prompt envelope.
Every row is required except the two explicitly optional rows. The grant is
caller-owned immutable policy for one attempt, not authentication against arbitrary
same-user processes. Worker output can never widen it. R1 has one attempt per run;
widening needs a new caller-authorized RUN_ID and has no budget-reset API.

| JSON field | Type and invariant |
| --- | --- |
| `schema` | Exact authorization schema ID |
| `task_id` | Bounded TASK_ID token |
| `run_id` | Caller-minted canonical UUID |
| `attempt_id` | Caller-minted canonical UUID |
| `provider` | Exactly `codex` |
| `scope_version` | Exactly `session-preserve-runtime-scope/v1` |
| `workspace` | Canonical absolute scope path |
| `authorized_roots` | 1–16 unique scope paths |
| `worker_writable_roots` | 1–16 unique paths inside authorized roots |
| `runtime_state_root` | Outside worker-writable authority; lexical check only |
| `controller_endpoint_root` | Outside worker-writable authority; lexical check only |
| `provider_evidence_store` | Provider-native isolated evidence outside worker-writable authority |
| `required_sandbox_posture.active_worker_sandboxed` | Boolean, must be true |
| `required_sandbox_posture.runtime_state_not_worker_writable` | Boolean, must be true |
| `required_sandbox_posture.controller_channel_unreachable` | Boolean, must be true |
| `required_sandbox_posture.policy_not_worker_writable` | Boolean, must be true |
| `required_sandbox_posture.provider_evidence_not_worker_writable` | Boolean, must be true; highest-ranked provider evidence cannot be worker-authored |
| `nested_start_policy` | Exactly `FORBIDDEN` |
| `wall_clock_seconds` | Integer 1..86400, positive fixed bound; future enforcement is monotonic |
| `idle_seconds` | Optional integer 1..wall_clock_seconds; omitted means no idle bound |
| `max_corrections` | Required explicit integer 0..3; reference caller default is 3; launch consumes zero |
| `observe_authorized` | Boolean for runtime observe, separate from Calculator GUI observation |
| `steer_authorized` | Boolean; false requires max_corrections = 0 |
| `calculator.observe` | Boolean for GUI observation |
| `calculator.mutate` | Boolean; true requires observe and foreground |
| `calculator.mutate_preexisting` | Optional boolean, normalized default **false**; true requires mutate |
| `calculator.foreground` | Boolean; required for any Calculator entry |
| `calculator.restore_foreground` | Boolean; true requires foreground |

Future active execution requires independent sandbox attestation: state, policy,
controller channel and provider-native evidence store must be outside the worker's
writable/reachable authority. The worker cannot replace policy/evidence or act as
the controlling caller. Protecting those objects does not prove that a worker
cannot start another independent controller/runtime through other same-user routes.
That nested-start residual is explicit below; mechanism/feasibility is unverified
in P0 and must be closed under N6–N11 before active public execution. Policy JSON
alone is never accepted as same-user authentication.

## Exhaustive binding field table

Binding input has an independent **12288 byte** ceiling, including whitespace.
The binding is immutable once established. It describes the selected runtime
app-server PROCESS_IDENTITY, not a client/helper PID. PID alone and latest-session
guessing are invalid. P0 validates claims structurally and cannot authenticate them.

| JSON field | Type and invariant |
| --- | --- |
| `schema` | Exact binding schema ID |
| `task_id` | Bounded TASK_ID token |
| `run_id` | Canonical UUID |
| `attempt_id` | Canonical UUID |
| `provider` | Exactly `codex` |
| `authorization_sha256` | Authorization digest defined below |
| `thread_id` | Canonical selected Codex UUIDv7 |
| `turn_id` | UUIDv7 when TURN_BOUND; exactly null only when THREAD_BOUND (before a turn exists) |
| `binding_phase` | `THREAD_BOUND` or `TURN_BOUND`; immutable artifact snapshots, not permission to rebind |
| `process_identity.pid` | Integer 1..2147483647 |
| `process_identity.birth_ns` | Integer 1..9223372036854775807, independent OS-observed incarnation |
| `process_identity.executable_sha256` | Lowercase SHA-256 |
| `process_identity.launch_id` | Canonical exact launch-correlation UUID |
| `process_birth_source` | Exactly `INDEPENDENT_OS_OBSERVATION` |
| `runtime_profile` | Exactly `codex-app-server-calculator-r1` |
| `runtime_version` | Bounded version token; no capability inference |
| `capabilities.openai_signed` | Boolean, must be true |
| `capabilities.launchservices_hosted` | Boolean, must be true |
| `capabilities.isolated_state` | Boolean, must be true |
| `capabilities.owner_config_unchanged` | Boolean, must be true |
| `capabilities.calculator_catalog_proven` | Boolean, must be true |
| `capabilities.other_capabilities_disabled` | Boolean, must be true |
| `sandbox_posture.active_worker_sandboxed` | Boolean, must be true |
| `sandbox_posture.runtime_state_not_worker_writable` | Boolean, must be true |
| `sandbox_posture.controller_channel_unreachable` | Boolean, must be true |
| `sandbox_posture.policy_not_worker_writable` | Boolean, must be true |
| `sandbox_posture.provider_evidence_not_worker_writable` | Boolean, must be true |
| `nested_start_enforcement` | Exactly `UNVERIFIED_PENDING_N6_N11`; explicit P0 residual, never a live attestation |

## Canonical digests and refs

Let C(x) be UTF-8 JSON with sorted keys, no whitespace, `ensure_ascii=False`,
`allow_nan=False`; scalar IDs remain JSON strings (including their quotes).
Validate first and normalize the optional `mutate_preexisting` default to false.
All other fields retain their values; optional idle omission remains omission.
Let `NUL` be one zero byte. Hex output is lowercase SHA-256.

- Authorization digest: SHA256(`session-preserve/runtime/authorization/v1` + NUL + C(authorization)).
- Binding digest: SHA256(`session-preserve/runtime/binding/v1` + NUL + C(binding)).
- Identity ref: SHA256(`session-preserve/runtime/identity-ref/v1` + NUL + kind + NUL + C(identity)).

`kind` is exactly task/run/attempt/process/socket/call. Task/run/attempt use their canonical
scalar ID; process uses exactly the four-field process_identity object. Domain
and kind separation prevent interchanging a run ref with an attempt ref. A digest
is consistency evidence, not a signature or authenticated caller identity.

CALCULATOR/APP_SERVER/HELPER resource refs use the process derivation. Socket refs
use kind socket and C of exactly run_id, attempt_id, handle_nonce (canonical UUIDs)
and independently observed inode (integer 1..9223372036854775807); no socket path is
included. Optional call correlation refs use kind call and a canonical client/RPC
correlation UUID. These are pure derivations, not an ownership or socket mechanism.
Receipt-only validation checks their hash shape; no raw resource/call identity is
available to authenticate or recompute them. The Python derivation helper can
check explicitly supplied canonical source IDs without any OS lookup.

With an explicit grant and binding, verify checks digest plus task/run/attempt/
provider equality. With a receipt and grant it checks authorization digest,
task/run/attempt refs, Calculator grant and correction maximum. With a receipt
and binding it checks binding digest, all four identity refs, native identity,
authorization digest and profile/version. Missing pairs stay unverified; no
raw identity can be recovered from a ref.

## Exhaustive receipt allowlist

Encoded maximum is normative **16384 bytes (16 KiB)** including whitespace.
All root fields below are required. Facts are typed derived evidence, never
authority. Bounds apply independently; fitting record counts does not waive the
byte limit. All nested objects reject extra fields.

| Field | Type / contents |
| --- | --- |
| `schema` | Exact runtime control receipt ID |
| `identity` | Exactly provider, task_ref, run_ref, attempt_ref, thread_id, turn_id, binding_phase, process_ref; same native rules as binding, refs are SHA-256 |
| `authorization_sha256`, `binding_sha256` | Canonical digests |
| `runtime_profile`, `runtime_version` | Same bounded profile/version as binding |
| `state` | RUNNING / COMPLETED / FAILED / STOPPED / AMBIGUOUS controller decision |
| `decision` | NONE / PROVIDER_COMPLETED / PROVIDER_FAILED / REQUESTED_STOP / DEADLINE_EXPIRED / IDLE_EXPIRED / CORRECTIONS_EXHAUSTED / CAPABILITY_UNAVAILABLE / CONTROLLER_LOST / GUI_EXECUTION_UNCERTAIN / TRANSPORT_LOST |
| `provider_terminal_fact` | NONE / COMPLETED / FAILED / STOPPED, separately observed fact |
| `execution_ambiguous` | Boolean, exactly whether ambiguity_reasons is nonempty |
| `ambiguity_reasons` | Unique list of at most 6: ACCEPTED_NOT_PERSISTED / UNCERTAIN_CORRECTION / GUI_EXECUTION / CONTROLLER_LOSS / TRANSPORT_LOSS / RESOURCE_UNVERIFIED |
| `correction_maximum` | Integer 0..3, paired with grant when supplied |
| `correction_count` | Integer 0..maximum; count of unreleased reservations |
| `corrections` | At most 32 records; unique canonical client_id, level, accepted, persisted, consumed, rejected, settled, non_delivery_proven, reservation_released |
| `calculator` | Exactly authorization, approval_count, click_count, session_proof, click_schema_string, calculator_preexisting, target, persistent_approval, previous_frontmost_captured, maximum_snapshot_age_ms, keys |
| `cleanup` | Exactly requested, released, skipped, errors, foreground_restored, verified, grace_seconds, owned_resources |
| `provider_calls` | At most 128 records: required kind/outcome, optional SHA-256 correlation_ref (unique when present) |

Correction flags are booleans and level is ACCEPTED / PERSISTED / CONSUMED /
REJECTED / UNCERTAIN. Persisted requires accepted; consumed requires persisted.
Non-delivery proof requires rejection, which cannot coexist with acceptance.
A reservation is released exactly for mechanically proven pre-delivery rejection;
settled is exactly consumed or released. UNCERTAIN is unsettled and may retain
earlier positive flags. Accepted without persistence requires the ambiguity reason
even at provider completion. Unproved rejection remains counted and ambiguous.
CORRECTIONS_EXHAUSTED requires STOPPED and count equal to the authorized maximum.
Correction records and STEER call facts require an established non-null turn.

Calculator authorization has the exact grant fields above. approval_count is
0..1; click_count is 0..128 and equals the length of keys and count of click-call
records. session_proof is UNPROVEN / HOLD / CURRENT_SESSION; CURRENT_SESSION
requires one first approval, HOLD represents a missing first approval. Clicks
require CURRENT_SESSION, observe/mutate/foreground and a string click schema.
Pre-existing mutation needs the explicit grant (default false). target is exactly
`com.apple.calculator`; persistent_approval must be false. Other flags are boolean.
maximum_snapshot_age_ms is an integer 1..1000. Keys are exactly Zero, One, Two,
Three, Four, Five, Six, Seven, Eight, Nine, Add, Equals, Clear. Receipt flags are
claims; their temporal/live authenticity is outside structural validation.

Cleanup requested/foreground_restored/verified are booleans; released/skipped/errors
are counts 0..16 matching record outcomes. grace_seconds is an integer 0..5.
At most 16 owned_resources carry exactly kind (CALCULATOR / SOCKET / APP_SERVER /
HELPER), unique SHA-256 identity_ref, outcome (RELEASED / SKIPPED / ERROR /
NOT_REQUESTED), exact_identity_verified and absence_verified booleans. Releases
require exact identity; verified cleanup requires absence proof for every released
resource and no skip/error. Pre-existing Calculator is never task-owned or closed.
Restoration facts require request, captured previous foreground and restore grant.
No actual release/restoration is implemented by these validators.

Call kind is LAUNCH / OBSERVE / RECONCILE / STEER / SCHEMA_READ / CALCULATOR_READ /
CALCULATOR_CLICK / STOP / CLEANUP. Outcome is ACCEPTED / REJECTED / UNCERTAIN /
OBSERVED. A record is not proof of a call or permission to replay it.

Excluded everywhere in receipts: AX tree, screenshots (including implicit logs),
raw GUI text, approval payload, account IDs, credentials/secrets, private home or
repository paths, device IDs, previous-frontmost bundle identity, raw task/correction
instructions, raw exception bodies and transcript/history duplication. No free
text fields can carry these values. Binding/grant may contain local scope material
and require separate retention; they are not privacy-bounded portable receipts.

## Retained active contract, deferred implementation

The [matrix](runtime-control-p0-conformance.md) accounts for every accepted
reference key exactly once. Deferred mechanisms are explicitly NOT_CARRIED in P0
with reasons; the following normative intent is retained without a live code path.

Lifecycle terminal COMPLETED / FAILED / STOPPED decisions are absorbing; late
provider success never reopens a decision or extends a deadline. STOPPED describes
the controller, not proof of provider termination. AMBIGUOUS freezes new actions
except exact-identity stop/close. Observe is read-only; reconcile alone may clear
ordinary coordinator loss. Controller loss and uncertain GUI execution remain
sticky for the attempt. N6/N7 must settle successor/fencing/deadline and connection
loss details before executable P1; P0 never reconstructs or executes a controller.

Initial launch consumes zero corrections. Reserve before the first provider-
affecting send, once per logical client ID. Never resend that ID; a new logical
correction requires a new reservation. Correlation is not idempotency proof.
Uncertain delivery remains counted; only exact mechanical pre-delivery rejection
releases it. Evidence order is ACCEPTED → PERSISTED → CONSUMED. Accepted without
persistence stays ambiguous even if a terminal event races the reply. That race
does not authorize another send. After unsuccessful corrections exhaust the
authorized maximum 0..3, stop/return with CORRECTIONS_EXHAUSTED; future steer returns
BUDGET_EXHAUSTED. No budget reset, retry, queue-for-next-turn or interrupt/resume
fallback exists. P0 verifies static facts, not a send history or temporal transition.

Future R1 Computer Use is **controller-issued, Calculator-only**, on the exact
same run/thread; it is not a generic model-initiated GUI loop. Entry requires
explicit observe and foreground authority. The controller rechecks exact-thread
full live tool inventory (`mcpServerStatus/list`, full detail) before session proof
and every click. Only fixed get_app_state / click through `mcpServer/tool/call`
on `computer-use` are permitted. No app/tool/raw-JS/browser/element-ID argument.
Click element_index is a string of 1–8 decimal digits, preserving leading zeros.

Only the unique first exact full Calculator get_app_state (`disableDiff=true`)
may receive the same-thread, message-only, no-turn-context form approval. The
controller accepts exactly once with `{action: "accept", content: null}`; never
select, echo, retain or persist an offered standing approval. The first accept
alone is not session proof. A second same-thread full read without another prompt
proves CURRENT_SESSION; missing first approval means HOLD. Repeated, sensitive,
unrelated or ambiguous approval fails closed before mutation.

Every click obtains a new full snapshot, binds exact identity/nonce/generation,
checks age <=1 second, resolves one semantic key and immediately sends its string
ID. Consume the nonce before send; no cross-snapshot reuse. Stale/invalid/ambiguous
elements stop before click; uncertainty after click is sticky and permits no new
facade/retry. P0 has **no tested public macOS/locale GUI scope**: tests are synthetic.
Any future unknown localization/semantic shape fails closed and requires review.

Only registered task-created resources may be cleaned up. Recheck full incarnation
and ownership atomically immediately before release, never PID/name/pattern alone.
Socket ownership includes run/attempt/nonce plus independent inode; exact handles
stay in memory. One close path uses <=5 seconds separate grace, never extra worker
time; verify absence, retain typed failures, no automatic cleanup retry. Previous
frontmost identity is memory-only. Restore only with explicit authority, matching
prior incarnation, and while the task surface is still frontmost; user focus changes
must not be overridden. Pre-existing Calculator is never closed.

The future public controller writes one terminal derived receipt: this is an
intentional public divergence from the reference's `automatic_write=false`.
P0 writes no terminal runtime receipt or active state. Public launch is new public
implementation design, not a byte-for-byte port of a private launcher/adapter.
N6–N11 and N12–N13 remain separate pre-P1 and release gates, not implemented here.

## Migration classes and archival limits

| Component | Class | New-host rule |
| --- | --- | --- |
| Contract, code, safe exports | FILE_STATE_ONLY | Copy ordinary files, verify integrity/privacy |
| Runtime discovery, transport, ownership | HOST_BINDING | Independently rediscover runtime/connection/incarnation |
| Accessibility / Screen Recording when required | TCC_PERMISSION | Observe readiness; permission grants require separate authority |
| Signed app / LaunchServices | SIGNING_REGISTRATION | Verify signed hosted route; no implicit signing/registration |
| Provider login / control pairing | ACCOUNT_OR_DEVICE_PAIRING | Owner reauth/pairing; never copy credentials |
| Process/socket/session approval/deadline/snapshot | EPHEMERAL | Never replay on another host or boot |
| Terminal run directory with bounded public artifacts | FILE_STATE_ONLY | Archival evidence only; no executable authority |
| Non-terminal state, active grant, endpoint, process/socket identity | EPHEMERAL | Discard actionability on another host/boot |

Copying files grants no permissions. A bounded terminal receipt may be safe archival
evidence after privacy review; machine-bound binding/ledger material is not thereby
portable or actionable. Actual state-location/retention/sandbox feasibility and
boot-session identity remain gated by N11/N13. Nothing in P0 enables replay.
