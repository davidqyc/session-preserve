# P1 to public P0 conformance matrix

Reference: `session-preserve-private-runtime-reference-p1/v1`
Contract SHA-256: `e3dcfe08480394b351b1905b29b205407a35a9bd2050ddc936ed89c76052b0d6`

This is an experimental P0 contract mapping, not runtime acceptance or permission
for active execution. [Normative public contracts](runtime-control-p0.md) and
[中文说明](runtime-control-p0.zh-CN.md) carry the frozen requirements and retained
active semantics. The [machine-readable matrix](runtime-control-p0-conformance.json)
is the canonical row inventory; this table renders the same rows.

Each object/section key and each scalar/array key in the accepted reference appears
exactly once. Arrays are one contract value, not a set of synthetic index keys.
PUBLIC_SCHEMA means a typed field; PUBLIC_VALIDATOR means local structural
validation; PUBLIC_TEST means a synthetic safety/documentation invariant.
NOT_CARRIED_WITH_REASON identifies an intentionally deferred mechanism or explicit
public divergence. Retained active requirements do not imply a live implementation.
None of these categories proves provider/GUI authenticity or execution success.

N1–N5 land in P0: exhaustive authorization/binding tables and ceilings; canonical
identity; false default pre-existing mutation grant; sandbox/evidence-store and
nested-start residual; complete carryover; neutral-reference hygiene; earliest
zero-state refusal; passive declared versions and pure shared schema IDs. N6–N11
remain unimplemented pre-P1 gates. N12–N13 remain release gates. No Fresh Review,
live canary, merge or release is implied.

Controller lifecycle decisions are absorbing, separate from provider terminal
facts. ACCEPTED without PERSISTED remains ambiguous, and a terminal race never
permits another send. Exhaustion uses CORRECTIONS_EXHAUSTED at the authorized
maximum 0..3. Future Calculator entry requires foreground authority, exactly one
`accept + content:null` approval without persistence, a second same-thread read
for CURRENT_SESSION (missing first approval means HOLD), live schema recheck
before each click, fresh age <=1 second and the fixed semantic key enum. Cleanup
uses one close path and <=5 seconds separate grace. Optional idle bound is retained.
Future public-controller terminal receipt writing intentionally diverges from
`automatic_write=false`; P0 never creates active state or writes such a receipt.
All six migration classes and every component mapping remain documented; terminal
bounded artifacts are archival only, and ephemeral state is never actionable on a
new host/boot. See the normative document for the full privacy exclusion list.

Coverage: **146 keys**, 10 contract sections, zero unexplained omissions.

| Reference key | Classification | Public target | Carryover / explicit reason |
| --- | --- | --- | --- |
| `contract_version` | PUBLIC_SCHEMA | `authorization.scope_version` | Public scope version is separate from the neutral reference identity. |
| `scope` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Private reference scope is not public authority. Public authorization has its own explicit scope contract. |
| `implementation` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Private implementation path/code is not distributed or vendored. Public P0 validators and CLI gates are independently implemented. |
| `validation` | PUBLIC_TEST | `tests/test_runtime_control_schemas.py#RuntimeSchemas.test_three_valid_artifacts` | Invented synthetic artifacts only; no real runtime validation. |
| `live_execution_authorized_by_this_contract` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No active runtime entry is authorized or implemented. |
| `identity` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_authorization` | Exact caller identity and scope are required; binding/receipt validation completes the identity contract. |
| `identity.required` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_binding` | Full task/run/attempt/native-thread/turn/process structure; explicit null-turn phase only. |
| `identity.task_id` | PUBLIC_SCHEMA | `authorization.task_id` | Bounded non-secret ASCII token, 1..64 characters. |
| `identity.run_attempt_ids` | PUBLIC_SCHEMA | `authorization.run_id,authorization.attempt_id` | Canonical caller-minted RFC UUIDs. |
| `identity.thread_turn_ids` | PUBLIC_SCHEMA | `binding.thread_id,binding.turn_id` | Canonical native UUIDv7 current profile; null only in explicit THREAD_BOUND phase. |
| `identity.process_identity` | PUBLIC_SCHEMA | `binding.process_identity` | Selected app-server PID, birth_ns, executable SHA-256, exact launch_id; immutable binding. |
| `identity.process_birth_source` | PUBLIC_SCHEMA | `binding.process_birth_source` | Independent OS observation is required as a typed claim; P0 does not authenticate it. |
| `identity.process_launch_source` | PUBLIC_SCHEMA | `binding.process_identity.launch_id` | Canonical exact launch-correlation UUID, never latest-session guessing. |
| `identity.pid_is_durable_authority` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_binding` | PID-only process identity rejected; full incarnation/hash/launch mandatory. |
| `identity.latest_session_guessing` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_verify_three_schemas_and_explicit_pairs_only` | Only named local artifacts/pairs, never sibling/session discovery. |
| `identity.all_present_identity_aliases_must_agree` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#verify_artifact` | Only canonical identity fields are admitted; extra aliases rejected, explicitly paired identities must agree. |
| `identity.duplicate_JSON_keys` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_pairs` | Reject duplicate keys at every depth before schema interpretation, with no key/value echo. |
| `runtime` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_probe_only_reads_static_metadata_and_stats_candidate` | Passive/static inspection only, no provider launch. |
| `runtime.route` | PUBLIC_SCHEMA | `binding.runtime_profile,binding.capabilities` | Public v1 structurally distinguishes generic no-CU codex-app-server-r1 from future codex-app-server-calculator-r1; profile is a claim, not stage authority or live authentication. |
| `runtime.thread_binding` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Live exact selected connection/thread binding cannot be proven by passive P0; deferred to independently reviewed P1 adapter. Static native identity is retained. |
| `runtime.state` | PUBLIC_SCHEMA | `authorization.provider_evidence_store,binding.sandbox_posture` | Isolated provider evidence outside worker-writable authority; no state created. |
| `runtime.owner_config_mutation` | PUBLIC_SCHEMA | `binding.capabilities.owner_config_unchanged` | Positive immutable typed claim; no owner config operations in P0. |
| `runtime.pinned_private_executable` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_probe_only_reads_static_metadata_and_stats_candidate` | Explicit configurable path, stat only, no pinned executable dependency. |
| `runtime.version_alone_proves_capability` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_missing_or_insufficient_probe_is_unknown_or_unverified` | Even declared version stays non-attesting; UNKNOWN/UNVERIFIED is explicit. |
| `runtime.required_attestations` | PUBLIC_SCHEMA | `binding.capabilities` | Intentional public divergence from the private all-six-positive rule: the generic no-CU profile requires calculator_catalog_proven=false while the other five capabilities remain true; the Calculator profile requires all six true. Structural validation does not authenticate runtime facts. |
| `runtime.adapter_included` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No transport/active adapter; earliest P0 gate. |
| `runtime.launch_resume_install_register` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No launch/resume/install/register interaction. |
| `lifecycle` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Static lifecycle/controller-provider distinction carried; no transition engine is implemented. |
| `lifecycle.states` | PUBLIC_SCHEMA | `receipt.state` | RUNNING/COMPLETED/FAILED/STOPPED/AMBIGUOUS controller classification. |
| `lifecycle.terminal_states` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | COMPLETED/FAILED require corresponding provider fact; STOPPED remains independent. |
| `lifecycle.terminal_states_absorbing` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Temporal transition enforcement needs the active P1 controller. P0 retains absorbing intent and validates only a static controller/provider projection. |
| `lifecycle.AMBIGUOUS` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Freeze/kill-switch action enforcement needs P1 controller; P0 has zero active actions. Exact-stop carve-out and sticky controller/GUI ambiguity are documented. |
| `lifecycle.STOPPED` | PUBLIC_SCHEMA | `receipt.state,receipt.provider_terminal_fact` | Controller decision and provider terminal fact remain separate. |
| `lifecycle.wall_clock` | PUBLIC_SCHEMA | `authorization.wall_clock_seconds` | Positive explicit bound; monotonic active enforcement is deferred. |
| `lifecycle.idle_clock` | PUBLIC_SCHEMA | `authorization.idle_seconds` | Optional positive idle bound <= wall bound. |
| `lifecycle.late_success` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Deadlines and late-event races need P1 controller. P0 retains no-reopen/no-extension intent without implementing clock or successor logic. |
| `lifecycle.maximum_calls` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Provider/control call list <=128 and receipt byte ceiling enforced independently. |
| `lifecycle.terminal_cleanup` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Single close path and actual <=5-second grace enforcement need P1 ownership adapter; P0 carries a static grace bound only and performs no cleanup. |
| `lifecycle.permanent_service` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_surface_and_excluded_verbs` | No daemon/server/queue/exec surface. |
| `observe_reconcile` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | Observe/reconcile fail closed with zero state in P0. |
| `observe_reconcile.evidence_sources` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Live provider/exact-rollout acquisition is an active P1 adapter responsibility; runtime verify reads only explicitly supplied bounded artifacts, not native history. |
| `observe_reconcile.normalized_evidence_owner` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Trusted exact-connection normalization is deferred to P1; P0 PASS explicitly cannot authenticate provider facts. |
| `observe_reconcile.transport_coordinator_loss` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Intentional public divergence: coordinator/client loss does not change the controller lifecycle state; reconnect/observe only refreshes client knowledge. Provider-connection loss is separately sticky TRANSPORT_LOSS. |
| `observe_reconcile.reconcile` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Full independent current-provider reconciliation is deferred to P1; reconcile is zero-state NOT_IMPLEMENTED_P0. |
| `observe_reconcile.uncertain_correction` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Dynamic retention/reconciliation of a reservation requires P2 controller accounting. Static uncertain counting is carried without a ledger/send engine. |
| `observe_reconcile.uncertain_GUI_execution` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Sticky action gating and no-new-facade enforcement require P3. Typed ambiguity is carried; P0 permits no GUI calls. |
| `observe_reconcile.automatic_retry` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_surface_and_excluded_verbs` | Retry absent; inactive verbs return before all I/O. |
| `observe_reconcile.automatic_resume` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_surface_and_excluded_verbs` | Resume absent; no fallback. |
| `observe_reconcile.automatic_recovery_resend` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No sends or recovery work at all in P0. |
| `live_steer` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Typed static budget/evidence projection only; sends and dynamic reservations are deferred. |
| `live_steer.method` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Actual turn/steer transport is deferred to P2. Retained exact-thread/expectedTurnId contract; no runtime/provider send code. |
| `live_steer.thread_guard` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | RPC threadId guard requires P2 provider interaction; static receipt/binding native identity is validated only. |
| `live_steer.turn_guard` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | RPC expectedTurnId guard requires P2; no queue/resume substitute. Static turn identity is retained. |
| `live_steer.client_correlation` | PUBLIC_SCHEMA | `receipt.corrections[].client_id` | Canonical logical-correction UUID; correlation is not an idempotency proof. |
| `live_steer.correlation_proves_idempotency` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P0 makes no send/idempotency claim; P2 must never infer idempotency from a client correlation alone. |
| `live_steer.evidence_levels` | PUBLIC_SCHEMA | `receipt.corrections[].level` | ACCEPTED/PERSISTED/CONSUMED/REJECTED/UNCERTAIN. |
| `live_steer.initial_launch_counts` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Actual launch/accounting is deferred to P1/P2; retained launch consumes zero rule, no launcher or ledger in P0. |
| `live_steer.default_max_corrections` | PUBLIC_SCHEMA | `authorization.max_corrections` | Caller reference default 3 is documented; JSON requires an explicit maximum. |
| `live_steer.allowed_budget_range` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_authorization` | Integer 0..3; steer_authorized=false requires 0, no coercion. |
| `live_steer.reserve_at` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Durable reserve-before-send timing requires P2 controller/ledger, not implemented in P0. |
| `live_steer.uncertain_counts` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Unreleased uncertain records count toward the authorized maximum. |
| `live_steer.release_rejected_reservation` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_correction` | Release only for explicit rejected + mechanical non_delivery_proven facts; no live proof made. |
| `live_steer.evidence_order` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_correction` | Consumed requires persisted requires accepted; conflicting flags rejected. |
| `live_steer.uncertainty_retains_previous_positive_facts` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_correction` | UNCERTAIN may retain accepted/persisted flags and must remain unsettled. |
| `live_steer.accepted_without_persistence` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Required ACCEPTED_NOT_PERSISTED ambiguity even when provider terminal fact is COMPLETED. |
| `live_steer.same_logical_id_resend` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Dynamic resend prevention requires P2 ledger/controller. Duplicate static record IDs are rejected; no sends exist in P0. |
| `live_steer.fourth_autonomous_correction` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | No over-budget autonomous send is allowed; actual send/budget gate is deferred to P2. Static receipt count is bounded 0..3. |
| `live_steer.third_unsuccessful_correction` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Public typed CORRECTIONS_EXHAUSTED uses the authorized maximum 0..3, never a fixed ordinal. |
| `live_steer.budget_reset_API` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | No active accounting/reset API exists in P0. P2 must retain no reset and single-attempt budget semantics. |
| `live_steer.maximum_records` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Maximum 32 records and encoded size checked; duplicate logical IDs rejected. |
| `computer_use` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_calculator` | Static fixed Calculator facts and grants only; no live approval or tool calls. |
| `computer_use.target` | PUBLIC_SCHEMA | `receipt.calculator.target` | Exactly com.apple.calculator, no arbitrary app slot. |
| `computer_use.server` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Live computer-use server/connection is deferred to P3; normative fixed server retained, no MCP start or call. |
| `computer_use.method` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Actual mcpServer/tool/call is deferred to P3; no wire transport implemented. |
| `computer_use.tools` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Only fixed get_app_state/click are retained for P3. P0 provides no tool implementation or generic router. |
| `computer_use.arbitrary_application_argument` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | Trailing active inputs never consumed; no arbitrary application interface. |
| `computer_use.caller_element_id_argument` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No caller element ID is parsed or used. |
| `computer_use.browser` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_surface_and_excluded_verbs` | No generic Computer Use/browser execution surface. |
| `computer_use.raw_JS_route` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No JavaScript or unrestricted active input evaluation. |
| `computer_use.generic_GUI_router` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_surface_and_excluded_verbs` | Only fixed calculator parser entry, NOT_IMPLEMENTED_P0. |
| `computer_use.explicit_authorization` | PUBLIC_SCHEMA | `authorization.calculator,receipt.identity` | Exact refs plus distinct observe/mutate/foreground/pre-existing/restore grants. |
| `computer_use.first_proof` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Unique first exact full get_app_state with disableDiff=true requires P3 live proof; no GUI state/approval acquisition in P0. |
| `computer_use.first_approval_shape` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Same-thread message-only no-turn-context form validation needs P3 live adapter; raw approval payloads are excluded from P0 artifacts. |
| `computer_use.first_approval_response` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Exactly one accept + content:null session response is retained for P3; P0 does not emit any approval. |
| `computer_use.first_approval_response.action` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P3 emits only accept for the exact first proof; P0 cannot respond or persist approval. |
| `computer_use.first_approval_response.content` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P3 content must be null; no raw payload response/log exists in P0. |
| `computer_use.first_approval_is_session_proof` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_calculator` | Approval alone is insufficient: clicks require separate CURRENT_SESSION fact. |
| `computer_use.second_proof` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Second same-thread full read without repeated approval must establish CURRENT_SESSION in P3. P0 checks only a typed claimed fact, never authenticates the read. |
| `computer_use.missing_first_approval` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_calculator` | HOLD/unproven means no click; CURRENT_SESSION requires exactly one approval. |
| `computer_use.repeated_sensitive_unrelated_ambiguous_approval` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P3 live elicitation must fail closed for these cases; P0 excludes payloads and has no live approval handler. |
| `computer_use.persistent_approval_emitted` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_calculator` | persistent_approval=true is rejected; P0 emits no approval response. |
| `computer_use.server_offered_persist` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P3 must ignore, not echo/select/retain standing approval metadata. P0 never contacts a server or stores approval content. |
| `computer_use.wire_schema_source` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Exact-thread mcpServerStatus/list with full detail is P3 live adapter work; no catalog/schema RPC in P0. |
| `computer_use.wire_schema_check` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Live full schema recheck before session proof and before every click is retained for P3, not replaced by static metadata or receipt flags. |
| `computer_use.element_index_type` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_calculator` | Click facts require click_schema_string=true; actual wire schema acquisition is deferred. |
| `computer_use.element_id` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P3 wire IDs are 1..8 decimal digits as strings, leading zeros preserved. P0 deliberately accepts no raw element ID field or caller selector. |
| `computer_use.resolution` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Fresh full snapshot, unique semantic match and immediate action require P3; P0 has no AX text, nonce, matching or click code. |
| `computer_use.maximum_snapshot_age_seconds` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_calculator` | Static claimed bound 1..1000 ms; live nonce/age validation is deferred. |
| `computer_use.cross_snapshot_reuse` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P3 single-use identity-bound snapshot nonces prevent reuse; P0 has no snapshots and exposes no GUI action path. |
| `computer_use.stale_invalid_ambiguous_elements` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | P3 stale/invalid/ambiguous matching fails closed. P0 accepts no raw elements and performs no clicks. |
| `computer_use.keys` | PUBLIC_SCHEMA | `receipt.calculator.keys` | Fixed Zero..Nine/Add/Equals/Clear semantic enum, no arbitrary plan text. |
| `receipts` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Allowlisted, typed, bounded static projection, not authority. |
| `receipts.schema` | PUBLIC_SCHEMA | `receipt.schema` | Separate frozen public receipt ID, preservation schema 3.0 unchanged. |
| `receipts.maximum_bytes` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Normative encoded maximum 16384 bytes including whitespace. |
| `receipts.construction` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Strict typed allowlist; detached validated JSON, not a raw event dump. |
| `receipts.identity_projection` | PUBLIC_SCHEMA | `receipt.identity` | Domain-separated task/run/attempt/process SHA-256 refs and native thread/turn UUIDs. |
| `receipts.root_fields` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Documented public root allowlist adds separate provider fact, digests and bounds; no preservation fields changed. |
| `receipts.identity_fields` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Documented provider discriminator/ref/native identity allowlist. |
| `receipts.correction_fields` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Documented evidence flags plus explicit non-delivery and release proof fields. |
| `receipts.calculator_fields` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Documented typed grants/session/click/key facts without raw GUI data. |
| `receipts.cleanup_fields` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | Documented typed counts/resources/grace/restoration without raw errors or paths. |
| `receipts.excluded` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#validate_receipt` | No free-text/raw payload fields; exhaustive unknown-field rejection at every depth. |
| `receipts.history_database` | PUBLIC_TEST | `tests/test_runtime_control_schemas.py#RuntimeSchemas.test_unknown_fields_and_exclusions_are_not_echoed` | Receipt has no transcript/history fields or raw payload store. |
| `receipts.automatic_write` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Intentional public divergence: future public controller writes one terminal receipt despite reference automatic_write=false. P0 writes no runtime state or terminal receipt; N6 ownership is deferred. |
| `foreground_cleanup` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_cleanup` | Typed cleanup projection; actual ownership discovery/release/restoration deferred. |
| `foreground_cleanup.previous_frontmost` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Exact previous bundle/incarnation stays controller memory-only in P1/P3; P0 has no focus acquisition or private app identity storage. |
| `foreground_cleanup.foreground_authorization_separate` | PUBLIC_SCHEMA | `authorization.calculator.foreground` | Foreground authority is distinct from observation/mutation and restoration. |
| `foreground_cleanup.Calculator_close` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_cleanup` | Pre-existing Calculator cannot appear as an owned cleanup resource. |
| `foreground_cleanup.resources` | PUBLIC_SCHEMA | `receipt.cleanup.owned_resources[].kind` | CALCULATOR/SOCKET/APP_SERVER/HELPER typed enum, no implementation. |
| `foreground_cleanup.socket_identity` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Run/attempt/handle nonce plus independent socket inode belongs to P1 ownership/IPC design. No socket implementation in P0; N9 remains gated. |
| `foreground_cleanup.process_release` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Full-identity/incarnation recheck and actual process release need P1 ownership adapter; never implemented as PID/name killing in P0. |
| `foreground_cleanup.adapter_release` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Atomic exact-handle recheck before release is deferred to P1; static claims do not implement host release. |
| `foreground_cleanup.release_verification` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_cleanup` | Verified cleanup requires exact released-resource absence facts; authenticity remains unverified. |
| `foreground_cleanup.restore_verification` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | Live prior-incarnation and still-task-frontmost checks require P3; P0 carries grant/typed result only, no restoration. User focus change must not be overridden. |
| `foreground_cleanup.cleanup_failure` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_cleanup` | Typed bounded skipped/error counters, verified=false on failure; no raw exceptions or retry. |
| `foreground_cleanup.maximum_owned_resources` | PUBLIC_VALIDATOR | `src/codex_preserve/runtime_control/_validation.py#_cleanup` | Maximum 16, unique bounded refs, no raw handles or paths. |
| `portability` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | All six migration classes and component mapping retained as documentation, not executable host migration. |
| `portability.classes` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | Exactly six frozen classes; no active replay mechanism. |
| `portability.classification` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | Every accepted component class is accounted for, plus public archival limits. |
| `portability.classification.contract_code_exports` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | FILE_STATE_ONLY: integrity/privacy verification before use. |
| `portability.classification.runtime_discovery_transport_ownership` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | HOST_BINDING: rediscover exact host identity. |
| `portability.classification.accessibility_screen_recording` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | TCC_PERMISSION: separate authority; copying files grants nothing. |
| `portability.classification.signed_app_launchservices` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | SIGNING_REGISTRATION: independently verify hosted signed route. |
| `portability.classification.provider_login_control_pairing` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | ACCOUNT_OR_DEVICE_PAIRING: Owner reauth/pairing, no secret copying. |
| `portability.classification.process_socket_session_approval_deadline_snapshot` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | EPHEMERAL: never replay on a new host/boot. |
| `portability.new_host` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | Rediscover/revalidate runtime/schema/permissions under separate authority; no host operations in P0. |
| `portability.private_coordinates_required` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | No private coordinates in the public matrix; neutral identifier/digest only. |
| `portability.copying_files_grants_permissions` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | File copying never grants permissions; documented and checked. |
| `portability.ephemeral_state_replay` | PUBLIC_TEST | `tests/test_runtime_control_conformance.py#P0Conformance.test_migration_mapping_and_archival_limits` | Non-terminal/active grant/endpoints/identities remain EPHEMERAL, never actionable on another boot. |
| `hard_boundaries` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | Process/network/state/parsing/stdin sentinels prove early fail-closed boundary. |
| `hard_boundaries.nested_agent` | PUBLIC_SCHEMA | `authorization.nested_start_policy` | Nested control remains forbidden policy. P0 synthetic/unverified bindings use `UNVERIFIED_PENDING_N6_N11`; the reviewed public R1 active path requires `OWNER_STAGED_GATE_ATTESTED` after the owner-staged launch gate and per-start confinement proof. Structural verify validates the claim shape but does not authenticate it. |
| `hard_boundaries.owner_config_mutation` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | Zero filesystem access from all inactive verbs. |
| `hard_boundaries.TCC_system_settings_credentials_account_network_mutation` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No process/network/GUI/provider interactions or mutations. |
| `hard_boundaries.production_control_restart` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_six_verbs_return_before_all_io_and_parsing` | No process control or provider discovery. |
| `hard_boundaries.daemon_login_item_registration` | PUBLIC_TEST | `tests/test_runtime_control_cli.py#P0CLI.test_surface_and_excluded_verbs` | No permanent-service commands or registration mechanism. |
| `hard_boundaries.public_integration_packaging_decision` | NOT_CARRIED_WITH_REASON | `docs/runtime-control-p0.md#retained-active-contract-deferred-implementation` | The private reference does not authorize public packaging. Separate public authority fixes one distribution, unchanged version/dependencies/schema; no private packaging choice is copied. |
