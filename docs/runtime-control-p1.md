# Experimental Runtime Control P1 composite proof

P1 is a source framework for `codex-app-server-r1`. The production
`SUPPORTED_RUNTIME_SET` is **empty**. No current Codex binary is supported,
including an App-embedded binary with a familiar version. Unknown, patched,
repacked or re-signed bytes fail `RUNTIME_DIGEST_UNSUPPORTED`. A source candidate
or passing synthetic test never grants real runtime admission, live binding,
P2 steer, P3 Computer Use, or public release.

The preservation schema remains 3.0. Export, verify and pack retain their
read-only behavior and do not import the runtime plane. The ProviderAdapter
registry, distribution, dependencies and P0 artifact byte ceilings/digest domains
are unchanged. Runtime state and receipts are separate from preservation packages.

## Explicit CLI

| Command | Behavior |
| --- | --- |
| `runtime start --run-id UUID --executable PATH [--input-file FILE]` | Validates and consumes an owner-staged grant; reserves one attempt; requires reviewed exact bytes and every applicable proof before binding; optional task file is read after binding |
| `runtime launch ...` | Alias of start with the same gates |
| `runtime observe --run-id UUID --attempt-id UUID --generation N` | Read-only exact generation observation; no latest selector or fence acquisition |
| `runtime reconcile --run-id UUID --attempt-id UUID --generation N` | Read-only evidence refresh; never reconnects, retries, resumes or clears sticky loss |
| `runtime stop --run-id UUID --attempt-id UUID --generation N` | Exact generation control or an authorized fenced closer after proven controller absence |
| `runtime steer`, `runtime calculator` | Earliest `NOT_IMPLEMENTED_P0`, exit 3, zero I/O even with trailing arguments |
| `runtime probe`, `runtime verify` | Existing passive/local-only P0 semantics |

There are no root, inbox, endpoint, registry, RTCA, realization, latest, retry or
resume overrides. No task text is accepted in argv. Start owns the foreground
run-scoped controller; it serves owner-only IPC until terminal closure. It does
not install a daemon/service or copy credentials. Production start currently
cannot get past exact digest admission and sends no model turn.

## Sealed RTCA admission

The public contract is `session-preserve-runtime-tool-catalog-attestation/v1`
with a separate `session-preserve-runtime-tool-catalog-review/v1` receipt.
`validate_rtca` validates structure/consistency; it does **not** authenticate a
reviewer. Production admission comes only from tracked, code-reviewed sealed
entries in `_rtca.SUPPORTED_RUNTIME_SET`. The loader never scans local files or
reads environment/CLI overrides. Test fixtures live only under tests and are
never registered or loaded by that path.

Each admission pins `(runtime_profile, platform, executable_sha256)`, exact
RTCA bytes, exact review-receipt bytes, and the digest-specific reviewed platform
realization. That realization is part of the review, including launch bytes,
source verification, method-surface derivation, protocol response normalization,
process/descendant ownership, signature/hosting attestations, provider-supported
isolated state, capability observations, notification classification and the
sandbox command route. There is deliberately no unreviewed general launcher
fallback. No such real realization is admitted by this candidate.

The RTCA validator covers:

| Component | Contract |
| --- | --- |
| Identity | Exact profile/platform/bytes; initialize version must match |
| Source | Public repository identity, commit and source digest; vendor provenance or independently reproducible byte-identical build; versions/signatures/symbols alone are rejected |
| Complete method surface | Bounded, unique method records with exact count and domain-separated digest; source-reviewed classification of every exact-thread complete inventory method |
| Unified inventory | A method name is mandatory when the surface contains one; null is allowed only for a reviewed absence classification |
| Pinned inputs | Model, provider, reasoning effort, permission profile, sandbox, disabled network, approvals, config, features, tools, disabled plugin IDs and thread-start digest |
| Construction and dispatch | Public evidence for construction sites, capability categories, reachable tools, the exact attested P1 tool set and closed dispatch |
| Gates and hot reload | Each category is pinned, exact-instance observed or proven absent in the digest; all listed hot-reload inputs are frozen |
| Plugins | Source-reviewed `plugin/installed` contribution fields; stable exact-cwd state with empty capability contribution |
| Confinement | Source-reviewed method, exact-thread or same-digest policy-equivalent route, backend, effective policy digest and exact errno for each deny |
| Review | Independent I2/I3 reviewer distinct from author; receipt binds exact RTCA bytes and re-derives source, surface, sites/categories, dispatch, plugin relation and canary route |

The only relocation slots are `cwd=@workspace` and
`sandbox.writableRoots=@writable_roots`. They are materialized from the validated,
resolved owner grant. The RTCA thread-start digest covers the fixed template;
the durable proof also binds the materialized input digest. The canary route
must report the effective policy digest including the actual resolved writable
roots, rather than the template digest. There is no arbitrary
configuration substitution. Any mismatch, especially reasoning effort, closes
admission. JSON boolean/integer distinctions are preserved in exact comparisons.
Any RTCA byte change invalidates its review receipt.

## Binding conjunction

`CompositeProof` establishes K1–K11 in order, before any task input or turn:

1. Exact process/executable/runtime identity.
2. Exact-source correspondence.
3. Valid applicable unsuspended sealed RTCA and complete method surface.
4. Fresh stdio-only child, sole client, dedicated provider state and exactly one thread.
5. Exact thread/start cwd, permission profile, effective writable roots/sandbox/network, approvals, model/provider and reasoning effort.
6. Closed gates for shell, filesystem, MCP, dynamic, plugin, Computer Use, delegation, meta, network and managed requirements.
7. Exact-thread `mcpServerStatus/list`, detail Full, every page; any server is rejected.
8. Equal plugin state before/after thread creation and empty contribution in every source-attested field.
9. Conditional mandatory unified inventory with every page, no duplicate/unknown/forbidden tools, and exact attested set equality.
10. Fresh confinement canary.
11. Local outbound method freeze and notification tripwire armed before binding flush.

Pagination requires an explicit terminal null cursor and rejects errors, missing
fields, repeated/empty cursors, page/item bounds and incomplete results. The
thread/process incarnation, sole-instance state, plugin state and observed gates
are rechecked at the binding boundary. Failures yield
stable typed errors and never publish a binding or send a task turn. Launch gaps
with unknown resource absence remain sticky ambiguity until exact stop.

## Per-start confinement

Every start creates independent nonce-scoped probes under runtime-state, inbox,
run, provider-state and endpoint roots. Owner-side DAC controls first prove the
same UID can append/create and connect. The worker script is executed through the
reviewed exact-thread sandbox route, never through a launcher-built sandbox.
Fallback requires explicit same-executable/same-policy source equivalence.

For every protected target, append and `O_CREAT|O_EXCL` must return exactly the
attested errno. Owner Unix socket and loopback TCP connection must also return
exact errno. A positive control writes exact nonce bytes and fsyncs in an
authorized writable root. Postchecks verify protected inode/digest, target
absence, zero accepted canary connections, exact positive bytes and helper
absence. All probes/listeners are cleaned with bounded absence verification.
Failures, including cleanup failures, are
`SANDBOX_CONFINEMENT_NOT_ATTESTED` with a bounded reason. No cached result is
accepted. The canary performs no GUI, TCC, screen/input, daemon, external-network
or provider-turn operation.

Tests model a passing sandbox route explicitly as synthetic. An actual local
unsandboxed Python command is a negative control and is rejected. These tests
exercise the harness and contract; they do not prove any real Codex confinement.

## Freeze and tripwire

The freeze wraps the realization request entry and requires a transport-level
outbound guard before binding publication. Each permitted request grants one
exact method/parameters send token; a direct transport call without that token
is refused. Notifications are also closed after initialization. It
allows only exact-thread read, exact-turn interrupt and one initial text-only
turn. Before the binding is durable, all such active requests are refused.
Turn overrides, settings updates, steer, config reload/write, feature toggles,
plugin enable/install and thread create/resume/fork are rejected locally, with
zero wire bytes. The initial send is consumed before wire dispatch, so a lost
reply cannot lead to resend or another attempt.

An observed unattested/MCP/dynamic/CU/delegation/meta/plugin/network tool call,
wrong thread/turn identity or unknown tool category suspends the exact RTCA,
interrupts the exact active turn if established, then closes the run with
`ATTESTED_TOOL_SET_VIOLATION_OBSERVED`. Suspension is durable and subsequent
starts using that review are refused. Only a newly independently reviewed
admission can supersede it. The v1 receipt uses the existing
`CAPABILITY_UNAVAILABLE` decision; the detailed typed violation is in the ledger.

## Durable lifecycle and ownership

Canonical roots come from the OS account record of real UID, ignoring HOME,
XDG, provider environment, argv and grant overrides. On macOS the state root is
`<account-home>/Library/Application Support/session-preserve/runtime`; on other
supported POSIX hosts it is `<account-home>/.local/state/session-preserve/runtime`.
The short endpoint root is `<account-home>/.sp-rt-ipc`, outside the worker roots.
Owners stage grants separately; start does not bootstrap or redefine these roots.

```text
<runtime-state>/<RUN_ID>/
  authorization.json       owner grant, atomically consumed from authorization-inbox
  controller.lock          kernel exclusive lock, close-on-exec
  preaction.log            bounded typed, synced append-only facts
  binding.json             immutable no-replace publication after proof
  receipt.json             immutable no-replace terminal projection when bound
  provider-state/          isolated native raw evidence, mode 0700
<endpoint-root>/<run-generation-locator>.sock
```

Directories are 0700, files/socket 0600. Grant and run-file reads are single-open,
no-follow, fstat/owner/mode/nlink checked and bounded. Grant byte/inode identity
is rechecked across inbox consumption. Start is serialized, reserves generation
1 and burns RUN_ID permanently. Same task or overlapping scope refuses another
active run; a terminal decision with a live/unverified exact resource still
blocks overlap. Scope resolution rejects aliases via symlinks and conservatively
compares case-folded paths. Provider-state equality is enforced before launch.
IPC path length is checked before reservation; bind never unlinks an old locator.
Peer UID, full run/attempt/generation and endpoint inode are checked.

The ledger records authorization digest, controller incarnation/boot, a clock
including sleep, deadline, launch intent, exact owned resources, proof digests,
binding flush, turn-send intent/observed turn, loss, terminal decision and release
intent/outcome. It accepts only typed fields, never prompts, raw protocol payloads,
credentials or provider/tool bodies. Provider-native evidence is read by exact
thread/turn and dedicated state root, never a latest-session selector.

Controller loss, provider connection loss and client loss are separate. Client
loss changes no lifecycle state. Provider connection loss is sticky transport
loss with no reconnect/resume. Controller loss remains sticky; observation and
reconciliation improve facts without acquiring a generation or restoring side
effects. Boot mismatch prevents action and deadline reuse. The conservative
unadmitted OS fallback cannot signal a provider by PID/name; missing independent
incarnation/launch/group ownership is `RESOURCE_UNVERIFIED`.

Only authorized stop acquires a fenced successor, and only after both kernel
lock acquisition and exact controller absence/boot proof. A closer never binds
an endpoint or reconnects to the provider. It adopts an absorbing terminal
controller decision, including a crash before receipt publication. Terminal
ledger publication precedes cleanup. Each resource release intent is durable
before live identity is re-derived and one release action is attempted. A prior
intent without verified outcome is verification-only; no second signal/close is
sent. Wrong/stale identities are never killed. A helper/group identity can bind the
exact leader process, PGID, session ID, leader birth and boot. The reviewed
ownership observer must independently re-derive group/descendant ownership;
unavailable group evidence remains RESOURCE_UNVERIFIED. A pre-binding failure has a typed
terminal ledger and no normal receipt; an unknown launch gap remains ambiguous
until authorized closure.

Provider-state is EPHEMERAL for control/migration authority and raw/local/sensitive
for privacy. It is retained locally and never copied into receipts/packages or
used to resume another host/boot. Broad cross-run read exposure remains a residual
when the reviewed sandbox cannot prove read isolation; disabled worker egress is
required. Writable roots never include authority, endpoint or provider-state.
Credential-copy mechanisms need separately reviewed exact cleanup and are not
provided by this candidate.

## Validation and review boundary

`tests/runtime_p1_fixtures.py` contains invented 0.0.0-synthetic attestations and
an explicit synthetic realization, separate from production loading. The focused
suite exercises gates, ordering, failures, local refusal, suspension, lifecycle,
framed stdio and unchanged P0/import contracts. Synthetic success grants no live
support. Protocol background information is available in the
[official App Server documentation](https://learn.chatgpt.com/docs/app-server);
only the reviewed exact source/digest may supply capability authority.

Candidate acceptance uses a fresh detached worktree of the exact candidate
commit, with matching tree and empty tracked/untracked/ignored status. Hygiene,
full unittest, golden regression, examples and diff checks run there. Findings
only in execution-workspace task scratch are WORKSPACE_SCRATCH_FINDING; tracked
candidate findings are PUBLISHABLE_TREE_HYGIENE_FAILURE. The scanner and ignore
rules are unchanged. Builder PASS means source candidate ready for fresh review,
with supported runtimes NONE and production live binding unauthorized.
