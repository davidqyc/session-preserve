# 实验性 Runtime Control P0 合同脚手架

[English / 完整规范字段表](runtime-control-p0.md) · [P1 对照矩阵](runtime-control-p0-conformance.md)

P0 artifact schema、validator、digest 与 passive API 保持兼容。
当前主动 CLI 范围见 [P1 composite proof 框架](runtime-control-p1.md)：生产支持集合为空，
steer / calculator 仍保留最早零状态门禁。下方 P0 行为表是历史基线，不表示 P1 仍禁用全部六个动词。

本轮仅提供 **EXPERIMENTAL / 实验性合同脚手架**，不属于稳定 preservation 兼容性承诺。
P0 不启动或控制 Codex，不提供 live steer，也不执行 Computer Use。
没有 controller、helper、IPC、daemon、server、queue 或真实 runtime state。

仍是同一个 `session-preserve` distribution；版本、空依赖及 preservation schema **3.0** 不变。
`export / verify / pack` 保持源会话只读及行为兼容。Runtime Control 不是 ProviderAdapter 导出来源。
三个独立 runtime v1 schema 不会自动进入 preservation package；没有第二套 transcript/history 数据库。

## 命令行为

| 命令 | P0 行为 |
| --- | --- |
| `runtime probe [--metadata FILE] [--executable PATH]` | 只读被动静态元数据；advisory，退出 0；缺少证据为 UNKNOWN/UNVERIFIED |
| `runtime verify ARTIFACT [--authorization FILE] [--binding FILE]` | 本地严格结构及显式配对一致性验证；PASS 退出 0，FAIL 退出 2 |
| `runtime start / observe / reconcile / steer / calculator / stop` | 最早入口返回 `NOT_IMPLEMENTED_P0`，退出 3，创建零文件/目录/状态 |

`runtime calculator` 只存在于 parser surface，仍是 NOT_IMPLEMENTED_P0。
六个拒绝动词在读取 stdin、解析授权、解析或创建 state root、provider discovery、runtime import
及任何 provider/process/network/GUI 操作之前返回；尾部参数包括 `--help` 均不读取、不回显。
未来任务、授权、纠偏及 Calculator action plan 使用 stdin/文件；P0 不消费这些主动命令输入。
没有 computer-use、resume、retry、exec、daemon、server、queue 动词。

Probe 不自动发现运行环境。显式静态 JSON 文件最多 4 KiB，只含 `provider: "codex"`
和 `declared_runtime_version`。版本来自文件声明，绝不执行 provider binary 获取。
executable 参数仅检查路径属性。有效版本也只标记 DECLARED，live capabilities 始终 UNVERIFIED。
不启动 app-server/thread/turn/MCP，不请求 TCC，不获得前台，也不写 provider state。

Verify 只读取点名的本地普通文件，限制字节数，输出稳定错误码，不回显未知字段名、原文、路径或异常体。
PASS 仅代表结构/一致性：**不证明 run 发生、不证明 provider/GUI 事实真实、不证明执行成功**。
缺失配对输入保持未验证，不搜索同目录文件或 provider history。
顶层 preservation `verify` 识别 runtime schema 后拒绝，并指向 `session-preserve runtime verify`；
这条路径不 import runtime_control。

## 授权、binding 和 receipt

规范 schema ID 为：

- `session-preserve-runtime-authorization/v1`：独立 8192 字节上限；
- `session-preserve-runtime-binding/v1`：独立 12288 字节上限；
- `session-preserve-runtime-control-receipt/v1`：规范 16384 字节上限。

三个 validator 都拒绝重复 JSON key、未知字段、错误类型、隐式转换、非法 ID、非有限数字及超长编码。
完整、唯一的规范字段表与 Python public API 清单见 [英文规范](runtime-control-p0.md)。
未列出的内部 symbol 不构成兼容性承诺。schema ID 在 shared pure module；shared pure helpers 不 import 任一 plane。
只有显式 runtime 入口允许 lazy import；preservation help/export/verify/pack 有子进程隔离证据。
没有 plugin entry-point/dynamic discovery。

TASK_ID 是 1–64 字符非秘密 ASCII token；RUN_ID/ATTEMPT_ID/launch/client correlation 是小写规范 UUID。
当前 Codex native thread/turn profile 要求 UUIDv7。process identity 必须含 pid、独立 OS birth_ns、
executable SHA-256 和精确 launch UUID；PID 单独或 latest-session 推测无效。
turn_id 仅在明确 THREAD_BOUND、尚未建立 turn 时可为 null。

授权区分 runtime observe 与 Calculator GUI observe、mutate、foreground、restore_foreground。
`steer_authorized=false` 要求 correction maximum=0；最大值范围 0..3，调用方参考默认 3，初次 launch 不计纠偏。
预存 Calculator 修改授权 `mutate_preexisting` 默认 false。idle bound 可省略；存在时必须为正且不超过 wall bound。
授权是调用方不可变 policy，**不是任意同用户进程的认证机制**。

未来主动执行必须独立证明 sandbox：state、policy、controller channel 和 provider-native evidence store
不能被 worker 写入/访问。保护已有授权/通道不等于阻止 worker 自行调用另一个 start。
binding 的 `nested_start_enforcement` 允许两个结构值：P0 synthetic/unverified artifact 使用
`UNVERIFIED_PENDING_N6_N11`；未来 active P1 只有在 owner-staged launch gate 与 confinement attestation
通过后才写 `OWNER_STAGED_GATE_ATTESTED`。结构 verify 只检查声明形状，不能认证该声明。
P0 本身仍不启动 runtime。

身份 ref 与授权/binding digest 使用 [规范定义](runtime-control-p0.md#canonical-digests-and-refs)
的 domain-separated SHA-256；一致性摘要不是签名或认证。
Receipt 是 typed allowlisted derived evidence，不是 authority；最多 32 条 correction、16 个 owned resource、128 次 call。
controller terminal decision 与 provider terminal fact 分开；STOPPED 不是 provider 已停止的证明。
ACCEPTED 未 PERSISTED 即使 provider 已完成也仍 ambiguous；只有机械证明 pre-delivery rejection 可释放 reservation。

Receipt 排除 AX tree、默认截图、raw GUI text、approval payload、account ID、credential/secret、私有 home/repo path、
device ID、前台 app identity、原始任务/纠偏文本、异常体及 transcript/history。没有自由文本载荷槽。
授权和 binding 的 scope 路径不属于 privacy-bounded receipt，需独立保留策略。

## Runtime profile 与 Calculator 条件约束

binding / receipt 的 `runtime_profile` 允许两个结构值：

- `codex-app-server-r1`：通用 no-CU profile；
- `codex-app-server-calculator-r1`：未来 Calculator/P3 profile。

profile 是结构声明，不是阶段授权，也不认证真实 runtime 行为。
通用 profile **必须** `calculator_catalog_proven=false`；其余五个 capability 与全部 sandbox posture 仍必须为 true。
若显式同时提供 authorization + generic binding，规范化后的五个 Calculator grant（含默认的 `mutate_preexisting=false`）必须全部 false。

通用 profile 的 receipt 必须是 zero-Calculator：五个 grant 全 false、approval/click 为 0、keys 为空、`session_proof=UNPROVEN`、
`click_schema_string=false`、`calculator_preexisting=false`、`previous_frontmost_captured=false`，且不得含 CALCULATOR_READ / CALCULATOR_CLICK 或 task-owned CALCULATOR resource。
`SCHEMA_READ` 仍可表示 inventory/schema 证据；非授权 GUI 异常只能用 `GUI_EXECUTION` / `GUI_EXECUTION_UNCERTAIN`（必要时加 RESOURCE_UNVERIFIED）表达，不能伪装成 Calculator activity。
`STEER` 在结构层仍可存在，因为后续 P2 可以复用同一 generic profile；这不表示 P1 已获 steer 阶段授权。

Calculator profile 保持既有 `calculator_catalog_proven=true` 和旧 fixture/digest 语义，P3 仍未授权。
`maximum_snapshot_age_ms` 仍是 1..1000 ms 的范围校验，不是 profile 固定常量。
结构 verify 仍是 `LOCAL_STRUCTURAL_ONLY` / `execution_attested=false`。

## 保留合同，延期主动机制

全部参考合同 section/key 的唯一映射与延期理由见 [对照矩阵](runtime-control-p0-conformance.md)。
终态 COMPLETED/FAILED/STOPPED absorbing，晚到 provider success 不重开终态或延长 deadline。
AMBIGUOUS 冻结新副作用，仅允许 exact-identity stop/close；controller loss 与 GUI uncertainty 对本 attempt sticky。
observe 不改变 controller 分类。经审阅的公共 R1 中，协调端/client 丢失不进入 controller lifecycle ambiguity；
重新连接/observe 只刷新 client 对仍存 controller 的认知。provider connection loss 对本 attempt sticky，不能靠 reconnect 恢复副作用权限。
不自动 retry/resume/resend，不提供 interrupt+resume fallback。

纠偏先 reserve 后 send；同一 logical ID 不重发；UNCERTAIN 保留预算与既有正向证据。
evidence 顺序 ACCEPTED → PERSISTED → CONSUMED；终态与 steer reply 的 race 不授权再发。
耗尽授权最大值而未收敛时 stop/return，typed reason 为 CORRECTIONS_EXHAUSTED；未来 steer 为 BUDGET_EXHAUSTED。
P0 只验证静态事实，尚不执行 controller、时间序列或 send accounting。

未来 R1 为 **controller-issued、Calculator-only**，不宣称通用模型驱动 GUI。
进入 Calculator 必须有 observe 和 foreground 授权。controller 在 session proof 及每次 click 前重新读取 same-thread
完整 live tool schema；只允许 computer-use 的 get_app_state/click，经 mcpServer/tool/call。
首个精确 full get_app_state（disableDiff=true）只接受一次 same-thread message-only、无 turn context 的 approval，
返回 `accept + content:null`，不选择/回显/持久化 standing approval。
第二次 same-thread full read 无新 approval 才证明 CURRENT_SESSION；缺少第一次 approval 则 HOLD。

每次 click 必须 fresh full snapshot，年龄 <=1 秒、唯一 semantic key、立即发送 1–8 位 decimal string ID，保留前导零。
nonce 发送前消费，不跨 snapshot 复用。固定 key 为 Zero..Nine、Add、Equals、Clear；无 app/tool/browser/raw JS/element-ID 参数。
P0 没有实际测试过的 public macOS/locale GUI 范围；未知本地化/语义形状必须 fail closed。
预存 Calculator 只有单独授权才能修改，始终不得 cleanup close。

cleanup 只有一条 close 路径，独立 grace <=5 秒；即时原子重查完整 ownership/incarnation，不能按 PID/name/pattern 清理。
验证资源 absence，typed 记录失败，不自动重试。前台身份只保存在内存。
仅已授权、prior identity/incarnation 有效、task surface 仍在前台时恢复；用户已切焦点则不抢回。
未来 public controller 在终态写一次 derived receipt，是对参考 `automatic_write=false` 的明确公共差异；P0 不写真实 receipt。
public launcher/adapter 是新公共实现设计，不 vendoring 私有脚本。

## 更换主机分类

| 组件 | Migration class |
| --- | --- |
| contract/code/safe export | FILE_STATE_ONLY |
| runtime discovery/transport/ownership | HOST_BINDING |
| Accessibility/Screen Recording（仅在需要时） | TCC_PERMISSION |
| signed app/LaunchServices | SIGNING_REGISTRATION |
| provider login/control pairing | ACCOUNT_OR_DEVICE_PAIRING |
| process/socket/session approval/deadline/snapshot | EPHEMERAL |

只有经过验证、privacy-bounded 的 terminal receipt 与明确 public conformance evidence 属于可移植 FILE_STATE_ONLY。authorization、binding、ledger、provider-state 等 machine-bound runtime material 即使本地保留，其 control/migration authority 仍为 EPHEMERAL，不可在新 host/boot 重放。
| validated terminal receipt / 明确 public conformance evidence | FILE_STATE_ONLY，仅 archival evidence |
| non-terminal state/active grant/endpoint/process identity | EPHEMERAL，新 host/boot 不可执行 |

复制文件不授予权限。终态 bounded receipt 与机器绑定 binding/ledger 必须区分；文件归档不使后者可迁移或可执行。
state retention/boot-session identity 等仍受 N11/N13 门禁约束。N6–N11 和 N12–N13 本轮未实现，也未进行 Fresh Review 或发布。
