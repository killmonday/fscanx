---
name: project-control-plane
description: Manage continuous project delivery through a project console, module backlog ledgers, scoped context packages, verification, and state synchronization.
triggers:
  - 项目控制台
  - backlog
  - Backlog
  - 阶段交付
  - 阶段范围
  - 当前阶段
  - 下一步做什么
  - 执行 backlog
  - 开发流程
  - 项目状态
  - 需求澄清
  - 共识规划
  - 需求模糊
  - 高风险项
  - 一直运行
  - 持续运行
  - 持续执行
  - 直到完成
  - 做完所有
  - 不用询问
  - 不要停顿
---

# Project Control Plane

Use this skill to manage a continuously evolving software project without forcing humans or AI to keep the whole project in working memory.

Core idea:

- `docs/项目控制台.md` is the fixed human-facing entry point.
- `docs/backlog/*.md` files are the module-level development state ledgers.
- `docs/modules/*.md` files contain module requirements and high-level design.
- Each implementation task loads only a scoped context package for the selected backlog item.
- State is synchronized when backlog status, active work, or blockers change.

Avoid one-off delivery language. Prefer:

- 当前阶段范围
- 阶段交付范围
- 版本范围
- 基线能力
- 阶段验收
- 演进路线
- 持续迭代计划
- 能力地图

Only use "MVP" when the user explicitly asks for it or when referring to existing files/titles that already contain that term.

## 硬禁止

本技能激活期间，以下行为绝对禁止：

- **禁止调用 `EnterPlanMode`。** 本技能有自己的规划体系——需求澄清走 Mode B0，backlog 生成走 Mode B，高风险共识走 Mode H（Planner → Architect → Critic 循环）。内置 plan mode 的 Phase 1-5 流程不知道 backlog、context-package、CHANGELOG 等要求，用它代替本技能规划流程会导致文档维护被跳过。
- **禁止用 `oh-my-claudecode:planner` agent 替代 Mode H 的完整 Planner → Architect → Critic 共识循环。** 单个 planner agent 没有 Architect 的 steelman antithesis 和 Critic 的 quality gate，不等同于 Mode H。
- **禁止在没有 backlog item 的情况下直接进入实现。** 任何非琐碎任务必须先在 `docs/backlog/` 中创建 backlog item，再通过 Mode D 执行。
- **禁止在 plan 批准后直接写代码而不维护文档。** 必须按 Mode D 步骤 12 同步 backlog、项目控制台、CHANGELOG。
- **禁止把 `/project-control-plane` 入口下的功能行为变更当作 trivial change。** 只要涉及功能行为、API 契约、数据模型、搜索语义、任务流转、文档状态或验收口径，即使只改 1 行，也必须走 Mode B/Mode D/Mode D-lite。
- **禁止把“先聊聊”阶段的草案直接当作已批准实现方案。** 用户后续说“批准”“修改吧”“开始做”时，必须重新判定 Mode；进入实现前必须补齐 backlog/plan 所需最小文档。
- **禁止在未获显式授权时修改运行时外部状态。** 包括但不限于 Meilisearch settings/index settings、数据库 schema/迁移状态、Redis/Celery 队列配置、服务配置、远端 issue/PR 状态。若确需修改，必须先说明影响范围并等待用户确认。

## 你必须做的第一件事

每次激活本技能时，按以下顺序执行：

1. 读 `docs/项目控制台.md`（不是 `docs/CLAUDE.md`）了解当前阶段和活动 backlog。
2. 检测用户是否明示持续运行（见下方持续运行检测规则）。若已激活持续运行，直接进入 Mode D-Chain。
3. 判断用户请求属于哪个 Mode（A-H 或 R）。
4. 如果用户明确要求“只检查/只审查/只出报告/不要改代码”，优先进入 Mode R（只读审计）。
5. 如果请求涉及新功能且没有对应 backlog item：进入 Mode B0（需求澄清）或 Mode B（backlog 生成）。
6. 如果已有 backlog item 且属高风险：进入 Mode H。高风险定义：P0 +（跨模块 | DB 迁移 | 安全认证 | >20 文件 | API 破坏性变更）。
7. 如果已有 backlog item 且为标准风险：进入 Mode D。

## 持续运行（Mode D-Chain）

当用户明示以下任一模式时，进入持续运行状态：

- 用户说"一直运行"、"持续运行"、"持续执行"、"一直做"、"做完所有"
- 用户说"直到完成所有 backlog"、"不用询问我"、"不要停顿"
- 用户说"批准你一直运行，直到我打断你或工作完成"
- 用户直接要求执行多个 backlog item（如"执行 BL-001 到 BL-003"）

**持续运行规则：**

1. 读 `docs/项目控制台.md`，确定所有 `未开始` 的 P0→P1→P2 backlog item 作为待执行队列。
2. 按优先级（P0 优先）和 backlog ID 顺序逐项执行。
3. 每个 item 走完整的 Mode D 流程（plan、实现、四层验证、文档同步），但不等待用户确认。
4. 一个 item 完成（含「已完成」状态更新）后，**立即**加载下一个 item 的上下文包并继续，只输出一行过渡摘要（如"BL-XXX 完成，开始 BL-YYY"）。
5. 仅以下情况停止：
   - 队列中的所有 backlog item 状态均为 `已完成`
   - 遇到高风险 item（Mode H 阈值的 P0+跨模块/DB/安全）且用户未预设可自行规划
   - 用户发送打断消息
   - 遇到无法自行恢复的错误（数据库不可达、依赖缺失等）
6. 环境服务（PostgreSQL、Redis、Meilisearch、uvicorn、Celery）若由于崩溃停止，需自动重启后继续。
7. 全部完成后，输出完成摘要（每个 item 的状态、验证结果、修改文件数），自动进入 Mode E 同步文档状态，然后主动建议运行 Mode F 阶段验收（列出验收证据清单）。
8. 注意：链模式下 reviewer 和 deslop 改为批量执行（每 3 个 item 提交一次 reviewer audit + deslop），不跳过。

过渡摘要格式：

```text
BL-XXX 完成（X files, ruff/mypy/pytest/tsc ✓）。开始 BL-YYY。
```

## When to use

Use this skill when the user asks to:

- Review project status.
- Decide the next project step.
- Initialize or maintain `docs/项目控制台.md`.
- Generate or maintain module backlog files.
- Turn requirements or module docs into backlog items.
- Clarify vague requirements before generating backlog items.
- Choose the next backlog item to execute.
- Execute a backlog item.
- Run consensus planning for high-risk backlog items.
- Synchronize development state after work.
- Prepare a phase acceptance check.
- Reduce document sprawl and context overload.
- Audit recent changes against plans / backlog / module docs without directly implementing fixes.
- Check whether recent work has omissions, regressions, stale tests, or stale docs.

## When not to use

Do not use this skill for:

- Small typo fixes.
- One-line obvious code changes.
- Pure Q&A that does not affect project flow.
- Emergency bug fixes where the user explicitly asks for direct action.

For trivial changes, act directly and keep documentation overhead minimal.

Trivial means only typo fixes, local wording changes, or obvious one-line mechanical edits that do not change runtime behavior, public contracts, data shape, search semantics, backlog state, or acceptance evidence. If the request entered through `/project-control-plane`, classify any user-visible behavior change as Mode D-lite at minimum.

## Expected project artifacts

```text
docs/
  项目控制台.md
  设计总览.md
  需求规格说明书初稿.md
  阶段交付范围说明.md
  当前实现总览.md
  开发文档索引.md

  modules/
    00-模块总览.md
    ...

  backlog/
    ...

plans/
  <date>-<backlog-id>-<task-name>.md
```

**`docs/设计总览.md`**：项目架构入口文档。覆盖技术栈选型、模块地图与模块间关系、核心业务流（分步描述 + 关键代码文件指针）、关键设计决策记录（每次做出影响架构或流程的决策时，第一时间更新此文档）。

## Artifact responsibilities

| Artifact | Responsibility | Update frequency |
|----------|----------------|------------------|
| `docs/项目控制台.md` | Current phase, active backlog, blockers, next recommendation | When backlog status, active work, or blockers change |
| `docs/设计总览.md` | Architecture overview: tech stack, module map & relations, core business flows, key design decisions | Every time a design decision is made that affects architecture or flow |
| `docs/backlog/*.md` | Source of truth for backlog item status | High |
| `docs/modules/*.md` | Module requirements, high-level design, flows, acceptance | Medium |
| `plans/*.md` | Per-task execution record | Every non-trivial task |
| `docs/当前实现总览.md` | Current code capability map | Medium |
| `docs/开发文档索引.md` | Navigation | Low/medium |
| `CHANGELOG.md` | All changes, dated | Every change（每次改动都记，必须带 `## YYYY-MM-DD` 日期标题） |

## Module and backlog numbering

Control-plane module files and backlog files must use the same numeric prefix.

Rules:

- `00` is reserved for overview/rules.
- `01+` represents module order for the current phase.
- `docs/modules/<NN>-<module>模块.md` must correspond to `docs/backlog/<NN>-<module>.md`.
- When adding a new module, assign the next number and create both files together.
- Do not renumber existing files unless the user explicitly approves a reordering.

Current numbering:

```text
00: docs/modules/00-模块总览.md ↔ docs/backlog/00-Backlog维护规则.md
01: docs/modules/01-Product管理模块.md ↔ docs/backlog/01-Product管理.md
02: docs/modules/02-PoC管理模块.md ↔ docs/backlog/02-PoC管理.md
03: docs/modules/03-关系匹配与审核模块.md ↔ docs/backlog/03-关系匹配与审核.md
04: docs/modules/04-AI别名识别模块.md ↔ docs/backlog/04-AI别名识别.md
05: docs/modules/05-异步任务模块.md ↔ docs/backlog/05-异步任务.md
06: docs/modules/06-运行部署与可观测性模块.md ↔ docs/backlog/06-运行部署与可观测性.md
```

## Backlog organization

Backlog files must be split by numbered module under `docs/backlog/`.

Example:

```text
docs/backlog/00-Backlog维护规则.md
docs/backlog/01-Product管理.md
docs/backlog/02-PoC管理.md
docs/backlog/03-关系匹配与审核.md
docs/backlog/04-AI别名识别.md
docs/backlog/05-异步任务.md
docs/backlog/06-运行部署与可观测性.md
```

## Backlog status values

Use only these status values:

```text
未开始
进行中
已完成
```

Do not invent extra states such as blocked, deferred, canceled, or reviewing. If an item is blocked or deferred, keep its status as `未开始` or `进行中` and record the reason in its status log or blocker section.

## Priority values

```text
P0：阻塞当前阶段主链路
P1：重要但不阻塞主链路
P2：体验、质量或工程优化
P3：远期增强
```

## Backlog item format

Use this lightweight structure:

```md
## BL-PROD-001 Product 创建与编辑能力收口

- 模块：Product 管理
- 优先级：P0
- 状态：未开始
- 当前阶段：阶段一
- 价值：资产维护人员可以稳定维护标准产品资产。
- 关联模块文档：docs/modules/01-Product管理模块.md
- 关联计划：
- 关联代码：
- 验收状态：未验收

### 范围

- ...

### 不做

- ...

### 验收条件

- [ ] ...
- [ ] ...

### 依赖

- ...

### 状态记录

- YYYY-MM-DD：...
```

## Context package rule

Never load all project documents by default.

For a selected backlog item, load only:

Required:

1. `docs/项目控制台.md`
2. The specific backlog item from `docs/backlog/*.md`
3. The related module document from `docs/modules/*.md`
4. Relevant section of `docs/当前实现总览.md`

As needed:

5. Relevant OpenAPI section
6. Relevant database/schema section
7. Relevant source files
8. Relevant tests

If the selected backlog item lacks enough context, stop and ask the user or create a pending documentation/backlog refinement task.

When the user asks for the next stage rather than a specific backlog item, load only:

1. `docs/项目控制台.md`
2. `docs/阶段交付范围说明.md`
3. `docs/backlog/00-Backlog维护规则.md`
4. Numbered backlog summaries under `docs/backlog/`
5. Numbered module overview under `docs/modules/00-模块总览.md`

Do not read implementation source until a concrete backlog item is selected.

## Acceptance gate rule

Backlog development status and phase acceptance status are separate.

Backlog status must still use only:

```text
未开始
进行中
已完成
```

Acceptance status may be recorded separately as:

```text
未验收
待验收
已验收
验收未通过
```

Rules:

- `已完成` means implementation and local verification for the backlog item are complete.
- `已验收` means the item passed phase-level acceptance evidence.
- Do not mark an item `已验收` only because its code exists.
- If phase acceptance fails, keep backlog status based on implementation reality and set acceptance status to `验收未通过` with the failed evidence.
- If acceptance has not been run, use `未验收` or `待验收`, not a backlog status workaround.

## Blocker classification

When updating `docs/项目控制台.md`, classify blockers so the next planning step can turn them into backlog or decisions.

Use these categories:

```text
待产品决策
待技术方案
待外部依赖
待验证
```

Rules:

- Do not invent a backlog status for blockers.
- Keep blocked backlog items as `未开始` or `进行中` and record the blocker in the item status log.
- Project-level blockers belong in `docs/项目控制台.md`.
- Item-specific blockers belong in the relevant backlog item.

## Vagueness detection rule

Before entering Mode B (backlog generation) or Mode D (execution), check whether the target is specific enough to proceed without clarification.

A backlog item or requirement is **specific** when at least one of these signals is present:

- References concrete file paths or function/symbol names
- Has numbered, testable acceptance criteria (not "功能完成" or "代码无错")
- Names specific API endpoints, database tables, or UI components
- References an existing module doc with clear scope boundaries

A backlog item is **vague** when:

- Described with broad verbs and no concrete scope (e.g., "完善 XX 管理", "优化系统")
- Acceptance criteria are generic boilerplate ("功能正常", "代码编译通过")
- **Falsifiability failure**: For any acceptance criterion, asking "如果用测试来证明这条没实现，我该测什么？" yields no clear answer. A criterion that cannot be proven false is not a criterion.
- Core entities are unstable (user names different entities for the same concept across descriptions)
- The scope could reasonably mean anything from a one-line change to a full module rewrite

If vague:

- For requirements without a backlog item: suggest Mode B0 (demand clarification) first.
- For existing backlog items: suggest the user run Mode B0 to refine the item, or Mode H (consensus planning) if the item is also high-risk.
- Do not silently proceed with vague scope. Surface the ambiguity and let the user choose.

This is not a hard gate with force/bypass syntax. It is a control-plane internal recommendation. If the user insists on proceeding, respect their decision but record the ambiguity as a risk.

## Closeout synchronization rule

Before reporting a project-control-plane task complete, check:

1. Relevant `plans/*.md` has result, risk, and next-step sections updated.
2. `CHANGELOG.md` records this change（每次改动都记，必须带 `## YYYY-MM-DD` 日期标题；如当天日期标题不存在则先创建）。
3. `docs/项目控制台.md` is synchronized if phase state, active backlog, or blockers changed.
4. Relevant `docs/backlog/*.md` has no item left `进行中` unless work will continue immediately.
5. `docs/设计总览.md` is updated if a new design decision was made（技术选型、流程变更、模块关系、架构边界）.
6. **Relevant `docs/modules/*.md` MUST be updated when module behavior, scope, or acceptance changed.** 编码前已按必答清单更新，此处为验证。
7. Verification evidence is recorded, or a clear test exemption is stated.
8. Deslop pass (ai-slop-cleaner) has been run on changed files and post-deslop regression tests pass, or the user explicitly waived this step.
9. The final report distinguishes current-turn changes from pre-existing dirty worktree changes; do not summarize the whole repository diff as if it was created by this task.
10. The final report distinguishes three categories whenever relevant: (a) issues fixed in this turn, (b) older issues exposed while working on this turn, and (c) unrelated historical issues that remain outside the scope.
11. Any failing verification command records: exact command, failing test/check, failure summary, whether evidence indicates it is pre-existing or caused by this task, and the recommended next step.
12. If actual operations diverged from a stated plan or promise, explain the divergence to the user and wait for instruction（向用户说明并等待指示）instead of silently continuing or self-approving the change.

## Documentation sync matrix

- **Any code change** → update `CHANGELOG.md`（一行即可，不做判断；必须带日期：`## YYYY-MM-DD`）
- **Design decision made** → update `docs/设计总览.md`
- **Module behavior / scope / flow change** → update the relevant `docs/modules/*.md`
- **Acceptance criteria / implementation state change** → update the relevant `docs/backlog/*.md`
- **Read-only audit report** → write to `plans/*.md` or a dedicated report file; do not update module docs unless the audit itself changes documented truth
- **Test-only fix** → default to backlog/plan updates only; do not force a module doc edit unless runtime behavior or documented acceptance changed

## Mode R: Recent-change audit (read-only)

Use when the user asks to:

- 检查最近几天的提交有没有问题
- 按设计/plan/backlog 核对最近实现
- 排查遗漏功能、回归 bug、测试滞后、文档残留
- 只出报告，不直接修改代码

Steps:

1. Confirm the audit scope: recent N days, selected modules, selected plans, and whether current dirty worktree changes are included.
2. Load only the minimum context package: `docs/项目控制台.md`, related `plans/*.md`, related `docs/backlog/*.md`, related `docs/modules/*.md`, recent changed files, and relevant tests.
3. Audit code, tests, docs, and stated scope for consistency.
4. Classify every finding into exactly one of:
   - 已确认代码问题
   - 测试滞后 / 测试夹具过期
   - 文档与代码不一致
   - 风险点但证据不足
5. For each finding, include:
   - 等级（高 / 中 / 低）
   - 分类
   - 位置（file:line or artifact section）
   - 现象
   - 影响场景
   - 建议
6. Clearly distinguish:
   - 已提交改动中的问题
   - 当前未提交工作区问题
7. Produce a read-only report and stop. Do not implement unless the user explicitly asks to continue.
8. If the user later asks to continue, convert the audit findings into a repair queue before entering Mode D or Mode D-lite.

Success criteria:

- The report clearly separates code bugs, stale tests, stale docs, and low-confidence risks.
- The report distinguishes committed changes from dirty-worktree-only findings.
- The report is directly usable as a repair queue.

## Mode A: Project status review

Use when the user asks:

- "现在项目到哪了？"
- "下一步做什么？"
- "看看当前阶段状态"
- "哪些 Backlog 还没完成？"

Steps:

1. Read `docs/项目控制台.md` if it exists.
2. Read relevant `docs/backlog/*.md` summaries if they exist.
3. Identify:
   - current phase goal
   - active backlog items
   - blockers
   - recently completed items
   - next recommended item
4. If the next recommended item is vague (see Vagueness detection rule), flag it: "推荐下一步是 {item}，但其范围较模糊，建议先走需求澄清（Mode B0）或共识规划（Mode H）。"
5. Reply with:
   - current state
   - top 1-3 risks
   - recommended next action
6. Do not implement unless the user explicitly asks.

Success criteria:

- User can understand project status without reading all docs.
- Recommendation names specific backlog IDs or says backlog/control-plane files are missing.
- Vague items are flagged with a clarification suggestion.

## Mode B0: Demand clarification

Use when the user proposes a new feature, greenfield module, or functional requirement but:

- The acceptance criteria are unclear or generic ("功能正常即可")
- Core domain entities are unstable or unnamed
- The scope could mean very different things at different sizes
- The user says "我先想想" or "帮我理清需求"
- Vagueness detection (see rule above) flags the input as underspecified

This mode is a lightweight version of the Socratic interview. It is NOT the full 20-round deep-interview cycle. The goal is to produce a concrete backlog item draft with testable acceptance criteria in at most 3-5 rounds.

Steps:

1. **Frame the problem space**:
   - Ask the user to state the goal in one sentence: "当这个功能完成时，用户能做什么？"
   - Ask what problem it solves and for whom.
   - If the user cannot answer, ask: "如果没有这个功能，现在用户会卡在哪一步？"

2. **Clarify core entities (ontology)**:
   - Ask the user to name the key nouns (entities) involved.
   - If entities shift between rounds, call it out: "你上一轮提到的是 X，这一轮说的是 Y — 它们是同一个东西还是不同概念？"
   - Stabilize to a consistent set of entities before moving to features.

3. **Establish constraints and non-goals**:
   - "这个功能有什么明确的边界？什么一定不做？"
   - Identify dependencies: "它依赖哪些已有模块或外部系统？"
   - Surface assumptions: "你假设用户已经登录，还是需要处理匿名访问？"

4. **Define testable acceptance criteria**:
   - For each scope item, ask: "如果我现在实现完了，你用什么具体行为来判断它是否满足要求？"
   - Push back on vague criteria: "'功能正常' 不是可测的 — 你期望看到什么具体的输入/输出？"
   - Acceptable criteria examples: "调用 POST /api/products 返回 201 且数据库有对应行" / "前端表单提交后 3 秒内显示成功提示"

5. **On round 3+ (Simplifier check)**:
   - Ask: "这个需求的最简版本是什么？如果只做 20% 的工作拿到 80% 的价值，那 20% 是什么？"
   - Use this to split the output into P0（当前必须）and P1-P3（后续）items.

6. **Produce backlog item draft**:
   - Format the output as a standard backlog item (see Backlog item format).
   - Populate: module, priority, status `未开始`, value, scope, non-scope, testable acceptance criteria, dependencies.
7. **Independent review**: Spawn a `general-purpose` Agent with critic instructions to review the draft independently. The agent loads the backlog item draft and related module doc fresh — it has no access to the clarification conversation, so it catches what the drafter missed. Review dimensions:
   - Entity drift: Do the entities named in the criteria match the module doc?
   - Falsifiability: For each criterion, "if this fails, what test proves it?"
   - Boundary: Could a reader distinguish in-scope from out-of-scope?
   - Assumptions: Are implicit dependencies (APIs, tables, services) listed?
   Revise based on agent feedback (max 2 review-revise iterations).
8. Ask the user to confirm priorities before treating as committed. Then transition to Mode B to formalize into the backlog file.

Round limit:

- Hard cap at 5 rounds. At round 5, produce the best draft possible with the current clarity and mark unresolved gaps explicitly.
- Allow early exit at round 3+ if the user says "够了" or "开始做吧".

Success criteria:

- Output is a valid backlog item draft with testable acceptance criteria.
- Core entities are named and stable (no entity drift in the final 2 rounds).
- No acceptance criterion reads "功能完成" or equivalent.
- Critic review has passed (no unresolved clarity/consistency/scope issues).

## Mode B: Backlog generation

Use when the user asks to turn requirements/module docs into backlog.

Steps:

1. Read requirements, phase scope, and relevant module docs.
2. **Clarity gate**: Before generating backlog items, check each candidate's acceptance criteria:
   - Every criterion must be specific and testable (not "功能完成" or "代码无错").
   - Every criterion must describe a concrete observable behavior or measurable outcome.
   - If any candidate has only generic criteria, stop and suggest Mode B0 (demand clarification) to refine before generating.
   - If the user insists on proceeding with vague criteria, record them as a risk in the backlog item.
3. Extract candidate work items.
4. Group by module.
5. Assign draft priority and `未开始` status.
6. Add acceptance conditions.
7. **Independent review**: Spawn a `general-purpose` Agent with critic instructions to review the draft independently. The agent loads the backlog items and related module docs fresh — it has no access to the drafting conversation. Review dimensions:
   - Falsifiability: For each criterion, "if this fails, what test proves it?"
   - Scope clarity: Could a reader distinguish in-scope from out-of-scope per item?
   - Dependency completeness: Are all predecessors (migrations, modules, APIs) listed?
   - Priority consistency: Would P0 items truly block the phase if skipped?
   Revise based on agent feedback (max 2 review-revise iterations).
8. Ask the user to confirm priorities before treating them as committed.

Rules:

- AI may draft backlog.
- Human decides priority and scope.
- Prefer fewer, verifiable items over many tiny TODOs.
- Do not mark generated items `进行中` or `已完成` unless current evidence proves it.

Success criteria:

- Each backlog item has value, scope, non-scope, acceptance, dependencies, and status.
- No item is so large that it means "finish the whole module".
- No item is so small that it is only a trivial implementation detail.
- No acceptance criterion is generic boilerplate.
- Critic review has passed (no unresolved clarity/testability/scope issues).

## Mode C: Phase planning

Use when backlog exists and the user asks what to do in the current phase.

Steps:

1. Read project console.
2. Read P0/P1 backlog items.
3. **Vagueness check**: For each candidate item, check if the scope and acceptance criteria are specific enough to execute. Flag vague items: "BL-XXX 的范围描述较模糊，建议先通过 Mode B0 澄清需求后再纳入阶段计划。"
4. Select a coherent set of current-phase items.
5. Propose execution order.
6. Define phase acceptance.
7. Identify excluded scope.
8. **Independent review**: Spawn a `general-purpose` Agent with critic instructions to review the phase plan independently. The agent loads the project console, all included backlog items, and their module docs fresh. Review dimensions:
   - Dependency graph: Does the execution order respect actual dependencies between items?
   - Scope coherence: Do the included items together achieve the phase goal, or is there a gap?
   - Phase acceptance testability: Can each phase-level acceptance criterion be verified objectively?
   - Excluded scope justification: Are excluded items clearly non-blocking for this phase?
   Revise based on feedback (max 2 iterations).
9. Ask user to confirm before implementation.

Output should include:

```text
阶段目标
纳入范围
不纳入范围
执行顺序
阶段验收
风险
待确认事项
```

Success criteria:

- Current phase is small enough to execute.
- Execution order respects dependencies.
- Acceptance is testable.
- No vague item is included without a clarification plan.

## 编码前必答清单

进入 Mode D 或 Mode D-lite 实现之前，逐项确认。此清单优先于所有实现步骤——**未答完不写代码**。

```
1. 这个改动会让哪个已有文档描述变成错的？
   → 搜索 docs/modules/、docs/当前实现总览.md、docs/设计总览.md
   → 找到受影响的文档 → 先更新它们

2. 这个改动涉及新的设计决策吗？（技术选型、流程变更、边界约定、架构关系）
   → 先更新 docs/设计总览.md 或 docs/modules/*.md

3. 这个改动需要被未来的人追溯原因吗？
   → 创建 backlog item
   → 例外：纯 typo、空格调整、颜色值微调，且不改变任何 API/行为/数据/文档描述

4. CHANGELOG 记录了吗？（含日期）
   → 每条记录必须挂在 `## YYYY-MM-DD` 日期标题下
   → 如果当天日期标题还不存在，先创建日期标题
   → 每次改动都记，一行即可，不做判断
```

## Mode D: Execute backlog item(s)

Use when the user explicitly asks to execute a specific backlog item, or when in Mode D-Chain (continuous execution).

When the user selects a single backlog item, execute only that item. When in Mode D-Chain, execute the entire queue sequentially without waiting for user confirmation between items.

### Mode D-lite: small behavior fix lane

Use Mode D-lite only when ALL conditions hold:

- The request entered through `/project-control-plane` but is a small behavior fix.
- Expected change is within one module and no more than 3 files.
- No database schema change, public API breaking change, security/auth change, cross-module refactor, or runtime external state change.
- The success criterion is concrete and falsifiable from the user report.

Mode D-lite requirements:

1. Read `docs/项目控制台.md` and the directly related source/test files.
2. **先过编码前必答清单**（见上方）。
3. Create or update a compact `plans/<date>-<task>.md` with problem, chosen fix, risks, and verification.
4. 必须创建 backlog item。唯一例外：改动纯属 typo/空格/颜色值调整，且不改变任何 API/行为/数据/文档描述。不得以"改动很小"为由跳过。
5. Implement the minimum fix only.
6. Run targeted verification and record any pre-existing failures separately from new failures.
7. Update `CHANGELOG.md`（每次改动都记，一行即可）。

Steps (single item / each item in chain):

1. Read `docs/项目控制台.md`. If in chain, read it once at the start; re-read only if state changed.
2. Read target backlog item.
3. Read related module document.
4. Read relevant code and tests.
5. **Clarity checklist**: Before coding, verify the backlog item is clear enough to implement. Check all four dimensions:
   - **Goal Clarity**: Can you state the deliverable in one sentence without qualifiers? Are the key entities and their relationships clear?
   - **Constraint Clarity**: Are boundaries, non-goals, and dependencies explicit? Is it clear what NOT to change?
   - **Criteria Clarity**: Is every acceptance criterion testable? Can you point to a specific file/test/behavior that would prove it?
   - **Context Clarity**: Do you understand the relevant existing code well enough to modify it safely? Have you read the callers, callees, and shared types of the target area?
6. If any dimension is unclear AND not in chain mode: produce a "待确认问题清单" and ask the user before coding. If in chain mode with unclear dimensions, record the ambiguity as a risk and proceed.
7. **Risk classification**: Classify the item:
   - **High-risk**: P0 priority, cross-module, security/auth, data migration, >20 files expected, public API breakage. If in chain mode and user has not explicitly said "自己处理高风险项": stop the chain and report. If user has authorized autonomous high-risk handling, proceed.
   - **Standard**: Everything else. → Proceed to step 8.
8. Create/update a plan file in `plans/`.
9. Set backlog item status to `进行中`.
10. Implement only the minimum required changes.
11. **Verification (four-layer loop)**:
    a. **Self-check per criterion**: For EACH acceptance criterion in the backlog item, collect fresh evidence. Run the relevant test, read the output, verify the behavior. If any criterion fails, continue implementation before marking complete. Do not skip criteria.
    b. **Reviewer verification** (independent, against acceptance criteria):
       - Standard changes (<5 files, <100 lines): standard-tier reviewer (sonnet-level).
       - Standard changes (5-20 files): standard-tier reviewer (sonnet-level).
       - >20 files or security/architectural changes: thorough-tier reviewer (opus-level).
       - The reviewer verifies against the SPECIFIC acceptance criteria from the backlog item, not a vague "is it done?".
       - On approval: proceed to step 11c in the same turn (do not pause to report).
       - On rejection: fix the issues raised, re-verify, loop until approved.
       - **Chain mode**: reviewer step is batched — every 3 completed items, submit the accumulated changes to a single reviewer audit (standard-tier for standard risk, thorough-tier for any high-risk in the batch). Do not skip.
    c. **Deslop pass**: Invoke `Skill("ai-slop-cleaner")` on the files changed during this execution. Keep scope bounded to the changed-file set. **Chain mode**: batched alongside reviewer — one deslop pass per 3 items.

    d. **Regression re-verification**: Re-run all relevant tests, build, and lint. Read the output. Confirm the post-deslop regression run passes. If regression fails, fix and re-run until passing.
12. Update:
    - backlog item status and status record
    - project console if backlog status, active work, or blockers changed
    - module doc if behavior changed — **inspect changed symbols (view names, URL paths, template files) and grep `docs/modules/` + `docs/当前实现总览.md` for any doc that references them; update all matches**
    - OpenAPI/database docs if contracts changed
    - Minimal design docs under docs/ if the change introduces new decisions or data flows
    - `CHANGELOG.md`
13. If code changed, run graph update if the project requires it.
14. **If in chain mode**: output the transition summary ("BL-XXX 完成，开始 BL-YYY") and immediately load the next backlog item's context (back to step 2). Do not pause for user confirmation.
    **If not in chain mode**: report completed, not completed, risks, and next step.
15. **意外发现记录**：实现过程中遇到以下情况时，在 backlog item 的状态记录中追加一条"意外发现"：
    - backlog 范围遗漏的关键场景或边界条件
    - 现有代码与 backlog 假设冲突（如数据模型、API 契约）
    - 需要额外依赖但 backlog 未声明（如新 package、新 MCP 服务、外部 API）
    - 验收条件覆盖不到的实现细节（如错误处理语义、事务边界）
    链模式下不停止，但累积的意外发现会在链完成后触发一次轻量回溯：列出所有意外发现，建议用户对受影响的 backlog item 走 Mode B0 澄清或直接更新 backlog。
16. **Repair-queue handoff**：如果当前工作是从 Mode R 审计进入实现，开始编码前先把 findings 归并成修复队列（P0: 功能正确性 / 数据正确性；P1: 测试与文档一致性；P2: 清理项），并在最终汇报中说明本轮修了哪些、暴露了哪些旧问题、哪些仍留待后续处理。

Success criteria:

- Backlog status reflects reality.
- Every acceptance criterion has fresh verification evidence.
- Reviewer verification passed against specific criteria (single item mode; chain mode may skip).
- Deslop pass completed and regression tests pass (or user waived / chain-mode skip).
- User-visible changes are in changelog.
- No task remains marked `进行中` if work stopped.
- No unrelated refactor or speculative expansion.

## Mode E: Synchronize state after work

Use when implementation happened and docs/status may be stale.

Steps:

1. Inspect changed files.
2. Identify affected backlog items.
3. Update backlog statuses.
4. Update project console only if backlog status, active work, or blockers changed.
5. Update related module docs only if behavior or scope changed.
6. Update changelog for user-visible changes.
7. Record verification result.

Success criteria:

- Backlog is the source of truth for item status.
- `docs/项目控制台.md` is accurate when status/active/blocker state changed.
- Plan file records what happened.

## Mode F: Phase acceptance

Use when the user asks whether a phase is complete.

Steps:

1. Read phase scope.
2. Read all included backlog items.
3. Check each acceptance condition.
4. Run or inspect verification evidence.
5. **Independent audit**: Spawn a `general-purpose` Agent as auditor to independently verify the evidence. The agent reads each backlog item, its acceptance criteria, and the claimed verification evidence fresh. It must:
   - For each criterion: is the evidence concrete (test output, file diff, API response) or hand-waving?
   - Does any `已完成` item lack evidence for one or more criteria?
   - Are there contract/doc inconsistencies? (OpenAPI vs routes, migrations vs models, module docs vs actual behavior)
   The auditor has no access to the implementation conversation — it judges only the evidence presented.
   Revise or supplement evidence based on auditor feedback (max 2 iterations).
6. Check documentation and contract consistency when relevant:
   - OpenAPI paths and schemas vs backend routes
   - database docs vs migrations/models
   - module docs vs implemented behavior
   - project console vs backlog state
6. Classify each item with allowed backlog statuses only:
   - `已完成` if implementation and local verification are complete
   - `进行中` if partially done or actively blocked
   - `未开始` if not started
7. Record separate acceptance status:
   - `已验收` if phase evidence passes
   - `验收未通过` if evidence fails
   - `待验收` if ready but not checked
   - `未验收` if not ready
8. Produce a phase acceptance summary.
9. Recommend whether to close the phase or continue.

Success criteria:

- No vague "looks good".
- Each phase goal has evidence or a named gap.
- Deferred work remains visible in backlog.
- Contract/document consistency checks are included or explicitly exempted.

## Mode G: Phase transition

Use when all current-phase backlog items are complete/accepted or the user asks to enter the next phase.

Steps:

1. Read `docs/项目控制台.md`.
2. Read current phase scope and backlog summaries.
3. Summarize completed baseline capabilities.
4. List unresolved blockers by category:
   - 待产品决策
   - 待技术方案
   - 待外部依赖
   - 待验证
5. Identify candidate next-stage themes from gaps, blockers, and user goals.
6. Ask the human to choose the next-stage target before generating committed backlog.
7. After confirmation, draft the next batch of numbered module backlog items.
8. Update project console only after the next-stage target or active backlog changes.

Rules:

- Do not automatically start new implementation just because the previous phase is complete.
- Do not silently expand scope from unresolved blockers.
- Prefer 1-3 coherent next-stage themes over a large mixed backlog.
- Keep prior completed backlog as historical state; create new items for new work.

Success criteria:

- The previous phase has a clear closure summary.
- The next phase starts from an explicit human-approved target.
- New backlog items are traceable to blockers, gaps, or stated goals.

## Mode H: High-risk consensus planning

Use when a backlog item is classified as high-risk (P0 + cross-module, security/auth, data migration, >20 files expected, or public API breakage) and the user wants technical consensus before implementation.

This mode runs a Planner → Architect → Critic consensus loop (maximum 5 iterations) against the specific backlog item.

Steps:

1. **Load context**: Read the target backlog item, related module doc, and relevant code areas. Do not load the entire codebase.
2. **Planner** creates an implementation plan covering:
   - Affected files and modules
   - Data flow changes
   - Migration strategy (if applicable)
   - Test strategy
   - Rollback plan (if applicable)
   - A compact RALPLAN-DR summary: Principles (3-5), Decision Drivers (top 3), Viable Options (>=2 with pros/cons)
3. **Architect** reviews for:
   - Architectural soundness (does this fit the existing system design?)
   - Coupling risk (does this create unwanted dependencies?)
   - Security and data integrity
   - Must provide the strongest counter-argument (steelman antithesis) and at least one real tradeoff tension
4. **Critic** evaluates against quality criteria:
   - Are acceptance criteria testable and covered by the plan?
   - Are alternatives fairly considered?
   - Are risks mitigated?
   - Are verification steps concrete?
   - Must enforce principle-option consistency
5. **Re-review loop** (max 5 iterations):
   - Any non-APPROVE Critic verdict → collect feedback → revise plan → Architect → Critic → repeat
   - If 5 iterations reached without APPROVE, present the best version to the user with remaining risks
6. **On consensus approval**: Proceed to Mode D (execution) with the verified plan. The plan file in `plans/` becomes the execution guide.
7. **On persistent rejection**: Report the unresolved issues to the user and ask whether to proceed anyway, revise the backlog item scope, or defer.

Architect and Critic steps MUST run sequentially (await Architect before launching Critic).

Success criteria:

- Consensus plan exists in `plans/` with ADR (Decision, Drivers, Alternatives considered, Why chosen, Consequences, Follow-ups).
- Acceptance criteria from the backlog item are addressed in the plan.
- The user has approved the plan before execution begins.

## Human/AI responsibility split

AI should:

- Draft backlog.
- Keep format consistent.
- Find gaps and contradictions.
- Detect vague requirements and suggest clarification (Mode B0).
- Flag high-risk items for consensus planning (Mode H).
- Load scoped context packages.
- Implement selected items with four-layer verification (Mode D).
- Update state documents after work.
- Surface uncertainty early.

Human should:

- Confirm priorities.
- Decide phase scope.
- Resolve business tradeoffs.
- Approve ambiguous acceptance criteria.
- Decide whether incomplete items can remain for later phases.
- Choose whether to run Mode B0 or proceed with vague requirements.
- Approve consensus plans for high-risk items before execution.

## Pitfalls

Avoid:

- Creating many documents without a control entry point.
- Treating old plans as current truth.
- Reading all docs for every task.
- Letting status scatter across plans, changelog, and module docs.
- Marking backlog items complete without verification.
- Implementing from a module doc without checking the backlog item.
- Letting AI silently choose priorities that require business judgment.
- Using one-off delivery terms when the project is continuous.
- Inventing backlog statuses beyond `未开始`、`进行中`、`已完成`.
- Generating backlog items with generic acceptance criteria ("功能完成") without flagging for clarification.
- Executing high-risk items without technical consensus when cross-module impact is uncertain.
- Skipping deslop pass after implementation (cleanup is part of done).
- Treating reviewer approval as the final step — deslop and regression must follow in the same turn.
- Calling EnterPlanMode instead of Mode H for consensus planning.
- Using oh-my-claudecode:planner agent as a shortcut for Mode H's full Planner → Architect → Critic loop.
- Writing code immediately after plan approval without first creating a backlog item and syncing docs per Mode D step 12.
- Treating `/project-control-plane` behavior changes as trivial edits just because the patch is small.
- Continuing directly from a “先聊聊” discussion into code without re-entering Mode D or Mode D-lite after user approval.
- Modifying Meilisearch settings, database migration state, service config, queues, or other runtime external state without explicit user authorization.
- Reporting full dirty-worktree diffs as if they were current-turn changes.
- Dismissing test failures as “pre-existing” without command, failing check, evidence, and next step.
- Silently continuing after actual operations diverge from the previously stated plan or promise; explain the divergence to the user and wait for instruction.
- Skipping module doc updates because "the change is small" — if a documented feature's behavior changed, the doc is now wrong regardless of patch size. Grep for affected symbols across `docs/modules/` to be sure.
- 跳过编码前必答清单直接写代码——"改动很小"不是豁免理由。清单必须在编码前逐项答完。
- CHANGELOG 漏记或缺少日期——所有改动都记，必须挂 `## YYYY-MM-DD` 日期标题下，没日期就无法追溯。
- 做设计决策时不更新 `docs/设计总览.md`——设计文档的第一落点是决策发生时，不是事后补充。

## Required final response shape

For project status or planning:

```text
- 当前判断：
- 推荐下一步：
- 需要你确认：
```

For recent-change audit (Mode R) completion:

```text
- 审计范围：
- 已确认代码问题：
- 测试滞后/夹具过期：
- 文档与代码不一致：
- 风险点但证据不足：
- 建议下一步：
```

For demand clarification (Mode B0) completion:

```text
- 澄清结果：
- 核心实体：
- 验收条件草稿：
- 待确认：
- 建议下一步：Mode B（生成正式 backlog item）
```

For consensus planning (Mode H) completion:

```text
- 共识结论：
- 方案摘要：
- 风险：
- 建议下一步：Mode D（执行）
```

For backlog execution completion:

```text
- 已完成：
- 修改文件：
- 验证（自检 + reviewer + deslop + 回归）：
- 未完成/风险：
- 建议下一步：
```
