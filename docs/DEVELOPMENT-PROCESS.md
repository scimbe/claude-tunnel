# Development Process — Design

> Draft, built via grilling. The delivery pipeline: LLM-grilled requirements → Haiku-sized Task Packets → swarm execution in isolated git/docker workspaces → full CI/CD. Human-in-the-loop only when context is genuinely missing.

## Vision

Requirements are refined by an LLM and decomposed into issues small enough that **one Haiku 4.5 agent can solve each in a single ~100k-token pass**. Swarms execute them in isolated **local git + docker** workspaces, integrated through a complete CI/CD chain. A human is consulted **only** when context is genuinely missing.

## Decision log

### D1 — Unit of work: the self-contained Task Packet

An issue is *Ready* only as a **Task Packet** containing everything needed to solve it with no external lookups:

- **Goal** — one outcome.
- **Acceptance tests** — machine-checkable definition of done.
- **Allowed surface** — the exact files/interfaces the task may touch.
- **Context bundle** — **all** context needed to solve it (relevant code, contracts, docs).

**Completeness is mandatory; the token budget governs decomposition, not context-trimming.** With a ~100k Haiku window, target ~40–50k for the packet so ~50k remains as working room.

- Complete context fits budget → **Ready**.
- Complete context exceeds budget → **decompose further**.
- Complete context cannot be assembled (real knowledge gap) → **escalate to human**.

This makes "context is missing" a precise, machine-testable condition rather than a judgement call.

### D2 — Readiness gate: mechanical + adversarial

A packet is judged *Ready* by two layers:

1. **Mechanical (deterministic):** acceptance tests + interface stubs must resolve / compile / typecheck against the **context bundle alone** — zero unresolved references. Catches missing symbols/files for free.
2. **Adversarial (semantic):** a **strong-model** grader (Opus/Sonnet) tries to *break* the packet — find any dependency, assumption, or domain fact the solver needs that isn't in the bundle. Every context element must be **sourced**. An unsourceable gap is the precise "context really missing" signal → escalate to human.

**Model tiering:** the strong model grills, decomposes, and grades; **Haiku 4.5 only executes** Ready packets. Intelligence is spent where completeness is decided; cheap tokens where work is mechanical.

### D3 — Swarm execution & coordination: worktree + docker, merge queue, DAG

Decomposition yields a **dependency DAG** of packets, not independent issues. Execution:

- **Isolation:** each claimed packet gets its own `git worktree` + branch, built and tested in a **hermetic ephemeral docker container** (the same image CI uses). No two agents share a working tree.
- **Validation:** the packet's acceptance tests run in CI in that container; green is the only way forward.
- **Integration:** passing packets enter a **merge queue** that serializes merges to `main` (rebase-test-merge), so concurrent green branches can't yield a broken integration.
- **Scheduling:** the DAG releases a packet to the swarm only once its prerequisites are merged; independent packets run in parallel.

Principle: **isolated work, serialized integration.**

### D4 — Merge gate: frozen tests + regression + static + adversarial review

To merge a Haiku packet, all four must hold:

1. **Frozen acceptance tests** — authored by the strong grader at packet creation, **immutable to the executing Haiku** (CI blocks any diff touching them). The solver cannot move its own goalposts.
2. **Full regression suite** green — not just the packet's tests; catches collateral breakage.
3. **Static gates** — lint, typecheck, security scan.
4. **Adversarial diff review** — a strong-model reviewer confirms the diff stays within the **allowed surface** and achieves the goal rather than gaming the test.

Principle: **the cheap model writes implementation but never touches the tests or the surface boundary that define correctness.**

### D5 — Context bundle assembly: closure + retrieval + grader loop

1. **Deterministic core:** from the allowed surface, compute the **static dependency closure** (imports, type refs, call graph) — pulls exactly the referenced code, not probabilistically.
2. **Doc retrieval:** add relevant `CONTEXT.md` terms / ADR / spec sections by reference.
3. **Grader-guided loop:** the D2 grader names any still-missing element → assembler fetches it → repeat until no gap (**Ready**), an unsourceable gap (**escalate**), or over-budget (**decompose**).

The adversarial grader that *judges* completeness also *drives* assembly; the deterministic closure means completeness does not depend on embedding recall.

### D6 — Failure handling: retry → re-decompose → escalate

1. **Bounded retry** — retry with failure diagnostics (failing test output, reviewer objection) added to context; optional one-tier model bump on the last attempt.
2. **Re-decompose** — if still failing, back to the strong decomposer, which splits it smaller or updates the **DAG** with a discovered dependency / corrected assumption.
3. **Escalate** — only an unsourceable gap surfaced during re-decomposition pulls in a human.

Principle: **a failure is a decomposition bug, not a dead end** — feeding it back makes packet-sizing improve over time.

### D7 — CD: trunk-based delivery, staging e2e, canary, signed artifacts

Every merge to `main`:

- Builds container images (Edge / Control Plane) **and reproducible, signed** Agent/Client binaries (a tampered Agent voids the ZK guarantee, so signing is part of the security model).
- Runs **integration + e2e** (Agent↔Edge↔Client) in ephemeral staging on the same docker substrate as D3.
- **Canary rollout + auto-rollback** for Edge/Control Plane; Agent/Client published as **signed, versioned releases** (feeds self-hosting, ADR-0017).
- Optional human approval only on final prod promotion.

### D8 — Orchestration substrate: durable engine + ruflo agents

The pipeline is a long-running, retry-heavy, human-in-the-loop workflow (a DAG of packets that fail / retry / re-decompose / block on humans). Durable orchestration state therefore lives in a **Temporal-class workflow engine** (deployable locally via docker): the DAG, retries, escalation, human-wait, and merge queue are durable workflow steps. **ruflo/claude-flow + the Agent SDK** provide agent spawning, coordination, and memory; Git worktrees + docker + CI (D3/D7) do isolation and integration. The engine holds the coordination truth; agents are stateless workers.

- Crash-safe, resumable, observable; a human-wait never loses state.
- Heavier setup than a pure ruflo/worktree prototype — accepted for autonomous reliability.
- ruflo's role narrows to agent execution + memory (AgentDB still feeds decomposition learning, D6), not durable coordination.

## End-to-end pipeline

```
Requirement
  │  strong model: grill intent + author acceptance tests
  ▼
Decompose ──► assemble context bundle (closure + retrieval + grader loop, D5)
  │                         │
  │              ┌──────────┴───────────┐
  │        Ready (complete,       over-budget ─► decompose further
  │        in-budget, testable)   unsourceable gap ─► ESCALATE TO HUMAN
  ▼
Task Packet (D1) ──► Readiness gate: mechanical + adversarial (D2)
  ▼
Swarm: Haiku agent, git worktree + ephemeral docker (D3)
  ▼
Merge gate: frozen tests + regression + static + adversarial review (D4)
  │        fail ─► retry ─► re-decompose ─► escalate (D6)
  ▼
Merge queue ─► main ─► CD: staging e2e ─► canary ─► signed release (D7)
```

**Model tiering throughout:** strong model grills / decomposes / grades / reviews; **Haiku 4.5 only executes**. Human-in-the-loop fires on exactly one condition everywhere: an **unsourceable context gap**.

## Open (not yet grilled)

- **Human-in-the-loop UX** — how escalations are surfaced and answers fed back.
- **Model-tier routing** — exact thresholds for Haiku→Sonnet→Opus escalation.
- **Pipeline observability** — cost/throughput/escape-rate metrics for the pipeline itself.

