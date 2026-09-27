# Roadmap

## Phase 0 / 1 — safe core (DONE)

The deterministic spine. No live target interaction, no bundled exploits.

- [x] Data models and enums
- [x] Scope engine (domains, wildcards, URLs, IPs, CIDRs, ports)
- [x] Policy / action-class gate (A–E)
- [x] Engagement intake
- [x] Program-brief parser with provenance and safe-default permissions
- [x] Content-addressed evidence store
- [x] SQLite persistence + finding dedup + immutability
- [x] Scope-gated external tool runner (records full provenance)
- [x] Report generator that refuses invented fields
- [x] CLI with a hard scope-confirmation step
- [x] Test suite (scope, policy, intel, intake, store, toolrun)

## Phase 2 — external tool adapters (DONE)

- [x] `toolrun` adapters for subfinder, dnsx, httpx, katana, nuclei (`recon/adapters.py`)
- [x] Output parsers for each tool (`recon/parsers.py`, tested with fixtures)
- [x] Attack-surface graph populated from recon results, nodes carry provenance (`graph.py`)
- [x] Deterministic recon planner + gated runner (`recon/planner.py`, `recon/runner.py`)
- [ ] Optional Strix / Agentic-Bug-Hunter adapter as an execution backend
      (interface is ready: any tool goes through `toolrun.run` + the gate)

## Phase 3 — validation pipeline (DONE)

- [x] Independent reproduction step before a finding leaves `draft` (`validation.py`)
- [x] Confidence scoring, labeled as a model estimate
- [x] Duplicate + previously-rejected checks against the finding DB

## Phase 4 — LLM layer, cost-routed (DONE)

- [x] Provider-agnostic abstraction (`llm/base.py`, swap without touching core)
- [x] Cheap/medium/strong tiers -> haiku/sonnet/opus (`llm/base.py` TIERS)
- [x] Anthropic provider (SDK, key from env, no hardcoded secrets) + fake for tests
- [x] Context discipline: tools write structured records, model gets summaries
- [x] Prompt-injection defenses: target/program content treated as untrusted data;
      the scope engine remains the only authority (`agents/interpret.py`, `agents/plan.py`)

## Phase 5 — platform workflow, read-only (DONE)

- [x] Import a program from a URL -> engagement (`platforms/`, `intake.import_program`)
- [x] Network fetch is opt-in with a ToS warning; manual paste is the reliable path
- [x] Normalize scope, prep an engagement (unconfirmed until human confirms)
- [x] Submission stays manual. No automated report submission.
- [ ] Program ranking (factual attributes vs model estimates) — not built yet

## Phase 6 — optimization (DONE except program ranking)

- [x] Scoped research memory: global / program / target / engagement (`memory.py`)
- [x] Advisory hypothesis loop (`agents/plan.py`); planner stays deterministic
- [x] Benchmark procedure against local targets (`benchmarks/README.md`)
- [x] Sandbox command builder: locked-down ephemeral container (`sandbox.py`)
- [ ] Automated regression scoring across benchmark runs — manual for now

## Phase 7 — research loop (DONE)

The pipeline used to stop when the scanners did. It does not any more.

- [x] Research state machine with explicit transitions; `NUCLEI_ZERO` transitions
      into application modeling (`research/state.py`)
- [x] Structured application model: users/roles/resources, endpoints as
      object + required role + state change, authorization matrix
      (`research/appmodel.py`)
- [x] Persistent, prioritized hypothesis queue; rejections update the model
      (`research/hypothesis.py`)
- [x] Information-gain reasoning step written before every action
      (`research/gain.py`)
- [x] Account abstraction (auth state + secret reference) and `RESEARCHER_ACTION`
      blockers that park work instead of ending it (`research/blockers.py`)
- [x] Gated single-request prober for targeted investigation (`research/probe.py`)
- [x] Differential analysis on authorization outcome + object identity, not text
      (`research/differential.py`)
- [x] Separate validation stage: reproducible? security-relevant? expected-behavior
      explanation? (`research/loop.py`)
- [x] Coverage bars per dimension + a research budget as the real stop condition
      (`research/coverage.py`)
- [x] Chronological research log of every decision (`research/log.py`)
- [x] Explicit `automation_allowed` / `manual_only` / `prohibited` technique policy;
      prohibited automation becomes a human task (`policy.py`)
- [x] Persistence fixes: full tool output to the evidence store (no 8KB
      truncation), graph in the DB after every step, legacy `graph_*.json`
      imported on first run
- [x] Tool-identity check (catches pip's `httpx` shadowing projectdiscovery's)
      and failure recovery with an alternative path
- [x] Benchmark target that is clean to scanners and broken for two identities
      (`benchmarks/mock_app.py`, `benchmarks/run_benchmark.py`)
- [x] Engagement research report: coverage, hypotheses tested and rejected with what
      each taught the model, validated evidence (`research/report.py`)
- [ ] Browser automation + UI-to-API correlation — not built. There is no browser
      driver in this repo, so there is nothing to correlate yet. When one lands, the
      hook is `AppModel.add_endpoint` plus a `browser_workflow` coverage dimension
      that already exists in `research/coverage.py`.
- [ ] LLM-driven hypothesis generation is advisory only; the deterministic
      generator carries the loop

## Non-negotiables (hold across all phases)

- Scope decisions are deterministic and separate from any LLM.
- Unknown targets are never auto-authorized.
- No autonomous submission or other consequential external action.
- Evidence stays local and tamper-evident.
- Reports never invent impact, severity, or results.
- A clean run with a deep investigation report is a success. Manufactured
  findings are a failure.
- Missing data is a blocker, never an assumption.
- A failed tool is diagnosed and recovered from, never silently read as
  "nothing found".
