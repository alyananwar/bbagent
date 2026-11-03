# bbagent

**A bug bounty research loop. It forms hypotheses, tests them with two researcher accounts, and only reports what it can reproduce.**

<p align="center">
  <img src="docs/demo.gif" alt="bbagent benchmark run against a local mock app: 8 hypotheses, 7 rejected, 1 validated authorization bug" width="800">
</p>

An authorized bug bounty research tool. This repo is the safe core: the parts
that decide what's allowed, keep evidence honest, and produce a clean report.
It does not attack anything on its own. Live recon and testing run as gated
wrappers around tools you already have (subfinder, httpx, nuclei, and so on),
and only after a target passes the scope engine.

The whole design assumes one thing: a target is authorized only when the
program's own scope says so. Being listed on a platform means nothing by itself.

## How it works

Recon is the first phase, not the engagement. The loop is a state machine:

```
SCOPE_VERIFIED -> RECON -> APPLICATION_MODELING -> HYPOTHESIS_GENERATED
                              ^                          |
                              |                          v
                     (learn from result) <- VALIDATION <- INVESTIGATION
```

A scan that matches zero templates transitions into application modeling. It is
not an exit. The only three ways an engagement ends are: the research budget is
spent, no hypothesis is worth testing against the current model, or authorization
says stop. Anything the agent needs from a human (a second test account, a
session token, permission for a manual-only technique) becomes a blocker: that
hypothesis parks, the rest of the research continues, and `bbagent resolve` puts
it back in the queue.

```bash
python3 -m bbagent.cli research          # the full loop
python3 -m bbagent.cli hypotheses        # what was tested, what it taught us
python3 -m bbagent.cli blockers          # what the agent needs from you
python3 -m bbagent.cli model             # roles, objects, authorization matrix
python3 -m bbagent.cli coverage          # coverage bars + budget
python3 -m bbagent.cli researchlog       # every decision, in order
python3 -m bbagent.cli researchreport    # the deliverable: coverage + rejections + evidence

# single-page app? hand it a capture of your own logged-in session
python3 -m bbagent.cli browser capture.har --workflow "create feature flag"
```

The report is the point. It shows what was modeled, which hypotheses were tested,
which were rejected and what each rejection taught the model, what is validated
with recorded evidence, and what is still waiting on a human. A run with no
findings and a full rejection list is a real result.

## What's built

- **Scope engine** (`scope.py`) — deterministic, no LLM. Handles domains,
  wildcards, URLs with paths, IPs, and CIDRs. Out-of-scope always beats
  in-scope. Anything unmatched is `unknown`, and unknown is never auto-allowed.
- **Policy gate** (`policy.py`) — maps an action class (A–E) plus the scope
  result to `allow` / `deny` / `require_approval`. Report submission and other
  external actions always need a human.
- **Program intelligence** (`program_intel.py`) — parses a plain-text scope
  brief into rules. Permissions default to "not allowed" and only flip on with
  explicit wording, so a half-parsed brief can't hand out authorization.
- **Intake** (`intake.py`) — turns a brief or a target list into an engagement.
- **Evidence store** (`evidence.py`) — content-addressed by SHA-256, so
  artifacts are tamper-evident and de-duplicated. Nothing uploads anywhere.
- **Findings + dedup** (`db.py`, `dedup.py`) — SQLite storage, root-cause
  fingerprints that group the same bug across URLs, finalized findings are
  immutable.
- **Tool runner** (`toolrun.py`) — runs an external tool only after the gate
  says allow (or you approve), and records tool, version, args, target, scope
  decision, and exit code. No payloads ship with it.
- **Report** (`report.py`) — submission-ready markdown that refuses to invent
  missing fields.
- **CLI** (`cli.py`).

### The research layer (`bbagent/research/`)

- **State machine** (`state.py`) — explicit states and legal transitions. Zero
  scanner findings transitions to deeper research; only budget exhaustion,
  hypothesis exhaustion, or an authorization stop are terminal.
- **Application model** (`appmodel.py`) — an endpoint operates on an object,
  requires a role, and may change state. Plus researcher-controlled accounts
  (auth state + a *reference* to a secret, never the secret) and an
  authorization matrix of `(role, endpoint) -> allowed | denied | unknown`.
- **Hypothesis engine** (`hypothesis.py`) — persistent, prioritized queue. Each
  hypothesis carries reasoning, the expected observation, the action class its
  test needs, and, once closed, what it taught the model. Rejections are kept.
- **Information gain** (`gain.py`) — the written reasoning step (what we know,
  what is missing, which hypothesis this tests, the lowest-impact evidence path)
  and deterministic hypothesis generation from the model.
- **Investigation** (`investigate.py`, `probe.py`) — one narrow, gated request
  per question, made as a chosen identity, with the response stored as evidence.
- **Differential analysis** (`differential.py`) — compares two identities
  structurally (authorization outcome + object ids), not as text diffs.
- **Blockers** (`blockers.py`) — `RESEARCHER_ACTION` items with the reasoning and
  the exact command to resolve them.
- **Coverage and budget** (`coverage.py`) — per-dimension coverage bars for auth,
  authorization, API, business logic, and browser workflows; the budget is the
  real stop condition.
- **Research log** (`log.py`) — timestamp, agent, hypothesis, action,
  authorization, result, for every decision.
- **Browser correlation** (`browser.py`) — imports a HAR or network capture from
  the researcher's own browser session and turns UI actions into modeled
  endpoints, with request-body keys a crawler never sees. Credentials are
  classified (`cookie` / `bearer` / `api_token`) and their values discarded; every
  captured URL is re-gated against scope before it is modeled. The tool never
  drives a browser and never holds a session.

## Quick start

```bash
cd bbagent
export PYTHONPATH=$(pwd)

# 1. import a program from its link. If the page can't be fetched (auth/JS),
#    it tells you to save the brief to a file and pass --brief.
python3 -m bbagent.cli import https://bugcrowd.com/acme --brief scope.txt
#    (or the older explicit form: program --brief scope.txt --url ...)

# 2. review what it parsed
python3 -m bbagent.cli scope

# 3. confirm scope (required before any target-directed action)
python3 -m bbagent.cli confirm

# 4. check a target through the gate
python3 -m bbagent.cli check shop.acme.com --class B
python3 -m bbagent.cli check admin.acme.com --class B   # denied (out of scope)
python3 -m bbagent.cli check evil.other.com --class B   # denied (unknown)

# 5. run gated recon (builds the attack-surface graph)
python3 -m bbagent.cli recon                 # passive + low-impact
python3 -m bbagent.cli recon --active --approve nuclei   # active scan, approved

# 5b. register the test identities the research loop compares
export BB_TOKEN_A=... BB_TOKEN_B=...
python3 -m bbagent.cli account A --role user --token 'Authorization=env:BB_TOKEN_A' --owns 1042
python3 -m bbagent.cli account B --role user --token 'Authorization=env:BB_TOKEN_B' --owns 1043

# 5c. run the research loop (continues past a clean scan)
python3 -m bbagent.cli research
python3 -m bbagent.cli blockers        # anything it needs from you
python3 -m bbagent.cli resolve B-acco-1a2b3c4d --note 'account B provided'

# 6. list findings, render a report, finalize
python3 -m bbagent.cli findings
python3 -m bbagent.cli report 3
python3 -m bbagent.cli approve 3
```

Recon shells out to external tools (subfinder, dnsx, httpx, katana, nuclei).
Install the ones you want on PATH; missing tools are reported, not fatal. Every
invocation passes the scope + policy gate first and is logged with full
provenance.

An LLM layer (`bbagent/llm`, `bbagent/agents`) can interpret messy prose briefs
and suggest hypotheses. It's optional, provider-agnostic, and reads its key from
the environment. It never authorizes a target: the scope engine does.

State lives in `./.bbagent` (SQLite DB + evidence) unless you pass `--workspace`.

### Scope brief format

Plain text. Something like:

```
In scope:
- *.acme.com
- acme.com
- https://api.acme.com/v1/
Out of scope:
- admin.acme.com
Rules:
Automated scanning is allowed. Active testing is permitted. No denial of service.
```

## Action classes

| Class | Meaning                                           | Default                                    |
| ----- | ------------------------------------------------- | ------------------------------------------ |
| A     | Passive (read docs, offline reasoning)            | allow                                      |
| B     | Low-impact active (HTTP, crawl, tech id)          | allow if program permits, else approval    |
| C     | Security testing (auth, injection, fuzz, PoC)     | approval every run                         |
| D     | Potentially impactful (state change, high volume) | deny unless program permits, then approval |
| E     | External (submit report, message staff)           | always approval                            |

## Tests

```bash
export PYTHONPATH=$(pwd)
for t in tests/test_*.py; do python3 "$t"; done
# or, if you have pytest:  python3 -m pytest -q
```

## State and secrets

State lives in the SQLite DB in the workspace: engagements, findings, tool runs,
scope decisions, the attack-surface graph, the application model, hypotheses,
blockers, the research log, and the current state. The graph is written after
**every** recon step, so a crash cannot discard discovered endpoints. Full tool
output goes to the content-addressed evidence store and the row keeps the hash.

Account secrets are never stored. `--token 'Authorization=env:BB_TOKEN_B'` records
the *reference*; the value is read from the environment at request time.

## What's deliberately not here yet

See `ROADMAP.md`. Short version: Strix / Agentic-Bug-Hunter adapters as execution
backends, platform scrapers, and running tools inside the sandbox container. The interfaces are shaped so they
drop in without touching the scope engine.

## Benchmarks

`benchmarks/mock_app.py` is deliberately clean to a template scanner and broken
only in a way that requires comparing two identities. It is the regression target
for "research depth, not scanner count":

```bash
PYTHONPATH=$(pwd) python3 benchmarks/run_benchmark.py
```
