# bbagent

An authorized bug bounty research tool. This repo is the safe core: the parts
that decide what's allowed, keep evidence honest, and produce a clean report.
It does not attack anything on its own. Live recon and testing run as gated
wrappers around tools you already have (subfinder, httpx, nuclei, and so on),
and only after a target passes the scope engine.

The whole design assumes one thing: a target is authorized only when the
program's own scope says so. Being listed on a platform means nothing by itself.

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

## What's deliberately not here yet

See `ROADMAP.md`. Short version: live recon agents, LLM multi-agent
orchestration, Strix / Agentic-Bug-Hunter adapters, platform scrapers, and the
sandbox container are later phases. The interfaces are shaped so they drop in
without touching the scope engine.
