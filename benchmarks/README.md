# Benchmarks

Run bbagent against intentionally vulnerable apps you control, never a real
company, to measure signal vs noise before trusting it on a live program.

## Local targets

Stand up any of these locally (Docker):

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop      # OWASP Juice Shop
docker run -d -p 8080:8080 webgoat/webgoat            # WebGoat
docker run -d -p 80:80    vulnerables/web-dvwa        # DVWA
```

## Point bbagent at a local target

Write a scope brief that only authorizes your local instance:

```
In scope:
- http://localhost:3000/
Rules:
Automated scanning is allowed. Active testing is permitted.
```

```bash
export PYTHONPATH=$(pwd)
python3 -m bbagent.cli import http://localhost:3000 --brief benchmarks/juice.txt
python3 -m bbagent.cli confirm
python3 -m bbagent.cli recon --active --approve nuclei
python3 -m bbagent.cli findings
```

## The depth benchmark (no Docker needed)

`mock_app.py` is deliberately clean to a template scanner: no known CVE, no
default creds, no stack traces, nothing for nuclei to match. Its only bug needs
two identities to see -- `GET /api/v2/orders/<id>` checks that you are
authenticated and never checks whether the order is yours. `/admin/users/<id>`
is correctly locked down, and `/health` is public, so a run that reports either
of those is producing noise.

```bash
PYTHONPATH=$(pwd) python3 benchmarks/run_benchmark.py            # full pipeline, incl. nuclei
PYTHONPATH=$(pwd) python3 benchmarks/run_benchmark.py --no-scan  # skip the ~10 min scan
```

Measured on this app (2026-09-27, nuclei 3.11.1): nuclei returns **11 template
matches, all informational** -- one `tech-detect` and ten
`http-missing-security-headers`. Zero of them are the bug. They are folded into
the application model as endpoint notes; only medium severity and above becomes a
hypothesis, and even then it has to be reproduced before it counts. A full
template run takes 20+ minutes, which is why the scanner pass gets its own wall
clock in `run_benchmark.py` -- letting it share the research budget starves the
reasoning phase, and the run stops having generated no hypotheses at all.

Pass condition: no finding comes from a scanner match, and the loop still ends with
a validated cross-account authorization finding plus rejected hypotheses explaining
what held up. Regression tests: `tests/test_loop.py`.

Last run: 11 scanner matches -> 0 findings; 8 hypotheses -> 7 rejected with a
recorded lesson, 1 validated (`/api/v2/orders/1042`, cross-account read, two
recorded responses as evidence, impact left to a human).

## What to measure (per run)

- vulnerabilities found / true positives / false positives
- time to first finding
- LLM cost and tool calls
- validation success and reproduction success
- coverage across classes (auth, IDOR, injection, XSS, SSRF, config)
- research depth, which is the number that matters here:
  hypotheses generated / tested / rejected-with-a-lesson / validated,
  and whether the run continued past a clean scanner pass at all

Record each run so a change to the planner/validation can be compared against a
baseline. A regression is any drop in true positives or rise in false positives.

## Rule

Local, authorized targets only. Do not benchmark against real programs.
