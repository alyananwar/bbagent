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

## What to measure (per run)

- vulnerabilities found / true positives / false positives
- time to first finding
- LLM cost and tool calls
- validation success and reproduction success
- coverage across classes (auth, IDOR, injection, XSS, SSRF, config)

Record each run so a change to the planner/validation can be compared against a
baseline. A regression is any drop in true positives or rise in false positives.

## Rule

Local, authorized targets only. Do not benchmark against real programs.
