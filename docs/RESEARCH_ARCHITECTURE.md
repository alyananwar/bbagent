# Research architecture

Why this exists: the pipeline used to end when the scanners did. `nuclei` matching
zero templates was read as "engagement complete", the attack surface lived in a
scratch JSON file written once at the end of a run, and the planner had a bug that
meant hosts were never probed at all. This document maps every requirement of the
refactor to the code that implements it and the test that holds it in place.

## The loop

```
SCOPE_VERIFIED
     |
     v
  RECON ------------------------------> APPLICATION_MODELING
  (scanners; zero hits is NOT an exit)        |
                                             v
        VALIDATION <--- INVESTIGATION <--- HYPOTHESIS_GENERATED
             |               |  ^                  ^
             |               |  |                  |
             +---------------+--+------------------+   (learn, re-model, continue)

Terminal states, and only these three:
  BUDGET_EXHAUSTED | HYPOTHESES_EXHAUSTED | HALTED_UNAUTHORIZED
Parked, not terminal:
  BLOCKED_ON_RESEARCHER  ->  resumes on `bbagent resolve`
```

## Requirement map

| # | Requirement | Implementation | Test |
|---|---|---|---|
| 1 | Research state machine, `NUCLEI_ZERO` goes deeper | `research/state.py`, `research/loop.py:_do_recon` | `test_research.py::test_recon_leads_to_modeling_not_to_an_exit`, `test_loop.py::test_loop_reaches_a_validated_authorization_finding_with_zero_scanner_hits` |
| 2 | Only real stop conditions are terminal | `research/state.py:TERMINAL` | `test_research.py::test_only_three_terminal_states` |
| 3 | Users / roles / resources model | `research/appmodel.py` (`Role`, `Account`, `Resource`) | `test_research.py::test_account_without_token_is_not_usable` |
| 4 | Endpoint operates on object, requires role, changes state | `research/appmodel.py:EndpointModel`, `infer_endpoint`, `classify_path` | `test_research.py::test_endpoint_is_modeled_as_object_role_and_state` |
| 5 | Reasoning over an authorization matrix | `AppModel.matrix`, `observe`, `unknown_authorization` | `test_research.py::test_authorization_matrix_and_gaps` |
| 6 | Persistent hypothesis queue with full record | `research/hypothesis.py`, `db.py` `hypotheses` table | `test_research.py::test_hypothesis_queue_persists_and_prioritizes` |
| 7 | All required statuses incl. `REQUIRES_HUMAN_ACTION` | `HypothesisStatus` | `test_loop.py::test_missing_second_account_becomes_a_blocker_not_an_exit` |
| 8 | A failed hypothesis updates the model | `loop.py:_do_investigation` -> `AppModel.learn` | `test_research.py::test_model_keeps_what_investigations_taught_it`, `test_rejected_hypothesis_keeps_what_it_taught` |
| 9 | Reasoning step before any tool call | `research/gain.py:reason`, logged in `loop.py:_do_investigation` | `test_loop.py::test_research_log_shows_reasoning_before_each_action` |
| 10 | Lowest-impact evidence path | `gain.py:_EVIDENCE_LADDER` | `test_research.py::test_reasoning_step_names_what_is_missing` |
| 11 | Targeted investigation instead of random scanning | `research/investigate.py`, `research/probe.py` (one gated request per question) | `test_loop.py` (whole file) |
| 12 | Account abstraction with auth state / token refs | `appmodel.py:Account`, `probe.py:account_headers` | `test_research.py::test_secrets_are_referenced_not_stored` |
| 13 | Missing data raises `RESEARCHER_ACTION`, never fabricates | `research/blockers.py`, `investigate.py` | `test_loop.py::test_missing_second_account_becomes_a_blocker_not_an_exit` |
| 14 | Resume automatically once the human provides it | `cli.py:cmd_resolve`, `BlockerQueue.resolve` | `test_loop.py::test_resolving_a_blocker_resumes_the_hypothesis` |
| 15 | Browser + API correlation | **not built** — no browser driver in this repo. Hook points: `AppModel.add_endpoint` and the existing `browser_workflow` coverage dimension | n/a (reported as a coverage gap, not as covered) |
| 16 | Differential analysis on objects and permissions | `research/differential.py` (`compare`, `compare_permission_sets`) | `test_research.py::test_same_object_reached_by_two_identities_is_flagged`, `test_enforced_boundary_is_not_flagged` |
| 17 | Separate validation stage (reproducible? relevant? benign?) | `loop.py:_do_validation`, `_benign_explanation` | `test_loop.py::test_public_endpoint_is_not_reported` |
| 18 | Coverage bars per dimension | `research/coverage.py` | `test_research.py::test_coverage_reports_untouched_dimensions_honestly` |
| 19 | Budget (time / calls) is the stop condition | `coverage.py:Budget`, checked each loop iteration | `test_research.py::test_budget_exhausts_on_calls`, `test_loop.py::test_budget_exhaustion_is_a_clean_stop` |
| 20 | No fabricated findings | `validation.py` unchanged + `report.py` refuses invented fields; impact always left to a human | `test_loop.py::test_research_report_shows_rejections_and_evidence` |
| 21 | Failure recovery: diagnose, retry, or find an alternative | `toolrun.py:wrong_binary`, partial-output capture, `orchestrator.py:_recover` | `test_persistence.py::test_wrong_binary_on_path_is_diagnosed_not_run`, `test_timeout_keeps_partial_output` |
| 22 | Chronological research log | `research/log.py`, written at every decision | `test_research.py::test_research_log_is_chronological_and_records_authorization` |
| 23 | `automation_allowed` / `manual_only` policy; prohibited automation becomes a human task | `policy.py:technique_policy`, `investigate.py` converts `MANUAL_ONLY` into a blocker | `test_policy.py::test_technique_policy_converts_automation_into_a_manual_task`, `test_technique_policy_blocks_prohibited_techniques` |

## Persistence failures that were fixed

| Symptom | Root cause | Fix | Test |
|---|---|---|---|
| Katana endpoints lost | `toolrun.run` stored `proc.stdout[-8000:]` and the parser read that truncated string | full stdout kept in `ToolRun.stdout` (excluded from the DB row) and written whole to the content-addressed evidence store | `test_persistence.py::test_katana_output_is_not_truncated` |
| Whole surface lost on a mid-run failure | the graph was written to `graph_N.json` once, after the entire recon | the DB owns the graph and it is saved after **every** step; a legacy `graph_N.json` is imported on first run | `test_persistence.py::test_graph_persists_after_every_step` |
| Nothing ever probed, so no endpoints existed to crawl | the planner treated "has children" as "probed", and `dnsx` attaches IP children to every resolved host | explicit `probed_<tool>` / `crawled` / `scanned` markers set by the runner | `test_persistence.py::test_httpx_is_planned_even_after_dnsx_adds_ip_children` |
| A step "succeeded" and produced nothing | pip's `httpx` CLI shadowed projectdiscovery's `httpx` on PATH; both exit 0 | per-tool identity hint checked against the binary's version output before it runs, plus a direct-probe fallback | `test_persistence.py::test_wrong_binary_on_path_is_diagnosed_not_run` |
| A partial crawl was thrown away on timeout | `TimeoutExpired` discarded stdout | partial output is kept and parsed | `test_persistence.py::test_timeout_keeps_partial_output` |
| A stalled katana crawl lost everything it had found | the crawl was unbounded, so it only ended when we killed it — and katana buffers output until exit, so the kill discarded the whole crawl (`kept 0 bytes`) | `-ct` bounds the crawl so the tool exits on its own | `test_recon.py::test_katana_crawl_is_time_bounded` |
| A port-scoped program authorized every port on the host | `_url_matches` compared only hostnames | the rule's port must match when it names one | `test_scope.py` + `test_loop.py::test_out_of_scope_target_is_never_probed` |
| A probe could follow a redirect out of scope, carrying auth headers | urllib follows 3xx by default | redirects are recorded, never followed | `test_research.py::test_probe_does_not_follow_redirects_out_of_scope` |

## Fixed in review

| Severity | Symptom | Root cause | Fix | Test |
|---|---|---|---|---|
| CRITICAL | a pasted token was written to the `app_models` table in plaintext | `cmd_account` only validated the `Header=env:VAR` shape at *read* time, in `probe.account_headers` | `Account.__post_init__` refuses anything but `Header=env:VAR`, so every caller is guarded, not just the CLI; the CLI prints the correct command instead | `test_research.py::test_raw_secret_is_refused_before_it_can_be_stored`, `test_app_model_never_persists_a_raw_secret` |
| HIGH | after the first blocker the engagement was bricked: `resolve` + `research` ran 0 iterations forever | `BLOCKED_ON_RESEARCHER` collapsed unconditionally into the terminal `HYPOTHESES_EXHAUSTED`, which was then persisted; `cmd_resolve` never cleared it | the collapse happens only when nothing is testable; `_load_state` re-enters a terminal state only if it is still true; `cmd_resolve` also resets the state | `test_loop.py::test_resolving_a_blocker_resumes_without_manual_state_surgery` |
| MEDIUM | `ftp://`/`file://` targets could be judged in scope and handed to urllib's FTP/file handlers | `_classify_target` treated any `://` as a URL and never checked the scheme; `build_opener` always includes `FTPHandler`/`FileHandler`/`DataHandler` | non-web schemes classify as `other` and no host/domain/IP/URL rule matches them; the prober refuses any scheme but http(s) before gating | `test_research.py::test_non_web_schemes_are_never_in_scope_or_probed`, `test_repo_rules_still_match_after_the_scheme_guard` |

## Scanner output is not a finding

A template match is either context or a lead, never a report. `gain.from_scanner`
attaches info/low matches to the endpoint as model notes, and promotes medium and
above into a hypothesis that still has to be reproduced in the validation stage
like anything else. On the benchmark app that means 11 informational matches
produce 0 findings and 0 hypotheses, and the one real bug is found by comparing two
identities instead.

## What has not changed

The scope engine, the A–E policy gate, evidence hashing, finding immutability, and
the "submission is always manual" rule are untouched. Every investigation request
re-runs the same gate a recon tool does; being authorized for recon earlier buys an
investigation nothing.
