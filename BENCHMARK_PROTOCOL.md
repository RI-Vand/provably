# Benchmark protocol (v0)

This document defines a minimal, reproducible benchmark framework for future public reporting.

## Goals

- Measure detection quality and hardening utility on representative vulnerable and clean code.
- Make runs reproducible across environments.
- Publish artifacts that others can rerun independently.

## Scope

- Python source hardening/audit pipeline.
- JS/TS web-stack pattern audit/fix pipeline.
- Business-logic contract extraction/check flows.

## Required benchmark assets

1. **Datasets**
   - Vulnerable corpus with labeled vulnerability classes.
   - Clean corpus with negative examples.
   - Business-logic scenarios for authorization/workflow/money/single-use decisions.

2. **Baselines**
   - Current `main` results.
   - Previous tagged release results.
   - Optional comparison against a documented external static-analysis baseline.

3. **Metrics**
   - Detection: precision, recall, F1, false-positive rate, false-negative rate.
   - Hardening: % findings auto-remediated, % requiring review, post-fix residual high/critical findings.
   - Performance: wall-clock time, files/sec, peak memory (same hardware profile).

4. **Reproducibility metadata**
   - Commit SHA, Python version, OS, CPU/RAM profile.
   - Exact command lines.
   - Dataset version IDs and checksums.

## Reproducible run format

- Run script outputs:
  - machine-readable JSON summary,
  - per-file findings,
  - aggregate metrics table,
  - environment manifest.
- Store outputs in a versioned benchmark artifact folder (or release attachment).

## Minimum acceptance bar for publishing results

- All benchmark commands and datasets available to the public.
- At least one independent rerun by a second environment.
- Metrics include both positive and negative sets (not vulnerable-only).
- Limitations section includes known blind spots and confidence caveats.

## Initial command skeleton

The existing test command remains a functional sanity baseline:

```bash
python -m unittest discover -v -p "tests_*.py"
```

This is not sufficient as a benchmark by itself; it is a prerequisite health check.
