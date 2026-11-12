# Threat model (current repository scope)

This document describes what this repository is designed to defend, what it assumes, and what it does not claim.

## System context

Provably is a local MCP server and hardening engine that:
- statically scans source input,
- rewrites a subset of risky patterns into safer forms,
- applies business-logic checks,
- and ships verified decision helpers (`provably_secure.py` + `verified_core/`).

## Assets to protect

- Application source code under review.
- Security-critical decision logic in shipped verified helpers.
- Integrity of `verified_core/` artifacts used at runtime.

## Primary attacker goals

- Inject code/commands/queries through app input flows.
- Bypass authorization/ownership/business-logic controls.
- Tamper with shipped verified artifacts to weaken runtime guards.
- Exfiltrate secrets accidentally committed in code/config.

## Trust boundaries

- **In scope:** static source analysis and rewrite behavior in this repository.
- **Out of scope:** infrastructure, runtime host compromise, dependency compromise, phishing/social engineering, undeclared business rules.

## Security controls in this repository

- Rule-based scanning for common vulnerability classes (`audit.py`).
- Automatic safer rewrites with explicit review fallback (`fixer.py`, `webstack.py`, `harden_core.py`).
- Runtime fail-closed loading and hash verification of `verified_core/` (`provably_secure.py`).
- Optional signed manifest verification (`PROVABLY_INTEGRITY_KEY` in `provably_secure.py`).
- Automated tests for no-network behavior and non-execution of submitted code (`tests_mcp.py`).

## Assumptions

- Correctness of Dafny/Z3 toolchain and generated runtime artifacts.
- Correctness of adapter glue and runtime dependencies listed in `VERIFICATION.md`.
- Consumers ship `provably_secure.py` and `verified_core/` together and do not bypass checks.
- Policies and business rules are explicitly declared by developers/agents.

## Exclusions and limitations

- Does not guarantee absence of all vulnerabilities.
- Does not cover unknown business requirements that were never specified.
- Does not provide full runtime protection against all post-deploy threats.
- Does not replace independent security review for production-critical systems.

## Abuse cases to track in future iterations

- Evasion of pattern-based detections (false negatives).
- Over-broad pattern matches causing false positives and unsafe rewrites.
- Misconfiguration of policy declarations causing accidental overexposure.
- Integrity bypass attempts via packaging/deployment mistakes.

## Validation status

The repository contains automated tests that validate representative security properties and packaging behavior, but does not yet include public benchmark datasets or independent external audit reports.
