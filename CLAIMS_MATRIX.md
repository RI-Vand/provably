# Claims and non-claims matrix

This matrix classifies major trust/security claims in repository documentation.

## Legend

- **Supported:** directly evidenced by repository implementation/tests/docs.
- **Partially supported:** some evidence exists, but wording is broader than evidence.
- **Unsupported:** no direct evidence in the repository.
- **Risky wording:** technically plausible but overly absolute/marketing-heavy.

## Matrix

| Claim area | Status | Why | Careful wording |
|---|---|---|---|
| Common vulnerabilities are fixed during coding loops | Partially supported | Hardening/audit loop exists, but not all classes can be auto-fixed | “Provably auto-remediates many common patterns and flags remaining issues for review.” |
| Security decisions are formally verified | Partially supported | Runtime uses generated `verified_core` with integrity checks; proof sources are not in this repo | “Security-critical decision helpers are generated from formally verified specs and runtime-checked for integrity.” |
| Local/no external service during tool execution | Partially supported | Tests enforce no-network behavior for tool modules and socket-disabled execution | “Current implementation is tested to run locally without outbound network calls during tool execution.” |
| No persistent local side effects | Partially supported | Tests cover no bytecode cache and read-only install behavior; blanket persistence claim is broader | “Current tests verify no bytecode cache writes and no file creation in representative read-only scenarios.” |
| Python auto-fix + JS/TS coverage | Supported (qualified) | Python fixer loop and web-stack pattern rewrites are implemented; review fallback remains | “Python is auto-remediated where safe; JS/TS covered patterns are rewritten with review fallbacks.” |
| Clean scan implies secure app | Risky wording | Scanner/contract checks are heuristic and scoped | “A clean scan means no findings under current checks, not a complete security guarantee.” |
| Fast/best-in-class performance | Unsupported | No benchmark artifacts or public performance measurements in repo | “Performance claims require public benchmark results.” |
| Independent external validation | Unsupported | No third-party audits/testimonials/case studies in repo | “External trust signals are not yet published in this repository.” |

## Non-claims to keep explicit

- Not unhackable.
- Not a substitute for threat modeling and secure deployment.
- Not a guarantee against vulnerabilities in dependencies/infrastructure.
- Not a guarantee for undeclared business rules.
