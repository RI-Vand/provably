# Provably

**Vibe-coded apps ship with the same holes every time. Provably automatically fixes many common web security patterns while Claude writes code, and flags the rest for review.**

Connect it once and Claude builds with a security workflow. It writes your app, Provably scans the code, rewrites dangerous spots into safer forms where possible, re-scans, and then checks your app's own business rules: who can see whose data, money that must never go negative, coupons that must only work once. Claude keeps looping until findings are addressed.

The part that matters most: the decisions that guard your app (who may open a record, where a redirect may go, what a command may receive, which files a request may touch, how many attempts a client gets, whether a payment adds up, whether a one-time token was already used) are not just tested. They run on code generated from **formally verified Dafny specs**, and your app refuses to start if the shipped verified core is missing or altered.

It is a local [MCP](https://modelcontextprotocol.io) server for Claude. It runs locally and is designed to operate without external service calls during MCP tool execution.

- **Local.** It runs on your machine. The current implementation is tested to run without outbound networking and without leaving bytecode cache folders during normal operation. It reads the code Claude sends it and runs none of it.
- **Source-available.** Free to use, read and modify under the [Functional Source License](#license). It is not an OSI open-source license: you may not use it to offer a competing product.
- **Scope: the code.** Provably works on your app's source. It does not cover phishing, social engineering, your hosting, or your dependencies.

## Install (one command)

You need [uv](https://docs.astral.sh/uv/) (it fetches the right Python by itself; Provably needs 3.10 or newer).
Install it once with `curl -LsSf https://astral.sh/uv/install.sh | sh` (macOS/Linux) or `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"` (Windows).

**Claude Code**: paste this in a terminal:

```
claude mcp add --scope user provably -- uvx --refresh --from git+https://github.com/rishivandavasi-byte/provably@stable provably-mcp
```

Or paste this to Claude Code and let it do it:

> Install the Provably MCP server for me. Make sure `uv` is installed, then run: `claude mcp add --scope user provably -- uvx --refresh --from git+https://github.com/rishivandavasi-byte/provably@stable provably-mcp`. Then run `claude mcp list` and tell me whether provably shows as connected.

**Claude Desktop**: add this to `claude_desktop_config.json` (Settings, Developer, Edit Config) and restart:

```json
{
  "mcpServers": {
    "provably": {
      "command": "uvx",
      "args": ["--refresh", "--from", "git+https://github.com/rishivandavasi-byte/provably@stable", "provably-mcp"]
    }
  }
}
```

If Claude Desktop cannot find `uvx`, put the full path to it in `"command"` (`which uvx` on macOS/Linux, `where uvx` on Windows).

Updates are automatic: the command follows the `stable` branch and `--refresh` makes `uvx` fetch the latest release each time the server starts, so nobody has to reinstall. It needs a network connection at start; each release is also tagged (for example `v0.1.1`), so you can pin a specific version by replacing `@stable` with that tag and removing `--refresh`.

## Tools

| Tool | What it does |
|---|---|
| `provably_protocol` | Returns the secure-build protocol Claude should follow (contract first, verified primitives, loop until clean). |
| `provably_harden` | Scans code, rewrites dangerous spots to safer forms where possible, re-scans, and returns hardened code. Python is auto-remediated where safe; JS/TS web stacks (Next.js, Express, Supabase, Firebase) are handled for covered patterns with review fallbacks. |
| `provably_audit` | Scans and reports, changing nothing. |
| `provably_spec` | Extracts the business-logic contract of a Flask app: routes, who can reach them, where money, privileges, one-time tokens and workflow steps are handled without a verified primitive. |
| `provably_bizcheck` | Checks that contract and returns findings with exact fixes. |

None of them runs your code. Command line, no Claude needed: `uvx --refresh --from git+https://github.com/rishivandavasi-byte/provably@stable provably-harden app.py` writes `app.hardened.py` and puts `provably_secure.py` and `verified_core/` next to it. Ship those two with the app.

## What "verified" means here

The decisions behind the fixes (who may open a record, where a redirect may go, what a command argument may be, which fields a route accepts, how many attempts a client gets, whether a file path stays in its folder,
which routes each role may reach, which workflow steps are allowed, whether a money transfer conserves value, whether a one-time token was already used) are made by code generated from formally verified
[Dafny](https://dafny.org) specs and compiled to Python (`verified_core/`). The app refuses to start if that verified core is missing or altered. `VERIFICATION.md` states what is proved, what the proofs rely on, and what is **not** proved
(for example: business rules nobody declared). The proofs themselves are not part of this repository. No tool makes an app unhackable, and Provably does not claim to: it takes the cheap, common, automated attacks off the table and puts proved guards on the ones that hurt most.

## Where the edges are

Provably goes deep on your app's code, and it is straight about what is outside it: your hosting, your dependencies, phishing and social engineering. It will not rewrite weak password hashing on its own (that needs a data migration), it cannot guess business rules nobody declared, and it does not guard an app while it runs. Anything it cannot fix safely comes back as a `review` item with the exact instruction. A clean scan means no findings from the current rule set, not a complete security guarantee.

## Trust artifacts

- `DEMO_PLAYBOOK.md` — reproducible security demos with exact commands and expected outcomes.
- `THREAT_MODEL.md` — attacker model, trust boundaries, assumptions, and exclusions.
- `CLAIMS_MATRIX.md` — claim-by-claim support status and careful wording.
- `BENCHMARK_PROTOCOL.md` — reproducible benchmark design for future public results.

## License

Provably is licensed under the **Functional Source License, Version 1.1, ALv2 Future License** ([FSL-1.1-ALv2](https://fsl.software)). In plain terms: you may use it (including at work and inside your own products),
read it and modify it. You may not use it to offer a competing commercial product or service, which includes a renamed or resold copy. Each version becomes available under the Apache License 2.0 two years after
it is released. The license grants no rights to the Provably name. This summary is not legal advice; the terms are in `LICENSE`. See also `NOTICE` and `THIRD_PARTY_NOTICES.md`.

Report vulnerabilities privately: see `SECURITY.md`.
