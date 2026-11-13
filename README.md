# Provably

Provably is a local security engine for Claude that hardens common web vulnerability patterns while code is being written and flags what still needs human review. **It makes your app way harder to hack.**

Vibe-coded apps ship with the same holes every time; Provably closes many of those gaps automatically, then checks business-logic risk areas such as authorization boundaries, money movement, single-use flows, and state transitions.

It runs as a local [MCP](https://modelcontextprotocol.io) server. Your code stays on your machine, and none of Provably's tools execute your app.

## Why teams use Provably

- **Local by design.** No database, no log, no history, no bytecode cache, and no network requests from the server process.
- **Formally verified guard decisions.** Critical guard logic is implemented in code proved with [Dafny](https://dafny.org) and compiled to Python (`verified_core/`); app startup fails if that guard layer is tampered with.
- **Practical workflow.** Claude writes code, Provably hardens common patterns, re-scans, and returns exact review items where safe auto-fixing is not possible.
- **Clear scope.** Provably secures application code paths it can analyze; it does not claim to cover all security risk.

## Give Provably to Claude (fastest path)

Copy this repository link and give it to Claude:

https://github.com/RI-Vand/provably

Then ask Claude:

> Install Provably from this repository and configure it for me. Make sure it stays updated automatically as new improvements are released. After installing, verify that Provably is connected and working.

## Install (one command)

You need [uv](https://docs.astral.sh/uv/) (it fetches Python automatically; Provably requires Python 3.10+).

Install `uv` once:
- macOS/Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Windows (PowerShell): `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`

**Claude Code** (terminal):

```bash
claude mcp add --scope user provably -- uvx --refresh --from git+https://github.com/RI-Vand/provably@stable provably-mcp
```

Or ask Claude Code to do it:

> Install the Provably MCP server for me. Make sure `uv` is installed, then run: `claude mcp add --scope user provably -- uvx --refresh --from git+https://github.com/RI-Vand/provably@stable provably-mcp`. Then run `claude mcp list` and tell me whether provably shows as connected.

**Claude Desktop** (`claude_desktop_config.json`, then restart):

```json
{
  "mcpServers": {
    "provably": {
      "command": "uvx",
      "args": ["--refresh", "--from", "git+https://github.com/RI-Vand/provably@stable", "provably-mcp"]
    }
  }
}
```

If Claude Desktop cannot find `uvx`, set `"command"` to the full path (`which uvx` on macOS/Linux, `where uvx` on Windows).

`@stable` with `--refresh` tracks the latest stable release at server start. For a fixed version, replace `@stable` with a tag (for example `v0.1.2`) and remove `--refresh`.

## Verify installation

Run:

```bash
claude mcp list
```

You should see `provably` as connected.

## Feature overview

| Tool | Purpose |
|---|---|
| `provably_protocol` | Returns the secure-build protocol Claude should follow (contract first, verified primitives, loop until clean). |
| `provably_harden` | Scans code, rewrites covered dangerous patterns to safer forms, re-scans, and returns hardened output. Python is auto-fixed; JS/TS web stacks are covered for specific patterns (Next.js, Express, Supabase, Firebase). |
| `provably_audit` | Scans and reports findings without modifying files. |
| `provably_spec` | Extracts a Flask business-logic contract (routes, access boundaries, risk points around money, privilege, single-use flows, workflow steps). |
| `provably_bizcheck` | Evaluates that contract and returns findings with concrete fix guidance. |

CLI (no Claude required):

```bash
uvx --refresh --from git+https://github.com/RI-Vand/provably@stable provably-harden app.py
```

This writes `app.hardened.py` and places `provably_secure.py` plus `verified_core/` beside it. Ship those with your app.

## Trust and evidence

- [VERIFICATION.md](VERIFICATION.md): what is proved, what assumptions the proofs rely on, and what is explicitly not proved.
- [THREAT_MODEL.md](THREAT_MODEL.md): threat boundaries and intended security posture.
- [BENCHMARK_PROTOCOL.md](BENCHMARK_PROTOCOL.md): reproducible evaluation protocol.
- [CHANGELOG.md](CHANGELOG.md): release-by-release changes.

## Limitations (important)

Provably focuses on application code patterns and business-logic checks in scope. It does **not** cover:

- phishing or social engineering,
- hosting and runtime infrastructure risk,
- dependency supply-chain risk,
- undeclared business rules it cannot infer,
- live runtime defense after deployment.

It also does not silently force unsafe rewrites. Anything it cannot safely fix returns as a `review` item with exact guidance.

No tool makes an app unhackable, and Provably does not claim to. It is designed to remove many common automated attack paths and raise the cost of successful exploitation.

## License

Provably is licensed under the **Functional Source License, Version 1.1, ALv2 Future License** ([FSL-1.1-ALv2](https://fsl.software)).

In plain terms: you may use it (including at work and inside your own products), read it, and modify it. You may not use it to offer a competing commercial product or service (including a renamed or resold copy). Each version becomes available under Apache License 2.0 two years after release. The license grants no rights to the Provably name.

This summary is not legal advice; see [LICENSE](LICENSE), [NOTICE](NOTICE), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Security

Report vulnerabilities privately via [SECURITY.md](SECURITY.md).

## Metadata suggestions

- **Repository description:** Local MCP security engine for Claude that hardens common web vulnerability patterns and applies formally verified guard logic.
- **Suggested topics:** `mcp`, `claude`, `application-security`, `formal-verification`, `secure-coding`
- **Package/project description text:** Makes vibe-coded apps way harder to hack: local MCP hardening, business-logic checks, and formally verified guard decisions.
