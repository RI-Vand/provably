# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open this repository's **Security** tab and choose **Report a vulnerability**.
Include the steps to reproduce and the version (see `CHANGELOG.md`). Please do not open a public issue for an unfixed vulnerability.

Useful reports include:

- a way to make `provably_harden` produce code that is *less* safe than its input;
- a way to make `provably-mcp` execute code, read files it was not given, write files, or make a network request;
- an input that crashes or hangs the server;
- a way to alter `verified_core/` without the hardened app refusing to start.

## What "verified" covers

See `VERIFICATION.md`.
