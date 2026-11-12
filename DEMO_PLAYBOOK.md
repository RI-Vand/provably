# Reproducible security demo playbook

This guide turns existing automated tests into public, reproducible demos with exact commands and expected outcomes.

## Prerequisites

- Python 3.10+
- `flask` installed for end-to-end hardening demos

## 1) Run all public tests

```bash
python -m unittest discover -v -p "tests_*.py"
```

Expected outcome:
- Test suite passes.
- Coverage includes MCP protocol behavior, hardening loop behavior, no-network behavior, packaging behavior, and hardened app runtime behavior.

## 2) Demo: SQL injection is detected and hardened

This demo is codified in:
- `tests_mcp.py::Protocol.test_audit_and_harden_find_and_fix_sql_injection`
- `tests_package.py::EndToEnd.run_hardened`

Command:

```bash
python -m unittest -v tests_mcp.Protocol.test_audit_and_harden_find_and_fix_sql_injection
```

Expected outcome:
- `provably_audit` output contains SQL injection findings.
- `provably_harden` output contains `fixed`.
- Hardened code output no longer contains direct SQL string concatenation.

## 3) Demo: submitted code is analyzed, not executed

This demo is codified in:
- `tests_mcp.py::Bizcheck.test_it_reads_the_code_and_runs_none_of_it`

Command:

```bash
python -m unittest -v tests_mcp.Bizcheck.test_it_reads_the_code_and_runs_none_of_it
```

Expected outcome:
- The marker file is not created.
- Business-logic findings are returned from static analysis.

## 4) Demo: no-network behavior for tool execution

This demo is codified in:
- `tests_mcp.py::NothingLeavesAndNothingIsWritten.test_tool_modules_import_no_networking`
- `tests_mcp.py::NothingLeavesAndNothingIsWritten.test_the_tools_work_with_every_way_of_opening_a_socket_disabled`

Commands:

```bash
python -m unittest -v tests_mcp.NothingLeavesAndNothingIsWritten.test_tool_modules_import_no_networking
python -m unittest -v tests_mcp.NothingLeavesAndNothingIsWritten.test_the_tools_work_with_every_way_of_opening_a_socket_disabled
```

Expected outcome:
- No tool modules import networking libraries from the blocked set.
- Tool calls still succeed when socket creation/connection methods are patched to fail.

## 5) Demo: hardened app resists SQLi at runtime

This demo is codified in:
- `tests_package.py::EndToEnd.test_from_the_repository_folder`

Command:

```bash
python -m unittest -v tests_package.EndToEnd.test_from_the_repository_folder
```

Expected outcome:
- Hardened app runs.
- Benign query returns expected row.
- Attack query does not return all rows.

## Notes

- These demos demonstrate repository behavior at the tested commit and environment.
- A clean demo run does not prove complete security; see `VERIFICATION.md` and `THREAT_MODEL.md` for assumptions and limits.
