#!/usr/bin/env python3
"""Provably: a local MCP server (stdio, JSON-RPC 2.0) that helps an AI assistant write safer web apps.

It runs on your machine, makes no network requests and keeps no database, log or history. It reads the code the assistant sends it and runs none of it. Python 3.10+, standard library only.
Install and configuration: see README.md."""
import json, os, sys
sys.dont_write_bytecode = True                    # importing our own modules must not leave __pycache__ folders in the install directory

if sys.version_info < (3, 10):
    sys.stderr.write("provably needs Python 3.10 or newer (this is %s)\n" % sys.version.split()[0]); sys.exit(1)
for _stream, _kw in ((sys.stdin, {"encoding": "utf-8", "errors": "replace"}), (sys.stdout, {"encoding": "utf-8", "newline": "\n"})):
    try:                                          # MCP is UTF-8 JSON lines. Windows consoles default to a legacy code page and would garble non-ASCII code.
        _stream.reconfigure(**_kw)
    except (AttributeError, ValueError):
        pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit, bizspec, harden_core
from protocol import PROTOCOL

VERSION = "0.1.0"
MAX_CODE = 2_000_000                              # characters accepted in one call
_RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


def _tools():
    return [
        {"name": "provably_protocol", "title": "Secure-build protocol", "annotations": {"title": "Secure-build protocol", **_RO},
         "description": "READ THIS FIRST when asked to build or change a web app or API. Returns the secure-build protocol to follow (contract first, verified primitives, loop until clean).",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "provably_harden", "title": "Harden code", "annotations": {"title": "Harden code", **_RO},
         "description": "Scan code for vulnerabilities, rewrite the dangerous spots to the safe form, re-scan, and return the hardened code. Call this on code you just wrote before showing it to the user. Python is fixed automatically; JS/TS is fixed for the covered patterns and otherwise reported. Nothing is saved or sent anywhere.",
         "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}, "filename": {"type": "string", "default": "app.py"}}, "required": ["code"]}},
        {"name": "provably_audit", "title": "Audit code", "annotations": {"title": "Audit code", **_RO},
         "description": "Scan code and report vulnerabilities without changing it.",
         "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}, "filename": {"type": "string", "default": "app.py"}}, "required": ["code"]}},
        {"name": "provably_spec", "title": "Extract business-logic contract", "annotations": {"title": "Extract business-logic contract", **_RO},
         "description": "Extract the business-logic contract of Flask code: every route, who can reach it, and where money, privileges, one-time tokens and workflow steps are handled without a verified primitive. Returns findings with exact fixes plus a draft default-deny policy. Static: runs nothing.",
         "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}},
        {"name": "provably_bizcheck", "title": "Check business logic", "annotations": {"title": "Check business logic", **_RO},
         "description": ("Business-logic contract check of Flask code: who can reach each route, and where money, privileges, one-time tokens and workflow steps are handled without a verified primitive. "
                         "It reads the code and runs nothing. Returns findings with exact fixes. Call after provably_harden and repeat until it reports nothing."),
         "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}},
    ]


def _biz_tail(code):
    """After hardening: the business-logic items that automatic fixing cannot decide, so the AI has to fix them next."""
    try:
        f = bizspec.extract(code)["findings"]
    except SyntaxError:
        return ""
    if not f:
        return "\n\nBusiness-logic contract: no open items. Still call provably_bizcheck before showing the code."
    return "\n\nBUSINESS-LOGIC ITEMS YOU MUST FIX (automatic fixing cannot decide your rules):\n" + "\n".join(f"- [{x['severity']}] {x['route']}: {x['message']}. Fix: {x['fix']}" for x in f) + \
        "\nApply these, then call provably_bizcheck. Read provably_protocol if you have not."


def _check_code(a):
    code = a.get("code")
    if not isinstance(code, str) or not code.strip():
        raise ValueError("code must be a non-empty string")
    if len(code) > MAX_CODE:
        raise ValueError("code is too large (limit %d characters)" % MAX_CODE)
    return code


def _bizcheck(code):
    spec = bizspec.extract(code)
    out = [bizspec.render(spec)]
    if spec["findings"]:
        out.append("NOT READY: fix every item above (use the 'fix' lines), then call provably_bizcheck again.")
    else:
        out.append("No findings in the business-logic contract check. This is not proof the app is secure: rules nobody declared, dependencies and infrastructure are outside it. Say so to the user.")
    return "\n".join(out)


def call(name, a):
    if name == "provably_protocol":
        return PROTOCOL
    code = _check_code(a)
    filename = a.get("filename") if isinstance(a.get("filename"), str) and a.get("filename") else "app.py"
    try:
        if name == "provably_audit":
            return audit.render(audit.audit_files({filename: code}), 60)
        if name == "provably_harden":
            r = harden_core.harden_source(code, filename)
            return harden_core.summary(r) + ("\n\n--- hardened code ---\n" + r["code"] if r["applied"] else "\n\n(no automatic changes)") + \
                ("\n\nNote: the hardened code imports provably_secure; ship provably_secure.py AND the verified_core folder alongside it (the app refuses to start without the verified code)." if "provably_secure" in r["code"] else "") + _biz_tail(r["code"])
        if name == "provably_spec":
            import json as _j
            spec = bizspec.extract(code)
            return bizspec.render(spec) + "\n\ndraft default-deny policy (review the roles, then pass it to provably_secure.policy_gate):\n" + _j.dumps(spec["policy"], indent=1)
        if name == "provably_bizcheck":
            return _bizcheck(code)
    except SyntaxError as e:
        raise ValueError("the code does not parse as Python (line %s): %s" % (e.lineno, e.msg))
    raise ValueError("unknown tool")


def handle(m):
    mid, method, p = m.get("id"), m.get("method"), m.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": p.get("protocolVersion", "2024-11-05"), "capabilities": {"tools": {}}, "serverInfo": {"name": "provably", "version": VERSION}, "instructions": PROTOCOL}
    if method == "tools/list":
        return {"tools": _tools()}
    if method == "tools/call":
        try:
            return {"content": [{"type": "text", "text": call(p.get("name"), p.get("arguments") or {})}]}
        except Exception as e:                    # the message only: never a traceback, never a path
            return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}
    if method == "ping":
        return {}
    if mid is None:
        return None                               # notifications (initialized, cancelled, ...) get no answer
    raise KeyError(method)


def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except ValueError:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}); continue
        if not isinstance(m, dict):
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}); continue
        try:
            res = handle(m)
            if m.get("id") is not None and res is not None:
                _send({"jsonrpc": "2.0", "id": m["id"], "result": res})
        except KeyError as e:
            _send({"jsonrpc": "2.0", "id": m.get("id"), "error": {"code": -32601, "message": f"method not found: {e}"}})
        except Exception:
            _send({"jsonrpc": "2.0", "id": m.get("id"), "error": {"code": -32603, "message": "internal error"}})


if __name__ == "__main__":
    main()
