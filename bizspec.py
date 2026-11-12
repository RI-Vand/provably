#!/usr/bin/env python3
"""bizspec - read a Flask app and write its BUSINESS-LOGIC contract: every route, who can reach it, what it reads, and where money, privileges, single-use
tokens and workflow steps are handled without a verified primitive. Output is a draft provably.spec.json plus findings. Static and heuristic: it
tells the AI/developer exactly what to decide and what to replace, it cannot know what your business rules *should* be.
    python3 bizspec.py app.py [--json]"""
import ast, json, re, sys

MONEY = re.compile(r"^(amount|price|total|cost|qty|quantity|balance|credits?|points?|discount|fee|tip|refund|payment|sum|count|units)$", re.I)
PRIV = re.compile(r"^(role|roles|is_?admin|admin|owner|owner_?id|user_?id|uid|account_?id|verified|approved|status|state|plan|tier|permissions?|is_?staff|superuser)$", re.I)
SINGLE = re.compile(r"(redeem|coupon|promo|voucher|claim|invite|reset|verify|confirm|otp|activate|one_?time|token)", re.I)
STEP = re.compile(r"(approve|ship|cancel|refund|publish|complete|deliver|pay|checkout|fulfil|close|reopen|archive|withdraw|payout)", re.I)
STATEWRITE = re.compile(r"(status|state)['\"]?\]?\s*=[^=]|SET\s+(status|state)", re.I)
ADMIN = re.compile(r"(admin|staff|superuser|internal|debug|manage)", re.I)
PRIVATE = re.compile(r"(admin|account|profile|settings|delete|export|dashboard|user|orders?|billing|invoice|internal|debug|manage)", re.I)
PUBLIC_OK = re.compile(r"(login|logout|register|signup|sign_up|health|ping|index|home|static|webhook|callback|oauth)", re.I)
LOGIN_DECOS = ("login_required", "require_login", "jwt_required", "auth_required", "authenticated")
VERIFIED = {"money": ("transfer_plan", "to_cents"), "single": ("SingleUse", "consume", "consume_sql"), "step": ("state_transition",), "authz": ("authorize", "policy_gate", "owner_only")}


def _route_info(fn):
    rules = []
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ("route", "get", "post", "put", "delete", "patch") and d.args \
                and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
            methods = ["GET"] if d.func.attr == "route" else [d.func.attr.upper()]
            for kw in d.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [e.value.upper() for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            rules.append((d.args[0].value, methods))
    return rules


def _reads(fn):
    names = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str) and "request" in ast.unparse(n.value):
            names.add(n.slice.value)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and n.args and isinstance(n.args[0], ast.Constant) \
                and isinstance(n.args[0].value, str) and "request" in ast.unparse(n.func.value):
            names.add(n.args[0].value)
    return sorted(names)


def extract(src):
    tree = ast.parse(src)
    routes, findings = [], []
    has_gate = "policy_gate" in src
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        info = _route_info(fn)
        if not info:
            continue
        decos = " ".join(ast.unparse(d) for d in fn.decorator_list)
        body = ast.unparse(fn)
        login = any(x in decos for x in LOGIN_DECOS) or ("session" in body and re.search(r"abort\(\s*40[13]", body) is not None)
        params = _reads(fn)
        for rule, methods in info:
            name = fn.name + " " + rule
            tags = [t for t, rx in (("single_use", SINGLE), ("workflow_step", STEP), ("admin", ADMIN)) if rx.search(name)]
            money = [p for p in params if MONEY.match(p)]
            if money:
                tags.append("money")
            routes.append({"rule": rule, "methods": methods, "func": fn.name, "login": bool(login), "params": params, "tags": tags})
            where = f"{'/'.join(methods)} {rule}"
            mutating = any(m in ("POST", "PUT", "DELETE", "PATCH") for m in methods)
            if money and not any(v in body for v in VERIFIED["money"]):
                findings.append({"id": "money-unverified", "severity": "high", "route": where, "message": f"reads {money} from the request but does not use verified money handling",
                                 "fix": "amount = provably_secure.to_cents(request.form['amount']); new_src, new_dst = provably_secure.transfer_plan(src_cents, dst_cents, amount, MAX_CENTS, src_id == dst_id); write BOTH balances in one transaction. Never use floats for money."})
            bad = [p for p in params if PRIV.match(p) and p.lower() not in ("status", "state")]
            if bad and mutating:
                findings.append({"id": "client-controls-privilege", "severity": "high", "route": where, "message": f"takes {bad} from the client; the server must decide these",
                                 "fix": "derive user id / role / owner / plan from the session or the database, never from request fields; keep this field out of the route's allowed params."})
            price_param = [p for p in params if re.match(r"^(price|total|cost|fee|discount)$", p, re.I)]
            if price_param and mutating:
                findings.append({"id": "client-sets-price", "severity": "high", "route": where, "message": f"price-like field(s) {price_param} come from the client",
                                 "fix": "look the price up server-side from the product id; recompute totals on the server."})
            if "single_use" in tags and mutating and not any(v in body for v in VERIFIED["single"]):
                findings.append({"id": "single-use-unenforced", "severity": "high", "route": where, "message": "looks like a one-time action (coupon/reset/invite/code) with no verified single-use check",
                                 "fix": "if not provably_secure.consume_sql(conn, 'used_tokens', token): abort(409)   (UNIQUE token column), or SingleUse().consume(token) in one process."})
            if "workflow_step" in tags and mutating and STATEWRITE.search(body) and not any(v in body for v in VERIFIED["step"]):
                findings.append({"id": "workflow-unenforced", "severity": "medium", "route": where, "message": "a workflow step with no declared state machine: steps can be skipped or repeated",
                                 "fix": "provably_secure.state_transition(EDGES, current_state_from_db, 'next_state') before changing the state; declare EDGES once."})
            if ("admin" in tags) and not login and not has_gate and not re.search(r"role|is_admin", body):
                findings.append({"id": "admin-unprotected", "severity": "high", "route": where, "message": "admin-looking route with no login or role check",
                                 "fix": "declare it admin-only in the policy ({'GET /admin': ['admin']}) and set session['role'] at login."})
            elif not mutating and not login and not has_gate and PRIVATE.search(name) and not PUBLIC_OK.search(name) and "session" not in body \
                    and not any(v in body for v in VERIFIED["authz"]):
                findings.append({"id": "private-without-auth", "severity": "high", "route": where, "message": "private-looking data route with no login or ownership check",
                                 "fix": "require login and check the record belongs to the user, or declare the route in the policy for the right roles."})
            elif mutating and not login and not has_gate and not PUBLIC_OK.search(name) and not any(v in body for v in VERIFIED["authz"]):
                findings.append({"id": "mutation-without-auth", "severity": "medium", "route": where, "message": "state-changing route reachable without login",
                                 "fix": "require login, then check the record belongs to the user (owner_only) or declare it in the policy."})
    policy = {}
    for r in routes:
        for m in r["methods"]:
            if m in ("HEAD", "OPTIONS"):
                continue
            private = bool(PRIVATE.search(r["func"] + " " + r["rule"])) and not PUBLIC_OK.search(r["func"] + " " + r["rule"])
            roles = ["admin"] if "admin" in r["tags"] else ["user", "admin"] if (r["login"] or private) else ["anon", "user", "admin"]   # secure default: private-looking routes need a login
            policy[f"{m} {r['rule']}"] = roles
    spec = {"version": 1, "routes": routes, "policy": policy,
            "contract_to_fill": {"roles": ["anon", "user", "admin"], "ownership": "which tables/ids belong to which user?", "single_use": [r["rule"] for r in routes if "single_use" in r["tags"]],
                                 "state_machines": {"<object>": [["from_state", "to_state"]]}, "money": {"unit": "cents", "max_amount_cents": None}},
            "findings": findings}
    return spec


def render(spec):
    out = [f"{len(spec['routes'])} routes, {len(spec['findings'])} business-logic finding(s)"]
    for f in spec["findings"]:
        out.append(f"  [{f['severity']}] {f['id']}  {f['route']}: {f['message']}\n      fix: {f['fix']}")
    return "\n".join(out)


if __name__ == "__main__":
    spec = extract(open(sys.argv[1]).read())
    print(json.dumps(spec, indent=1) if "--json" in sys.argv else render(spec))
    sys.exit(1 if spec["findings"] else 0)
