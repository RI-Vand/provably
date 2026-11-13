"""fixer - rewrite the vulnerable spots the scanner found into the safe form, using the real syntax tree (never regex on code).
Every edit is applied alone and kept only if the file still parses. Anything that cannot be rewritten without changing what the
program means is NOT guessed: it is returned as `review` with an exact instruction."""
import ast, re, shlex

MARK = re.compile("\ue000(\\d+)\ue001")
IDENT_KW = {"FROM", "INTO", "TABLE", "JOIN", "UPDATE", "BY", "SET", "IN", "AS", "ON", "LIMIT", "OFFSET"}
NO_PLACEHOLDER_SQL = ("PRAGMA", "DROP", "CREATE", "ALTER", "ATTACH", "DETACH", "VACUUM", "REINDEX")   # statements that cannot take bound parameters
SHELL_META = re.compile(r"[|;&<>$`(){}*?~\n\\]")


class Src:
    def __init__(self, text):
        self.text, self.starts = text, [0]
        for ln in text.split("\n"):
            self.starts.append(self.starts[-1] + len(ln) + 1)
        self.lines = text.split("\n")

    def off(self, lineno, col):
        line = self.lines[lineno - 1] if lineno - 1 < len(self.lines) else ""
        return self.starts[lineno - 1] + len(line.encode()[:col].decode(errors="ignore"))

    def span(self, n):
        return self.off(n.lineno, n.col_offset), self.off(n.end_lineno, n.end_col_offset)

    def seg(self, n):
        a, b = self.span(n)
        return self.text[a:b]


def dotted(n):
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        d = dotted(n.value)
        return f"{d}.{n.attr}" if d else n.attr
    return ""


def last(n):
    return dotted(n).split(".")[-1]


class Fixer:
    def __init__(self, code, findings, auth=True):
        self.src, self.findings, self.auth = Src(code), findings, auth
        self.tree = ast.parse(code)
        self.parent = {c: p for p in ast.walk(self.tree) for c in ast.iter_child_nodes(p)}
        self.edits, self.review, self.env_required, self.needs = [], [], [], set()
        self.alias = {}
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self.alias[a.asname] = a.name
        self.paramstyle = "%s" if re.search(r"psycopg|pymysql|mysql", code) and "sqlite3" not in code else "?"

    def d(self, n):
        x = dotted(n)
        head, _, rest = x.partition(".")
        return (self.alias.get(head, head) + ("." + rest if rest else "")) if x else x

    # ---- helpers -------------------------------------------------------------------------------------------------------
    def enclosing_func(self, n):
        while n in self.parent:
            n = self.parent[n]
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return n
        return None

    def at(self, line, kinds):
        return [n for n in ast.walk(self.tree) if isinstance(n, kinds) and getattr(n, "lineno", -1) <= line <= getattr(n, "end_lineno", -2)
                and n.lineno == line]

    def _callee_defs(self, call):
        """local definitions this call can reach: module-level functions by name, methods through self./cls., a class name, a fresh instance or a variable built from a class"""
        if not hasattr(self, "_defs"):
            self._defs = {n.name: n for n in self.tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            self._classes = {c.name: {m.name: m for m in c.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))} for c in ast.walk(self.tree) if isinstance(c, ast.ClassDef)}
            self._inst = {}
            for n in ast.walk(self.tree):
                if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id in self._classes:
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            self._inst[t.id] = n.value.func.id
        f = call.func
        if isinstance(f, ast.Name):
            return [self._defs[f.id]] if f.id in self._defs else []
        if not isinstance(f, ast.Attribute):
            return []
        v = f.value
        if isinstance(v, ast.Name) and v.id in ("self", "cls"):
            encl = self.enclosing_func(call)
            owners = [c for c in ast.walk(self.tree) if isinstance(c, ast.ClassDef) and encl is not None and encl in c.body]
            return [self._classes[o.name][f.attr] for o in owners if f.attr in self._classes[o.name]]
        cls = None
        if isinstance(v, ast.Name):
            cls = v.id if v.id in self._classes else self._inst.get(v.id)
        elif isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in self._classes:
            cls = v.func.id
        return [self._classes[cls][f.attr]] if cls and f.attr in self._classes[cls] else []

    def callee_ranges(self, line):
        """line ranges of the helpers a call on this line reaches, up to three calls deep (route -> method -> function -> sink)"""
        out, seen, frontier = [], set(), self.at(line, ast.Call)
        for _ in range(3):
            nxt = []
            for c in frontier:
                for d in self._callee_defs(c):
                    if id(d) not in seen:
                        seen.add(id(d)); out.append((d.lineno, d.end_lineno)); nxt += [n for n in ast.walk(d) if isinstance(n, ast.Call)]
            frontier = nxt
        return out

    def parts(self, n):
        """Flatten text building into [('c', text) | ('e', source)]. None if n is not text building."""
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return [("c", n.value)]
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            l, r = self.parts(n.left), self.parts(n.right)
            if l is None and r is None:
                return None
            return (l if l is not None else [("e", self.src.seg(n.left))]) + (r if r is not None else [("e", self.src.seg(n.right))])
        if isinstance(n, ast.JoinedStr):
            out = []
            for v in n.values:
                out.append(("c", v.value) if isinstance(v, ast.Constant) else ("e", self.src.seg(v.value)))
            return out
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod) and isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
            args = n.right.elts if isinstance(n.right, ast.Tuple) else [n.right]
            chunks = re.split(r"%[sd]", n.left.value.replace("%%", "\ue002"))
            if len(chunks) - 1 != len(args):
                return None
            out = []
            for i, c in enumerate(chunks):
                out.append(("c", c.replace("\ue002", "%")))
                if i < len(args):
                    out.append(("e", self.src.seg(args[i])))
            return out
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and isinstance(n.func.value, ast.Constant) \
                and isinstance(n.func.value.value, str) and not n.keywords:
            chunks = re.split(r"\{\d*\}", n.func.value.value)
            if len(chunks) - 1 != len(n.args):
                return None
            out = []
            for i, c in enumerate(chunks):
                out.append(("c", c))
                if i < len(n.args):
                    out.append(("e", self.src.seg(n.args[i])))
            return out
        return None

    def add(self, node_or_span, new, rule, line, desc):
        a, b = self.src.span(node_or_span) if not isinstance(node_or_span, tuple) else node_or_span
        self.edits.append((a, b, new, rule, line, desc))

    def skip(self, rule, line, why):
        self.review.append({"rule": rule, "line": line, "action": why})

    # ---- fixes ---------------------------------------------------------------------------------------------------------
    @staticmethod
    def fixed_choice(src):
        """True when the interpolated expression is a string literal or a conditional between string literals (e.g. "ASC" if x else "DESC")."""
        try:
            node = ast.parse(src.strip(), mode="eval").body
        except SyntaxError:
            return False
        def ok(n):
            return (isinstance(n, ast.Constant) and isinstance(n.value, str)) or (isinstance(n, ast.IfExp) and ok(n.body) and ok(n.orelse))
        return ok(node)

    def sqli(self, f):
        for call in self.at(f["line"], ast.Call):
            if not (isinstance(call.func, ast.Attribute) and call.func.attr in ("execute", "executemany", "executescript", "raw")) or len(call.args) != 1:
                continue
            arg, name_assign = call.args[0], None
            if isinstance(arg, ast.Name):
                fn = self.enclosing_func(call) or self.tree
                assigns = [a for a in ast.walk(fn) if isinstance(a, ast.Assign) and len(a.targets) == 1 and isinstance(a.targets[0], ast.Name)
                           and a.targets[0].id == arg.id and a.lineno < call.lineno]
                if len(assigns) != 1:
                    continue
                name_assign, arg = assigns[0], assigns[0].value
            ps = self.parts(arg)
            if not ps or not any(k == "e" for k, _ in ps):
                continue
            ps = [list(p) for p in ps]
            head = "".join(v for k, v in ps if k == "c").lstrip().upper()
            if head.startswith(NO_PLACEHOLDER_SQL):      # DDL, PRAGMA, ATTACH...: the database refuses placeholders here, so a rewrite would produce invalid SQL
                self.skip("sqli", f["line"], "This statement type cannot take placeholders: check every variable in it against a fixed allow-list (or a strict identifier pattern).")
                return
            if all(k == "c" or self.fixed_choice(v) for k, v in ps):      # every interpolated piece is one of a few string literals: nothing the caller controls
                self.skip("sqli", f["line"], "Every interpolated piece is a fixed string chosen in code, not input: nothing to parameterise.")
                return
            sql, params = "", []
            for i, (k, v) in enumerate(ps):
                if k == "c":
                    sql += v.replace("%", "%%") if self.paramstyle == "%s" else v
                    continue
                nxt = ps[i + 1][1] if i + 1 < len(ps) and ps[i + 1][0] == "c" else ""
                nxt_raw = nxt.replace("%%", "%") if self.paramstyle == "%s" else nxt
                sql_raw = sql.replace("%%", "%") if self.paramstyle == "%s" else sql
                expr, done = v, False
                for q in "'\"":
                    lw, lq = sql_raw.endswith(q + "%"), sql_raw.endswith(q)
                    rw, rq = nxt_raw.startswith("%" + q), nxt_raw.startswith(q)
                    if (lw or lq) and (rw or rq):
                        sql_raw = sql_raw[:-2] if lw else sql_raw[:-1]
                        nxt_raw = nxt_raw[2:] if rw else nxt_raw[1:]
                        expr = ('"%" + ' if lw else "") + f"str({v})" + (' + "%"' if rw else "")
                        done = True
                        break
                if not done:
                    toks = re.findall(r"[A-Za-z_]+|\W", sql_raw.rstrip())
                    if (toks and toks[-1].upper() in IDENT_KW) or sql_raw.rstrip().endswith("."):
                        self.skip("sqli", f["line"], "A table/column name is built from a variable and cannot be a parameter: check it against a fixed allow-list.")
                        return
                    if "'" in nxt_raw[:1] or '"' in nxt_raw[:1]:
                        self.skip("sqli", f["line"], "Quoting around a variable is unusual here: rewrite this query with placeholders by hand.")
                        return
                sql = sql_raw.replace("%", "%%") if self.paramstyle == "%s" else sql_raw
                if i + 1 < len(ps) and ps[i + 1][0] == "c":
                    ps[i + 1][1] = nxt_raw.replace("%", "%%") if self.paramstyle == "%s" else nxt_raw
                    ps[i + 1][1] = ps[i + 1][1]
                sql += self.paramstyle
                params.append(expr)
            # constants already escaped above for the %s style; undo double escaping of the pieces we re-escaped
            sql = sql.replace("%%%%", "%%")
            tup = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
            if name_assign is not None:
                nm = name_assign.targets[0].id
                self.add(name_assign, f"{nm} = {sql!r}\n{' ' * name_assign.col_offset}{nm}_params = {tup}", "sqli", f["line"], "parameterised query")
                self.add(call.args[0], f"{nm}, {nm}_params", "sqli", f["line"], "parameterised query")
            else:
                self.add(call.args[0], f"{sql!r}, {tup}", "sqli", f["line"], "parameterised query")
            return
        self.skip(f["rule"], f["line"], "Build this query with placeholders (? or %s) and pass the values as a separate tuple.")

    def cmdi(self, f):
        for call in self.at(f["line"], ast.Call):
            d = self.d(call.func)
            shell_kw = next((k for k in call.keywords if k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True), None)
            if not call.args or not ((d.startswith("subprocess.") and shell_kw) or d == "os.system"):
                continue
            ps = self.parts(call.args[0])
            if not ps or not any(k == "e" for k, _ in ps):
                continue
            exprs, text = [], ""
            for k, v in ps:
                if k == "c":
                    if SHELL_META.search(v):
                        self.skip("cmdi", f["line"], "The command uses shell features (pipes, redirects, globs). Split it into separate subprocess.run([...]) calls.")
                        return
                    text += v
                else:
                    text += f"\ue000{len(exprs)}\ue001"
                    exprs.append(v)
            try:
                toks = shlex.split(text)
            except ValueError:
                continue
            argv = []
            for t in toks:
                pieces, pos = [], 0
                for m in MARK.finditer(t):
                    if t[pos:m.start()]:
                        pieces.append(repr(t[pos:m.start()]))
                    pieces.append(f"str({exprs[int(m.group(1))]})")
                    pos = m.end()
                if t[pos:]:
                    pieces.append(repr(t[pos:]))
                argv.append(self.guard_arg(pieces, len(argv)))
            lst = "[" + ", ".join(argv) + "]"
            if d == "os.system":
                self.add(call, f"subprocess.run({lst}, check=False)", "cmdi", f["line"], "no shell, argument list")
                self.needs.add("subprocess")
            else:
                self.add(call.args[0], lst, "cmdi", f["line"], "argument list")
                self.add(shell_kw.value, "False", "cmdi", f["line"], "shell off")
            return
        if self.popen(f):
            return
        self.skip(f["rule"], f["line"], "Call subprocess.run([program, arg, ...]) with shell=False.")

    def path(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) not in ("send_file", "open") or not call.args:
                continue
            a0, base, rest = call.args[0], None, []
            if isinstance(a0, ast.Call) and self.d(a0.func) == "os.path.join" and a0.args and isinstance(a0.args[0], ast.Constant):
                base, rest = a0.args[0].value, [self.src.seg(x) for x in a0.args[1:]]
            else:
                ps = self.parts(a0)
                if ps and ps[0][0] == "c" and len(ps) == 2 and ps[1][0] == "e":
                    base, rest = ps[0][1].rstrip("/"), [ps[1][1]]
            if base and rest:
                self.add(a0, f"provably_secure.safe_join({base!r}, {', '.join(rest)})", "pathtrav", f["line"], "path pinned inside base folder")
                self.needs.add("provably_secure")
                return
        self.skip(f["rule"], f["line"], "Wrap the path: provably_secure.safe_join(base_folder, user_value).")

    def redirect(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) == "redirect" and call.args and not isinstance(call.args[0], ast.Constant) \
                    and "safe_redirect_target" not in self.src.seg(call.args[0]):
                self.add(call.args[0], f"provably_secure.safe_redirect_target({self.src.seg(call.args[0])})", "redirect", f["line"], "allow-listed redirect")
                self.needs.add("provably_secure")
                return
        self.skip(f["rule"], f["line"], "Wrap the target: provably_secure.safe_redirect_target(url, allowed_hosts).")

    def deser(self, f):
        swap = {"pickle.loads": "json.loads", "pickle.load": "json.load", "cPickle.loads": "json.loads", "marshal.loads": "json.loads"}
        for call in self.at(f["line"], ast.Call):
            d = self.d(call.func)
            if d in swap:
                self.add(call.func, swap[d], "deser", f["line"], "json instead of pickle")
                self.needs.add("json")
                return
            if d in ("yaml.load", "yaml.unsafe_load", "yaml.full_load") and call.args:
                self.add(call, f"yaml.safe_load({self.src.seg(call.args[0])})", "deser", f["line"], "yaml.safe_load")
                return
        self.skip(f["rule"], f["line"], "Use json for data; never load pickle or unsafe YAML from outside.")

    def secret(self, f):
        for st in self.at(f["line"], (ast.Assign, ast.AnnAssign)):
            tgt = st.targets[0] if isinstance(st, ast.Assign) else st.target
            if not (isinstance(st.value, ast.Constant) and isinstance(st.value.value, str)):
                continue
            if isinstance(tgt, ast.Name):
                nm = tgt.id.upper()
            elif isinstance(tgt, ast.Attribute):
                nm = "SECRET_KEY" if tgt.attr == "secret_key" else tgt.attr.upper()
            elif isinstance(tgt, ast.Subscript) and isinstance(tgt.slice, ast.Constant):
                nm = str(tgt.slice.value).upper()
            else:
                continue
            if f["rule"] == "flasksecret":
                new = f'os.environ.get("{nm}") or secrets.token_hex(32)'
                self.needs |= {"os", "secrets"}
            else:
                new = f'os.environ["{nm}"]'
                self.needs.add("os")
                self.env_required.append(nm)
            self.add(st.value, new, f["rule"], f["line"], "secret moved out of the code")
            return
        self.skip(f["rule"], f["line"], "Move this secret to an environment variable and rotate it; it is already exposed.")

    def flag(self, f, kwname, old, new, desc):
        for call in self.at(f["line"], ast.Call):
            for k in call.keywords:
                if k.arg == kwname and isinstance(k.value, ast.Constant) and k.value.value == old:
                    self.add(k.value, new, f["rule"], f["line"], desc)
                    return True
        return False

    def debug(self, f):
        if self.flag(f, "debug", True, "False", "debug off"):
            return
        for st in self.at(f["line"], ast.Assign):
            if isinstance(st.value, ast.Constant) and st.value.value is True:
                self.add(st.value, "False", "debug", f["line"], "debug off")
                return
        self.skip("debug", f["line"], "Turn debug off.")

    def tls(self, f):
        if not self.flag(f, "verify", False, "True", "certificate checking on"):
            self.skip("tls", f["line"], "Remove the setting that disables certificate checking.")

    def bind(self, f):
        for call in self.at(f["line"], ast.Call):
            for k in call.keywords:
                if k.arg == "host" and isinstance(k.value, ast.Constant) and k.value.value == "0.0.0.0":
                    self.add(k.value, '"127.0.0.1"', "bind", f["line"], "bind to localhost")
                    return

    def cookie(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) == "set_cookie":
                have = {k.arg for k in call.keywords}
                want = [("httponly", "True"), ("secure", "True"), ("samesite", '"Lax"')]
                add = [f"{k}={v}" for k, v in want if k not in have]
                if add:
                    pos = self.src.span(call)[1] - 1
                    self.add((pos, pos), ", " + ", ".join(add), "cookie", f["line"], "cookie flags")
                return

    def decorator(self, f, deco, desc):
        for fn in self.at(f["line"], (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(deco.split(".")[-1] in self.src.seg(d) for d in fn.decorator_list):
                return
            pos = self.src.off(fn.lineno, 0)
            self.add((pos, pos), " " * fn.col_offset + "@" + deco + "\n", f["rule"], f["line"], desc)
            self.needs.add("provably_secure")
            return

    def authn(self, f):
        if self.auth:
            self.decorator(f, "provably_secure.login_required", "default-deny login check")
            if not getattr(self, "_session_note", False):
                self._session_note = True
                self.skip("authn", f["line"], "Login checks were added. In your login route, after the password check succeeds, set session['user'] = <user id>; until then protected routes answer 401 to everyone. Also check that each record belongs to the logged-in user (ownership).")
        else:
            self.skip("authn", f["line"], "Add a login check to this route.")

    def ratelimit(self, f):
        self.decorator(f, "provably_secure.rate_limit", "login rate limit")

    def bodylimit(self, f):
        for st in self.tree.body:
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) and last(st.value.func) == "Flask" and isinstance(st.targets[0], ast.Name):
                pos = self.src.off(st.end_lineno + 1, 0) if st.end_lineno < len(self.src.lines) else len(self.src.text)
                pre = "" if pos <= len(self.src.text) and self.src.text[:pos].endswith("\n") else "\n"
                self.add((pos, pos), pre + f'{st.targets[0].id}.config["MAX_CONTENT_LENGTH"] = 1_000_000\n', "bodylimit", f["line"], "1 MB request limit")
                return


    def idor(self, f):
        for fn in self.at(f["line"], (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = self.src.seg(fn)
            if "owner_only" in body or not re.search(r"\b(from|join|into|update)\s+[\"'`]?(users?|accounts?|profiles?|members?|customers?)\b", body, re.I):
                self.skip("idor", f["line"], self.MANUAL["idor"])
                return
            done = False
            for n in ast.walk(fn):
                key = None
                if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and ast.unparse(n.value) in ("request.args", "request.form", "request.values", "request.json"):
                    key = n.slice.value
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and ast.unparse(n.func.value) in ("request.args", "request.form", "request.values") and n.args and isinstance(n.args[0], ast.Constant):
                    key = n.args[0].value
                if isinstance(key, str) and re.fullmatch(r"id|user_id|uid|account_id|owner_id|pk", key):
                    a, b = self.src.span(n)
                    self.add((a, b), "provably_secure.owner_only(" + self.src.seg(n) + ")", "idor", f["line"], "only the record's owner may use this id")
                    self.needs.add("provably_secure")
                    done = True
            if not done:
                self.skip("idor", f["line"], self.MANUAL["idor"])
            return

    def strictparams(self, f):
        """Build {route: [fields]} from the code. Only routes whose field reads are all constant keys are listed; if any helper function outside a route
        reads request fields, nothing is emitted (we cannot tell which route it serves), so the fix never refuses legitimate input."""
        parents = {c: p for p in ast.walk(self.tree) for c in ast.iter_child_nodes(p)}
        def reads(fn):
            keys, dynamic = set(), False
            for n in ast.walk(fn):
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "request" and n.attr in ("json", "data", "get_json", "get_data", "stream"):
                    keys.add("*json")             # the body is read wholesale: allow_params keeps size/depth limits but cannot list its keys
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "request" and n.attr in ("args", "form", "values"):
                    p = parents.get(n)
                    if isinstance(p, ast.Subscript) and p.value is n and isinstance(p.slice, ast.Constant) and isinstance(p.slice.value, str):
                        keys.add(p.slice.value)
                    elif isinstance(p, ast.Attribute) and p.attr in ("get", "getlist") and isinstance(parents.get(p), ast.Call) and parents[p].args \
                            and isinstance(parents[p].args[0], ast.Constant) and isinstance(parents[p].args[0].value, str):
                        keys.add(parents[p].args[0].value)
                    else:
                        dynamic = True
            return keys, dynamic
        spec, helper_reads = {}, False
        for fn in [n for n in self.tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            path = None
            for d in fn.decorator_list:
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ("route", "get", "post", "put", "delete", "patch") \
                        and d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
                    path = d.args[0].value
            keys, dynamic = reads(fn)
            if path is None:
                helper_reads = helper_reads or bool(keys) or dynamic
            elif not dynamic:
                spec[path] = sorted(keys | spec.get(path, set()))
        if helper_reads or not spec:
            self.skip("strictparams", f["line"], "Routes read request fields in a way that cannot be listed automatically. Add provably_secure.allow_params(app, {route: [fields]}) by hand.")
            return
        for st in self.tree.body:
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) and last(st.value.func) == "Flask" and isinstance(st.targets[0], ast.Name):
                pos = self.src.off(st.end_lineno + 1, 0) if st.end_lineno < len(self.src.lines) else len(self.src.text)
                pre = "" if pos <= len(self.src.text) and self.src.text[:pos].endswith("\n") else "\n"
                self.add((pos, pos), pre + f"provably_secure.allow_params({st.targets[0].id}, {spec!r})\n", "strictparams", f["line"], "each route accepts only the fields it reads")
                self.needs.add("provably_secure")
                return

    def shield(self, f):
        for st in self.tree.body:
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) and last(st.value.func) == "Flask" and isinstance(st.targets[0], ast.Name):
                pos = self.src.off(st.end_lineno + 1, 0) if st.end_lineno < len(self.src.lines) else len(self.src.text)
                pre = "" if pos <= len(self.src.text) and self.src.text[:pos].endswith("\n") else "\n"
                self.add((pos, pos), pre + f"provably_secure.shield({st.targets[0].id})\n", "shield", f["line"], "security headers + cross-site request check")
                self.needs.add("provably_secure")
                return

    def policy(self, f):
        """Default-deny route policy generated from the app's own routes: every route that exists today stays reachable by the roles it is reachable by today
        (login-protected -> user/admin, admin-looking -> admin only, otherwise public); anything added LATER is refused until someone declares it."""
        import bizspec
        spec = bizspec.extract(self.src.text)
        if not spec["policy"]:
            return
        for st in self.tree.body:
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) and last(st.value.func) == "Flask" and isinstance(st.targets[0], ast.Name):
                pos = self.src.off(st.end_lineno + 1, 0) if st.end_lineno < len(self.src.lines) else len(self.src.text)
                pre = "" if pos <= len(self.src.text) and self.src.text[:pos].endswith("\n") else "\n"
                self.add((pos, pos), pre + f"provably_secure.policy_gate({st.targets[0].id}, {spec['policy']!r})\n", "policy", f["line"], "default-deny route policy: undeclared routes are refused")
                self.needs.add("provably_secure")
                admin = [k for k, v in spec["policy"].items() if v == ["admin"]]
                if admin:
                    self.skip("policy", f["line"], f"{', '.join(admin)} are admin-only in the generated policy. After your admin login succeeds, set session['role'] = 'admin'; until then these routes answer 403 to everyone.")
                return

    def codei(self, f):
        for call in self.at(f["line"], ast.Call):
            if self.d(call.func) == "eval" and call.args and not isinstance(call.args[0], ast.Constant):
                self.add(call.func, "ast.literal_eval", "codei", f["line"], "literal_eval instead of eval")
                self.needs.add("ast")
                return
        self.skip(f["rule"], f["line"], "Remove eval/exec; parse with json or ast.literal_eval and dispatch through a fixed dict of allowed functions.")

    def ssti(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) == "render_template_string" and len(call.args) == 1 and not call.keywords and not isinstance(call.args[0], ast.Constant):
                self.add(call, f'{self.src.seg(call.func)}("{{{{ provably_text }}}}", provably_text={self.src.seg(call.args[0])})', "ssti", f["line"], "fixed template, text as data")
                return
        self.skip(f["rule"], f["line"], "Render a fixed template and pass user data as variables.")

    def ssrf(self, f):
        for call in self.at(f["line"], ast.Call):
            if (self.d(call.func).split(".")[0] in ("requests", "httpx") or last(call.func) == "urlopen") and call.args and not isinstance(call.args[0], ast.Constant) \
                    and "safe_url" not in self.src.seg(call.args[0]):
                a = call.args[0]
                self.add(a, f'provably_secure.safe_url({self.src.seg(a)}, os.environ.get("ALLOWED_HOSTS", "").split(","))', "ssrf", f["line"], "allow-listed, public hosts only")
                self.needs |= {"provably_secure", "os"}
                if "ALLOWED_HOSTS" not in self.env_required:
                    self.env_required.append("ALLOWED_HOSTS")
                return
        self.skip(f["rule"], f["line"], "Use provably_secure.safe_url(url, allowed_hosts) before fetching.")

    def popen(self, f):
        for call in self.at(f["line"], ast.Call):
            if self.d(call.func) != "os.popen" or not call.args:
                continue
            outer = self.parent.get(self.parent.get(call))
            if not (isinstance(self.parent.get(call), ast.Attribute) and self.parent[call].attr == "read" and isinstance(outer, ast.Call)):
                continue
            ps = self.parts(call.args[0])
            if ps and any(k == "e" for k, _ in ps):
                argv = self.argv_from(ps)
                if argv:
                    self.add(outer, f"subprocess.run({argv}, capture_output=True, text=True).stdout", "cmdi", f["line"], "no shell, argument list")
                    self.needs.add("subprocess")
                    return True
        return False

    def guard_arg(self, pieces, index):
        """A token that is purely user data (no literal text before it) could start with '-' and be read as an option
        (argument injection, e.g. host='-f'). Wrap it so such a value is refused. The program name (index 0) is left alone."""
        joined = " + ".join(pieces)
        if index > 0 and pieces and pieces[0].startswith("str(") and not pieces[0].startswith("str('"):
            self.needs.add("provably_secure")
            return f"provably_secure.safe_arg({joined})"
        return joined

    def argv_from(self, ps):
        exprs, text = [], ""
        for k, v in ps:
            if k == "c":
                if SHELL_META.search(v):
                    return None
                text += v
            else:
                text += f"\ue000{len(exprs)}\ue001"
                exprs.append(v)
        try:
            toks = shlex.split(text)
        except ValueError:
            return None
        argv = []
        for t in toks:
            pieces, pos = [], 0
            for m in MARK.finditer(t):
                if t[pos:m.start()]:
                    pieces.append(repr(t[pos:m.start()]))
                pieces.append(f"str({exprs[int(m.group(1))]})")
                pos = m.end()
            if t[pos:]:
                pieces.append(repr(t[pos:]))
            argv.append(self.guard_arg(pieces, len(argv)))
        return "[" + ", ".join(argv) + "]"

    MANUAL = {
        "weakhash": "Replace the md5/sha1 check. Step 1: run `python3 migrate_passwords.py app.db users pw --apply` (wraps every stored hash in scrypt, nobody is locked out). Step 2: in login, fetch the row by name, then `ok, upgrade = provably_secure.verify_any(password, row_pw)`; if ok and upgrade, save provably_secure.hash_password(password). New accounts: store hash_password(password).",
        "plainpw": "Store hash_password(pw) instead of the password and compare with verify_password.",
        "idor": "Check that the record belongs to the logged-in user before returning it: sqlite -> provably_secure.scope_sqlite(conn, {table: owner_column}, session['user']) once per request, then provably_secure.scoped_execute(conn, sql, params); other databases -> add AND owner_id = current user to the query.",
    }
    HANDLERS = {"sqli": "sqli", "sqli_built": "sqli", "cmdi": "cmdi", "pathtrav": "path", "redirect": "redirect", "deser": "deser", "secret": "secret",
                "flasksecret": "secret", "debug": "debug", "tls": "tls", "bind": "bind", "cookie": "cookie", "authn": "authn", "authn_read": "authn", "shield": "shield", "policy": "policy", "strictparams": "strictparams", "idor": "idor", "ratelimit": "ratelimit",
                "bodylimit": "bodylimit", "codei": "codei", "ssti": "ssti", "ssrf": "ssrf",
                "upload": "upload", "weakrand": "weakrand", "jwt": "jwt", "xss": "xss", "xxe": "xxe", "perm": "perm", "errleak": "errleak", "timing": "timing", "assertauth": "assertauth", "cors": "cors", "csrf": "csrf", "tmp": "tmp", "hdrinj": "hdrinj", "massassign": "massassign", "logsecret": "logsecret", "zipslip": "zipslip"}

    # ---- second wave: rules that used to be flag-only -------------------------------------------------------------------
    def upload(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) != "save" or len(call.args) != 1 or not isinstance(call.func, ast.Attribute):
                continue
            a0, base = call.args[0], "uploads"
            if isinstance(a0, ast.Call) and self.d(a0.func) == "os.path.join" and a0.args and isinstance(a0.args[0], ast.Constant):
                base = a0.args[0].value
            else:
                ps = self.parts(a0)
                if ps and ps[0][0] == "c" and ps[0][1].strip("/"):
                    base = ps[0][1].rstrip("/")
            self.add(call, f"provably_secure.safe_upload({self.src.seg(call.func.value)}, {base!r})", "upload", f["line"], "random server-side name, extension allow-list, size cap")
            self.needs.add("provably_secure")
            return
        self.skip(f["rule"], f["line"], "Save through provably_secure.safe_upload(file, folder).")

    RAND = {"getrandbits": "randbits", "choice": "choice", "randrange": "randbelow"}

    def weakrand(self, f):
        done = False
        for st in self.at(f["line"], (ast.Assign, ast.Return, ast.AnnAssign, ast.Expr)):
            for c in ast.walk(st):
                if not isinstance(c, ast.Call):
                    continue
                d = self.d(c.func)
                if d in ("random.getrandbits", "random.choice") or (d == "random.randrange" and len(c.args) == 1):
                    self.add(c.func, "secrets." + self.RAND[d.split(".")[1]], "weakrand", f["line"], "secrets instead of random"); done = True
                elif d == "random.randint" and len(c.args) == 2:
                    lo, hi = self.src.seg(c.args[0]), self.src.seg(c.args[1])
                    self.add(c, f"({lo} + secrets.randbelow(({hi}) - ({lo}) + 1))", "weakrand", f["line"], "secrets instead of random"); done = True
                elif d == "random.choices" and c.args and any(k.arg == "k" for k in c.keywords):
                    k = next(k for k in c.keywords if k.arg == "k")
                    self.add(c, f"[secrets.choice({self.src.seg(c.args[0])}) for _ in range({self.src.seg(k.value)})]", "weakrand", f["line"], "secrets instead of random"); done = True
                elif d == "random.random":
                    self.add(c, "(secrets.randbits(53) / 2**53)", "weakrand", f["line"], "secrets instead of random"); done = True
        if done:
            self.needs.add("secrets")
        else:
            self.skip(f["rule"], f["line"], "Use the secrets module (secrets.token_urlsafe) for anything an attacker must not guess.")

    def jwt(self, f):
        for call in self.at(f["line"], ast.Call):
            if self.d(call.func).startswith("jwt.") and last(call.func) == "decode" and call.args:
                self.add(call, f'jwt.decode({self.src.seg(call.args[0])}, os.environ["JWT_SECRET"], algorithms=["HS256"])', "jwt", f["line"], "signature always verified, algorithm pinned")
                self.needs |= {"os", "jwt"}
                self.env_required.append("JWT_SECRET")
                return
        self.skip(f["rule"], f["line"], "Verify tokens with an explicit algorithm list and a secret from the environment.")

    def xss(self, f):
        for st in self.at(f["line"], (ast.Return, ast.Assign)):
            v = st.value
            if isinstance(v, ast.Tuple) and v.elts:
                v = v.elts[0]
            for c in ast.walk(v):
                if isinstance(c, ast.Call) and last(c.func) in ("Markup", "mark_safe") and c.args:
                    self.add(c.args[0], f"provably_secure.escape_html({self.src.seg(c.args[0])})", "xss", f["line"], "escaped before marking safe")
                    self.needs.add("provably_secure")
                    return
            ps = self.parts(v)
            if ps and any(k == "e" for k, _ in ps):
                out = []
                for k, t in ps:
                    out.append(repr(t) if k == "c" else (t if re.match(r"(render_template|escape\(|provably_secure\.escape_html)", t) else f"provably_secure.escape_html({t})"))
                self.add(v, " + ".join(out), "xss", f["line"], "every inserted value HTML-escaped")
                self.needs.add("provably_secure")
                return
        self.skip(f["rule"], f["line"], "Escape with provably_secure.escape_html or render through an auto-escaping template.")

    def xxe(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) == "fromstring" and call.args:
                self.add(call, f"provably_secure.safe_xml({self.src.seg(call.args[0])})", "xxe", f["line"], "XML with DOCTYPE/ENTITY refused")
                self.needs.add("provably_secure")
                return
        self.skip(f["rule"], f["line"], "Parse untrusted XML with provably_secure.safe_xml(text) (or defusedxml).")

    def perm(self, f):
        for call in self.at(f["line"], ast.Call):
            if self.d(call.func) == "os.chmod" and len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                self.add(call.args[1], "0o750" if call.args[1].value == 0o777 else "0o640", "perm", f["line"], "no world access")
                return
        self.skip(f["rule"], f["line"], "Use mode 0o750 / 0o640.")

    def errleak(self, f):
        for st in self.at(f["line"], ast.Return):
            self.add(st.value, '("Something went wrong", 500)', "errleak", f["line"], "generic message; details stay in the server log")
            return
        self.skip(f["rule"], f["line"], "Log the exception server-side and return a generic message.")

    def timing(self, f):
        for c in self.at(f["line"], ast.Compare):
            if len(c.ops) == 1 and isinstance(c.ops[0], (ast.Eq, ast.NotEq)):
                call = f"provably_secure.safe_compare({self.src.seg(c.left)}, {self.src.seg(c.comparators[0])})"
                self.add(c, call if isinstance(c.ops[0], ast.Eq) else f"(not {call})", "timing", f["line"], "constant-time comparison")
                self.needs.add("provably_secure")
                return
        self.skip(f["rule"], f["line"], "Compare secrets with provably_secure.safe_compare.")

    def assertauth(self, f):
        for st in self.at(f["line"], ast.Assert):
            self.add(st, f"if not ({self.src.seg(st.test)}):\n{' ' * st.col_offset}    raise PermissionError('forbidden')", "assertauth", f["line"], "real check that survives python -O")
            return
        self.skip(f["rule"], f["line"], "Replace assert with an if/raise or abort(403).")

    def cors(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) == "CORS":
                allow = '[o for o in os.environ.get("CORS_ORIGINS", "").split(",") if o]'
                star = next((k for k in call.keywords if k.arg in ("origins", "resources") and re.search(r"[\'\"]\*[\'\"]", self.src.seg(k.value))), None)
                if star is not None and star.arg == "origins":
                    self.add(star.value, allow, "cors", f["line"], "only origins listed in CORS_ORIGINS"); self.needs.add("os"); return
                if not any(k.arg == "origins" for k in call.keywords) and not call.keywords and len(call.args) == 1:
                    self.add(call, f"CORS({self.src.seg(call.args[0])}, origins={allow})", "cors", f["line"], "only origins listed in CORS_ORIGINS"); self.needs.add("os"); return
        self.skip(f["rule"], f["line"], "List the exact origins allowed instead of '*'.")

    def csrf(self, f):
        for st in self.at(f["line"], (ast.Assign,)):
            if isinstance(st.value, ast.Constant) and st.value.value is False:
                self.add(st.value, "True", "csrf", f["line"], "CSRF protection on"); return
        self.skip(f["rule"], f["line"], "Do not exempt state-changing routes from CSRF protection.")

    def tmp(self, f):
        for call in self.at(f["line"], ast.Call):
            if self.d(call.func) == "tempfile.mktemp":
                kw = ", ".join(self.src.seg(k) for k in call.keywords)
                self.add(call, f"tempfile.NamedTemporaryFile(delete=False{', ' + kw if kw else ''}).name", "tmp", f["line"], "file created atomically, not just named")
                return
        self.skip(f["rule"], f["line"], "Use tempfile.NamedTemporaryFile(delete=False) or mkstemp.")

    def hdrinj(self, f):
        for st in self.at(f["line"], ast.Assign):
            if isinstance(st.targets[0], ast.Subscript):
                self.add(st.value, f"provably_secure.clean_header({self.src.seg(st.value)})", "hdrinj", f["line"], "CR/LF stripped from header value")
                self.needs.add("provably_secure"); return
        for call in self.at(f["line"], ast.Call):
            if last(call.func) in ("add_header", "set_header") and len(call.args) > 1:
                self.add(call.args[1], f"provably_secure.clean_header({self.src.seg(call.args[1])})", "hdrinj", f["line"], "CR/LF stripped from header value")
                self.needs.add("provably_secure"); return
        self.skip(f["rule"], f["line"], "Strip CR/LF from header values: provably_secure.clean_header(v).")

    def massassign(self, f):
        for call in self.at(f["line"], ast.Call):
            for k in call.keywords:
                if k.arg is None and re.search(r"request\.|data|payload|body|params", self.src.seg(k.value)):
                    self.add(k.value, f"provably_secure.reject_privileged({self.src.seg(k.value)})", "massassign", f["line"], "client cannot set role/admin/owner/price/balance/id fields")
                    self.needs.add("provably_secure"); return
        self.skip(f["rule"], f["line"], "Copy only an allow-list of fields from the request into the model.")

    def logsecret(self, f):
        for call in self.at(f["line"], ast.Call):
            for a in call.args:
                if not isinstance(a, ast.Constant) and re.search(r"(password|passwd|secret|token|api_?key)", self.src.seg(a), re.I):
                    self.add(a, repr("[redacted]"), "logsecret", f["line"], "secret not logged")
                    return
        self.skip(f["rule"], f["line"], "Never log passwords, tokens or keys.")

    def zipslip(self, f):
        for call in self.at(f["line"], ast.Call):
            if last(call.func) in ("extractall", "extract") and isinstance(call.func, ast.Attribute) and call.args:
                self.add(call, f"provably_secure.safe_extract({self.src.seg(call.func.value)}, {self.src.seg(call.args[0])})", "zipslip", f["line"], "every member pinned inside the target folder")
                self.needs.add("provably_secure"); return
        self.skip(f["rule"], f["line"], "Extract through provably_secure.safe_extract(archive, dest).")

    def run(self):
        for f in sorted(self.findings, key=lambda x: x["line"]):
            h = self.HANDLERS.get(f["rule"])
            if h:
                n_e, n_r = len(self.edits), len(self.review)
                getattr(self, h)(f)
                if len(self.edits) == n_e and h in ("sqli", "cmdi", "path", "redirect", "deser", "codei", "ssti", "ssrf"):
                    for lo, hi in self.callee_ranges(f["line"]):
                        for L in range(lo, hi + 1):
                            del self.review[n_r:]
                            getattr(self, h)({**f, "line": L})
                            if len(self.edits) > n_e:
                                break
                        if len(self.edits) > n_e:
                            break
                    if len(self.edits) == n_e:
                        del self.review[n_r:]
                        getattr(self, h)(f)
            elif f["rule"] in self.MANUAL:
                self.skip(f["rule"], f["line"], self.MANUAL[f["rule"]])
        text, applied = self.src.text, []
        edits = sorted(self.edits, key=lambda e: (e[0], e[1]))
        keep, end = [], -1
        for e in edits:
            if e[0] >= end:
                keep.append(e)
                end = max(end, e[1])
        for a, b, new, rule, line, desc in reversed(keep):
            trial = text[:a] + new + text[b:]
            try:
                ast.parse(trial)
            except SyntaxError:
                self.skip(rule, line, "Automatic rewrite was unsafe here; apply the fix by hand.")
                continue
            if self.makes_worse(text, trial):
                self.skip(rule, line, "Automatic rewrite would introduce a new finding; apply the fix by hand.")
                continue
            applied.append({"rule": rule, "line": line, "desc": desc, "before": text[a:b], "after": new})
            text = trial
        text = self.add_imports(text) if applied else text
        return text, sorted(applied, key=lambda x: x["line"]), self.review, self.env_required

    @staticmethod
    def makes_worse(before, after):
        """Safety net: an edit is kept only if re-scanning the result shows no rule with MORE findings than before it. The scan is the same one that
        found the problem, so a rewrite that trades one finding for another (or leaves the same one in place plus a new one) goes back to the person as a
        review item instead of into their code. If the scan itself cannot run, the edit is kept: the syntax check above still applies."""
        try:
            import audit
            from collections import Counter
            was = Counter(f["rule"] for f in audit.audit_python(before, "<fix>"))
            now = Counter(f["rule"] for f in audit.audit_python(after, "<fix>"))
        except Exception:
            return False
        return any(now[r] > was[r] for r in now)

    def add_imports(self, text):
        tree = ast.parse(text)
        have = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                have |= {a.asname or a.name for a in n.names}
        need = [n for n in sorted(self.needs) if n not in have and re.search(rf"\b{n}\.", text)]
        if not need:
            return text
        body = tree.body
        i = 0
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
            i = 1
        while i < len(body) and isinstance(body[i], ast.ImportFrom) and body[i].module == "__future__":
            i += 1
        lines = text.split("\n")
        at = body[i].lineno - 1 if i < len(body) else len(lines)
        if i < len(body) and body[i].decorator_list if hasattr(body[i], "decorator_list") else False:
            at = body[i].decorator_list[0].lineno - 1
        lines[at:at] = [f"import {n}" for n in need]
        return "\n".join(lines)


def inline_dispatch(code):
    """TABLE['key'](x) -> func(x) when TABLE is a module-level dict of names: the dispatch hid the call from the fixer"""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code
    table = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Dict):
            for k, v in zip(n.value.keys, n.value.values):
                if isinstance(k, ast.Constant) and isinstance(v, (ast.Name, ast.Attribute)):
                    table[(n.targets[0].id, k.value)] = ast.unparse(v)
    lines = code.splitlines(keepends=True)
    spans = []
    for n in ast.walk(tree):
        f = n.func if isinstance(n, ast.Call) else None
        if isinstance(f, ast.Subscript) and isinstance(f.value, ast.Name) and isinstance(f.slice, ast.Constant) and (f.value.id, f.slice.value) in table and f.lineno == f.end_lineno:
            spans.append((f.lineno - 1, f.col_offset, f.end_col_offset, table[(f.value.id, f.slice.value)]))
    for ln, a, b, text in sorted(spans, reverse=True):
        raw = lines[ln].encode()
        lines[ln] = (raw[:a] + text.encode() + raw[b:]).decode()
    return "".join(lines)


def fix_python(code, findings, auth=True):
    return Fixer(inline_dispatch(code), findings, auth).run()
