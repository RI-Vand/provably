#!/usr/bin/env python3
"""audit - find vulnerabilities in code that an AI model wrote, from the code itself.

Raw material: the real syntax tree (Python) or the real source text (JavaScript), never a summary of it.
Method: taint analysis with function summaries. Untrusted input (request data, URL parameters, input(), argv) is followed through
assignments, formatting, calls and helper functions to dangerous calls (SQL, shell, files, URLs, deserialisation, redirects, templates, HTML),
unless it passes a sanitiser or a guard. On top of that sit configuration rules (debug on, TLS checks off, cookie flags, weak crypto,
hardcoded secrets) and logic heuristics for the failures the research flags as most common (missing authentication, missing ownership
check, mass assignment, check-then-update races, secret comparison, user enumeration, ReDoS).

Every finding carries a CWE and OWASP category, a plain-English explanation, a fix (preferring the stdlib-only helpers in
`secure_helpers.py`), a confidence, and (where one exists) the exploit payload used by the generated attack test.

A scanner that cries wolf gets switched off, so every rule is kept precise.
"""
import ast
import hashlib
import json
import re

# ------------------------------------------------------------------------------------------------------------------------------
# Rules: id -> (CWE, OWASP 2021, severity, title, plain explanation, fix, payload)
# ------------------------------------------------------------------------------------------------------------------------------
R = {
    "sqli": ("CWE-89", "A03 Injection", "CRITICAL", "SQL injection", "User input is placed into a database query as text, so an attacker can rewrite the query.",
             "Pass values as parameters: cursor.execute('SELECT ... WHERE id = ?', (value,)). Never build the query with f-strings, +, % or .format().", "' OR '1'='1"),
    "sqli_built": ("CWE-89", "A03 Injection", "HIGH", "SQL built from text", "The query is assembled by string formatting. Even if today's values are safe, one future change makes it injectable.",
                   "Use placeholders and pass the values separately.", "' OR '1'='1"),
    "cmdi": ("CWE-78", "A03 Injection", "CRITICAL", "Command injection", "User input reaches a shell command, so an attacker can run their own commands.",
             "Do not use a shell. Call subprocess.run([program, arg1, arg2], shell=False) with a fixed program and validated arguments.", "; echo PWNED"),
    "codei": ("CWE-95", "A03 Injection", "CRITICAL", "Code injection", "Text is executed as code (eval/exec/compile/import by name).",
              "Remove eval/exec. Parse data with json or ast.literal_eval and dispatch through a fixed dictionary of allowed functions.", "__import__('os').getcwd()"),
    "pathtrav": ("CWE-22", "A01 Broken Access Control", "HIGH", "Path traversal", "A user-supplied file name can climb out of the intended folder (../../etc/passwd).",
                 "Resolve the path and check it stays inside the base folder: provably_secure.safe_join(base, name).", "../../etc/passwd"),
    "zipslip": ("CWE-22", "A01 Broken Access Control", "HIGH", "Unsafe archive extraction", "Extracting an archive without checking member names lets it write files anywhere (zip slip).",
                "Extract members one at a time through provably_secure.safe_join, or use tarfile filter='data'.", "../evil.txt"),
    "ssrf": ("CWE-918", "A10 SSRF", "HIGH", "Server-side request forgery", "The server fetches a URL chosen by the user, so an attacker can make it call internal services or cloud metadata.",
             "Check the URL against an allow-list of hosts and block private addresses: provably_secure.safe_url(url, allowed_hosts).", "http://169.254.169.254/latest/meta-data/"),
    "deser": ("CWE-502", "A08 Software and Data Integrity", "CRITICAL", "Unsafe deserialisation", "Loading pickled/marshalled/YAML data from an untrusted source can run arbitrary code.",
              "Use json for data. For YAML use yaml.safe_load. Never unpickle untrusted bytes.", "cos\nsystem\n"),
    "xxe": ("CWE-611", "A05 Security Misconfiguration", "HIGH", "XML external entity / entity expansion", "The standard XML parsers can be made to read files or exhaust memory.",
            "Use defusedxml instead of xml.etree / xml.dom / lxml for untrusted XML.", "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/passwd'>]>"),
    "ssti": ("CWE-1336", "A03 Injection", "CRITICAL", "Template injection", "User input is used as the template itself, which lets an attacker run code inside it.",
             "Render a fixed template and pass user data as variables.", "{{7*7}}"),
    "xss": ("CWE-79", "A03 Injection", "HIGH", "Cross-site scripting", "User input is placed into HTML without escaping, so an attacker can run script in other people's browsers.",
            "Escape with html.escape (or use an auto-escaping template). Never mark user text as safe.", "<script>alert(1)</script>"),
    "redirect": ("CWE-601", "A01 Broken Access Control", "MEDIUM", "Open redirect", "The app redirects to an address chosen by the user, which is used in phishing.",
                 "Only redirect to relative paths or an allow-list: provably_secure.safe_redirect_target(url, allowed_hosts).", "https://evil.example"),
    "hdrinj": ("CWE-113", "A03 Injection", "MEDIUM", "Header injection", "User input goes into a response header; a newline lets an attacker add headers or split the response.",
               "Reject CR/LF characters before putting text in a header.", "x\r\nSet-Cookie: a=b"),
    "secret": ("CWE-798", "A07 Identification and Authentication Failures", "CRITICAL", "Hardcoded secret", "A password, key or token is written in the code, so anyone with the code has it.",
               "Read it from an environment variable or secret manager and rotate the leaked one.", ""),
    "weakhash": ("CWE-328", "A02 Cryptographic Failures", "HIGH", "Weak password hashing", "MD5/SHA-1/plain SHA-256 are fast to brute-force. Passwords need a slow, salted hash.",
                 "Use provably_secure.hash_password (scrypt) and verify_password.", ""),
    "plainpw": ("CWE-256", "A02 Cryptographic Failures", "CRITICAL", "Plain-text password comparison", "The password is compared directly with a stored value, which means it is stored unhashed.",
                "Store only a salted slow hash and compare with provably_secure.verify_password.", ""),
    "weakrand": ("CWE-338", "A02 Cryptographic Failures", "HIGH", "Predictable random number for a secret", "The random module is predictable; a token made from it can be guessed.",
                 "Use the secrets module: provably_secure.new_token().", ""),
    "tls": ("CWE-295", "A02 Cryptographic Failures", "HIGH", "Certificate checking turned off", "Disabling TLS verification lets anyone on the network impersonate the server.",
            "Remove verify=False / CERT_NONE.", ""),
    "debug": ("CWE-489", "A05 Security Misconfiguration", "HIGH", "Debug mode enabled", "Debug mode exposes an interactive console and stack traces to attackers.",
              "Never enable debug outside local development; read it from configuration that defaults to off.", ""),
    "flasksecret": ("CWE-798", "A07 Identification and Authentication Failures", "CRITICAL", "Hardcoded session signing key", "A fixed SECRET_KEY lets anyone forge session cookies.",
                    "Generate it once with secrets.token_hex(32) and load it from the environment.", ""),
    "cookie": ("CWE-614", "A05 Security Misconfiguration", "MEDIUM", "Cookie without safety flags", "A cookie set without HttpOnly, Secure and SameSite can be stolen by scripts or sent across sites.",
               "Set httponly=True, secure=True, samesite='Lax' (or 'Strict').", ""),
    "cors": ("CWE-942", "A05 Security Misconfiguration", "HIGH", "Open CORS", "Allowing every origin (especially with credentials) lets any website read your users' data.",
             "List the exact origins you trust.", ""),
    "csrf": ("CWE-352", "A01 Broken Access Control", "HIGH", "CSRF protection disabled", "State-changing requests can be forged from another site.",
             "Keep CSRF protection on, or use provably_secure.csrf_token/verify_csrf.", ""),
    "jwt": ("CWE-347", "A02 Cryptographic Failures", "CRITICAL", "Token signature not checked", "Accepting unsigned or unverified tokens lets anyone log in as anyone.",
            "Always verify the signature with a fixed algorithm list.", ""),
    "upload": ("CWE-434", "A04 Insecure Design", "HIGH", "Unrestricted file upload", "The file is saved under the name the client sent, with any extension, so an attacker can overwrite files, plant a script or upload a page that runs in other users' browsers.",
               "Save through provably_secure.safe_upload(file, folder): random server-side name, extension allow-list, size cap.", "../../app.py or shell.html"),
    "tmp": ("CWE-377", "A05 Security Misconfiguration", "MEDIUM", "Insecure temporary file", "mktemp returns a name that another process can grab first.",
            "Use tempfile.mkstemp or NamedTemporaryFile.", ""),
    "perm": ("CWE-732", "A05 Security Misconfiguration", "MEDIUM", "World-writable permissions", "Mode 777/666 lets any user on the machine change the file.",
             "Use 0o600 for secrets and 0o644/0o755 otherwise.", ""),
    "assertauth": ("CWE-617", "A01 Broken Access Control", "MEDIUM", "assert used as a security check", "Python removes assert statements when run with -O, so the check disappears.",
                   "Raise an explicit exception instead.", ""),
    "authn": ("CWE-306", "A07 Identification and Authentication Failures", "HIGH", "State-changing route with no login check", "This route changes data but nothing in it or on it checks who the caller is.",
              "Require login (decorator or dependency) and use default-deny routing (provably_ai.shield).", ""),
    "authn_read": ("CWE-200", "A01 Broken Access Control", "HIGH", "Route returns account data with no login check", "This route reads from an account-type table (users, orders, payments...) and nothing checks who is asking, so anyone can pull the data.",
                   "Require login first, then check the record belongs to the caller.", "anonymous GET for another user's row"),
    "idor": ("CWE-639", "A01 Broken Access Control", "HIGH", "Record fetched by ID with no ownership check", "The route loads a record using an ID from the request but never checks that it belongs to the caller.",
             "Load by (id AND owner) or call the policy kernel before returning or changing the record.", "another user's id"),
    "massassign": ("CWE-915", "A01 Broken Access Control", "HIGH", "Mass assignment", "Request fields are copied straight into a record, so an attacker can set fields such as role or is_admin.",
                   "Copy only an explicit allow-list of fields.", '{"is_admin": true}'),
    "race": ("CWE-362", "A04 Insecure Design", "MEDIUM", "Check-then-update race", "The value is checked and then changed in separate steps, so two requests at once can both pass the check (double spend).",
             "Do the check and the update in one atomic step: a database transaction with a lock, or a single UPDATE ... WHERE balance >= amount.", ""),
    "toctou": ("CWE-367", "A04 Insecure Design", "LOW", "Check-then-use on a file", "The file can change between the check and the use.",
               "Open the file directly and handle the error.", ""),
    "timing": ("CWE-208", "A02 Cryptographic Failures", "MEDIUM", "Secret compared with ==", "A normal comparison stops at the first difference, which leaks how much of a secret matched.",
               "Use provably_secure.constant_time_equals (hmac.compare_digest).", ""),
    "enum": ("CWE-204", "A07 Identification and Authentication Failures", "MEDIUM", "Login reveals which accounts exist", "Different messages for 'no such user' and 'wrong password' let attackers list valid accounts.",
             "Return one identical message for both.", ""),
    "ratelimit": ("CWE-307", "A07 Identification and Authentication Failures", "MEDIUM", "No limit on login attempts", "Without a limit, attackers can try millions of passwords.",
                  "Apply provably_secure.RateLimiter or the Shield's login limiter.", ""),
    "redos": ("CWE-1333", "A04 Insecure Design", "MEDIUM", "Regex that can hang", "A pattern with nested repeats can take exponential time on crafted input.",
              "Rewrite the pattern without nested quantifiers, or cap the input length.", "a" * 40 + "!"),
    "shield": ("CWE-693", "A05 Security Misconfiguration", "MEDIUM", "No security headers or cross-site request check", "The app sets no browser security headers (CSP, clickjacking, MIME sniffing, HSTS) and accepts form posts from other sites, which enables clickjacking and CSRF.",
               "Call provably_secure.shield(app) once after creating the app.", "a malicious page that posts to this app using the visitor's login"),
    "policy": ("CWE-862", "A01 Broken Access Control", "MEDIUM", "No default-deny route policy", "Any route that nobody remembered to protect (or that gets added later) is open to everyone, which is how most 'forgotten admin page' breaches happen.",
               "Call provably_secure.policy_gate(app, {\"GET /\": [\"anon\", \"user\"], \"POST /pay\": [\"user\"], \"GET /admin\": [\"admin\"]}) so only declared (role, route) pairs are allowed.", "requesting a route that was added later and never protected"),
    "strictparams": ("CWE-20", "A04 Insecure Design", "LOW", "Routes accept fields they never read", "No route restricts which query/form fields it accepts, so attackers can probe for hidden parameters and send oversized or unexpected input freely.",
                    "Call provably_secure.allow_params(app, {route: [fields]}) so each route accepts only what it uses.", "adding ?admin=1 or a 10 MB value to a route that never reads it"),
    "bodylimit": ("CWE-770", "A04 Insecure Design", "LOW", "No request size limit", "The app reads whole request bodies but sets no maximum, so one huge upload can exhaust memory.",
                  "Set MAX_CONTENT_LENGTH (Flask) or a body-size check.", ""),
    "errleak": ("CWE-209", "A05 Security Misconfiguration", "MEDIUM", "Internal error details sent to the user", "Returning exception text or tracebacks shows attackers how the app works.",
                "Log the details and return a generic message.", ""),
    "logsecret": ("CWE-532", "A09 Logging Failures", "MEDIUM", "Secret written to a log", "Passwords and tokens in logs are readable by everyone with log access.",
                  "Never log secrets; log an identifier instead.", ""),
    "bind": ("CWE-1327", "A05 Security Misconfiguration", "LOW", "Listens on all network interfaces", "Binding to 0.0.0.0 exposes the service to the whole network.",
             "Bind to 127.0.0.1 unless it must be public, and put it behind a reverse proxy.", ""),
    "unvalidatedint": ("CWE-20", "A03 Injection", "LOW", "Request value used as a number without bounds", "Huge or negative numbers from a request can cause slowdowns or logic errors.",
                       "Validate with provably_secure.bounded_int(value, lo, hi).", "-1"),
    # JavaScript
    "js_eval": ("CWE-95", "A03 Injection", "CRITICAL", "eval / new Function", "Text is executed as code.", "Remove eval and new Function; use JSON.parse.", ""),
    "js_innerhtml": ("CWE-79", "A03 Injection", "HIGH", "innerHTML / document.write with dynamic data", "Untrusted text becomes live HTML.", "Use textContent, or sanitise with DOMPurify.", "<img src=x onerror=alert(1)>"),
    "js_sqli": ("CWE-89", "A03 Injection", "CRITICAL", "SQL built with a template literal", "A query string is built from variables.", "Use placeholders ($1 or ?) and pass values separately.", "' OR '1'='1"),
    "js_cmdi": ("CWE-78", "A03 Injection", "CRITICAL", "Command built from variables", "A shell command is built from variables.", "Use execFile with an argument array.", "; echo PWNED"),
    "js_cors": ("CWE-942", "A05 Security Misconfiguration", "HIGH", "Open CORS", "Every website may call this API.", "List trusted origins.", ""),
    "js_tls": ("CWE-295", "A02 Cryptographic Failures", "HIGH", "TLS checking disabled", "rejectUnauthorized: false accepts forged certificates.", "Remove it.", ""),
    "js_jwt": ("CWE-347", "A02 Cryptographic Failures", "CRITICAL", "JWT signature not checked", "jwt.decode does not verify; algorithm 'none' accepts unsigned tokens.", "Use jwt.verify with an algorithms list.", ""),
    "js_rand": ("CWE-338", "A02 Cryptographic Failures", "HIGH", "Math.random for a secret", "Math.random is predictable.", "Use crypto.randomBytes / crypto.randomUUID.", ""),
    "js_path": ("CWE-22", "A01 Broken Access Control", "HIGH", "File path from the request", "A request value is used as a file path.", "Resolve and check the path stays inside the base folder.", "../../etc/passwd"),
    "js_proto": ("CWE-1321", "A08 Software and Data Integrity", "HIGH", "Prototype pollution", "Merging request objects into another object can overwrite Object.prototype.", "Reject __proto__/constructor keys or use Object.create(null).", '{"__proto__": {"x": 1}}'),
    "js_redirect": ("CWE-601", "A01 Broken Access Control", "MEDIUM", "Open redirect", "The app redirects to an address from the request.", "Redirect only to relative paths or an allow-list.", "https://evil.example"),
    "js_ssrf": ("CWE-918", "A10 SSRF", "HIGH", "Server-side request forgery", "The server fetches a URL from the request.", "Allow-list hosts and block private addresses.", "http://169.254.169.254/"),
}
SEV_W = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 1}


def finding(rule, line, col=0, evidence="", message="", confidence="high", file="<code>", extra=None):
    cwe, owasp, sev, title, why, fix, payload = R[rule]
    f = {"rule": rule, "cwe": cwe, "owasp": owasp, "severity": sev, "title": title, "why": why, "fix": fix, "line": line, "col": col,
         "evidence": evidence.strip()[:160], "message": message or title, "confidence": confidence, "file": file, "payload": payload}
    if extra:
        f.update(extra)
    return f


# ------------------------------------------------------------------------------------------------------------------------------
# Python: taint analysis
# ------------------------------------------------------------------------------------------------------------------------------
SOURCE_PREFIXES = ("request.", "flask.request.", "self.request.", "req.", "event.", "websocket.", "sys.argv", "input(", "environ.get(")
SOURCE_ROOTS = {"request", "req"}
SANITIZERS = {"int", "float", "bool", "len", "abs", "round", "hash", "id", "ord", "chr", "bin", "hex", "isinstance", "type", "range", "enumerate",
              "shlex.quote", "quote", "os.path.basename", "basename", "secure_filename", "html.escape", "escape", "escape_html", "clean_header", "reject_privileged", "safe_extract", "safe_xml", "safe_upload", "markupsafe.escape", "urllib.parse.quote",
              "quote_plus", "uuid.UUID", "UUID", "Decimal", "bounded_int", "safe_join", "safe_url", "safe_redirect_target", "validate", "Path.name",
              "uuid4", "token_hex", "token_urlsafe", "hash_password", "constant_time_equals", "re.escape", "json.dumps", "dumps"}
SAFE_METHODS = {"isdigit", "isalnum", "isalpha", "startswith", "endswith", "isnumeric", "isidentifier", "isascii", "__len__", "count", "index", "find"}
ROUTE_DECOS = {"route", "get", "post", "put", "delete", "patch", "websocket", "api_view", "options", "head"}
STATE_DECOS = {"post", "put", "delete", "patch"}
AUTH_WORDS = re.compile(r"is_?admin|admin|session|login_required|jwt_required|auth|permission|requires|depends|current_user|get_current|verify_token|authenticated|token_required|"
                        r"role_required|admin_required|session\[|g\.user|request\.user|oauth|bearer|policy|shield", re.I)
SECRETISH = re.compile(r"(password|passwd|secret|token|api_?key|hmac|signature|digest|auth_?key)", re.I)
OWNERISH = re.compile(r"(owner|user_?id|author|created_by|account_id|customer|tenant|org)", re.I)
TOKENFN = re.compile(r"(token|secret|password|passwd|otp|nonce|csrf|reset|api_?key|session|salt|verification|invite|code)", re.I)
MONEYISH = re.compile(r"(balance|credits?|stock|quantity|inventory|funds|points|wallet|coins)", re.I)
LOCKISH = re.compile(r"lock|atomic|transaction|with_for_update|select_for_update|BEGIN IMMEDIATE|synchronized|Semaphore|Mutex|compare_and_swap|F\(", re.I)


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        b = dotted(node.value)
        return f"{b}.{node.attr}" if b else node.attr
    if isinstance(node, ast.Call):
        b = dotted(node.func)
        return f"{b}()" if b else None
    if isinstance(node, ast.Subscript):
        b = dotted(node.value)
        return f"{b}[]" if b else None
    return None


def last(d):
    return (d or "").split(".")[-1]


def const_str(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


class Func:
    def __init__(self, node, cls=None):
        self.node, self.name, self.cls = node, node.name, cls
        a = node.args
        self.params = [x.arg for x in a.posonlyargs + a.args] + [x.arg for x in a.kwonlyargs]
        if self.params and self.params[0] in ("self", "cls"):
            self.self_off = 1
        else:
            self.self_off = 0
        self.decos = [dotted(d.func if isinstance(d, ast.Call) else d) or "" for d in node.decorator_list]
        self.deco_text = " ".join(ast.unparse(d) for d in node.decorator_list)
        self.is_route = any(last(d) in ROUTE_DECOS for d in self.decos) or (self.params[:1] == ["request"] and not self.self_off)
        self.methods = set()
        for d in node.decorator_list:
            if isinstance(d, ast.Call):
                if last(dotted(d.func)) in STATE_DECOS:
                    self.methods.add(last(dotted(d.func)).upper())
                for kw in d.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        self.methods |= {e.value.upper() for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            elif last(dotted(d)) in STATE_DECOS:
                self.methods.add(last(dotted(d)).upper())
        self.state_changing = bool(self.methods & {"POST", "PUT", "DELETE", "PATCH"})
        self.ret_deps = set()
        self.ret_source = False
        self.sink_params = {}      # param index -> set of rules


class Dealias(ast.NodeTransformer):
    """Rewrite `import os as o` / `from os import popen as p` so sinks are recognised under their real names."""
    def __init__(self, tree):
        self.mod, self.sym = {}, {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname and a.asname != a.name:
                        self.mod[a.asname] = a.name
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    if a.name != "*":
                        self.sym[a.asname or a.name] = f"{n.module}.{a.name}"
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Name) and n.value.id == "request":
                self.sym[n.targets[0].id] = "request"
        self.table = {}        # TABLE = {'key': func}: a call TABLE['key'](x) is a call of func(x)
        for n in tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Dict):
                for k, v in zip(n.value.keys, n.value.values):
                    if isinstance(k, ast.Constant) and isinstance(v, (ast.Name, ast.Attribute)):
                        self.table[(n.targets[0].id, k.value)] = v

    def visit_Call(self, node):
        self.generic_visit(node)
        f = node.func
        if isinstance(f, ast.Subscript) and isinstance(f.value, ast.Name) and isinstance(f.slice, ast.Constant) and (f.value.id, f.slice.value) in self.table:
            node.func = ast.copy_location(self.visit(__import__("copy").deepcopy(self.table[(f.value.id, f.slice.value)])), f)
        return node

    def _expr(self, dotted_name, node):
        parts = dotted_name.split(".")
        cur = ast.Name(id=parts[0], ctx=ast.Load())
        for p in parts[1:]:
            cur = ast.Attribute(value=cur, attr=p, ctx=ast.Load())
        return ast.copy_location(cur, node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            if node.id in self.mod:
                return self._expr(self.mod[node.id], node)
            if node.id in self.sym:
                return self._expr(self.sym[node.id], node)
        return node


def dealias(tree):
    d = Dealias(tree)
    if not (d.mod or d.sym or d.table):
        return tree
    return ast.fix_missing_locations(d.visit(tree))


class Analyzer:
    def __init__(self, code, filename="<code>"):
        self.code, self.file = code, filename
        self.lines = code.split("\n")
        self.tree = dealias(ast.parse(code))
        self.funcs = {}
        self.by_name = {}
        self.findings = {}
        self.module_flags = {"max_len": False}
        self._collect()

    def ev(self, node):
        i = getattr(node, "lineno", 1)
        return self.lines[i - 1] if 0 < i <= len(self.lines) else ""

    def add(self, rule, node, message="", confidence="high", extra=None):
        key = (rule, getattr(node, "lineno", 0))
        if key not in self.findings:
            self.findings[key] = finding(rule, getattr(node, "lineno", 0), getattr(node, "col_offset", 0), self.ev(node), message, confidence, self.file, extra)

    def _collect(self):
        def walk(body, cls=None):
            for n in body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    f = Func(n, cls)
                    self.funcs[id(n)] = f
                    self.by_name.setdefault(n.name, []).append(f)
                    walk(n.body, cls)
                elif isinstance(n, ast.ClassDef):
                    walk(n.body, n.name)
        walk(self.tree.body)
        self.classes = {n.name for n in ast.walk(self.tree) if isinstance(n, ast.ClassDef)}
        self.inst = {}         # variable -> class it was built from (`svc = Service()`), so `svc.run(x)` can be followed into Service.run
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id in self.classes:
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        self.inst[t.id] = n.value.func.id

    def resolve(self, node):
        """which local function(s) does this call go to? plain names and self./cls. calls, plus calls through a class (`Helper.run(x)`), a fresh instance (`Helper().run(x)`)
        or a variable built from a class (`h = Helper(); h.run(x)`): the sink is often inside such a helper and the taint has to be followed there"""
        f = node.func
        if isinstance(f, ast.Name):
            return self.by_name.get(f.id)
        if not isinstance(f, ast.Attribute):
            return None
        v = f.value
        if dotted(v) in ("self", "cls"):
            return self.by_name.get(f.attr)
        cls = None
        if isinstance(v, ast.Name):
            cls = v.id if v.id in self.classes else self.inst.get(v.id)
        elif isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in self.classes:
            cls = v.func.id
        if cls is None:
            return None
        return [m for m in self.by_name.get(f.attr, []) if m.cls == cls] or None

    # ---- expression taint ----------------------------------------------------------------------------------------------
    def tainted(self, node, env, fn=None):
        if node is None:
            return False
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            return env.get(node.id, False)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            d = dotted(node) or ""
            if any(d.startswith(p) for p in SOURCE_PREFIXES) or d.split(".")[0].split("[")[0] in SOURCE_ROOTS:
                return True
            if isinstance(node, ast.Attribute) and env.get("$attr:" + d):
                return True
            return self.tainted(node.value, env, fn)
        if isinstance(node, ast.Call):
            return self.call_tainted(node, env, fn)
        if isinstance(node, ast.BinOp):
            return self.tainted(node.left, env, fn) or self.tainted(node.right, env, fn)
        if isinstance(node, ast.BoolOp):
            return any(self.tainted(v, env, fn) for v in node.values)
        if isinstance(node, ast.IfExp):
            return self.tainted(node.body, env, fn) or self.tainted(node.orelse, env, fn)
        if isinstance(node, ast.JoinedStr):
            return any(self.tainted(v.value, env, fn) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.tainted(e, env, fn) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.tainted(v, env, fn) for v in node.values if v is not None)
        if isinstance(node, ast.Starred):
            return self.tainted(node.value, env, fn)
        if isinstance(node, (ast.Await, ast.UnaryOp)):
            return False if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) else self.tainted(getattr(node, "value", getattr(node, "operand", None)), env, fn)
        if isinstance(node, ast.NamedExpr):
            return self.tainted(node.value, env, fn)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self.tainted(node.elt, env, fn) or any(self.tainted(g.iter, env, fn) for g in node.generators)
        return False

    def call_tainted(self, node, env, fn):
        d = dotted(node.func) or ""
        base = last(d)
        if d in SANITIZERS or base in SANITIZERS:
            return False
        if any(d.startswith(p) for p in SOURCE_PREFIXES) or d.startswith("input"):
            return True
        if isinstance(node.func, ast.Attribute):
            if base in SAFE_METHODS:
                return False
            if self.tainted(node.func.value, env, fn):
                return True
        args = list(node.args) + [k.value for k in node.keywords]
        targets = self.resolve(node)
        if targets and len(targets) == 1:
            t = targets[0]
            off = t.self_off if isinstance(node.func, ast.Attribute) else 0
            if t.ret_source:
                return True
            for i in t.ret_deps:
                j = i - off
                if 0 <= j < len(node.args) and self.tainted(node.args[j], env, fn):
                    return True
            for k in node.keywords:
                if k.arg in t.params and t.params.index(k.arg) in t.ret_deps and self.tainted(k.value, env, fn):
                    return True
            return False
        return any(self.tainted(a, env, fn) for a in args)

    def dynamic_str(self, node, env, fn):
        """True when the string is assembled from non-constant parts (formatting, concatenation, % or .format)."""
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return not (const_str(node.left) and const_str(node.right)) and (self.dynamic_str(node.left, env, fn) or self.dynamic_str(node.right, env, fn) or
                                                                                not const_str(node.left) or not const_str(node.right))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" and (node.args or node.keywords):
            return True
        if isinstance(node, ast.Name):
            return env.get("$dyn:" + node.id, False)
        return False

    # ---- sinks ---------------------------------------------------------------------------------------------------------
    def check_call(self, node, env, fn):
        d = dotted(node.func) or ""
        base = last(d)
        args = node.args
        a0 = args[0] if args else None
        t0 = self.tainted(a0, env, fn) if a0 is not None else False
        anyt = any(self.tainted(a, env, fn) for a in list(args) + [k.value for k in node.keywords])
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        sink = lambda rule, **k: self.sink_hit(rule, node, fn, **k)

        # SQL
        if base in ("execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "text", "mogrify") and a0 is not None and not (base == "text" and d == "text" and False):
            dyn = self.dynamic_str(a0, env, fn)
            if t0 or (dyn and anyt):
                sink("sqli")
            elif dyn and base in ("execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "mogrify"):
                sink("sqli_built", taint=False, confidence="medium")
        # command execution
        if d in ("os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput") and a0 is not None:
            if t0 or self.dynamic_str(a0, env, fn):
                sink("cmdi", taint=t0)
        if d.startswith("subprocess.") and base in ("run", "call", "check_call", "check_output", "Popen") and a0 is not None:
            shell = kw.get("shell")
            shell_on = isinstance(shell, ast.Constant) and shell.value is True
            if shell_on and (t0 or self.dynamic_str(a0, env, fn)):
                sink("cmdi", taint=t0)
            elif not shell_on and isinstance(a0, (ast.List, ast.Tuple)) and a0.elts and self.tainted(a0.elts[0], env, fn):
                sink("cmdi", taint=True, confidence="medium")
        # code
        if d in ("eval", "exec", "compile") and a0 is not None and not const_str(a0):
            sink("codei", taint=t0)
        if d in ("__import__", "importlib.import_module") and t0:
            sink("codei", taint=True)
        # files
        if (d in ("open", "io.open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "os.listdir", "os.makedirs", "send_file", "FileResponse") or
                base in ("read_text", "read_bytes", "write_text", "write_bytes", "send_file", "send_from_directory", "FileResponse")) and (t0 or (isinstance(node.func, ast.Attribute) and self.tainted(node.func.value, env, fn))):
            sink("pathtrav", taint=True)
        if d in ("shutil.copy", "shutil.copyfile", "shutil.move", "shutil.copy2", "os.rename") and anyt:
            sink("pathtrav", taint=True)
        if base in ("extractall", "extract") and (d.endswith("zip.extractall") or "tar" in d.lower() or "zip" in d.lower() or base == "extractall"):
            if not any(k.arg == "filter" for k in node.keywords):
                sink("zipslip", taint=False, confidence="medium")
        # network
        if (d.startswith(("requests.", "httpx.", "urllib.request.", "aiohttp.")) or d in ("urlopen", "urllib.urlopen")) and base in ("get", "post", "put", "delete", "head", "patch", "request", "urlopen", "Request") and t0:
            sink("ssrf", taint=True)
        if d.endswith(("session.get", "session.post", "client.get", "client.post")) and t0 and d.split(".")[0] in ("session", "client", "s", "http"):
            sink("ssrf", taint=True)
        # deserialisation
        if d in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "marshal.load", "dill.loads", "shelve.open", "jsonpickle.decode"):
            sink("deser", taint=t0)
        if d in ("yaml.load", "yaml.load_all", "yaml.unsafe_load") and not any(k.arg == "Loader" and "Safe" in ast.unparse(k.value) for k in node.keywords) and not (len(args) > 1 and "Safe" in ast.unparse(args[1])):
            sink("deser", taint=t0)
        # xml
        if d in ("ET.parse", "ET.fromstring", "ElementTree.parse", "ElementTree.fromstring", "etree.parse", "etree.fromstring", "minidom.parseString", "minidom.parse", "xml.dom.minidom.parseString", "xml.sax.parseString", "xml.etree.ElementTree.fromstring") and t0:
            sink("xxe", taint=True)
        # templates / html
        if base in ("render_template_string", "from_string") and t0:
            sink("ssti", taint=True)
        if d in ("Template", "jinja2.Template", "string.Template") and t0 and d != "string.Template":
            sink("ssti", taint=True)
        if base in ("Markup", "mark_safe") and t0:
            sink("xss", taint=True)
        if base in ("HttpResponse", "make_response", "Response", "HTMLResponse") and t0 and self.htmlish(a0):
            sink("xss", taint=True)
        if base in ("redirect", "HttpResponseRedirect", "RedirectResponse") and t0 and not self.guarded(fn, "redirect"):
            sink("redirect", taint=True)
        # headers
        if isinstance(node.func, ast.Attribute) and base in ("add_header", "set_header") and len(args) > 1 and self.tainted(args[1], env, fn):
            sink("hdrinj", taint=True)
        # misconfiguration
        if base == "run" and any(k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            self.add("debug", node)
        if base == "run" and any(k.arg == "host" and isinstance(k.value, ast.Constant) and k.value.value == "0.0.0.0" for k in node.keywords):
            self.add("bind", node, confidence="medium")
        for k in node.keywords:
            if k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False:
                self.add("tls", node)
            if k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True and base != "run":
                self.add("debug", node, confidence="medium")
        if d in ("ssl._create_unverified_context",) or (base == "check_hostname" and False):
            self.add("tls", node)
        if base in ("md5", "sha1") and d.startswith("hashlib") and anyt is not None:
            if any(SECRETISH.search(ast.unparse(a)) and re.search(r"pass|pwd", ast.unparse(a), re.I) for a in args):
                self.add("weakhash", node)
        if d in ("hashlib.sha256", "hashlib.sha512", "hashlib.sha1", "hashlib.md5") and any(re.search(r"pass(word)?|pwd|\bpw\b|\bpw_|_pw\b", ast.unparse(a), re.I) for a in args) and fn is not None and not re.search(r"hmac|pbkdf|scrypt|bcrypt", ast.unparse(fn.node)):
            self.add("weakhash", node)
        if base == "save" and node.args and len(node.args) == 1 and re.search(r"\.filename|secure_filename", ast.unparse(node.args[0])) and "safe_upload" not in ast.unparse(node):
            self.add("upload", node)
        if d in ("tempfile.mktemp",):
            self.add("tmp", node)
        if d in ("os.chmod",) and len(args) > 1 and isinstance(args[1], ast.Constant) and args[1].value in (0o777, 0o666):
            self.add("perm", node)
        if base in ("set_cookie",) and not (any(k.arg == "httponly" and getattr(k.value, "value", None) is True for k in node.keywords) and
                                           any(k.arg == "secure" and getattr(k.value, "value", None) is True for k in node.keywords) and any(k.arg == "samesite" for k in node.keywords)):
            self.add("cookie", node, confidence="medium")
        if base == "CORS" or (base == "add_middleware" and "CORSMiddleware" in ast.unparse(node)):
            txt = ast.unparse(node)
            if re.search(r"""['"]\*['"]""", txt) or (base == "CORS" and not node.keywords and len(args) == 1):
                self.add("cors", node)
        if base in ("decode",) and d.startswith("jwt"):
            txt = ast.unparse(node)
            if re.search(r"verify_signature['\"]\s*:\s*False|verify\s*=\s*False|['\"]none['\"]", txt) or (len(args) < 2 and "algorithms" not in txt and "key" not in txt):
                self.add("jwt", node)
        if base in ("csrf_exempt",):
            self.add("csrf", node, confidence="medium")
        # regex DoS
        if d in ("re.compile", "re.match", "re.search", "re.fullmatch", "re.findall", "re.sub", "re.split") and a0 is not None and const_str(a0) and self.redos(a0.value):
            self.add("redos", node)
        # secrets in logs
        if (d.startswith(("logging.", "logger.", "log.", "app.logger.")) or d == "print") and any(re.search(r"(password|passwd|secret|token|api_?key)", ast.unparse(a), re.I) and not const_str(a) for a in args):
            self.add("logsecret", node, confidence="medium")
        # unsafe getattr/setattr on user keys, mass assignment
        if base == "setattr" and len(args) > 1 and self.tainted(args[1], env, fn):
            self.add("massassign", node, confidence="medium")
        if base in ("update",) and isinstance(node.func, ast.Attribute) and dotted(node.func.value) and dotted(node.func.value).endswith("__dict__") and anyt:
            self.add("massassign", node)
        if anyt and any(isinstance(k.value, ast.Call) is False for k in node.keywords) and any(k.arg is None and self.tainted(k.value, env, fn) for k in node.keywords):
            if re.match(r"[A-Z]", base or "") or base in ("create", "update", "insert", "update_one", "insert_one"):
                self.add("massassign", node)
        if any(k.arg is None and self.tainted(k.value, env, fn) for k in node.keywords) and (re.match(r"[A-Z]", base or "") or base in ("create", "update")):
            self.add("massassign", node)
        # local function summary: passing taint into a function that reaches a sink
        targets = self.resolve(node)
        if targets and len(targets) == 1 and targets[0].sink_params:
            t = targets[0]
            off = t.self_off if isinstance(node.func, ast.Attribute) else 0
            for i, rules in t.sink_params.items():
                j = i - off
                if 0 <= j < len(args) and self.tainted(args[j], env, fn):
                    for rule in rules:
                        sink(rule, taint=True, via=t.name)

    def htmlish(self, node):
        txt = ast.unparse(node) if node is not None else ""
        return "<" in txt

    def guarded(self, fn, what):
        if fn is None:
            return False
        src = ast.unparse(fn.node)
        if what == "redirect":
            return bool(re.search(r"url_has_allowed_host_and_scheme|safe_redirect|is_safe_url|startswith\(\s*['\"]/['\"]\s*\)|allowed_hosts|urlparse\(.*\)\.(netloc|hostname)", src))
        if what == "path":
            return bool(re.search(r"(realpath|resolve)\(.*\)|safe_join|commonpath|is_relative_to|secure_filename|basename", src)) and bool(re.search(r"startswith|is_relative_to|commonpath|safe_join", src))
        if what == "ssrf":
            return bool(re.search(r"ipaddress|is_private|safe_url|allowed_hosts|ALLOWED|allowlist|whitelist", src))
        return False

    def sink_hit(self, rule, node, fn, taint=True, confidence="high", via=None):
        if rule == "pathtrav" and self.guarded(fn, "path"):
            confidence = "low"
        if rule == "ssrf" and self.guarded(fn, "ssrf"):
            confidence = "low"
        msg = ""
        if via:
            msg = f"untrusted data is passed to {via}(), which reaches a dangerous call"
        elif taint:
            msg = "untrusted input flows into this call"
        if getattr(self, "_probe", None) is not None:        # summary computation: just record that a sink was reached
            self._probe.add(rule)
            return
        self.add(rule, node, msg, confidence)

    def redos(self, pat):
        return bool(re.search(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*]|\((?:[^()\\]|\\.)*[+*]\)\{\d+,\}|\(\.\*\)[+*]|\(\w\+\)\+|\([^)]*\|[^)]*\)[+*]\s*[+*]", pat)) or \
            bool(re.search(r"\(([^()]*\w[+*][^()]*)\)[+*?]", pat) and re.search(r"(\\w|\.|\\S|\[[^\]]+\])[+*]\)[+*]", pat))

    # ---- statements ----------------------------------------------------------------------------------------------------
    def exec_block(self, body, env, fn):
        for st in body:
            self.exec_stmt(st, env, fn)

    def bind(self, target, val, dyn, env):
        if isinstance(target, ast.Name):
            env[target.id] = val
            env["$dyn:" + target.id] = dyn
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                self.bind(e, val, dyn, env)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, val, dyn, env)
        elif isinstance(target, ast.Attribute) and dotted(target):
            env["$attr:" + dotted(target)] = val          # `g.x = <user data>` taints later reads of g.x

    def visit_calls(self, node, env, fn):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                self.check_call(sub, env, fn)

    def exec_stmt(self, st, env, fn):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn is not None and id(st) in self.funcs and getattr(self, "_nest", 0) < 3:
            # a function defined inside another one sees the outer function's variables (a closure): run its body with the taint known at this point,
            # so `s = request.args[..]` followed by `def _inner(): return urlopen(s)` is not lost
            f = self.funcs[id(st)]
            inner = dict(env); inner.update({p: False for p in f.params})
            self._nest = getattr(self, "_nest", 0) + 1
            saved = getattr(f, "_ret_tainted", False)
            try:
                self.exec_block(st.body, inner, f)
            finally:
                self._nest -= 1; f._ret_tainted = saved
            return
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(st, ast.Assign):
            self.visit_calls(st.value, env, fn)
            v, dyn = self.tainted(st.value, env, fn), self.dynamic_str(st.value, env, fn)
            for t in st.targets:
                self.bind(t, v, dyn, env)
                self.assign_checks(t, st, env, fn)
        elif isinstance(st, ast.AnnAssign) and st.value is not None:
            self.visit_calls(st.value, env, fn)
            self.bind(st.target, self.tainted(st.value, env, fn), self.dynamic_str(st.value, env, fn), env)
        elif isinstance(st, ast.AugAssign):
            self.visit_calls(st.value, env, fn)
            if isinstance(st.target, ast.Name):
                env[st.target.id] = env.get(st.target.id, False) or self.tainted(st.value, env, fn)
                env["$dyn:" + st.target.id] = env.get("$dyn:" + st.target.id, False) or isinstance(st.op, ast.Add)
        elif isinstance(st, ast.Return):
            if st.value is not None:
                self.visit_calls(st.value, env, fn)
                if fn is not None:
                    self.return_checks(st, env, fn)
        elif isinstance(st, ast.Expr):
            self.visit_calls(st.value, env, fn)
        elif isinstance(st, ast.If):
            self.visit_calls(st.test, env, fn)
            e1, e2 = dict(env), dict(env)
            self.exec_block(st.body, e1, fn)
            self.exec_block(st.orelse, e2, fn)
            for k in set(e1) | set(e2):
                env[k] = e1.get(k, False) or e2.get(k, False)
            if self.is_guard(st):
                for n in ast.walk(st.test):
                    if isinstance(n, ast.Name):
                        env[n.id] = False
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            self.visit_calls(st.iter, env, fn)
            self.bind(st.target, self.tainted(st.iter, env, fn), False, env)
            for _ in range(2):
                self.exec_block(st.body, env, fn)
            self.exec_block(st.orelse, env, fn)
        elif isinstance(st, ast.While):
            self.visit_calls(st.test, env, fn)
            for _ in range(2):
                self.exec_block(st.body, env, fn)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for it in st.items:
                self.visit_calls(it.context_expr, env, fn)
                if it.optional_vars is not None:
                    self.bind(it.optional_vars, self.tainted(it.context_expr, env, fn), False, env)
            self.exec_block(st.body, env, fn)
        elif isinstance(st, ast.Try):
            self.exec_block(st.body, env, fn)
            for h in st.handlers:
                self.exec_block(h.body, env, fn)
            self.exec_block(st.orelse, env, fn)
            self.exec_block(st.finalbody, env, fn)
        elif isinstance(st, ast.Assert):
            self.visit_calls(st.test, env, fn)
            if fn is not None and AUTH_WORDS.search(ast.unparse(st.test)):
                self.add("assertauth", st)
        elif isinstance(st, (ast.Delete, ast.Raise)):
            for sub in ast.walk(st):
                if isinstance(sub, ast.Call):
                    self.check_call(sub, env, fn)

    def is_guard(self, st):
        """`if x not in ALLOWED: raise/return/abort`  or  `if not re.fullmatch(...)`: after it, x is validated."""
        if not st.body or st.orelse:
            return False
        tail = st.body[-1]
        ends = isinstance(tail, (ast.Raise, ast.Return, ast.Continue, ast.Break)) or (isinstance(tail, ast.Expr) and isinstance(tail.value, ast.Call) and last(dotted(tail.value.func)) in ("abort", "exit", "error", "HTTPException"))
        t = st.test
        neg = (isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not)) or (isinstance(t, ast.Compare) and any(isinstance(o, (ast.NotIn, ast.NotEq)) for o in t.ops))
        return ends and neg

    def assign_checks(self, target, st, env, fn):
        name = dotted(target) or ""
        if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
            name = f"{dotted(target.value) or ''}.{target.slice.value}"          # app.config["SECRET_KEY"] -> app.config.SECRET_KEY
        val = st.value
        if isinstance(val, ast.Constant) and isinstance(val.value, str) and len(val.value) >= 6:
            if re.search(r"(secret_key|SECRET_KEY)", name):
                self.add("flasksecret", st)
            elif re.search(r"(password|passwd|api_?key|secret|token|private_key)", name, re.I) and not re.search(r"(example|changeme|placeholder|<|\$\{|os\.environ|getenv)", val.value, re.I):
                self.add("secret", st, confidence="medium")
        if re.search(r"^(app\.config\.DEBUG|DEBUG|app\.debug)$", name) and isinstance(val, ast.Constant) and val.value is True:
            self.add("debug", st)
        if re.search(r"(WTF_CSRF_ENABLED|CSRF_ENABLED)", name) and isinstance(val, ast.Constant) and val.value is False:
            self.add("csrf", st)
        if re.search(r"SESSION_COOKIE_(SECURE|HTTPONLY)", name) and isinstance(val, ast.Constant) and val.value is False:
            self.add("cookie", st)
        if re.search(r"MAX_CONTENT_LENGTH", name):
            self.module_flags["max_len"] = True
        if isinstance(val, ast.Call) and dotted(val.func) in ("random.random", "random.randint", "random.choice", "random.getrandbits", "random.choices", "random.randrange") \
                and re.search(r"(token|secret|password|passwd|otp|nonce|session|csrf|api_?key|reset|code)", name, re.I):
            self.add("weakrand", st)
        if isinstance(val, ast.Call) and last(dotted(val.func)) in ("join",) and "random" in ast.unparse(val) and re.search(r"(token|secret|password|key|otp|session)", name, re.I):
            self.add("weakrand", st, confidence="medium")
        if fn is not None and TOKENFN.search(fn.name) and re.search(r"\brandom\.(random|randint|choice|choices|getrandbits|randrange|sample)\b", ast.unparse(val)) and "secrets" not in ast.unparse(val):
            self.add("weakrand", st, confidence="medium")
        if isinstance(val, ast.Call) and "random" in ast.unparse(val) and "secrets" not in ast.unparse(val) and re.search(r"(token|secret|otp|nonce|csrf|reset|api_?key)", name, re.I) and not any(f["rule"] == "weakrand" and f["line"] == st.lineno for f in self.findings.values()):
            self.add("weakrand", st, confidence="medium")
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute) and target.value.attr == "headers" and self.tainted(val, env, fn):
            self.add("hdrinj", st)

    def return_checks(self, st, env, fn):
        v = st.value
        if fn.is_route:
            if self.tainted(v, env, fn) and self.html_return(v):
                self.add("xss", st)
            src = ast.unparse(v)
            if re.search(r"str\(\s*(e|err|exc|ex|error)\s*\)|traceback\.format_exc|repr\(\s*(e|err|exc)\s*\)", src):
                self.add("errleak", st)
        if TOKENFN.search(fn.name) and re.search(r"\brandom\.(random|randint|choice|choices|getrandbits|randrange|sample)\b", ast.unparse(v)) and "secrets" not in ast.unparse(v):
            self.add("weakrand", st, confidence="medium")
        if self.tainted(v, env, fn):
            fn._ret_tainted = True

    def html_return(self, v):
        for n in ast.walk(v):
            if isinstance(n, ast.JoinedStr) and any(isinstance(p, ast.Constant) and "<" in str(p.value) for p in n.values):
                return True
            if isinstance(n, ast.BinOp) and any(isinstance(m, ast.Constant) and isinstance(m.value, str) and "<" in m.value for m in ast.walk(n)):
                return True
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and isinstance(n.func.value, ast.Constant) and "<" in str(n.func.value.value):
                return True
        return False

    # ---- driver --------------------------------------------------------------------------------------------------------
    def run_func(self, f, taint_params):
        env = {p: (i in taint_params) for i, p in enumerate(f.params)}
        f._ret_tainted = False
        self.exec_block(f.node.body, env, f)
        return f._ret_tainted

    def summaries(self):
        funcs = list(self.funcs.values())
        for _ in range(3):
            for f in funcs:
                for i, p in enumerate(f.params):
                    if i < f.self_off:
                        continue
                    self._probe = set()
                    saved = dict(self.findings)
                    rt = self.run_func(f, {i})
                    if rt:
                        f.ret_deps.add(i)
                    if self._probe:
                        f.sink_params[i] = set(self._probe)
                    self._probe = None
                    self.findings = saved
                f._ret_tainted = False
                self._probe = set()
                saved = dict(self.findings)
                if self.run_func(f, set()):
                    f.ret_source = True
                self._probe = None
                self.findings = saved

    def logic_checks(self, f):
        src = ast.unparse(f.node)
        name_l = f.name.lower()
        route_paths = []
        for d in f.node.decorator_list:
            if isinstance(d, ast.Call) and d.args and const_str(d.args[0]):
                route_paths.append(d.args[0].value.lower())
        path_text = " ".join(route_paths)
        has_auth = bool(AUTH_WORDS.search(f.deco_text) or AUTH_WORDS.search(src))
        if f.is_route and f.state_changing and not has_auth and not re.search(r"login|signin|register|signup|token|webhook|health|callback|public", name_l + path_text):
            self.add("authn", f.node, f"{f.name}() changes data but nothing checks who is calling", "medium")
        if f.is_route and not f.state_changing and not has_auth and not re.search(r"login|signin|register|signup|token|webhook|health|callback|public|static", name_l + path_text) \
                and re.search(r"\b(from|join|into|update)\s+[\"'`]?(users?|accounts?|customers?|members?|orders?|payments?|invoices?|messages?|profiles?|sessions?|tokens?|credentials?)\b", src, re.I):
            self.add("authn_read", f.node, f"{f.name}() returns account data but nothing checks who is asking", "medium")
        if f.is_route and re.search(r"login|signin|authenticate|token", name_l + path_text) and (f.state_changing or "POST" in f.methods or f.name.startswith(("login", "signin"))):
            if not re.search(r"limiter|rate_?limit|throttle|lockout|attempts|RateLimiter|slowapi|too_many", f.deco_text + src, re.I):
                self.add("ratelimit", f.node, confidence="medium")
            msgs = [n.value.lower() for n in ast.walk(f.node) if const_str(n)]
            u = any(re.search(r"(no such|unknown|not found|invalid|incorrect|wrong) (user|username|email|account)|user (not found|does not exist)", m) for m in msgs)
            p = any(re.search(r"(wrong|incorrect|invalid|bad) password|password (is )?(wrong|incorrect|invalid)", m) for m in msgs)
            if u and p:
                self.add("enum", f.node)
            for n in ast.walk(f.node):
                if isinstance(n, ast.Compare) and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops):
                    txt = ast.unparse(n)
                    if re.search(r"\.password\b|\bpassword_hash\b|\bstored_password\b", txt) and re.search(r"\bpassword\b|\bpwd\b", txt) and "hash" not in txt.lower().replace("password_hash", ""):
                        self.add("plainpw", n)
        if f.is_route:
            id_params = [p for p in f.params if re.search(r"(^id$|_id$|^uid$|^pk$|^uuid$|^slug$|^key$|^i$|^n$|^num$|^oid$|^rid$|^ident$|^item$)", p)]
            used = [p for p in id_params if re.search(rf"(\.get\(\s*{p}\b|\(\s*{p}\s*,\s*\)|id\s*=\s*{p}\b|\.get_or_404\(\s*{p}\b|\[\s*{p}\s*\]|WHERE\s+\w*id\w*\s*=.*{p}|filter_by\(\s*\w*id\w*\s*=\s*{p}|find_one\(.*{p}|objects\.get\(.*{p}|\.query\.get\(\s*{p})", src)]
            if used and not re.search(r"current_user|session\[|g\.user|request\.user|user_id\s*==|owner|\.user\s*==|policy|authorized|authorize|can_access|has_permission|capability|shield", src, re.I):
                self.add("idor", f.node, f"{f.name}() loads a record by {used[0]} without checking it belongs to the caller", "medium")
            req_id = re.search(r"request\.(?:args|form|values|json)\s*\[\s*['\"](?:id|user_id|uid|account_id|owner_id|pk)['\"]\s*\]|request\.(?:args|form|values)\.get\(\s*['\"](?:id|user_id|uid|account_id|owner_id|pk)['\"]", src)
            if req_id and re.search(r"\b(from|join|into|update)\s+[\"'`]?(users?|accounts?|profiles?|members?|customers?)\b", src, re.I) \
                    and not re.search(r"owner_only|current_user|session\[|g\.user|request\.user|owner|authorize|can_access|has_permission|policy", src, re.I):
                self.add("idor", f.node, f"{f.name}() uses a record id from the request on account data without checking it is the caller's own", "medium")
            if f.state_changing and not f.methods - {"GET"} == set() and re.search(r"\*\*\s*request\.(json|form|get_json\(\)|data|values)|\*\*\s*(data|payload|body|params)\b", src):
                for n in ast.walk(f.node):
                    if isinstance(n, ast.Call) and any(k.arg is None for k in n.keywords) and re.match(r"[A-Z]|create|update", last(dotted(n.func)) or ""):
                        self.add("massassign", n)
            if re.search(r"request\.(get_data|data|files|stream)|get_json\(", src) and not self.module_flags["max_len"] and not re.search(r"content_length|MAX_CONTENT|len\(.*data.*\)\s*[<>]", src):
                self.add("bodylimit", f.node, confidence="low")
        # check-then-update race on money-like attributes
        cmp_attrs, upd_attrs = set(), set()
        for n in ast.walk(f.node):
            if isinstance(n, ast.Compare):
                for e in [n.left] + list(n.comparators):
                    if isinstance(e, ast.Attribute) and MONEYISH.search(e.attr):
                        cmp_attrs.add(ast.unparse(e))
            if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute) and MONEYISH.search(n.target.attr):
                upd_attrs.add(ast.unparse(n.target))
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Attribute) and MONEYISH.search(t.attr):
                        upd_attrs.add(ast.unparse(t))
        if cmp_attrs & upd_attrs and not LOCKISH.search(src) and not LOCKISH.search(f.deco_text):
            self.add("race", f.node, f"{f.name}() checks {sorted(cmp_attrs & upd_attrs)[0]} and then changes it in separate steps", "medium")
        sql_txt = " ".join(const_str(n) and n.value.lower() or "" for n in ast.walk(f.node) if isinstance(n, ast.Constant) and isinstance(n.value, str))
        if f.is_route and f.state_changing and re.search(r"\bselect\b.*\bfrom\s+(\w+)", sql_txt) and re.search(r"\bupdate\s+(\w+)\s+set", sql_txt) and not LOCKISH.search(src) \
                and not re.search(r"begin\s+immediate|for\s+update|rowcount|returning|used\s*=\s*0\s+and|and\s+\w+\s*=\s*0", sql_txt + src, re.I) \
                and set(re.findall(r"from\s+(\w+)", sql_txt)) & set(re.findall(r"update\s+(\w+)\s+set", sql_txt)):
            self.add("race", f.node, f"{f.name}() reads a row and then updates it in separate steps; two requests can both pass the check", "medium")
        # time-of-check/time-of-use on files
        for n in ast.walk(f.node):
            if isinstance(n, ast.If) and isinstance(n.test, ast.Call) and dotted(n.test.func) in ("os.path.exists", "os.path.isfile", "os.access", "path.exists"):
                if any(isinstance(m, ast.Call) and dotted(m.func) in ("open",) for b in n.body for m in ast.walk(b)):
                    self.add("toctou", n)
        # timing-unsafe comparison of secrets
        for n in ast.walk(f.node):
            if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.Eq, ast.NotEq)):
                l, r = n.left, n.comparators[0]
                if isinstance(l, ast.Constant) or isinstance(r, ast.Constant):
                    continue
                ls, rs = ast.unparse(l), ast.unparse(r)
                if (SECRETISH.search(ls) or SECRETISH.search(rs)) and not re.search(r"len\(|is None|\.get\(.*\)\s*is|\bNone\b|\.count|type\(", ls + rs) and not re.search(r"(_id|_len|_type|_name|_count|_at|_url)\b", ls + rs):
                    if not (f.name.startswith("test_")):
                        self.add("timing", n, confidence="medium")

    def module_checks(self):
        for n in self.tree.body:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    self.assign_checks(t, n, {}, None)
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
                self.check_call(n.value, {}, None)
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Call) and not any(isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)) and n in ast.walk(p) for p in ast.walk(self.tree) if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)) and False):
                pass

    def shield_check(self):
        flask_assign = next((st for st in self.tree.body if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) and last(dotted(st.value.func)) == "Flask"), None)
        if flask_assign is not None and not re.search(r"shield\(|Talisman|X-Frame-Options|Content-Security-Policy|flask_wtf|CSRFProtect", ast.unparse(self.tree)):
            self.add("shield", flask_assign, "Flask app has no security headers or cross-site request check", "medium")
        if flask_assign is not None and re.search(r"@\w+\.(route|get|post|put|delete|patch)\(", ast.unparse(self.tree)) and "policy_gate(" not in ast.unparse(self.tree):
            self.add("policy", flask_assign, "no default-deny policy: undeclared routes are open", "medium")
        if flask_assign is not None and not re.search(r"allow_params\(", ast.unparse(self.tree)) and re.search(r"request\.(args|form|values)", ast.unparse(self.tree)):
            self.add("strictparams", flask_assign, "routes accept fields they never read", "low")

    def run(self):
        try:
            self.shield_check()
            for st in self.tree.body:      # size limit is set at module level: it must be known before functions are checked
                if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and "MAX_CONTENT_LENGTH" in ast.unparse(st):
                    self.module_flags["max_len"] = True
            self.summaries()
            for f in self.funcs.values():
                taint = set(range(f.self_off, len(f.params))) if f.is_route else set()
                self.run_func(f, taint)
                self.logic_checks(f)
            top = [st for st in self.tree.body if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
            env = {}
            self.exec_block(top, env, None)
            for n in self.tree.body:
                if isinstance(n, ast.Assign):
                    for t in n.targets:
                        self.assign_checks(t, n, {}, None)
        except RecursionError:
            pass
        return sorted(self.findings.values(), key=lambda f: (f["line"], f["rule"]))


def audit_python(code, filename="<code>"):
    try:
        return Analyzer(code, filename).run() + audit_secrets(code, filename, skip_assign=True)
    except SyntaxError as e:
        return [finding("secret", e.lineno or 1, 0, "", f"could not parse {filename}: {e.msg}", "low", filename)][:0] + audit_secrets(code, filename)


# ------------------------------------------------------------------------------------------------------------------------------
# Secrets (any language)
# ------------------------------------------------------------------------------------------------------------------------------
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "an AWS access key"), (r"AIza[0-9A-Za-z_\-]{35}", "a Google API key"), (r"\bsk-[A-Za-z0-9_\-]{20,}", "an API secret key"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY", "a private key"), (r"\bghp_[A-Za-z0-9]{36}", "a GitHub token"), (r"\bgithub_pat_[A-Za-z0-9_]{50,}", "a GitHub token"),
    (r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "a Slack token"), (r"\bsk_live_[0-9a-zA-Z]{20,}", "a Stripe live key"), (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "a JWT"),
    (r"(?i)\b(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://[^\s:/@]+:[^\s@]{3,}@", "a database URL with a password"),
]
GENERIC_SECRET = re.compile(r"""(?ix)\b(password|passwd|pwd|secret|api_?key|access_?key|auth_?token|private_?key|client_?secret)\w*\s*[:=]\s*["']([^"'\s]{8,})["']""")
PLACEHOLDER = re.compile(r"(?i)(example|changeme|placeholder|your[_-]|xxx|<.*>|\$\{|%\(|os\.environ|getenv|process\.env|\*{3,}|dummy|test|sample|redacted|todo|none|null)")


def entropy(s):
    from math import log2
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * log2(s.count(c) / len(s)) for c in set(s))


def audit_secrets(text, filename="<code>", skip_assign=False):
    out = []
    for i, line in enumerate(text.split("\n"), 1):
        for pat, what in SECRET_PATTERNS:
            if re.search(pat, line):
                out.append(finding("secret", i, 0, line, f"{filename} contains {what}", "high", filename))
                break
        else:
            m = GENERIC_SECRET.search(line)
            if m and not skip_assign and not PLACEHOLDER.search(m.group(2)) and entropy(m.group(2)) > 2.5:
                out.append(finding("secret", i, 0, line, f"hardcoded {m.group(1)}", "medium", filename))
    return out


# ------------------------------------------------------------------------------------------------------------------------------
# JavaScript / TypeScript: source patterns (lower precision than the Python analysis, and labelled as such)
# ------------------------------------------------------------------------------------------------------------------------------
JS_RULES = [
    ("js_eval", r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'`]|setInterval\s*\(\s*[\"'`]"),
    ("js_innerhtml", r"\.innerHTML\s*[+]?=\s*(?![\"'`]\s*[;)]?\s*$)(?!\s*[\"'][^\"'$+]*[\"']\s*;)|document\.write(ln)?\s*\(|dangerouslySetInnerHTML|\.outerHTML\s*="),
    ("js_sqli", r"\.(query|execute|raw|all|get|run)\s*\(\s*`[^`]*\$\{|\.(query|execute|raw)\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
    ("js_cmdi", r"\b(exec|execSync|spawn|spawnSync)\s*\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)|child_process[^;\n]*\bexec\b\s*\(\s*[a-zA-Z_]"),
    ("js_cors", r"cors\(\s*\)|origin\s*:\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*"),
    ("js_tls", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"),
    ("js_jwt", r"jwt\.decode\s*\(|algorithms?\s*:\s*\[?\s*[\"']none[\"']|ignoreExpiration\s*:\s*true"),
    ("js_rand", r"(?i)(token|secret|password|key|otp|nonce|session|csrf)\w*\s*[:=][^;\n]*Math\.random\s*\("),
    ("js_path", r"(readFile(Sync)?|createReadStream|sendFile|writeFile(Sync)?|unlink(Sync)?)\s*\(\s*(req\.|`[^`]*\$\{req\.|[^,)]*\+\s*req\.)"),
    ("js_proto", r"(_\.merge|lodash\.merge|Object\.assign|\$\.extend)\s*\([^)]*req\.(body|query)|\[\s*req\.(body|query|params)\.[a-zA-Z]+\s*\]\s*="),
    ("js_redirect", r"res\.redirect\s*\(\s*(req\.|`[^`]*\$\{req\.)"),
    ("js_ssrf", r"(axios|fetch|got|request|http\.get|https\.get)(\.(get|post|put|delete))?\s*\(\s*(req\.(body|query|params)|`[^`]*\$\{req\.)"),
]


def audit_js(code, filename="<code>"):
    out = []
    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        if line.strip().startswith(("//", "*", "/*")):
            continue
        for rule, pat in JS_RULES:
            if re.search(pat, line):
                out.append(finding(rule, i, 0, line, "", "medium", filename))
        if re.search(r"(?i)app\.use\(\s*(?!helmet)", line) is None:
            pass
    out += audit_secrets(code, filename)
    return out


# ------------------------------------------------------------------------------------------------------------------------------
# Front door
# ------------------------------------------------------------------------------------------------------------------------------
def audit_files(files):
    """files: {name: text}. Returns the full report dict."""
    findings = []
    for name, text in files.items():
        low = name.lower()
        if low.endswith(".py"):
            findings += audit_python(text, name)
        elif low.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            findings += audit_js(text, name)
        elif low.endswith((".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".txt", ".sh", ".dockerfile")) or low.endswith("dockerfile"):
            if not low.endswith(("package-lock.json", "yarn.lock")):
                findings += audit_secrets(text, name)
        else:
            findings += audit_secrets(text, name)
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["rule"], f["line"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    counts = {s: sum(1 for f in uniq if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    score = max(0, 100 - sum(SEV_W[f["severity"]] * (1 if f["confidence"] != "low" else 0.3) for f in uniq))
    blockers = [f for f in uniq if f["severity"] in ("CRITICAL", "HIGH") and f["confidence"] != "low"]
    return {"findings": uniq, "counts": counts, "score": round(score), "blockers": len(blockers), "passed": not blockers,
            "files": len(files), "digest": hashlib.sha256(json.dumps(sorted(files.items())).encode()).hexdigest()[:16]}


def render(report, limit=30):
    """Plain-text report for chat windows."""
    c = report["counts"]
    lines = [f"Provably audit: score {report['score']}/100 | {c['CRITICAL']} critical, {c['HIGH']} high, {c['MEDIUM']} medium, {c['LOW']} low | "
             f"{'PASS' if report['passed'] else 'BLOCKED: fix the critical/high findings before shipping'}"]
    for f in report["findings"][:limit]:
        lines.append(f"- [{f['severity']}] {f['title']} ({f['cwe']}) at {f['file']}:{f['line']}  {f['evidence'][:90]}\n    why: {f['why']}\n    fix: {f['fix']}")
    if len(report["findings"]) > limit:
        lines.append(f"... and {len(report['findings']) - limit} more")
    return "\n".join(lines)
