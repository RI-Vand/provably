"""tests_mcp - the local MCP server end to end over stdio, the way Claude Desktop uses it.   python3 tests_mcp.py"""
import json, os, shutil, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
SERVER = os.path.join(HERE, "mcp_server.py")
VULN = 'import os, sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route("/u")\ndef u():\n    c = sqlite3.connect("x.db")\n    return str(c.execute("SELECT * FROM t WHERE n=" + request.args["n"]).fetchall())\n'
SHOP = ('from flask import Flask, request, session\napp = Flask(__name__)\nBAL = {"a": 100}\n'
        '@app.route("/pay", methods=["POST"])\ndef pay():\n    BAL["a"] -= float(request.form["amount"])\n    return "ok"\n'
        '@app.route("/admin/users")\ndef users():\n    return "all users"\n')


def rpc(msgs, env=None, raw=None, timeout=120):
    e = {**os.environ, **(env or {})}
    data = raw if raw is not None else ("\n".join(json.dumps(m) for m in msgs) + "\n").encode("utf-8")
    p = subprocess.run([sys.executable, SERVER], input=data, capture_output=True, env=e, timeout=timeout)
    out = [json.loads(l) for l in p.stdout.decode("utf-8").splitlines() if l.strip()]
    return out, p.stderr.decode("utf-8", "replace")


def call(name, args, env=None):
    out, _ = rpc([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}], env)
    return out[0]["result"]


def text(res):
    return res["content"][0]["text"]


class Protocol(unittest.TestCase):
    def test_initialize_and_tool_list(self):
        out, err = rpc([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, {"jsonrpc": "2.0", "id": 3, "method": "ping"}])
        self.assertEqual([o["id"] for o in out], [1, 2, 3], "a notification must get no answer")
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "provably"); self.assertEqual(out[0]["result"]["protocolVersion"], "2025-03-26")
        names = [t["name"] for t in out[1]["result"]["tools"]]
        self.assertEqual(names, ["provably_protocol", "provably_harden", "provably_audit", "provably_spec", "provably_bizcheck"])
        for t in out[1]["result"]["tools"]:
            self.assertIn("inputSchema", t); self.assertIn("readOnlyHint", t["annotations"]); self.assertFalse(t["annotations"]["destructiveHint"])
        self.assertEqual(err, "", "the server must not write to stderr in normal use")

    def test_protocol_tool_returns_the_protocol(self):
        self.assertIn("PROVABLY SECURE-BUILD PROTOCOL", text(call("provably_protocol", {})))

    def test_audit_and_harden_find_and_fix_sql_injection(self):
        a = text(call("provably_audit", {"code": VULN})); self.assertIn("sql", a.lower())
        h = text(call("provably_harden", {"code": VULN}))
        self.assertIn("fixed", h); self.assertIn("--- hardened code ---", h); self.assertNotIn('"SELECT * FROM t WHERE n=" +', h)
        self.assertIn("provably_bizcheck", h)                  # the hardened answer ends by telling the AI what to do next about business logic

    def test_spec_is_static_and_returns_a_policy(self):
        self.assertIn("default-deny policy", text(call("provably_spec", {"code": SHOP})))

    def test_non_ascii_code_survives_a_legacy_locale_and_crlf(self):
        code = "# café — 日本語 🙂\n" + VULN
        env = {"PYTHONUTF8": "0", "PYTHONIOENCODING": "ascii", "LC_ALL": "C", "LANG": "C", "PYTHONCOERCECLOCALE": "0"}
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "provably_harden", "arguments": {"code": code}}}
        raw = (json.dumps(msg, ensure_ascii=False) + "\r\n").encode("utf-8")          # UTF-8 bytes and Windows line ends, as a client on Windows sends them
        out, err = rpc(None, env, raw=raw)
        self.assertNotIn("isError", out[0]["result"], text(out[0]["result"])); self.assertIn("日本語", text(out[0]["result"])); self.assertIn("🙂", text(out[0]["result"]))

    def test_bad_input_never_kills_the_server(self):
        raw = b'not json\n[1,2]\n' + json.dumps({"jsonrpc": "2.0", "id": 5, "method": "nope"}).encode() + b'\n' + \
              json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "provably_audit", "arguments": {"code": ""}}}).encode() + b'\n' + \
              json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "provably_nope", "arguments": {"code": "x=1"}}}).encode() + b'\n' + \
              json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "provably_audit", "arguments": {"code": "x" * 2_000_001}}}).encode() + b'\n' + \
              json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "provably_spec", "arguments": {"code": "def ("}}}).encode() + b'\n' + \
              json.dumps({"jsonrpc": "2.0", "id": 10, "method": "ping"}).encode() + b'\n'
        out, _ = rpc(None, raw=raw)
        self.assertEqual(out[0]["error"]["code"], -32700); self.assertEqual(out[1]["error"]["code"], -32600); self.assertEqual(out[2]["error"]["code"], -32601)
        for i in (3, 4, 5, 6):
            self.assertTrue(out[i]["result"]["isError"], out[i]); self.assertNotIn("Traceback", text(out[i]["result"])); self.assertNotIn(HERE, text(out[i]["result"]))
        self.assertIn("does not parse", text(out[6]["result"])); self.assertEqual(out[7]["result"], {})


class Bizcheck(unittest.TestCase):
    def test_it_reads_the_code_and_runs_none_of_it(self):
        marker = os.path.join(tempfile.mkdtemp(), "ran"); self.addCleanup(shutil.rmtree, os.path.dirname(marker), True)
        t = text(call("provably_bizcheck", {"code": "open(%r, 'w').write('x')\n" % marker + SHOP}))
        self.assertFalse(os.path.exists(marker), "the submitted code was executed")
        self.assertIn("/pay", t)

    def test_findings_say_what_to_fix_and_a_clean_result_is_not_called_proof(self):
        t = text(call("provably_bizcheck", {"code": SHOP})); self.assertIn("NOT READY", t)
        safe = text(call("provably_bizcheck", {"code": "from flask import Flask\napp = Flask(__name__)\n"}))
        self.assertIn("not proof", safe); self.assertNotIn("NOT READY", safe)

    def test_every_tool_is_declared_read_only(self):
        out, _ = rpc([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        for t in out[0]["result"]["tools"]:
            self.assertTrue(t["annotations"]["readOnlyHint"], t["name"]); self.assertFalse(t["annotations"]["openWorldHint"], t["name"])

    def test_common_vulnerabilities_are_reported_and_secrets_never_echoed_back_as_code(self):
        cases = {"sql": VULN,
                 "secret": 'from flask import Flask\napp = Flask(__name__)\nAPI_KEY = "pv_demo_8c1f5e9a4b7d20365e8a1c4f7b9d2063"\n',
                 "debug": 'from flask import Flask\napp = Flask(__name__)\nif __name__ == "__main__":\n    app.run(debug=True)\n'}
        for name, code in cases.items():
            self.assertIn("score", text(call("provably_audit", {"code": code})).lower(), name)
            h = text(call("provably_harden", {"code": code}))
            self.assertNotIn("pv_demo_8c1f5e9a4b7d", h.split("--- hardened code ---")[-1], name)
            self.assertNotIn("debug=True", h.split("--- hardened code ---")[-1], name)


class NothingLeavesAndNothingIsWritten(unittest.TestCase):
    TOOL_MODULES = ("mcp_server", "audit", "harden_core", "harden", "fixer", "bizspec", "webstack", "protocol")
    NETWORK = {"socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp", "smtplib", "ftplib", "telnetlib", "xmlrpc", "websocket", "websockets", "asyncio", "socketserver"}

    def test_tool_modules_import_no_networking(self):
        import ast
        for m in self.TOOL_MODULES:
            with open(os.path.join(HERE, m + ".py"), encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for n in ast.walk(tree):
                mods = [a.name for a in n.names] if isinstance(n, ast.Import) else ([n.module or ""] if isinstance(n, ast.ImportFrom) else [])
                for mod in mods:
                    self.assertNotIn(mod.split(".")[0], self.NETWORK, "%s imports %s" % (m, mod))

    def test_the_tools_work_with_every_way_of_opening_a_socket_disabled(self):
        prog = ("import socket, sys, json\n"
                "def boom(*a, **k): raise RuntimeError('network used')\n"
                "socket.socket = boom; socket.create_connection = boom; socket.getaddrinfo = boom; socket.gethostbyname = boom\n"
                "sys.path.insert(0, %r)\nimport mcp_server as m\n"
                "code = %r\n"
                "for tool in ('provably_protocol','provably_audit','provably_harden','provably_spec','provably_bizcheck'):\n"
                "    r = m.handle({'id': 1, 'method': 'tools/call', 'params': {'name': tool, 'arguments': {'code': code}}})\n"
                "    assert 'isError' not in r, (tool, r)\nprint('ok')\n") % (HERE, VULN)
        p = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.stdout.strip(), "ok", p.stdout + p.stderr)

    def test_no_bytecode_cache_is_left_behind_even_without_the_usual_env_flag(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); tree = os.path.join(d, "p")
        shutil.copytree(HERE, tree, ignore=shutil.ignore_patterns("__pycache__", ".git"))
        env = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
        msgs = [{"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": n, "arguments": {"code": VULN}}} for i, n in enumerate(("provably_audit", "provably_harden", "provably_spec", "provably_bizcheck"), 1)]
        p = subprocess.run([sys.executable, os.path.join(tree, "mcp_server.py")], input=("\n".join(map(json.dumps, msgs)) + "\n").encode(), capture_output=True, env=env, timeout=120)
        self.assertEqual(len(p.stdout.splitlines()), 4, p.stderr)
        found = [os.path.join(r, x) for r, dirs, _ in os.walk(tree) for x in dirs if x == "__pycache__"]
        self.assertEqual(found, [], "the server left bytecode caches in the install folder")

    @unittest.skipUnless(os.name == "posix", "needs POSIX permissions")
    def test_runs_from_a_read_only_install_and_creates_no_files(self):
        src = tempfile.mkdtemp(); self.addCleanup(lambda: (subprocess.run(["chmod", "-R", "u+rwX", src]), shutil.rmtree(src, True)))
        install = os.path.join(src, "provably"); shutil.copytree(HERE, install, ignore=shutil.ignore_patterns("__pycache__", ".git"))
        home = os.path.join(src, "home"); work = os.path.join(src, "work"); os.makedirs(home); os.makedirs(work)
        for d in (src, home, work, install):
            os.chmod(d, 0o755)
        subprocess.run(["chmod", "-R", "a-w", install], check=True)
        sub = None
        if os.geteuid() == 0:                     # root ignores permission bits: run as an unprivileged user, like a real install
            probe = os.path.realpath(sys.executable)
            while probe != os.path.dirname(probe):
                if not os.stat(probe).st_mode & 0o001:
                    self.skipTest("this Python lives under a directory that unprivileged users cannot enter (%s)" % probe)
                probe = os.path.dirname(probe)
            for d in (home, work):
                os.chown(d, 65534, 65534)
            sub = lambda: (os.setgid(65534), os.setuid(65534))
        msgs = [{"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": n, "arguments": {"code": VULN}}} for i, n in enumerate(("provably_audit", "provably_harden", "provably_spec", "provably_bizcheck"), 1)]
        before = (sorted(os.listdir(home)), sorted(os.listdir(work)))
        env = {"PATH": os.environ["PATH"], "HOME": home, "TMPDIR": work, "PYTHONDONTWRITEBYTECODE": "1"}
        p = subprocess.run([sys.executable, os.path.join(install, "mcp_server.py")], input=("\n".join(map(json.dumps, msgs)) + "\n").encode(), capture_output=True, cwd=work, env=env, preexec_fn=sub, timeout=120)
        out = [json.loads(l) for l in p.stdout.decode().splitlines()]
        self.assertEqual(len(out), 4, p.stderr.decode()); self.assertTrue(all("isError" not in o["result"] for o in out), out)
        self.assertEqual((sorted(os.listdir(home)), sorted(os.listdir(work))), before, "the server created files outside its own read-only folder")


if __name__ == "__main__":
    unittest.main(verbosity=1)
