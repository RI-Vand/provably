"""tests_package - the install route: one pinned command must give a working server. Checks versions, that the wheel carries everything the server imports, that nothing else gets in,
and (PROVABLY_TEST_PACKAGING=1, needs network for the build backend) builds the wheel, installs it in a clean environment and runs the real console scripts."""
import ast, importlib.util, json, os, re, shutil, subprocess, sys, tempfile, unittest, zipfile
HERE = os.path.dirname(os.path.abspath(__file__))


def read(*p):
    with open(os.path.join(HERE, *p), encoding="utf-8") as f:
        return f.read()


def pyproject():
    t = read("pyproject.toml"); name = re.search(r'^name = "([^"]+)"', t, re.M).group(1); ver = re.search(r'^version = "([^"]+)"', t, re.M).group(1)
    forced = re.findall(r'^"([^"]+)" = "provably_mcp/[^"]+"', t, re.M)
    return name, ver, forced, t


def local_imports(start):
    mods = {f[:-3] for f in os.listdir(HERE) if f.endswith(".py")}; seen, todo = set(), [start]
    while todo:
        m = todo.pop()
        if m in seen:
            continue
        seen.add(m)
        for n in ast.walk(ast.parse(read(m + ".py"))):
            names = [a.name for a in n.names] if isinstance(n, ast.Import) else ([n.module] if isinstance(n, ast.ImportFrom) and n.module else [])
            todo += [x.split(".")[0] for x in names if x.split(".")[0] in mods]
    return seen


SAMPLE = 'import sqlite3\\nfrom flask import Flask, request\\napp = Flask(__name__)\\n@app.route("/u")\\ndef u():\\n    c = sqlite3.connect("x.db")\\n    return str(c.execute("SELECT name FROM t WHERE n=" + request.args["n"]).fetchall())\\n'.replace("\\n", "\n")


class Metadata(unittest.TestCase):
    def test_every_version_agrees(self):
        _, ver, _, _ = pyproject()
        self.assertEqual(re.search(r'VERSION = "([^"]+)"', read("mcp_server.py")).group(1), ver)
        self.assertEqual(re.search(r'__version__ = "([^"]+)"', read("provably_mcp", "__init__.py")).group(1), ver)
        self.assertEqual(re.search(r"^## (\S+)", read("CHANGELOG.md"), re.M).group(1), ver)

    def test_the_wheel_carries_every_module_the_server_and_cli_import(self):
        _, _, forced, _ = pyproject(); forced_mods = {f[:-3] for f in forced if f.endswith(".py")}
        need = local_imports("mcp_server") | local_imports("harden") | local_imports("harden_core")
        self.assertEqual(need - forced_mods, set(), "imported by the server but missing from the wheel")
        self.assertIn("verified_core", forced); self.assertIn("provably_secure", forced_mods)       # copied into hardened apps by the CLI

    def test_license_and_notices_are_complete(self):
        lic = read("LICENSE")
        self.assertIn("Functional Source License, Version 1.1, ALv2 Future License", lic); self.assertIn("Competing Use", lic)
        for f in ("LICENSE", "NOTICE", "README.md", "pyproject.toml", "SECURITY.md"):
            self.assertNotRegex(read(f), r"\{\{|\$\{", f + " has an unresolved placeholder")
        self.assertRegex(read("NOTICE"), r"Copyright 20\d\d \S")
        self.assertIn('license = "FSL-1.1-ALv2"', pyproject()[3])

    def test_readme_install_command_matches_the_package(self):
        name, ver, _, t = pyproject()
        m = re.search(r"claude mcp add --scope user provably -- uvx --refresh --from git\+https://github\.com/([\w.-]+/[\w.-]+)@stable (\S+)", read("README.md"))
        self.assertIsNotNone(m); self.assertIn(m.group(2), t)      # the console script it runs exists in [project.scripts]
        self.assertIn('Source = "https://github.com/%s"' % m.group(1), t)


class EndToEnd(unittest.TestCase):
    """a hardened app really runs with the shipped provably_secure.py + verified_core (from the repository folder here, from the installed wheel below)"""
    def run_hardened(self, harden_cmd, extra_env=None):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "shop.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(SAMPLE)
        import sqlite3
        c = sqlite3.connect(os.path.join(d, "x.db")); c.execute("create table t(n integer, name text)"); c.executemany("insert into t values(?,?)", [(1, "alice"), (2, "bob")]); c.commit(); c.close()
        env = {**os.environ, "PYTHONUTF8": "1", **(extra_env or {})}
        r = subprocess.run(harden_cmd + ["--no-auth", os.path.join(d, "shop.py")], capture_output=True, text=True, env=env, cwd=d, timeout=120); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.exists(os.path.join(d, "provably_secure.py"))); self.assertTrue(os.path.exists(os.path.join(d, "verified_core", "MANIFEST.json")))
        prog = ("import importlib.util, json\nspec = importlib.util.spec_from_file_location('hardened_app', 'shop.hardened.py'); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
                "c = m.app.test_client(); a = c.get('/u?n=1'); b = c.get('/u?n=1 OR 1=1')\nprint(json.dumps([a.status_code, a.get_data(as_text=True), b.get_data(as_text=True)]))\n")
        p = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, cwd=d, env={**env, "PYTHONPATH": ""}, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        status, ok, attack = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(status, 200); self.assertIn("alice", ok); self.assertNotIn("bob", attack, "the injection returned every row")

    @unittest.skipIf(importlib.util.find_spec("flask") is None, "flask not installed")
    def test_from_the_repository_folder(self):
        self.run_hardened([sys.executable, os.path.join(HERE, "harden.py")])


@unittest.skipUnless(os.environ.get("PROVABLY_TEST_PACKAGING") == "1", "set PROVABLY_TEST_PACKAGING=1 (needs network for the build backend)")
class Wheel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(); cls.wheel_dir = os.path.join(cls.d, "dist"); src = os.path.join(cls.d, "src")
        shutil.copytree(HERE, src, ignore=shutil.ignore_patterns("__pycache__", ".git", "dist", "build", "*.egg-info"))
        r = subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", cls.wheel_dir, src], capture_output=True, text=True, timeout=600)
        assert r.returncode == 0, r.stdout[-1500:] + r.stderr[-1500:]
        cls.wheel = os.path.join(cls.wheel_dir, os.listdir(cls.wheel_dir)[0])
        cls.venv = os.path.join(cls.d, "venv"); subprocess.run([sys.executable, "-m", "venv", cls.venv], check=True)
        cls.bin = os.path.join(cls.venv, "Scripts" if os.name == "nt" else "bin")
        r = subprocess.run([os.path.join(cls.bin, "python"), "-m", "pip", "install", "--quiet", cls.wheel], capture_output=True, text=True, timeout=600); assert r.returncode == 0, r.stderr[-1500:]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, True)

    def test_wheel_contents(self):
        names = zipfile.ZipFile(self.wheel).namelist(); top = {n.split("/")[0] for n in names}
        self.assertEqual(top, {"provably_mcp", [t for t in top if t.endswith(".dist-info")][0]}, top)       # a single package: no generic top-level names such as 'audit'
        for must in ("mcp_server.py", "audit.py", "provably_secure.py", "verified_core/MANIFEST.json", "cli.py"):
            self.assertIn("provably_mcp/" + must, names)
        for bad in ("tests_", "fixtures", "proofs", "__pycache__", ".env", ".sqlite"):
            self.assertFalse([n for n in names if bad in n], bad)
        self.assertTrue([n for n in names if n.endswith("licenses/LICENSE")], "the license is not inside the wheel")

    def test_console_script_speaks_mcp(self):
        exe = os.path.join(self.bin, "provably-mcp" + (".exe" if os.name == "nt" else ""))
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        p = subprocess.run([exe], input="\n".join(map(json.dumps, msgs)) + "\n", capture_output=True, text=True, encoding="utf-8", timeout=120)
        out = [json.loads(l) for l in p.stdout.splitlines()]
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "provably"); self.assertEqual(len(out[1]["result"]["tools"]), 5); self.assertEqual(p.stderr.strip(), "")

    @unittest.skipIf(importlib.util.find_spec("flask") is None, "flask not installed")
    def test_installed_harden_command_produces_an_app_that_runs(self):
        EndToEnd("test_from_the_repository_folder").run_hardened([os.path.join(self.bin, "provably-harden" + (".exe" if os.name == "nt" else ""))])

    def test_install_left_no_extra_top_level_modules(self):
        site = subprocess.run([os.path.join(self.bin, "python"), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"], capture_output=True, text=True).stdout.strip()
        tops = {n for n in os.listdir(site) if not n.endswith((".dist-info", ".pth")) and n not in ("__pycache__", "pip", "_distutils_hack", "pkg_resources", "setuptools")}
        self.assertEqual(tops - {"pip"}, {"provably_mcp"}, tops)


if __name__ == "__main__":
    unittest.main(verbosity=1)
