#!/usr/bin/env python3
"""harden - scan code for vulnerabilities, rewrite the dangerous spots to the safe form, re-scan.
  python3 harden.py app.py                 -> app.hardened.py (+ provably_secure.py and verified_core/ next to it)
  python3 harden.py ./project [--inplace]  Nothing is stored or sent anywhere: this tool only reads the files you point it at and writes the hardened copies."""
import argparse, ast, os, pathlib, shutil, sys
import audit, fixer

HERE = pathlib.Path(__file__).resolve().parent


def harden_source(code, filename="app.py", auth=True, _trace=None):
    """Returns the result dict. `_trace` (a dict, optional) receives the intermediate scan results for callers that need them."""
    before = audit.audit_files({filename: code})
    res = {"file": filename, "score_before": before["score"], "counts_before": before["counts"], "findings_before": before["findings"],
           "applied": [], "review": [], "env_required": [], "db_ids": [], "new_db_entries": 0}
    if not filename.lower().endswith(".py"):
        import webstack
        new, applied, review, envs = webstack.fix_web({os.path.basename(filename): code})
        res.update(code=new[os.path.basename(filename)], score_after=before["score"], passed=before["passed"], env_required=envs,
                   applied=[{"rule": a["rule"], "line": 0, "desc": a["desc"], "before": "", "after": ""} for a in applied],
                   review=[{"rule": r["rule"], "line": 0, "action": r["action"]} for r in review] + [{"rule": f["rule"], "line": f["line"], "action": f["fix"]} for f in before["findings"]])
        return res
    cur, first_applied, first_review, envs = code, None, [], []
    for pass_no in range(3):
        rep = audit.audit_files({filename: cur})
        if not rep["findings"]:
            break
        try:
            new, applied, review, env = fixer.fix_python(cur, rep["findings"], auth)
        except SyntaxError:
            break
        if pass_no == 0:
            first_applied, first_review = applied, review
        res["applied"] += applied
        envs += env
        if new == cur:
            break
        cur = new
    after = audit.audit_files({filename: cur})
    res.update(code=cur, score_after=after["score"], counts_after=after["counts"], passed=after["passed"], findings_after=after["findings"],
               env_required=sorted(set(envs)), review=first_review or [{"rule": f["rule"], "line": f["line"], "action": f["fix"]} for f in after["findings"]])
    if _trace is not None:
        _trace.update(before=before, after=after, cur=cur, first_applied=first_applied, first_review=first_review)
    return res


def summary(r):
    L = [f"{r['file']}: score {r['score_before']} -> {r['score_after']}/100 | {'PASS' if r['passed'] else 'NEEDS REVIEW'}"]
    for a in r["applied"]:
        L.append(f"  fixed  [{a['rule']}] line {a['line']}: {a['desc']}")
    for v in r["review"]:
        L.append(f"  review [{v['rule']}] line {v['line']}: {v['action']}")
    for e in r.get("env_required", []):
        L.append(f"  action: set environment variable {e} (the old value was in the code, so treat it as leaked and rotate it)")
    return "\n".join(L)


def collect(target):
    t = pathlib.Path(target)
    skip = {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist"}
    if t.is_file():
        return [t]
    return [p for p in t.rglob("*") if p.is_file() and p.suffix in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs") and not (skip & set(p.parts))
            and ".hardened" not in p.name and p.name not in ("provably_secure.py", "audit.py")]


WEB_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".sql", ".rules", ".json", ".yml", ".yaml", ".toml")


def collect_web(target):
    t = pathlib.Path(target)
    skip = {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist", ".next", "out"}
    out = {}
    for p in t.rglob("*"):
        if p.is_file() and not (skip & set(p.parts)) and (p.suffix in WEB_EXT or p.name.startswith(".env")) and p.name not in ("package-lock.json", "yarn.lock", "tsconfig.json") and p.stat().st_size < 2_000_000:
            out[str(p.relative_to(t))] = p.read_text(encoding="utf-8", errors="ignore")
    return out


def harden_web_project(target, inplace=False):
    """Next.js / React / Express + Supabase / Firebase: project-level fixes (auth on API routes, RLS, rules, env names, XSS, ...). Returns (ok, outdir)."""
    import webstack
    root = pathlib.Path(target)
    files = collect_web(target)
    if not any(n.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".sql", ".rules")) for n in files):
        return True, None
    new, applied, review, envs = webstack.fix_web(files)
    print(f"{target}: web stack - {len(applied)} fixed, {len(review)} need review")
    for a in applied:
        print(f"  fixed  [{a['rule']}] {a['file']}: {a['desc']}")
    for r in review:
        print(f"  review [{r['rule']}] {r['file']}: {r['action']}")
    for e in envs:
        print(f"  action: set environment variable {e} (the old value was in the code, so treat it as leaked and rotate it)")
    out = root if inplace else root.with_name(root.name + ".hardened")
    if applied:
        if not inplace:
            shutil.copytree(root, out, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", "node_modules", ".next"))
        for name, text in new.items():
            if text != files.get(name):
                (out / name).parent.mkdir(parents=True, exist_ok=True)
                (out / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"  wrote {out}")
    return not any(r["rule"] in ("api_no_auth", "service_key_in_browser", "hardcoded_secret") for r in review), out


def read_source(p):
    return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan code for vulnerabilities and write a hardened copy. Nothing leaves your machine.")
    ap.add_argument("target", help="a .py/.js/.ts file or a project folder")
    ap.add_argument("--inplace", action="store_true", help="overwrite the files instead of writing *.hardened.* copies")
    ap.add_argument("--no-auth", action="store_true", help="do not add the default-deny login check to routes")
    a = ap.parse_args(argv)
    ok = True
    tp = pathlib.Path(a.target)
    if tp.is_dir():
        wok, _ = harden_web_project(a.target, a.inplace)
        ok = ok and wok
    for p in collect(a.target):
        if p.suffix != ".py" and tp.is_dir():
            continue
        r = harden_source(read_source(p), str(p), not a.no_auth)
        print(summary(r))
        if r["applied"]:
            out = p if a.inplace else p.with_name(p.stem + ".hardened" + p.suffix)
            out.write_text(r["code"], encoding="utf-8", newline="\n")
            if "provably_secure" in r["code"]:
                if not (out.parent / "provably_secure.py").exists():
                    shutil.copy(HERE / "provably_secure.py", out.parent / "provably_secure.py")
                if not (out.parent / "verified_core").exists():           # the verified code the helpers run on; the app refuses to start without it
                    shutil.copytree(HERE / "verified_core", out.parent / "verified_core", ignore=shutil.ignore_patterns("__pycache__"))
            print(f"  wrote {out}")
        ok = ok and r["passed"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
