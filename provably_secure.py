"""provably_secure - stdlib-only safe replacements the fixer swaps in. Each helper has ONE job and fails closed.
Properties of each helper are attack-tested in proofs.py (and verified in Dafny when a spec exists in proofs/)."""
import functools, hashlib, hmac, ipaddress, json, os, re, secrets, socket, sys, threading, time
from urllib.parse import urlparse

# ---- the verified core -------------------------------------------------------------------------------------------------------------------------
# The security DECISIONS (ownership, redirect target, command argument, strict params, rate limit, path containment) are made by code that Dafny
# compiled from formally proven specifications. The functions below only convert types, call that code, and act on its answer.
# If the verified core is missing or does not match its manifest we refuse to start: fail closed, never fall back to unverified logic.
_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_core():
    d = os.path.join(_HERE, "verified_core")
    try:
        manifest = json.load(open(os.path.join(d, "MANIFEST.json")))
        for rel, want in manifest["generated"].items():
            if not hmac.compare_digest(hashlib.sha256(open(os.path.join(d, rel), "rb").read()).hexdigest(), str(want)):
                raise RuntimeError("verified_core/%s does not match its manifest" % rel)
        ikey = os.environ.get("PROVABLY_INTEGRITY_KEY")
        if ikey:    # the manifest is only a self-description; with a key that is NOT stored next to the code, someone who can write files cannot re-sign it
            got = hmac.new(ikey.encode(), open(os.path.join(d, "MANIFEST.json"), "rb").read(), "sha256").hexdigest()
            if not hmac.compare_digest(got, open(os.path.join(d, "MANIFEST.sig")).read().strip()):
                raise RuntimeError("verified_core/MANIFEST.json is not signed with PROVABLY_INTEGRITY_KEY")
    except (OSError, KeyError, ValueError) as e:
        raise RuntimeError("provably_secure: verified_core/ is missing or unreadable (%s). Ship the verified_core folder next to provably_secure.py." % e)
    sys.path.insert(0, d)
    try:
        import _dafny, PathTrav, Redirect, Idor, Cmdi, StrictParams, RateLimit, Authz, StateMachine, Ledger, SingleUse as SingleUseCore
    finally:
        sys.path.remove(d)
    return _dafny, PathTrav, Redirect, Idor, Cmdi, StrictParams, RateLimit, Authz, StateMachine, Ledger, SingleUseCore, manifest


_dafny, _PT, _RD, _ID, _CM, _SP, _RL, _AZ, _SM, _LG, _SU, VERIFIED_MANIFEST = _load_core()
_S = _dafny.Seq


def _str(seq):
    return "".join(seq)


def _segments(path):
    seps = {os.sep, os.altsep} - {None}
    return [x for x in re.split("|".join(re.escape(c) for c in seps), path) if x]


def safe_join(base, *names):
    """Join names under base. Raises ValueError if the result would leave base (../, absolute paths, symlinks, NUL).
    Lexical normalisation and the containment decisions are the verified PathTrav methods; os.path.realpath (symlinks) is trusted."""
    base_real = os.path.realpath(base)
    base_segs = _segments(base_real)
    segs = []
    for n in names:
        n = str(n)
        if "\x00" in n:
            raise ValueError("NUL in path")
        if os.path.isabs(n) or n[:1] in ("/", os.sep):
            segs.append(_PT.Seg_Root())
        for part in _segments(n):
            segs.append(_PT.Seg_Cur() if part == "." else _PT.Seg_Up() if part == ".." else _PT.Seg_Name(_S(part)))
    ok, _ = _PT.default__.SafeJoin(_S([_S(x) for x in base_segs]), _S(segs))      # verified lexical check: ".." can never climb out of base
    if not ok:
        strike(2, "path traversal attempt")
        raise ValueError("path escapes base folder")
    naive = base_real
    for n in names:
        naive = os.path.join(naive, str(n))
    real = os.path.realpath(naive)                                                 # what the OS will really open (symlinks, .. after a symlink)
    if not _PT.default__.Contained(_S([_S(x) for x in base_segs]), _S([_S(x) for x in _segments(real)])):   # verified containment of THAT path
        strike(2, "path traversal attempt (symlink)")
        raise ValueError("path escapes base folder")
    return real


def safe_redirect_target(url, allowed_hosts=(), default="/"):
    """Return url only if it is a same-site relative path or an allow-listed http(s) host; otherwise default. Decision = verified Redirect.SafeRedirect."""
    def same_site(u):
        return u[:1] == "/" and (len(u) == 1 or u[1] not in "/\\") and not any(ord(c) < 32 or c == "\\" for c in u)
    if not isinstance(default, str) or not same_site(default):
        default = "/"                                                          # the proof's precondition: default is a same-site path
    if not isinstance(url, str):
        return default
    try:
        u = urlparse(url)
        host = (u.hostname or "").lower()
    except ValueError:
        return default
    allowed = {h.lower() for h in allowed_hosts if h}                          # the proof's precondition: "" is never an allowed host
    return _str(_RD.default__.SafeRedirect(_S(url), _RD.Parsed_Parsed(_S(u.scheme), _S(host), bool(u.netloc)), _dafny.Set([_S(h) for h in allowed]), _S(default)))


def _is_public(ip):
    a = ipaddress.ip_address(ip)
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def safe_url(url, allowed_hosts):
    """Allow-listed http(s) host whose every resolved address is public. Raises ValueError otherwise."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.hostname.lower() not in {h.lower() for h in allowed_hosts}:
        raise ValueError("url not allowed")
    for info in socket.getaddrinfo(u.hostname, u.port or 443):
        if not _is_public(info[4][0]):
            raise ValueError("url resolves to a non-public address")
    return url


def hash_password(password, n=2 ** 15, r=8, p=1):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), maxmem=128 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(got.hex(), dk)
    except Exception:
        return False


def wrap_legacy_hash(legacy_hex):
    """Protect an existing weak digest right now, without knowing the password: store scrypt(legacy_digest). A leaked database then needs
    scrypt-level effort per guess instead of MD5-level. Verified by verify_any(); upgraded to a pure scrypt hash at the user's next login."""
    return hash_password(legacy_hex)


def _legacy_digest(password, algo):
    return hashlib.new(algo, password.encode()).hexdigest()


def verify_any(password, stored, legacy_algos=("md5", "sha1", "sha256")):
    """Check a password against any stored format and say whether the stored value should be replaced.
    Returns (ok, upgrade). When upgrade is True, save hash_password(password) for this user (only if ok is True)."""
    stored = str(stored or "")
    if stored.startswith("scrypt$"):
        if verify_password(password, stored):
            return True, False
        for a in legacy_algos:                       # scrypt(legacy digest) produced by wrap_legacy_hash
            if verify_password(_legacy_digest(password, a), stored):
                return True, True
        return False, False
    for a in legacy_algos:                           # bare legacy digest still in the database
        d = _legacy_digest(password, a)
        if len(stored) == len(d) and hmac.compare_digest(d, stored.lower()):
            return True, True
    return False, False


def new_token(nbytes=32):
    return secrets.token_urlsafe(nbytes)


def safe_arg(value):
    """For command arguments built from user input: refuse values that start with '-' (they would be parsed as options, e.g. ping -f). Verified Cmdi.SafeArg."""
    v = str(value)
    if not _CM.default__.SafeArg(_S(v)):
        strike(2, "option injection attempt")
        raise ValueError("argument looks like an option")
    return v


def bounded_int(value, lo, hi):
    v = int(value)
    if not lo <= v <= hi:
        raise ValueError("number out of range")
    return v


def safe_compare(a, b):
    return hmac.compare_digest(str(a).encode(), str(b).encode())


class RateLimiter:
    """Sliding window, in memory. key -> max `limit` hits per `window` seconds. The allow/refuse decision is the verified RateLimit.Allow
    (the cap can never be exceeded and refused calls never change state). Times are integer milliseconds. limit is capped at 250 (the verified
    counter is recursive)."""
    MAX_KEYS = 50_000   # hard cap so a flood of distinct clients cannot exhaust memory
    MAX_LIMIT = 250

    def __init__(self, limit=5, window=60):
        if not (0 <= limit <= self.MAX_LIMIT) or window <= 0:
            raise ValueError("limit must be 0..%d and window > 0" % self.MAX_LIMIT)
        self.limit, self.window, self.hits, self.lock = limit, window, {}, threading.Lock()
        self.wms = max(1, int(round(window * 1000)))

    def allow(self, key):
        now = int(time.monotonic() * 1000)
        with self.lock:
            if len(self.hits) >= self.MAX_KEYS:        # evict keys whose hits have all expired; if still full, refuse new keys (fail closed)
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < self.wms}
                if len(self.hits) >= self.MAX_KEYS and key not in self.hits:
                    return False
            q = [t for t in self.hits.get(key, []) if now - t < self.wms]      # dropping expired entries cannot change Count (it ignores them)
            if q != sorted(q) or (q and q[-1] > now) or len(q) > self.limit:    # the proof's preconditions; if ever false, fail closed
                return False
            ok, acc2 = _RL.default__.Allow(_S(q), now, self.limit, self.wms)
            q = list(acc2)
            if q:
                self.hits[key] = q
            else:
                self.hits.pop(key, None)
            return bool(ok)


_limiter = RateLimiter()
_acct_limiter = RateLimiter(limit=min(RateLimiter.MAX_LIMIT, int(os.environ.get("PROVABLY_ACCT_LIMIT", "10") or 10)), window=60)


# ---- who is the client? ------------------------------------------------------------------------------------------------------------------------
# Behind a reverse proxy (a typical reverse-proxy -> app layout) request.remote_addr is the PROXY, so every visitor would share one rate-limit bucket and one
# tripwire ban. The opposite mistake (believing X-Forwarded-For blindly) lets any client choose its own address. So: the number of trusted proxies is declared
# (PROVABLY_PROXY_HOPS, default 0 = trust nobody) and only the entry that many places from the RIGHT of X-Forwarded-For is used; everything left of it is
# attacker-supplied and ignored.
def _hops():
    try:
        return max(0, min(8, int(os.environ.get("PROVABLY_PROXY_HOPS", "0"))))
    except ValueError:
        return 0


def client_ip(remote_addr=None, xff=None, hops=None):
    """Best-effort true client address. With hops=n trusted proxies in front, the n-th entry from the right of X-Forwarded-For. If the header is missing,
    shorter than the declared chain, or not an IP address, fall back to the socket address (never to attacker-chosen text)."""
    hops = _hops() if hops is None else hops
    if remote_addr is None:
        from flask import request
        remote_addr = request.remote_addr
        if xff is None:
            xff = request.headers.get("X-Forwarded-For")
    remote_addr = str(remote_addr or "?")
    if hops <= 0 or not xff:
        return remote_addr
    parts = [p.strip() for p in str(xff).split(",") if p.strip()]
    if len(parts) < hops:
        return remote_addr
    try:
        return str(ipaddress.ip_address(parts[-hops]))
    except ValueError:
        return remote_addr


def _rate_key(ip):
    """IPv6 clients usually own a whole /64, so one address per request would be free to rotate: bucket by the /64."""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return ip
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False))
    return str(a)


def _public_ip(ip):
    try:
        return _is_public(ip.split("%")[0])
    except ValueError:
        return False


_ACCT_FIELDS = ("name", "username", "user", "email", "login", "account", "id")


def _account_key():
    """The account a login-style request is aimed at (first of name/username/email/... in the form or JSON body), normalised; None if absent."""
    import unicodedata
    from flask import request
    vals = [request.form.get(f) for f in _ACCT_FIELDS]
    if not any(vals):
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            vals = [body.get(f) for f in _ACCT_FIELDS]
    for v in vals:
        if isinstance(v, str) and v.strip():
            return unicodedata.normalize("NFKC", v).strip().casefold()[:128]
    return None


def rate_limit(fn):
    """Flask decorator for login-style routes: 5 calls/minute per client (IPv6 by /64) AND 10 calls/minute per targeted account (PROVABLY_ACCT_LIMIT),
    so rotating addresses does not give unlimited guesses at one account. Then HTTP 429. State is per process (deploy.py runs one worker for that reason).
    Trade-off: an attacker can burn a victim's account budget to delay their login; they cannot get in faster."""
    @functools.wraps(fn)
    def w(*a, **k):
        from flask import request, abort
        if not _limiter.allow((_rate_key(client_ip()), fn.__name__)):
            strike(1, "login rate limit")
            abort(429)
        acct = _account_key()
        if acct is not None:
            if acct in _decoy_accounts():                                  # nobody real logs in as "admin"/"root" here: a credential-stuffing tool does
                strike(_strike_limit(), "decoy account " + acct)
            if is_banned("u:" + acct) or not _acct_limiter.allow((acct, fn.__name__)):
                abort(429)
        return fn(*a, **k)
    return w


def require_login(fn):
    """Flask decorator: default-deny. Needs session['user'] (set it at login) or HTTP 401."""
    @functools.wraps(fn)
    def w(*a, **k):
        from flask import session, abort
        if not session.get("user"):
            abort(401)
        return fn(*a, **k)
    return w


login_required = require_login   # alias: scanners and humans recognise this name


_BANNED = {}                     # ip -> ban expiry (monotonic); capped so a flood cannot exhaust memory
DECOYS = ("/.env", "/.git/config", "/wp-login.php", "/wp-admin", "/phpmyadmin", "/server-status", "/admin/backup.sql", "/backup.zip", "/.aws/credentials",
          "/actuator/env", "/actuator/heapdump", "/.git/HEAD", "/.DS_Store", "/config.json", "/console", "/debug", "/api/swagger.json", "/swagger.json", "/.vscode/sftp.json", "/dump.sql", "/db.sqlite3", "/id_rsa")


def _ban_key(k):
    k = str(k)
    return k if k.startswith("u:") else _rate_key(k)       # IPv6 clients are banned by /64, users by id


def ban(ip, seconds=3600):
    ip = _ban_key(ip)
    now = time.monotonic()
    if len(_BANNED) >= 10_000:
        for k in [k for k, t in _BANNED.items() if t < now]:
            _BANNED.pop(k, None)
    if len(_BANNED) < 10_000:
        _BANNED[ip] = now + seconds


def is_banned(ip):
    ip = _ban_key(ip)
    t = _BANNED.get(ip)
    if t is None:
        return False
    if t < time.monotonic():
        _BANNED.pop(ip, None)
        return False
    return True


def tripwires(app, seconds=3600):
    """Decoy URLs that no real user ever visits (/.env, /.git/config, /wp-login.php ...). Whoever requests one is a scanner or attacker: log it, ban
    that address for an hour, answer 404. Automated exploitation tools probe these first, so each probe costs them the whole session."""
    import logging
    from flask import request, abort
    log = logging.getLogger("provably.tripwire")
    real = {r.rule for r in app.url_map.iter_rules()}

    @app.before_request
    def _provably_tripwire():
        ip = client_ip()
        if is_banned(ip):
            abort(403)
        if request.path in DECOYS and request.path not in real:
            # A private/loopback socket address that arrives WITH forwarding headers while no proxy is declared is almost certainly our own reverse proxy:
            # banning it would lock out every visitor. Log loudly and do not ban (set PROVABLY_PROXY_HOPS=1 to fix the cause).
            if _hops() == 0 and not _public_ip(ip) and (request.headers.get("X-Forwarded-For") or request.headers.get("Forwarded")):
                log.error("tripwire hit from %s via a proxy that is not declared: NOT banning. Set PROVABLY_PROXY_HOPS=1 so clients are told apart.", ip)
            else:
                ban(ip, seconds)
                log.warning("tripwire hit: %s requested %s - banned for %ss", ip, request.path, seconds)
            abort(404)
    return app


_BENIGN_PARAM = re.compile(r"^(utm_[a-z_]+|fbclid|gclid|_|csrf_token|_csrf|csrf)$", re.I)
MAX_BODY_SCAN = int(os.environ.get("PROVABLY_MAX_BODY", 1024 * 1024))


def _json_body(max_nodes=20000, max_depth=24):
    """Inspect a JSON request body whatever its Content-Type claims (routes often call json.loads(request.data) or get_json(force=True)).
    Returns (keys, longest_string, ok). ok is False for absurd nesting/size. A body that is not JSON yields nothing (the route's own parser will reject it)."""
    from flask import request, abort
    if request.mimetype in ("application/x-www-form-urlencoded", "multipart/form-data"):
        return set(), 0, True
    n = request.content_length
    if not n:
        return set(), 0, True
    if n > MAX_BODY_SCAN:
        abort(413)
    raw = request.get_data(cache=True)
    if raw.lstrip()[:1] not in (b"{", b"["):
        return set(), 0, True
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):
        return set(), 0, True
    keys, longest, seen, stack = set(), 0, 0, [(doc, 1)]
    while stack:
        node, depth = stack.pop()
        seen += 1
        if seen > max_nodes or depth > max_depth:
            return keys, longest, False
        if isinstance(node, dict):
            for k, v in node.items():
                keys.add(k); stack.append((v, depth + 1))
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
        elif isinstance(node, str):
            longest = max(longest, len(node))
    return keys, longest, True


def allow_params(app, spec, max_len=4096):
    """Positive security model: each route accepts ONLY the query/form/JSON fields its code actually reads (spec = {route_rule: [names]}).
    An unknown field, or a value longer than max_len, is refused with 400 before the route runs, so probing for hidden parameters, mass assignment
    and oversized-input tricks all fail at the door. Every value of a repeated parameter counts (?id=1&id=<huge>), and JSON bodies are checked at every
    nesting level, so list nested key names too. A route that takes a free-form JSON document lists "*json": its keys are then not restricted, but size,
    depth and string length still are. Set PROVABLY_STRICT=log to only log (while you check nothing legitimate is refused) or off to disable."""
    import logging
    from flask import request, abort, session
    log = logging.getLogger("provably.strict")

    @app.before_request
    def _provably_strict_params():
        mode = os.environ.get("PROVABLY_STRICT", "enforce").lower()
        rule = request.url_rule.rule if request.url_rule else None
        if mode == "off" or rule not in spec:
            return
        allowed = set(spec[rule])
        free_json = "*json" in allowed
        allowed.discard("*json")
        pairs = list(request.args.items(multi=True)) + list(request.form.items(multi=True))
        keys = {k for k, _ in pairs} | set(request.files.keys())
        longest = max([len(v) for _, v in pairs] or [0])
        jkeys, jlong, jok = _json_body()
        if not free_json:
            keys |= jkeys
        longest = max(longest, jlong, 0 if jok else max_len + 1)
        benign = {k for k in keys if _BENIGN_PARAM.match(k)}                   # trusted classification; the accept/refuse rule itself is verified
        extra = {k for k in keys if k not in allowed and k not in benign}
        if not _SP.default__.Check(_dafny.Set([_S(k) for k in keys]), _dafny.Set([_S(k) for k in allowed]), _dafny.Set([_S(k) for k in benign]), max_len, longest):
            log.warning("strict params: %s rejected unexpected %s", rule, sorted(extra) or "oversized or over-nested value")
            if mode != "log":
                # a field like is_admin/role that no form of ours sends is a canary: only someone probing for mass assignment sends it
                strike(_strike_limit() if any(_PRIVILEGED.match(str(k)) for k in extra) else 2, "unexpected input", user=session.get("user"))
                abort(400)
    return app


def keyring(app, env="PROVABLY_SECRET_KEYS"):
    """Signing-key rotation: PROVABLY_SECRET_KEYS="newest,older,oldest". New sessions are signed with the first key; the rest still verify, so rotating
    never logs anyone out, and a leaked key stops working once it falls off the list. Needs Flask >= 3.1. Use rotate_keys.py to do the rotation."""
    keys = [k for k in os.environ.get(env, "").split(",") if k]
    if keys:
        app.config["SECRET_KEY"] = keys[0]
        app.config["SECRET_KEY_FALLBACKS"] = keys[1:]
    return app


def shield(app):
    """Add browser security headers and refuse cross-site state-changing requests (CSRF) on a Flask app. Call once after creating the app.
    Cross-site check: a POST/PUT/PATCH/DELETE whose Origin (or Referer) host differs from the request host is rejected with 403.
    Requests with neither header (curl, server-to-server) pass, since CSRF needs a browser, which always sends one of them."""
    from flask import request, abort
    from urllib.parse import urlparse

    @app.before_request
    def _provably_origin_check():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            src = request.headers.get("Origin") or request.headers.get("Referer")
            if src and src != "null" and urlparse(src).netloc.lower() != request.host.lower():
                abort(403)
            if src == "null":
                abort(403)

    tripwires(app)
    keyring(app)
    _install_depth(app)
    if os.environ.get("PROVABLY_WATCHDOG") == "1" and not app.extensions.get("provably_watchdog"):
        app.extensions["provably_watchdog"] = integrity_watch(app)
    from werkzeug.exceptions import HTTPException

    guard_sinks()

    @app.errorhandler(Exception)
    def _provably_any_error(e):           # unhandled exception: log server-side, tell the client nothing (no stack trace, no SQL, no paths)
        if isinstance(e, HTTPException):
            return "", e.code
        app.logger.exception("unhandled error")
        return "", 500

    @app.errorhandler(HTTPException)
    def _provably_plain_error(e):         # same minimal body for every error: no framework page, no version, nothing for a scanner to fingerprint
        return "", e.code

    @app.after_request
    def _provably_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp
    return app


def owner_only(value):
    """Wrap a record id taken from the request on account data: only the logged-in owner may use it (403 otherwise). Returns the id unchanged."""
    from flask import session, abort
    u = session.get("user")
    if not _ID.default__.OwnerOnly(_ID.Opt_None() if u is None else _ID.Opt_Some(_S(str(u))), _S(str(value))):      # verified Idor.OwnerOnly
        strike(4, "asked for a record that is not theirs", user=u)       # a real user never does this: two of these in ten minutes and the client is banned
        abort(403)
    return value


def csrf_token(session_id, secret):
    return hmac.new(secret.encode(), session_id.encode(), "sha256").hexdigest()


def verify_csrf(session_id, secret, token):
    return hmac.compare_digest(csrf_token(session_id, secret), str(token))



# ---- business logic: verified primitives ------------------------------------------------------------------------------------------------------
# Most real breaches are not injection, they are logic: skipping a payment step, replaying a coupon, withdrawing a negative amount, reaching a route nobody
# decided about. These primitives make those decisions in verified code. Declare the rules once; everything not declared is refused.

def authorize(policy, role, action):
    """Default deny. policy = {action: [roles]}. True only if (role, action) is explicitly listed. Verified Authz.Authorize."""
    rules = _dafny.Set([_AZ.Rule_Rule(_S(str(r)), _S(str(a))) for a, roles in policy.items() for r in roles])
    return bool(_AZ.default__.Authorize(rules, _S(str(role)), _S(str(action))))


def policy_gate(app, policy, role_of=None):
    """Default-deny route policy: policy = {"GET /": ["anon", "user"], "POST /transfer": ["user"], "GET /admin": ["admin"]}. A request whose (role, "METHOD /route")
    is not listed gets 401 (anonymous) or 403 (logged in) BEFORE the route runs, so a route added later (by you or an AI) stays closed until someone declares it. The decision is the verified
    Authz.Authorize. role_of() defaults to session['role'] if set, else 'user' when session['user'] is set, else 'anon'.
    PROVABLY_POLICY=log only logs (use while checking nothing legitimate is refused); off disables. The static folder and OPTIONS are not gated."""
    import logging
    from flask import request, session, abort
    log = logging.getLogger("provably.policy")
    rules = _dafny.Set([_AZ.Rule_Rule(_S(str(r)), _S(str(a))) for a, roles in policy.items() for r in roles])

    def default_role():
        r = session.get("role")
        if r is not None:
            return str(r)
        return "user" if session.get("user") is not None else "anon"

    @app.before_request
    def _provably_policy():
        mode = os.environ.get("PROVABLY_POLICY", "enforce").lower()
        if mode == "off" or request.url_rule is None or request.endpoint == "static" or request.method == "OPTIONS":
            return
        method = "GET" if request.method == "HEAD" else request.method
        role = str((role_of or default_role)())
        action = method + " " + request.url_rule.rule
        if not _AZ.default__.Authorize(rules, _S(role), _S(action)):
            log.warning("policy: %s refused for role %s", action, role)
            if mode != "log":
                if role != "anon":                                    # anonymous 401s are normal (expired tabs, polling UIs); a logged-in user probing routes is not
                    strike(1, "route not allowed for role", user=session.get("user"))
                abort(401 if role == "anon" else 403)        # 401 = log in first, 403 = logged in but not allowed
    return app


def state_transition(edges, cur, nxt):
    """edges = [("cart","paid"), ("paid","shipped")]. Returns nxt if the move is declared, else raises ValueError (no skipping, no going back). Verified StateMachine.Transition."""
    es = _dafny.Set([_SM.Edge_Edge(_S(str(a)), _S(str(b))) for a, b in edges])
    if not _SM.default__.Transition(es, _S(str(cur)), _S(str(nxt))):
        raise ValueError("transition %r -> %r is not allowed" % (cur, nxt))
    return nxt


def to_cents(value, max_digits=15):
    """Parse a money amount into integer cents. Accepts int/str/Decimal with at most 2 decimals; refuses floats, NaN, inf, exponents, signs other than a leading -."""
    import decimal
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError("money must be a string, int or Decimal, never a float")
    t = str(value).strip()
    if not re.fullmatch(r"-?\d{1,%d}(\.\d{1,2})?" % max_digits, t):
        raise ValueError("not a valid amount")
    return int((decimal.Decimal(t) * 100).to_integral_exact())


def transfer_plan(src_balance, dst_balance, amount, max_amount, same_account=False):
    """Move `amount` (integer cents) from src to dst. Returns (new_src, new_dst) or raises ValueError. Verified Ledger.TransferPlan: value is conserved, nothing
    goes negative, zero/negative/oversized/self transfers are refused. Read both balances and write both results in ONE database transaction."""
    for v in (src_balance, dst_balance, amount, max_amount):
        if isinstance(v, bool) or not isinstance(v, int):
            raise TypeError("amounts must be integers (cents), got %r" % (v,))
    if src_balance < 0 or dst_balance < 0 or max_amount < 0:
        raise ValueError("invalid balances")
    ok, a, b = _LG.default__.TransferPlan(src_balance, dst_balance, amount, max_amount, bool(same_account))
    if not ok:
        raise ValueError("transfer refused")
    return int(a), int(b)


class SingleUse:
    """A coupon / reset link / invite / one-time code that works exactly once. consume(token) is True only the first time, even under concurrent requests (lock).
    The set logic is verified (SingleUse.Consume). For several processes use consume_sql: a UNIQUE column makes the database do the atomic part."""
    MAX_TOKENS = 5_000_000

    def __init__(self):
        self.used, self.lock = _dafny.Set([]), threading.Lock()

    def consume(self, token):
        with self.lock:
            if len(self.used) >= self.MAX_TOKENS:
                return False                                   # fail closed rather than grow without bound
            ok, self.used = _SU.default__.Consume(self.used, _S(str(token)))
            return bool(ok)


def consume_sql(conn, table, token):
    """Multi-process single use: the table must have a UNIQUE/PRIMARY KEY `token` column. True only for the first insert of this token."""
    import sqlite3
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        raise ValueError("unsafe table name")
    try:
        conn.execute("INSERT INTO %s(token) VALUES (?)" % table, (str(token),)); conn.commit(); return True
    except sqlite3.IntegrityError:
        return False


# ---- runtime sink guards: apply whether or not the scanner saw the bug -----------------------------------------------------------------------------
# Every dangerous operation goes through a guard at the moment it runs. A missed bug still hits the guard. Not verified in Dafny (covered by tests).
_SINKS_ON = False


_EXTRA_WRITE_ROOTS = set()          # folders the developer explicitly handed to safe_upload / safe_extract
_CODE_EXT = (".py", ".pyc", ".pyo", ".pth", ".so", ".pyd", ".sh")
_CORE_DIR = os.path.realpath(os.path.join(_HERE, "verified_core"))


_TMPDIR = None                       # resolved once, BEFORE open/os.open are patched: tempfile probes candidate dirs with os.open, which would recurse into the guard


def _write_roots():
    import tempfile
    roots = [os.getcwd(), _TMPDIR or tempfile.gettempdir()] + [p for p in os.environ.get("PROVABLY_WRITE_DIRS", "").split(os.pathsep) if p] + list(_EXTRA_WRITE_ROOTS)
    return [os.path.realpath(r) for r in roots]


def _guard_open_path(file, mode):
    if isinstance(file, int) or not any(c in mode for c in "wax+"):
        return
    p = os.path.realpath(os.fspath(file) if not isinstance(file, bytes) else os.fsdecode(file))
    if p.startswith("/dev/"):
        return
    if (p == _CORE_DIR or p.startswith(_CORE_DIR + os.sep) or p.lower().endswith(_CODE_EXT)) and not os.environ.get("PROVABLY_WRITE_CODE"):
        raise PermissionError("provably: writing code files or the verified core is blocked (PROVABLY_WRITE_CODE=1 to allow)")
    if not any(p == r or p.startswith(r + os.sep) for r in _write_roots()):
        raise PermissionError("provably: write outside allowed folders (set PROVABLY_WRITE_DIRS to allow more)")


def guard_sinks():
    """Install process-wide guards (idempotent): outbound connections to private/metadata addresses, shell=True, writes outside the app's folders,
    unsafe pickle, unsigned/alg=none JWTs. Opt out per guard with PROVABLY_ALLOW_INTERNAL_NET=1, PROVABLY_ALLOW_SHELL=1, PROVABLY_ALLOW_PICKLE=1."""
    global _SINKS_ON, _TMPDIR
    if _SINKS_ON:
        return
    _SINKS_ON = True
    import tempfile
    _TMPDIR = tempfile.gettempdir()
    import builtins, subprocess, pickle, pathlib      # pathlib first: on Python <= 3.10 it keeps its own reference to io.open / os.open at import time
    real_gai, real_open, real_popen = socket.getaddrinfo, builtins.open, subprocess.Popen.__init__

    def gai(host, *a, **k):
        res = real_gai(host, *a, **k)
        if not os.environ.get("PROVABLY_ALLOW_INTERNAL_NET"):
            allow = {h.strip().lower() for h in os.environ.get("PROVABLY_INTERNAL_HOSTS", "localhost,127.0.0.1,::1").split(",")}
            h = host.decode() if isinstance(host, bytes) else host
            for info in res:
                ip = info[4][0]
                if ip and not _is_public(ip.split("%")[0]):
                    a_ip = ipaddress.ip_address(ip.split("%")[0])
                    if a_ip.is_loopback and str(h).lower() in allow:
                        continue
                    if (a_ip.is_private and not a_ip.is_link_local) and str(h).lower() in allow:
                        continue
                    raise PermissionError("provably: connection to a non-public address blocked")
        return res
    socket.getaddrinfo = gai

    def op(file, mode="r", *a, **k):
        _guard_open_path(file, mode)
        return real_open(file, mode, *a, **k)
    builtins.open = op
    import io
    io.open = op                                   # pathlib.Path.open / write_text / write_bytes go through io.open, not builtins.open

    real_os_open = os.open
    _W = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

    def os_open(path, flags, *a, **k):
        if flags & _W and k.get("dir_fd") is None and not isinstance(path, int):
            _guard_open_path(path, "w")
        return real_os_open(path, flags, *a, **k)
    os.open = os_open
    acc = getattr(pathlib, "_NormalAccessor", None)           # Python <= 3.10: Path.open / write_text call io.open through this class attribute, bound before the lines above ran
    if acc is not None:
        cur = vars(acc).get("open")
        if cur is real_open:
            acc.open = staticmethod(op)
        elif cur is real_os_open:
            acc.open = staticmethod(os_open)

    if not os.environ.get("PROVABLY_ALLOW_SHELL"):
        def noshell(*a, **k):
            raise PermissionError("provably: os.system/os.popen run a shell; use subprocess with an argument list (PROVABLY_ALLOW_SHELL=1 to allow)")
        os.system = os.popen = noshell

    def popen(self, args, *a, **k):
        if (k.get("shell") or (len(a) > 6 and a[6])) and not os.environ.get("PROVABLY_ALLOW_SHELL"):
            raise PermissionError("provably: shell=True is blocked; pass an argument list")
        return real_popen(self, args, *a, **k)
    subprocess.Popen.__init__ = popen

    if not os.environ.get("PROVABLY_ALLOW_PICKLE"):
        def nope(*a, **k):
            raise PermissionError("provably: pickle loading is blocked (it runs code); use JSON")
        for n in ("loads", "load"):
            setattr(pickle, n, nope)
    try:
        import jwt as _jwt
        real_dec = _jwt.decode

        def dec(token, key="", algorithms=None, options=None, **k):
            if not algorithms or any(str(x).lower() == "none" for x in algorithms):
                raise PermissionError("provably: jwt.decode needs an explicit algorithms list, never 'none'")
            opts = dict(options or {})
            opts["verify_signature"] = True
            return real_dec(token, key, algorithms=algorithms, options=opts, **k)
        _jwt.decode = dec
    except ImportError:
        pass


def safe_upload(file_storage, directory, allowed_ext=(".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".csv"), max_bytes=10 * 1024 * 1024):
    """Save an uploaded file under `directory` with a random server-chosen name (the client's name is never used as a path). Returns the stored name.
    Refuses extensions outside allowed_ext and files larger than max_bytes. Path containment is the verified safe_join."""
    ext = os.path.splitext(os.path.basename(str(getattr(file_storage, "filename", "") or "")))[1].lower()
    if ext not in allowed_ext:
        raise ValueError("file type not allowed")
    name = secrets.token_hex(16) + ext
    _EXTRA_WRITE_ROOTS.add(os.path.realpath(directory))
    dest = safe_join(directory, name)
    data = file_storage.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("file too large")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return name


def safe_xml(data):
    """Parse XML, refusing any DOCTYPE/ENTITY (blocks XXE and entity-expansion bombs). Returns an ElementTree root.
    The refusal is made by the XML parser itself (so UTF-16/32 or other encodings cannot hide a DOCTYPE from a byte pattern); the pattern is a fast pre-check."""
    import xml.etree.ElementTree as ET
    from xml.parsers import expat
    raw = data.encode() if isinstance(data, str) else bytes(data)
    if len(raw) > 5 * 1024 * 1024:
        raise ValueError("XML too large")
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", raw, re.I):
        raise ValueError("XML with DOCTYPE/ENTITY is not accepted")

    def no(*a, **k):
        raise ValueError("XML with DOCTYPE/ENTITY is not accepted")
    p = expat.ParserCreate()
    p.StartDoctypeDeclHandler = p.EntityDeclHandler = p.UnparsedEntityDeclHandler = p.ExternalEntityRefHandler = no
    try:
        p.Parse(raw, True)
    except expat.ExpatError:
        pass                                    # malformed: ET.fromstring below raises its normal ParseError
    return ET.fromstring(raw)


def escape_html(value):
    import html
    return html.escape(str(value), quote=True)


_SCOPES = {}


def scope_sqlite(conn, spec, user):
    """Owner filter BY CONSTRUCTION for sqlite. spec={table: owner_column}, user=logged-in id.
    Reads: SELECTs on a scoped table are redirected to a temp view that only holds `user`'s rows, and the sqlite authorizer denies any read of the
    real table that does not come through that view (so no query shape sees another owner's row). Writes: temp triggers abort any insert/update/delete
    whose row is not owned by `user`, and any update that changes the owner. Call per request; applies to this connection only."""
    import sqlite3
    ident = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    if user is None:
        raise PermissionError("not logged in")
    for t, col in spec.items():
        if not (ident.fullmatch(t) and ident.fullmatch(col)):
            raise ValueError("unsafe name")
        if col not in [r[1] for r in conn.execute("PRAGMA main.table_info(%s)" % t)]:
            raise ValueError("no such owner column")
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS _provably_user(v TEXT)")
    conn.execute("DELETE FROM _provably_user")
    conn.execute("INSERT INTO _provably_user VALUES (?)", (str(user),))
    me = "(SELECT v FROM temp._provably_user)"
    for t, col in spec.items():
        conn.execute("DROP VIEW IF EXISTS temp._provably_v_%s" % t)
        conn.execute("CREATE TEMP VIEW _provably_v_%s AS SELECT * FROM main.%s WHERE CAST(%s AS TEXT) = %s" % (t, t, col, me))
        for k in "iud":
            conn.execute("DROP TRIGGER IF EXISTS temp._provably_%s_%s" % (t, k))
        conn.execute("CREATE TEMP TRIGGER _provably_%s_i BEFORE INSERT ON main.%s WHEN CAST(NEW.%s AS TEXT) IS NOT %s BEGIN SELECT RAISE(ABORT, 'provably: not your row'); END" % (t, t, col, me))
        conn.execute("CREATE TEMP TRIGGER _provably_%s_u BEFORE UPDATE ON main.%s WHEN CAST(OLD.%s AS TEXT) IS NOT %s OR CAST(NEW.%s AS TEXT) IS NOT %s BEGIN SELECT RAISE(ABORT, 'provably: not your row'); END" % (t, t, col, me, col, me))
        conn.execute("CREATE TEMP TRIGGER _provably_%s_d BEFORE DELETE ON main.%s WHEN CAST(OLD.%s AS TEXT) IS NOT %s BEGIN SELECT RAISE(ABORT, 'provably: not your row'); END" % (t, t, col, me))
    scoped = {t.lower() for t in spec}
    views = {"_provably_v_" + t.lower() for t in spec}
    state = {"top": None}

    def auth(action, a1, a2, db, source):
        if action in (21, 18, 23, 9):
            if source is None:
                state["top"] = action
            return sqlite3.SQLITE_OK
        if action == 20 and a1 and a1.lower() in scoped and not (source and (source.startswith("_provably_") or source.lower() in views)):   # SQLITE_READ
            if state["top"] == 21 or source is None and state["top"] is None:
                return sqlite3.SQLITE_DENY                  # SELECT reading the raw table directly
        return sqlite3.SQLITE_OK
    conn.set_authorizer(auth)
    _SCOPES[id(conn)] = (scoped, views)
    return conn


def scoped_execute(conn, sql, params=()):
    """execute() for a scope_sqlite connection: redirects FROM/JOIN <scoped table> to its owner-filtered view."""
    scoped, _ = _SCOPES[id(conn)]
    def sub(m):
        return m.group(1) + "_provably_v_" + m.group(2) if m.group(2).lower() in scoped else m.group(0)
    if re.match(r"\s*(SELECT|WITH)\b", sql, re.I):
        sql = re.sub(r"(?i)\b(FROM\s+|JOIN\s+|,\s*)([A-Za-z_][A-Za-z0-9_]*)\b", sub, sql)
    return conn.execute(sql, params)


_PRIVILEGED = re.compile(r"^(id|_id|pk|role|roles|is_?admin|admin|is_?staff|is_?superuser|superuser|permissions?|scopes?|groups?|owner(_id)?|user_?id|account_?id|balance|credits?|price|total|amount_paid|discount|verified|is_?verified|email_?verified|approved|status|created_?at|updated_?at|password_?hash|tenant(_id)?)$", re.I)


def reject_privileged(data):
    """Mass-assignment guard: drop fields the client must never set (role, is_admin, owner, price, balance, id, ...). Returns a new dict."""
    if not isinstance(data, dict):
        data = dict(data or {})
    return {k: v for k, v in data.items() if not _PRIVILEGED.match(str(k))}


def clean_header(value):
    """Remove CR/LF (response splitting) from a value going into a header."""
    return re.sub(r"[\r\n\x00]", "", str(value))


_MAX_ARCHIVE_MEMBER = 100 * 1024 * 1024


def safe_extract(archive, dest):
    """Extract a ZipFile/TarFile with every member path pinned inside dest (zip-slip) and no links/devices. Verified safe_join decides containment."""
    import tarfile, zipfile
    os.makedirs(dest, exist_ok=True)
    _EXTRA_WRITE_ROOTS.add(os.path.realpath(dest))
    if isinstance(archive, zipfile.ZipFile):
        for m in archive.infolist():
            target = safe_join(dest, m.filename)
            if m.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if m.file_size > _MAX_ARCHIVE_MEMBER:
                raise ValueError("archive member too large")
            with archive.open(m) as src, open(target, "wb") as out:
                data = src.read(_MAX_ARCHIVE_MEMBER + 1)
                if len(data) > _MAX_ARCHIVE_MEMBER:     # header lied about the size
                    raise ValueError("archive member too large")
                out.write(data)
        return
    for m in archive.getmembers():
        if m.issym() or m.islnk() or m.isdev():
            raise ValueError("link or device in archive")
        safe_join(dest, m.name)
    for m in archive.getmembers():
        if m.size > _MAX_ARCHIVE_MEMBER:
            raise ValueError("archive member too large")
    if hasattr(tarfile, "data_filter"):     # 3.12+, and the security backports to 3.8-3.11
        archive.extractall(dest, filter="data")
    else:                                   # old interpreter without the filter: members were already checked above (safe_join, no links/devices, size cap)
        archive.extractall(dest)


# ==== defence in depth ==========================================================================================================================
# Everything above stops KNOWN bug classes. A skilled attacker does not need a known class: they need many probes to find something, a stolen session to
# use it, a way to sweep data once they have found it, and a quiet place to stay. These layers change that economy, with no knowledge of your bugs:
#   1 probe budget      every refusal is a strike; a handful of strikes bans the client (an hour, doubling for repeat offenders), so blind probing costs the attacker
#                       their address after a few tries instead of thousands of tries for free
#   2 sweep brake       a client that touches too many DIFFERENT records of one route, or pulls too many bytes, is stopped and its account is frozen - so a
#                       missing ownership check leaks tens of rows, not the table
#   3 session defence   cookies are bound to the client that logged in, expire when idle and in absolute time, and can be revoked; a stolen cookie replayed
#                       from elsewhere is refused and costs the thief their address
#   4 opaque ids        record ids in URLs can be sealed to (kind, user): they cannot be guessed, enumerated or reused by another account
#   5 canaries          fields, accounts and URLs that no honest client touches: one touch bans immediately
#   6 integrity         code files are re-hashed in the background; any change or new .py file locks the app (503) and logs it; the manifest can be signed with a
#                       key that is not on the server's disk
# All limits are env-tunable (PROVABLY_STRIKE_LIMIT, _STRIKE_WINDOW, _ENUM_LIMIT, _EGRESS_BYTES, _IDLE, _ABSOLUTE, _BIND) and local/loopback traffic is never struck.
import collections
import logging as _logging

_dlog = _logging.getLogger("provably.depth")
_STRIKES, _OFFENCES, _SLOCK = {}, {}, threading.Lock()
_MAXKEYS = 20_000


def _envf(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return float(default)


def _strike_limit():
    return _envf("PROVABLY_STRIKE_LIMIT", 8)


def _decoy_accounts():
    return {a.strip().casefold() for a in os.environ.get("PROVABLY_DECOY_ACCOUNTS", "").split(",") if a.strip()}


def _proxy_suspected(request):
    """A private socket address that arrives with forwarding headers while no proxy is declared: it is our own proxy, so it must never be struck or banned."""
    return _hops() == 0 and not _public_ip(client_ip()) and bool(request.headers.get("X-Forwarded-For") or request.headers.get("Forwarded"))


def _strikeable(ip, request):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if a.is_loopback and not os.environ.get("PROVABLY_STRIKE_LOOPBACK"):
        return False
    return not _proxy_suspected(request)


def _prune(d, now, ttl):
    for k in [k for k, v in d.items() if not v or now - (v[-1][0] if isinstance(v, list) else v) > ttl]:
        d.pop(k, None)


def strike(weight=1.0, why="", user=None):
    """Record misbehaviour by the current client (no-op outside a request, never raises). Score >= PROVABLY_STRIKE_LIMIT within PROVABLY_STRIKE_WINDOW bans the
    client address (1 h, doubling per repeat, cap 3 days) and, if a logged-in user is involved, freezes that user (15 min, doubling) and revokes their sessions."""
    try:
        from flask import has_request_context, request, g
        if not has_request_context():
            return
        g.provably_struck = True
        keys = []
        ip = client_ip()
        if _strikeable(ip, request):
            keys.append(_rate_key(ip))
        if user is not None:
            keys.append("u:" + str(user))
        now, window, limit = time.monotonic(), _envf("PROVABLY_STRIKE_WINDOW", 600), _strike_limit()
        for k in keys:
            with _SLOCK:
                if len(_STRIKES) >= _MAXKEYS:
                    _prune(_STRIKES, now, window)
                if len(_STRIKES) >= _MAXKEYS and k not in _STRIKES:
                    continue
                q = [(t, w) for t, w in _STRIKES.get(k, []) if now - t < window] + [(now, float(weight))]
                _STRIKES[k] = q
                hit = sum(w for _, w in q) >= limit
                if hit:
                    n = _OFFENCES.get(k, 0)
                    if len(_OFFENCES) < _MAXKEYS or k in _OFFENCES:
                        _OFFENCES[k] = n + 1
                    _STRIKES.pop(k, None)
            if hit:
                secs = min(900 * 2 ** n, 86400) if k.startswith("u:") else min(3600 * 2 ** n, 3 * 86400)
                ban(k, secs)
                if k.startswith("u:"):
                    revoke_sessions(k[2:])
                _dlog.warning("banned %s for %ss: %s", k, int(secs), why)
    except Exception:                      # a bug in the defence must never take the app down or let a request through differently
        _dlog.exception("strike() failed")


_EPOCH = {}                                # user -> session epoch; bumping it kills every cookie issued before


def revoke_sessions(user):
    """Invalidate every existing session cookie of this user (server-side revocation for signed-cookie sessions). In-memory: one worker, or share the dict."""
    u = str(user)
    if len(_EPOCH) < _MAXKEYS or u in _EPOCH:
        _EPOCH[u] = _EPOCH.get(u, 0) + 1


def login_user(user, role=None, **extra):
    """Start a fresh session for `user` (drops anything the browser sent first: no session fixation) and make it permanent so lifetimes apply."""
    from flask import session
    session.clear()
    session["user"] = user
    if role is not None:
        session["role"] = role
    session.update(extra)
    session.permanent = True
    return user


def _fingerprint(app, request):
    mode = os.environ.get("PROVABLY_BIND", "ua+ip").lower()
    if mode == "off":
        return None
    parts = [request.headers.get("User-Agent", "")]
    if "ip" in mode:
        try:
            a = ipaddress.ip_address(client_ip().split("%")[0])
            parts.append(str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False)))
        except ValueError:
            parts.append("?")
    key = app.secret_key or b""
    key = key.encode() if isinstance(key, str) else bytes(key)
    return hmac.new(key, "|".join(parts).encode(), "sha256").hexdigest()[:32]


def _install_depth(app):
    from flask import request, session, abort, g
    if app.extensions.get("provably_depth"):
        return
    app.extensions["provably_depth"] = True
    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    if os.environ.get("PROVABLY_HTTPS") == "1":                       # deploy.py sets this: browsers then refuse the cookie over plain http and from sibling domains
        app.config["SESSION_COOKIE_SECURE"] = True
        app.config["SESSION_COOKIE_NAME"] = "__Host-session"
        app.config["SESSION_COOKIE_PATH"] = "/"
        app.config["SESSION_COOKIE_DOMAIN"] = None

    @app.before_request
    def _provably_session_guard():
        user = session.get("user")
        if user is None:
            return
        if is_banned("u:" + str(user)):
            session.clear(); g.provably_struck = True
            abort(403)
        now = int(time.time())
        ep = _EPOCH.get(str(user), 0)
        if session.get("_ep", 0) != ep:                                # a cookie from before any revocation carries no epoch: that means 0
            session.clear(); abort(401)                                # revoked
        if "_ep" not in session and ep:
            session["_ep"] = ep
        iat, seen = session.setdefault("_iat", now), session.get("_seen", now)
        if now - iat > _envf("PROVABLY_ABSOLUTE", 12 * 3600) or now - seen > _envf("PROVABLY_IDLE", 30 * 60):
            session.clear(); abort(401)
        if now - seen >= 60 or "_seen" not in session:
            session["_seen"] = now
        fp = _fingerprint(app, request)
        if fp is None:
            return
        bound = session.get("_fp")
        if bound is None:
            session["_fp"] = fp                                       # first request after login: bind the cookie to this browser and network
        elif not hmac.compare_digest(str(bound), fp):
            session.clear()
            strike(_strike_limit(), "session cookie replayed from a different client", user=user)
            abort(401)

    egress, seen_vals = {}, {}
    state_lock = threading.Lock()

    @app.after_request
    def _provably_depth_after(resp):
        try:
            if getattr(g, "provably_struck", False):
                return resp
            st, rule = resp.status_code, request.url_rule
            if st == 404 and rule is None and request.path not in ("/favicon.ico", "/robots.txt") and not request.path.startswith("/static/") \
                    and not request.path.lower().endswith(_ASSET_EXT):
                strike(0.25, "404 probe")                          # content bugs (a missing image) are not attacks; scanners ask for .php, /admin, /.git ...
            elif st in (403, 429):
                strike(1, "refused request %s" % st, user=session.get("user"))
            elif 200 <= st < 300 and rule is not None and request.endpoint != "static":
                return _sweep_brake(resp, rule.rule)
        except Exception:
            _dlog.exception("depth after_request failed")
        return resp

    def _sweep_brake(resp, rule):
        ip = client_ip()
        if not _strikeable(ip, request) and session.get("user") is None:
            return resp
        user = session.get("user")
        keys = ([_rate_key(ip)] if _strikeable(ip, request) else []) + (["u:" + str(user)] if user is not None else [])
        now = time.monotonic()
        vals = sorted((k, v) for k, v in list(request.args.items(multi=True)) + list(request.form.items(multi=True)) if not _BENIGN_PARAM.match(k))
        digest = hashlib.sha1(repr(vals).encode()).hexdigest()[:16] if vals else None
        try:
            size = resp.content_length if resp.content_length is not None else (0 if resp.direct_passthrough else len(resp.get_data()))
        except Exception:
            size = 0
        enum_limit, byte_limit = int(_envf("PROVABLY_ENUM_LIMIT", 80)), int(_envf("PROVABLY_EGRESS_BYTES", 64 * 1024 * 1024))
        over = None
        with state_lock:
            if len(seen_vals) > _MAXKEYS:
                seen_vals.clear()
            if len(egress) > _MAXKEYS:
                egress.clear()
            for k in keys:
                if digest is not None:
                    d = seen_vals.setdefault((k, rule), {})
                    for h in [h for h, t in d.items() if now - t > 300]:
                        d.pop(h, None)
                    d[digest] = now
                    if len(d) > enum_limit:
                        over = "swept %d different records of %s" % (len(d), rule)
                q = egress.setdefault(k, collections.deque())
                while q and now - q[0][0] > 600:
                    q.popleft()
                q.append((now, size))
                if sum(b for _, b in q) > byte_limit:
                    over = "pulled more than %d bytes in 10 minutes" % byte_limit
        if over:
            strike(_strike_limit(), over, user=user)
            from flask import make_response
            return make_response("", 429)
        return resp


# ---- opaque ids: a record id that cannot be guessed, enumerated, or used by another account -------------------------------------------------------
def _id_key(label):
    from flask import current_app
    master = os.environ.get("PROVABLY_ID_KEY") or current_app.secret_key
    if not master:
        raise RuntimeError("set PROVABLY_ID_KEY (or app.secret_key) before sealing ids")
    master = master.encode() if isinstance(master, str) else bytes(master)
    return hmac.new(master, b"provably-id|" + label, "sha256").digest()


def seal_id(kind, rid, user="__session__"):
    """Turn a record id into an opaque token bound to (kind, user). user defaults to the logged-in user; pass None for a public object. Deterministic per
    (kind, user, id), so links stay stable. Format: nonce(8) | id XOR keystream | tag(12); HMAC-SHA256 throughout (nonce = PRF of the inputs, SIV style)."""
    import base64
    if user == "__session__":
        from flask import session
        user = session.get("user")
    rid_b = str(rid).encode()
    if not rid_b or len(rid_b) > 64:
        raise ValueError("id must be 1..64 bytes")
    ctx = b"|".join([str(kind).encode(), b"" if user is None else str(user).encode()])
    nonce = hmac.new(_id_key(b"nonce"), ctx + b"|" + rid_b, "sha256").digest()[:8]
    stream = hmac.new(_id_key(b"enc"), nonce, "sha256").digest()
    ct = bytes(a ^ b for a, b in zip(rid_b, stream))
    tag = hmac.new(_id_key(b"mac"), ctx + b"|" + nonce + ct, "sha256").digest()[:12]
    return base64.urlsafe_b64encode(nonce + ct + tag).decode().rstrip("=")


def open_id(kind, token, user="__session__"):
    """Inverse of seal_id. Raises ValueError (and strikes the client) for anything not sealed by us for this (kind, user): forged, edited, other user's, other kind."""
    import base64
    if user == "__session__":
        from flask import session
        user = session.get("user")
    try:
        raw = base64.urlsafe_b64decode(str(token) + "=" * (-len(str(token)) % 4))
        nonce, ct, tag = raw[:8], raw[8:-12], raw[-12:]
        if not ct or len(ct) > 64:
            raise ValueError
        ctx = b"|".join([str(kind).encode(), b"" if user is None else str(user).encode()])
        want = hmac.new(_id_key(b"mac"), ctx + b"|" + nonce + ct, "sha256").digest()[:12]
        if not hmac.compare_digest(want, tag):
            raise ValueError
        stream = hmac.new(_id_key(b"enc"), nonce, "sha256").digest()
        return bytes(a ^ b for a, b in zip(ct, stream)).decode()
    except (ValueError, TypeError, UnicodeDecodeError):
        strike(3, "forged or foreign record token", user=user)
        raise ValueError("invalid id") from None


# ---- integrity watchdog -------------------------------------------------------------------------------------------------------------------------
_ASSET_EXT = (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".mp4")
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "site-packages"}


def _scan_code(roots, limit=5000):
    out = {}
    for root in roots:
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in _SKIP_DIRS]
            for f in fn:
                if f.lower().endswith(_CODE_EXT) or f == "MANIFEST.json":
                    p = os.path.join(dp, f)
                    try:
                        with open(p, "rb") as fh:
                            out[p] = hashlib.sha256(fh.read()).hexdigest()
                    except OSError:
                        pass
                    if len(out) >= limit:
                        return out
    return out


def integrity_watch(app, roots=None, interval=20.0):
    """Hash every code file (.py/.pth/.so/.sh and the manifest) under the app folder and this library's folder now, and again every `interval` seconds.
    Any changed, removed or NEW code file locks the app: every request gets 503 and a CRITICAL log line names the files. Set PROVABLY_INTEGRITY_EXIT=1 to also
    exit the process (an orchestrator then restarts a clean copy). Returns a dict whose "locked"/"changed" entries report the state. Enabled by shield() when
    PROVABLY_WATCHDOG=1 (deploy.py sets it). Detects tampering after the fact; it cannot prevent it - the read-only container does that."""
    from flask import abort
    roots = [os.path.realpath(r) for r in (roots or [os.getcwd(), _HERE])]
    roots = [r for r in roots if not any(r != o and r.startswith(o + os.sep) for o in roots)]
    base = _scan_code(roots)
    state = {"locked": False, "changed": [], "files": len(base)}

    def loop():
        while not state["locked"]:
            time.sleep(interval)
            cur = _scan_code(roots)
            if cur != base:
                state["changed"] = sorted({p for p in set(cur) | set(base) if cur.get(p) != base.get(p)})
                state["locked"] = True
                _dlog.critical("INTEGRITY: code changed on disk, app locked: %s", state["changed"][:10])
                if os.environ.get("PROVABLY_INTEGRITY_EXIT") == "1":
                    os._exit(70)
    threading.Thread(target=loop, daemon=True, name="provably-integrity").start()

    @app.before_request
    def _provably_locked():
        if state["locked"]:
            abort(503)
    return state
