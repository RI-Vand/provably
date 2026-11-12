"""The secure-build protocol that the connected AI is told to follow (the text of provably_protocol and of the server instructions)."""
PROTOCOL = """PROVABLY SECURE-BUILD PROTOCOL. Follow it for every web app or API you write or change while this connector is active.
1. CONTRACT FIRST. Before writing code, decide and state in a few lines: the roles (anon / user / admin); which records each user owns; every action that moves
   money, credits or stock; every one-time thing (coupon, reset link, invite, OTP); every workflow with states (e.g. order: cart -> paid -> shipped).
   If the request leaves one of these open, ask ONE short question, or take the safest reading and say so.
2. BUILD WITH THE VERIFIED PRIMITIVES, not hand-rolled logic (import provably_secure):
   policy_gate(app, {"GET /": ["anon","user"], "POST /pay": ["user"], ...})  every route + role declared; anything undeclared is refused
   owner_only(id) the record belongs to the logged-in user | to_cents + transfer_plan  money is integer cents, conserved, never negative, never a float
   SingleUse / consume_sql  one-time tokens work once even under concurrent requests | state_transition(EDGES, current, next)  workflow steps cannot be skipped
   safe_join / safe_redirect_target / safe_arg / safe_url / hash_password / allow_params for the injection and input classes.
3. NEVER TAKE FROM THE CLIENT: price, total, discount, role, is_admin, user_id, owner, status. Look them up or derive them on the server.
4. ATOMIC: every balance / stock / token change happens in ONE database transaction; one-time uniqueness comes from a UNIQUE constraint.
5. LOOP BEFORE YOU SHOW CODE: call provably_harden, then provably_bizcheck. Apply every 'fix' line, call again, repeat until bizcheck reports nothing.
   Never tell the user the code is secure while a high finding is open.
6. REPORT HONESTLY: tell the user what was checked, which business rules you assumed (so they can correct you), and what is NOT covered: rules nobody declared,
   dependencies, secrets handling, infrastructure. Never claim the app is unhackable.
7. Ship provably_secure.py and the verified_core folder with the app (the app refuses to start without the verified code)."""
