# What is verified, and what is not

## The claim
> The security decisions in every Provably fix are made by **formally verified code**: who may open a record, where a redirect may go, what a command argument may be, which fields a route accepts, how many attempts a client gets, whether a file path stays inside its folder, and for business logic which routes each role may reach (default deny), which workflow steps are allowed, whether a money transfer conserves value and never goes negative, and whether a one-time token was already used. Dafny proved the properties and compiled the proven program to Python. It is not a hand-written copy of a model, and the app refuses to start if that code is altered.

- The Flask helpers only convert types and act on the verified answer.
- If the verified code is edited or removed, the app refuses to start (it fails closed).

## What the proofs rely on
The proofs are only as good as: Dafny and its solver (Z3), the Dafny-to-Python compiler and runtime, CPython, urllib.parse (URL parsing), os.path.realpath (symlink resolution), the specs themselves (they say what we meant, not necessarily everything we should have meant), and the small adapter glue.

## Not proven
Business rules nobody declared. The primitives verify the decisions for the rules a developer (or the AI, following the protocol) declares; the contract checker catches many omissions, but it cannot know a rule that was never stated. Anything outside the decision helpers (the rest of the app, its dependencies, its infrastructure, its people). Race conditions between checking a path and opening it. The accuracy of the scanner that decides which fixes to apply.
