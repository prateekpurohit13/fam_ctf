# [04] The Endpoint — Writeup

**Points:** 400
**Category:** Dynamic Analysis / Native RE
**Flag:** `FAM{x_s1gn4tur3_r3v3rs3d_n1c3ly}`

## Challenge

> The server only trusts what it can verify. Intercept. Modify. But can you keep it honest?
>
> hint: only admin has clearance
>
> Endpoint: `https://ctf.fampay.co/api/check`

Given: `fam-ctf.apk`.

## Endpoint recon

- `GET /api/check` → 501 (only POST)
- `POST {}` → `{"error": "invalid json"}`
- `POST {"username":"..."}` with no/invalid signature → `{"error": "X-Signature verification failed"}`
- valid signature, non-admin user → `{"error": "access denied"}`

So the server authenticates each request by an `X-Signature` header over the body, and gates a flag behind `username == admin`.

## APK analysis (jadx)

`com.ctf.fam.MainActivity` builds the request:

```java
String body = "{\"username\":\"" + username + "\"}";
String sig  = computeSignature("POST", "/api/check", body);   // native
// ...
conn.setRequestProperty("X-Signature", sig);
conn.setRequestProperty("Content-Type", "application/json");
```

`computeSignature` is a JNI native method in `libfam.so`. The usernames shown in the app come from another native method `getUsernames()` — and **`admin` is not in that list**. So the app can never legitimately produce an admin signature; we must forge one.

## Reversing libfam.so (objdump, x86_64 variant)

### JNI glue — `Java_..._computeSignature`
Builds `message = method + "|" + path + "|" + body` (separator `|` at rodata `0x32d9`), then calls the real hash at `0x68f0`. For us: `POST|/api/check|{"username":"admin"}`.

### The hash (`0x68f0`)
- **State:** four 64-bit words, init constants at rodata `0x3570`.
- **XOR key:** 19-byte table at `0x34f0`, each byte XOR `0xAA` → ASCII `FAM_s3cr3t_k3y_2026`.
- **Per input byte i:**
  - `mixed = msg[i] ^ key[i % 19]`
  - `state[i&3] ^= mixed`
  - `state[(i+1)&3] += state[i&3]`
  - `state[(i+2)&3] = fmix64(state[(i+2)&3])`
  - `state[(i+3)&3] ^= 0x517cc1b727220a95 * state[(i+1)&3]`
  - parallel FNV-1a accumulator `h` over the raw byte (basis `0xcbf29ce484222325`, prime `0x100000001b3`)
- **`fmix64` (`0x7390`)** is the MurmurHash3 64-bit finalizer (`^= >>33; *0xff51afd7ed558ccd; ^= >>33; *0xc4ceb9fe1a85ec53; ^= >>33`).
- **Finalization:** 4 rounds of `for c in 0..3: state[c] = fmix64(state[c] ^ state[(c+1)%4])`.
- **Output:** `%016llx` of each of the 4 state words → 64 hex chars.

### The backdoor ("keep it honest")
After finalization:

```c
if (h == 0xdcc67eca15a7c732)          // FNV of exactly {"username":"admin"}
    state[2] ^= 0xdeadbeefcafebabe;   // sabotage
```

The native library **deliberately corrupts** the signature for the admin message. The server verifies the *honest* signature (computed without this tweak). This is the whole point of the challenge title/prompt: the app is dishonest for `admin`; you must reconstruct the honest hash.

## Exploitation

1. Reimplemented the hash in Python (`sign.py`).
2. **Validated** against a legit username: `guest` → `access denied` (signature accepted), confirming the reimplementation is byte-exact.
3. For `admin`, the FNV `h` equals `0xdcc67eca15a7c732`, so I computed the signature **without** applying the `state[2] ^= 0xdeadbeef...` sabotage — the "honest" signature the server expects.

```
message = POST|/api/check|{"username":"admin"}
honest sig = 2c64c639cabe5382ccd9fe4681277a847ef6be05f7b3aefdf685681298952188
```

```bash
curl -s -X POST "https://ctf.fampay.co/api/check" \
  -H "Content-Type: application/json" \
  -H "X-Signature: 2c64c639cabe5382ccd9fe4681277a847ef6be05f7b3aefdf685681298952188" \
  --data '{"username":"admin"}'
# {"flag": "FAM{x_s1gn4tur3_r3v3rs3d_n1c3ly}", "message": "Welcome, admin."}
```

## Tools used
- **jadx** — decompile the APK; find `computeSignature`, `getUsernames`, and the `X-Signature`/body construction.
- **objdump** (mingw) — disassemble `libfam.so` (x86_64) to reverse the hash, constants, key table, and the backdoor.
- **Python** — reimplement the hash and forge the honest admin signature.
- **curl** — replay the forged request.

No emulator/Frida/Ghidra needed — the signing scheme is self-contained and forgeable offline once reversed.

## Key takeaway
A client-side signing routine is not a trust anchor: anything the app can compute, an attacker can re-derive from the binary — including hardcoded keys (`FAM_s3cr3t_k3y_2026`) and even intentionally hidden logic. The "honest vs. sabotaged" twist is a nice reminder to diff what the client *sends* against what the server *expects*, and to read the whole function (the `if h == const` branch was the crux, not the hash itself).
