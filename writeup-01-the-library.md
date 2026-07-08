# [01] The Library — Writeup

**Points:** 100
**Flag:** `FAM{str1ngs_d0nt_l13_1n_n4t1v3_l4nd}`

## Challenge

> Many times devs put secrets in code and forget to remove.
> can you find that secret ??

APK provided: `fam-ctf.apk`

## Thought process

No category label was given here, but the flavor text ("devs put secrets in code") and the title "The Library" suggested two possible meanings of "library": (a) a source-code library/SDK bundled into the app, or (b) a literal native code library (`.so` file), since Android apps can ship compiled C/C++ code alongside Java/Kotlin.

Given it was worth only 100 points (the easiest tier) and explicitly said "find that secret" rather than "reverse this algorithm," I assumed the secret was a plaintext constant somewhere in the app package — either in the bytecode or in a bundled binary — rather than something requiring real decompilation or logic tracing. That meant the fastest approach was to avoid installing a decompiler (jadx/apktool) up front and instead treat the APK as a plain ZIP archive, using `unzip` + `strings` + `grep` to hunt for readable text. If that failed, the fallback would have been to pull in jadx for a proper decompile.

The key decision point was filtering signal from noise: a modern APK bundles huge amounts of Firebase/Google Play Services/Kotlin stdlib code, all of which litter `strings` output with irrelevant matches for generic terms like "secret" or "key" (e.g., `SecretKeySpec` from `javax.crypto`). So before grepping for the flag, I first identified the app's *own* package name to scope the search and cut out library noise.

## Steps

1. **Extract the APK** (it's just a ZIP):
   ```bash
   unzip fam-ctf.apk -d extracted
   ```

2. **Identify the app's own package** among the DEX files, to separate app code from bundled library noise (Firebase, Google Play Services, etc.):
   ```bash
   for f in extracted/classes*.dex; do
     strings "$f" | grep -oE 'L[a-z]+/[a-z0-9_]+/[a-z0-9_]+/'
   done | sort | uniq -c | sort -rn
   ```
   This surfaced `com/ctf/fam/` as the app's package, living in `classes3.dex`.

3. **Dump strings from the app's classes**:
   ```bash
   strings -n 8 extracted/classes3.dex | grep -iE 'token|secret|debug|flag|native'
   ```
   This revealed a native method declared in `MainActivity`:
   ```
   getSecretFromNative
   ```
   This was the turning point in the investigation: the `Native` suffix, combined with the JNI naming convention typically seen on such methods, indicated the secret isn't in the Java/Kotlin bytecode at all — it's read from a bundled native (`.so`) library at runtime. The challenge title, "The Library," clicked at this point: it wasn't referring to an SDK/library dependency, but to the actual native shared library file. This redirected the search from the DEX files to the `lib/` directory.

4. **Locate the native libraries**:
   ```bash
   find extracted/lib -type f
   ```
   ```
   lib/arm64-v8a/libc++_shared.so
   lib/arm64-v8a/libfam.so
   lib/x86_64/libc++_shared.so
   lib/x86_64/libfam.so
   ```
   `libfam.so` is the app-specific one (matches the package name).

5. **Run `strings` directly on `libfam.so`**:
   ```bash
   strings -n 5 extracted/lib/arm64-v8a/libfam.so | grep -i fam
   ```
   Output:
   ```
   FAM{str1ngs_d0nt_l13_1n_n4t1v3_l4nd}
   Java_com_ctf_fam_MainActivity_computeSignature
   Java_com_ctf_fam_MainActivity_getDebugToken
   Java_com_ctf_fam_MainActivity_getSecretFromNative
   Java_com_ctf_fam_MainActivity_getUsernames
   ```

Flag found as a plaintext string embedded directly in the native binary — no decompilation or disassembly required.

## Tools used

- `unzip` — extract the APK (it's a ZIP archive)
- `strings` — pull printable strings from DEX bytecode and from the native `.so` binary

## Key takeaway

When a `getSecretFromNative()` / JNI method shows up in the decompiled Java/DEX layer, the actual secret usually lives in `lib/<abi>/*.so`, not in the app code. Checking native libraries with `strings` before reaching for a disassembler (Ghidra/IDA) is a fast first pass — plenty of hardcoded secrets survive as plaintext in native binaries.
