Title: msseccore.sys — Uninitialized OSVERSIONINFOW zeroed before RtlGetVersion in DriverEntry (CWE-908), fixed
Date: 2026-06-26
Slug: msseccore_33ca946f-msseccore-report-20260626-042118
Category: Corpus
Author: Argus
Summary: KB5073724
Severity: Low

### 1. Overview

- **Unpatched Binary:** `msseccore_unpatched.sys`
- **Patched Binary:** `msseccore_patched.sys`
- **Overall Similarity Score:** 0.9011
- **Diff Statistics:** 43 matched functions, 32 identical functions, 11 changed functions, 0 unmatched functions in both directions.
- **Verdict:** The patch introduces a defense-in-depth zero-initialization of a stack `OSVERSIONINFOW` structure (CWE-908) in `DriverEntry`, while the remaining changes are compiler code-generation differences (`memset` folded into inline SSE zeroing, register reallocation), a CRT `memmove` rewrite, a pool-type constant change in a fallback allocation path, and a notification class constant update.

### 2. Vulnerability Summary

- **Severity:** Low
- **Vulnerability Class:** Use of Uninitialized Resource (CWE-908)
- **Affected Function:** `DriverEntry`

**Root Cause & Exploitability:**
The unpatched `DriverEntry` function allocates an `OSVERSIONINFOW` structure on the kernel stack. It sets only the first 4 bytes (`dwOSVersionInfoSize` = `0x114`) before passing the structure to `RtlGetVersion()`; the remaining `0x110` bytes (including the 256-byte `szCSDVersion` wide-string field at structure offset `0x14`) are left uninitialized. The patched binary adds an explicit `memset` that zeroes those `0x110` bytes before the call.

This is a defense-in-depth zero-initialization. The practical impact is minimal: the structure is a local stack variable that never leaves `DriverEntry`, only `dwMajorVersion`/`dwMinorVersion` are read after the call, and the structure is not copied to any lower-privilege context, returned to a caller, or written to shared state. `RtlGetVersion` on this build fully populates the structure and returns `STATUS_SUCCESS`, so no residual-data information-disclosure path is demonstrated. The change eliminates reliance on the API to overwrite every field.

**Attacker-Reachable Entry Point & Call Chain:**
1. The vulnerability is triggered automatically during system boot or driver initialization. No direct attacker input is required to trigger the uninitialized memory condition.
2. `DriverEntry` (module entry point)
3. `RtlGetVersion` (target of the uninitialized pointer argument)

### 3. Pseudocode Diff

```c
// UNPATCHED DriverEntry
OSVERSIONINFOW versionInformation; // Stack-allocated
// MISSING: Zero-initialization of the structure
versionInformation.dwOSVersionInfoSize = 0x114; // Only 4 bytes are explicitly set

// Passes structure with 0x110 bytes of uninitialized stack data
if (RtlGetVersion(&versionInformation) >= STATUS_SUCCESS) {
    // ... uses versionInformation.dwMajorVersion etc.
}

// ------------------------------------------------------------------

// PATCHED DriverEntry
OSVERSIONINFOW versionInformation;
memset(&versionInformation.dwMajorVersion, 0, 0x110); // ADDED: zeros the 0x110 bytes after the size field
versionInformation.dwOSVersionInfoSize = 0x114;

if (RtlGetVersion(&versionInformation) >= STATUS_SUCCESS) {
    // ...
}
```

### 4. Assembly Analysis

**Unpatched `DriverEntry` Sequence (function @ 0x1C000A008):**
```assembly
00000001C000A070  lea     rcx, [rsp+1A8h+VersionInformation]                 ; &OSVERSIONINFOW
00000001C000A075  mov     [rsp+1A8h+VersionInformation.dwOSVersionInfoSize], 114h  ; sets ONLY dwOSVersionInfoSize (4 bytes)
; No instructions zero the remaining 0x110 bytes of the structure
00000001C000A07D  call    cs:__imp_RtlGetVersion                             ; RtlGetVersion(&VersionInformation)
```

**Patched `DriverEntry` Sequence (function @ 0x1C000A078):**
```assembly
00000001C000A0E2  xor     edx, edx                                          ; fill byte = 0
00000001C000A0E4  lea     rcx, [rsp+1B0h+VersionInformation.dwMajorVersion]  ; &OSVERSIONINFOW + 4
00000001C000A0E9  mov     r8d, 110h                                          ; count = 0x110
00000001C000A0EF  call    memset                                            ; ADDED: zero 0x110 bytes
00000001C000A0F4  lea     rcx, [rsp+1B0h+VersionInformation]                 ; &OSVERSIONINFOW
00000001C000A0F9  mov     [rsp+1B0h+VersionInformation.dwOSVersionInfoSize], 114h  ; sets dwOSVersionInfoSize
00000001C000A101  call    cs:__imp_RtlGetVersion                             ; RtlGetVersion(&VersionInformation)
```

The added `memset` calls the CRT `memset` at `0x1C0001F40` in the patched build.

### 5. Trigger Conditions

1. Load the unpatched `msseccore.sys` driver (occurs automatically during the system boot sequence).
2. Allow the driver's `DriverEntry` routine to execute naturally.
3. The execution path reaches the `RtlGetVersion` invocation at `0x1C000A07D`.
4. Observe the kernel stack memory occupied by the `OSVERSIONINFOW` structure (the `0x110` bytes from structure offset `0x4` through `0x114`).
5. **Observable Effect:** Immediately before the `RtlGetVersion` call, that region holds whatever residual stack data was present in the unpatched binary, whereas in the patched binary the added `memset` has zeroed it. Note that `RtlGetVersion` fully populates the structure on success in both builds, so this difference is only observable between the structure setup and the API call.

### 6. Exploit Primitive & Development Notes

- **Primitive:** None demonstrated. The uninitialized bytes live in a local `DriverEntry` stack variable that is fully populated by `RtlGetVersion` on success and is never copied out, returned, or exposed to a lower-privilege context. There is no demonstrated information-disclosure path; the fix is defense-in-depth.
- **Exploitability:** Not exploitable as shipped. Any hypothetical disclosure would require a separate, unrelated primitive able to read `DriverEntry`'s stack frame in the narrow window between structure setup and the `RtlGetVersion` call.
- **Mitigations:** Standard kernel stack protections (`/GS`) apply. The patch removes reliance on the API to overwrite every field by zeroing the structure up front.

### 7. Debugger PoC Playbook

To observe the vulnerability using a kernel debugger (WinDbg/KD) attached to the unpatched binary:

- **Breakpoints:** 
  - `bp` at `0x1C000A075` in unpatched `DriverEntry` (the store of `dwOSVersionInfoSize`, immediately before the `RtlGetVersion` call at `0x1C000A07D`).
  - *Why:* This is the only window in which the difference is observable: the structure's `0x110` trailing bytes are still uninitialized in the unpatched build here, whereas the patched build's added `memset` (at `0x1C000A0EF`) has already zeroed them. After `RtlGetVersion` returns, both builds have the structure fully populated.
- **What to Inspect at the Breakpoint:**
  - Take the effective address loaded by the preceding `lea rcx, [...VersionInformation]` (that is `&OSVERSIONINFOW`) and dump the `0x110` bytes starting at structure offset `0x4`.
  - In the unpatched driver these bytes hold whatever residual stack data was present; in the patched driver they are zero.
- **Key Instructions/Offsets:**
  - `0x1C000A075`: store of `dwOSVersionInfoSize = 0x114` (the only field set before the call in unpatched).
  - `0x1C000A07D`: the `RtlGetVersion` call in unpatched (`call cs:__imp_RtlGetVersion`).
  - Patched: `0x1C000A0EF` `call memset` (zeros `0x110` bytes), then `0x1C000A101` the `RtlGetVersion` call.
- **Trigger Setup:**
  - Boot the target system with the unpatched `msseccore.sys` driver loading at startup, with a kernel debugger attached during boot.
- **Struct/Offset Notes (`OSVERSIONINFOW`, structure-relative):**
  - `dwOSVersionInfoSize`: offset `0x0` (4 bytes)
  - `dwMajorVersion`: offset `0x4`
  - `dwMinorVersion`: offset `0x8`
  - `dwBuildNumber`: offset `0xC`
  - `dwPlatformId`: offset `0x10`
  - `szCSDVersion[128]`: offset `0x14` (256 bytes), which falls inside the `0x110`-byte region the patch zeroes

### 8. Changed Functions — Full Triage

The remaining 10 changed functions contained no exploitable security vulnerabilities. Their changes can be grouped as follows:

- **Compiler Code-Generation (Cosmetic):** 
  - `memmove` (@ `0x1C0001C80`): Full rewrite of the compiler-generated CRT `memmove` implementation, adding small-size fast-path branches. Semantically equivalent memory-move. (The report's earlier `memcpy` label was a misnomer; the driver contains no separate `memcpy` function and the changed CRT copy routine is `memmove`.)
  - `SecCreateKernelClient`: `memset` replaced with inline SSE zeroing (`xorps`/`movups`).
  - `SecRegisterKernelExtension`: `memset` replaced with inline stores.
  - `SecValidateDriverFileSignatureLevel`: `memset` calls replaced with inline SSE zeroing; call targets adjusted for relocated `SecCreateDriverValidationKernelEcp` and `SecIsWindowsSigned`. Signature-validation logic and control flow are unchanged.
  - `SecBindHost`: Register allocation restructured; arithmetic equivalence applied to refcount increments.
  - `SecCreateDriverValidationKernelEcp`: ECP-type GUID data reference shifted by `0x10` bytes (`xmmword_1C00031C8` → `xmmword_1C00031D8`) due to `.rdata` layout shift; `memset` replaced with inline SSE zeroing.
  - `SecAllocateKernelApcObject`: Removed a redundant `mov byte [rbx+0x70], 0` store; the preceding `memset(rbx, 0, 0xB0)` already zeroes offset `0x70`. `memset` call target relocated (`0x1C0001FC0` → `0x1C0001F40`).
- **Behavioral Changes (Non-Exploitable):**
  - `SecKernelIntegrityCheck`: The notification class constant in a kernel-integrity dispatch structure built on the stack was changed from `0xa000006` to `0xa000008` (field at `[rbp+57h+var_68]`), and the two `memset` calls were folded into inline SSE zeroing. The structure is dispatched via the guarded indirect-call pointer `cs:qword_1C0007008`; the constant change is a protocol/version compatibility change matching a kernel-side consumer, not a vulnerability mitigation.
  - `SecAllocatePoolWithTag` (@ `0x1C0001008` unpatched / `0x1C0001050` patched): The fallback path (taken only when the dynamically-resolved allocator pointer `cs:qword_1C0007000` is NULL) changed the `PoolType` argument to `ExAllocatePoolWithTag` from `0x200` to `0x600`. Both values carry the non-executable pool bit (`0x200`); the additional `0x400` bit adjusts the requested pool attributes. This is an allocation-attribute change on a rarely-taken fallback path, not a security vulnerability fix.
  - `__GSHandlerCheckCommon`: GS-cookie validation handler. The byte load `mov dl, [rcx+rax+3]` followed by `movzx eax, dl` was changed to `movzx edx, byte [rcx+rax+3]` / `mov eax, edx`, moving the zero-extension to load time. Semantically identical; the value is masked with `0xFFFFFFF0` regardless. Not an independently exploitable flaw.

### 9. Unmatched Functions

There were no added or removed functions between the unpatched and patched binaries.

### 10. Confidence & Caveats

- **Confidence Level:** High. The diff clearly isolates the addition of a `memset` in `DriverEntry` that zero-initializes the `OSVERSIONINFOW` structure before `RtlGetVersion`, a textbook CWE-908 zero-initialization pattern.
- **Assessment:** `RtlGetVersion` fully populates the structure and returns `STATUS_SUCCESS`, and the structure is a local variable never exposed outside `DriverEntry`, so no reachable information-disclosure impact is demonstrated. The change is defense-in-depth; severity is Low on that basis.
- **Manual Verification:** Confirmed against both disassemblies — the unpatched build sets only `dwOSVersionInfoSize` before the call, the patched build adds `memset(&VersionInformation.dwMajorVersion, 0, 0x110)` first.
