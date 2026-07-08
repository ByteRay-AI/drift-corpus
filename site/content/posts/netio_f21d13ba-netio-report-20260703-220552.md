Title: netio.sys — NBL refcount hardening + WFP stream-inspection verifier/telemetry
Date: 2026-07-03
Slug: netio_f21d13ba-netio-report-20260703-220552
Category: Corpus
Author: Argus
Summary: KB5087545
Severity: Unknown
KBDate: 2026-05-12

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | `netio_unpatched.sys` |
| Patched binary | `netio_patched.sys` |
| Overall similarity | 0.6138 |
| Matched functions | 1582 |
| Changed functions | 1250 |
| Identical functions | 332 |
| Unmatched (unpatched → patched) | 0 / 0 |

**Verdict:** The changes in this patch to the WFP stream-inspection pipeline are servicing and defensive-hardening churn, not a fix for a demonstrable reachable vulnerability. Specifically: (a) `NetioDereferenceNetBufferListChain` already performed an atomic (`lock xadd`) reference-count decrement in the unpatched build; the patch removes a non-atomic last-reference fast path, widens the decrement to 64-bit, and adds an `RtlFailFast` on reference-count underflow — a robustness change, not a race fix; (b) the new `StreamInvalidDataLength-*` path is added inside `StreamNormalizeClassifyOut` and is dominated by Driver-Verifier and telemetry instrumentation (`StreamVerifierBreak`, which only bugchecks when the WFP stream verifier flag is set, plus `MicrosoftTelemetryAssert…` and WPP tracing); the unpatched build already clamps the stream length. No omitted bounds/length fix was found anywhere in the packet/record parsers — every parser carries identical bounds checks in both builds, and netio.sys contains no TLS/DTLS/record parser at all.

---

## 2. Vulnerability Summary

### Finding 1 — NBL reference-count decrement hardening (No security-relevant change)
- **Severity:** None (defensive hardening)
- **Class:** Not a demonstrable vulnerability. The unpatched decrement is already atomic.
- **Affected function:** `NetioDereferenceNetBufferListChain` @ `0x1C0004180` (unpatched) / `0x140011CB0` (patched)
- **What the unpatched build actually does:** The unpatched routine already uses an interlocked decrement. For the common last-reference case it takes a fast path: it reads the count with `cmp dword ptr [rbx+40h], 1` and, if the count is exactly 1, stores zero with a plain `mov [rbx+40h], r12d` and frees. For every other case it falls through to `lock xadd [rbx+40h], eax` (an atomic fetch-and-add of -1). There is no plain `sub qword [rbx+0x40], 1` anywhere in the function.
- **What the patched build changes:** The patched routine removes the non-atomic last-reference fast path and always uses `lock xadd [rbx+40h], rax` (widened from 32-bit to 64-bit). It then adds an underflow guard: if the post-decrement value is negative it executes `mov ecx, 0Eh; int 29h` (`RtlFailFast`, code 0x0E). The inline cleanup body was extracted into the helper `NetiopCleanupNetBufferListInformation` @ `0x140015880`.
- **Why this is not a reachable vulnerability:** The removed fast path only fires when the observed reference count is already 1 (the sole remaining reference). Under the standard reference-count invariant — a new reference can only be taken by a thread that already holds one — no concurrent thread can raise the count from 1, so the non-atomic zero store on that path is safe. The general decrement was already atomic in both builds. The `RtlFailFast` on underflow is a fail-fast integrity check that converts a hypothetical refcount bug into an immediate controlled stop; it detects corruption rather than fixing a demonstrated race. Direction is correct (the patched build is stricter), so this is not a regression.

### Finding 2 — WFP stream-length verifier/telemetry path (No security-relevant change)
- **Severity:** None (Driver-Verifier + telemetry instrumentation)
- **Class:** Diagnostic instrumentation; the length clamp that prevents over-read already exists in both builds.
- **Affected function:** `StreamNormalizeClassifyOut` @ `0x1C000C944` (unpatched) / `0x140023C28` (patched)
- **What the unpatched build already does:** `StreamNormalizeClassifyOut` already validates the permit length against the stream data length and clamps it. When the requested length `v8` exceeds the available data length `v14` it calls `StreamVerifierBreak(0x5000, …)` and clamps `a4[3] = *((_QWORD*)*a4 + 6)`.
- **What the patched build adds:** A new entry gate that fires when the recorded permit length is zero but the stream context still reports pending data length. In assembly (patched): `cmp [rax+30h], rbx` / `jnz` then `cmp [rax+80h], rbx` / `jz` at `0x140023C7C`–`0x140023C8D`, followed by `call WfpStreamCalloutDiagTraceInvalidDataLength`, `mov ecx, 5003h`, `call StreamVerifierBreak` at `0x140023CDE`. On this path the code forces the classify verdict (`*a6 = 7`, state `= 2`), records the length, and emits the telemetry strings `"StreamInvalidDataLength-StreamActionAllow"` / `"StreamInvalidDataLength-StreamActionNone"`.
- **Why this is not a reachable OOB fix:** `StreamVerifierBreak` (`0x1C005FFB8`) is `KeBugCheckEx(0xC4, …)` guarded by a WFP-stream-verifier flag bit — it only bugchecks when the stream verifier is enabled (a debugging feature, off in production) and otherwise returns without effect. The remaining additions are `MicrosoftTelemetryAssert…`, a one-shot `g_LogStreamInvalidData` log gate, and WPP tracing. The load-bearing functional change is forcing a block verdict and recording the length when length accounting is inconsistent; it does not add a missing bounds check ahead of a copy. The string `"InvalidStreamDataLength"` claimed at `0x14008e858` does not exist in either build; only the two `"StreamInvalidDataLength-*"` strings are present, and only in the patched build.

---

## 3. Pseudocode Diff

### `NetioDereferenceNetBufferListChain` — reference count handling

```c
// UNPATCHED (0x1C0004180) — decrement is ALREADY atomic
// fast path when the observed count is the last reference:
if (*(DWORD*)(nbl+0x40) == 1) {           // cmp dword ptr [rbx+40h], 1
    *(DWORD*)(nbl+0x40) = 0;               // mov [rbx+40h], r12d  (non-atomic store, last ref)
    // inline cleanup / free
} else {
    int prev = _InterlockedExchangeAdd((LONG*)(nbl+0x40), -1); // lock xadd [rbx+40h], eax
    if (prev == 1) { /* now zero: inline cleanup / free */ }
}

// PATCHED (0x140011CB0) — always atomic + underflow fail-fast
long long prev = _InterlockedExchangeAdd64((LONG64*)(nbl+0x40), -1); // lock xadd [rbx+40h], rax
long long now  = prev - 1;
if (now > 0) goto next;                     // still referenced
if (now < 0) __fastfail(0x0E);              // mov ecx,0Eh ; int 29h
// now == 0:
NetiopCleanupNetBufferListInformation(nbl); // extracted cleanup helper (0x140015880)
```

### `StreamNormalizeClassifyOut` — length handling

```c
// UNPATCHED (0x1C000C944) — length clamp already present
if (a4[3] != 0 && a4[3] > streamDataLen) {
    StreamVerifierBreak(0x5000, a4[3], streamDataLen, 0);  // verifier-only bugcheck
    a4[3] = streamDataLen;                                 // clamp
}

// PATCHED (0x140023C28) — adds verifier/telemetry gate for the zero-permit case
if (recordedPermitLen == 0 && ctx->DataLength != 0) {
    WfpStreamCalloutDiagTraceInvalidDataLength(...);        // WPP/tlg trace helper
    StreamVerifierBreak(0x5003, ...);                       // verifier-only bugcheck
    // force block verdict, record length, emit "StreamInvalidDataLength-*" telemetry
    *a6 = 7; state = 2; recordedPermitLen = ctx->DataLength;
}
```

---

## 4. Assembly Analysis

### Unpatched `NetioDereferenceNetBufferListChain` (base `0x1C0004180`)

```asm
00000001C00041D7  cmp     dword ptr [rbx+40h], 1     ; last-reference fast-path test
00000001C00041DB  jnz     loc_1C00043A2              ; not the last ref -> atomic path
00000001C00041E1  mov     [rbx+40h], r12d            ; r12d = 0, non-atomic zero (last ref only)
; ... inline cleanup / free ...
00000001C00043A2  mov     eax, 0FFFFFFFFh            ; eax = -1
00000001C00043A7  lock xadd [rbx+40h], eax          ; ATOMIC fetch-and-add, prior value in eax
00000001C00043AC  cmp     eax, 1                     ; prior == 1 (now zero)?
00000001C00043AF  jnz     loc_1C0004233             ; if not, walk to next NBL
```

### Patched `NetioDereferenceNetBufferListChain` (base `0x140011CB0`)

```asm
0000000140011D41  or      rax, 0FFFFFFFFFFFFFFFFh    ; rax = -1
0000000140011D45  lock xadd [rbx+40h], rax          ; atomic fetch-and-add (64-bit), prior in rax
0000000140011D4B  sub     rax, 1                     ; post-decrement value
0000000140011D4F  jg      loc_140011D05             ; > 0 -> still referenced
0000000140011D51  test    rax, rax
0000000140011D54  jnz     loc_140011DA0             ; < 0 -> fail fast
0000000140011D56  call    NetiopCleanupNetBufferListInformation ; == 0 -> cleanup helper
0000000140011DA0  mov     ecx, 0Eh                  ; RtlFailFast code 0x0E
0000000140011DA5  int     29h                       ; __fastfail on refcount underflow
```

### `WfpStreamInspectReceive` cleanup site

Unpatched `WfpStreamInspectReceive` (base `0x1C00061B0`) delegates chain cleanup with a real call:

```asm
00000001C00305C5  call    NetioDereferenceNetBufferListChain   ; actual delegation site
```

The instruction at `0x1C000629E` is `call cs:__guard_dispatch_icall_fptr` (an indirect callout dispatch), not a call to `NetioDereferenceNetBufferListChain`.

Patched `WfpStreamInspectReceive` (base `0x140014F50`) inlines the equivalent cleanup: it calls `NetiopCleanupNetBufferListInformation` at `0x1400151DE` and carries the same `RtlFailFast` (`int 29h`) at `0x14001522D`. The `v12 != 23 && v12 != 2` test seen near the entry is only a WPP trace guard (it gates a `WPP_SF_qqdl` call); it does not reject or return on any protocol type.

### `StreamNormalizeClassifyOut` new verifier/telemetry gate (patched base `0x140023C28`)

```asm
0000000140023C78  cmp     [rax+30h], rbx            ; recorded permit length == 0 ?
0000000140023C7C  jnz     loc_140023EFB             ; already recorded -> normal path
0000000140023C86  cmp     [rax+80h], rbx            ; stream ctx DataLength == 0 ?
0000000140023C8D  jz      loc_140023EFB             ; zero -> normal path
0000000140023CCF  call    WfpStreamCalloutDiagTraceInvalidDataLength
0000000140023CDE  mov     ecx, 5003h                ; new StreamVerifierBreak code
0000000140023CEE  call    StreamVerifierBreak       ; bugchecks only if stream verifier enabled
```

---

## 5. Trigger Conditions

No reachable trigger for a memory-safety defect was demonstrated against the unpatched build.

- The general NBL reference-count decrement in `NetioDereferenceNetBufferListChain` is already atomic in the unpatched build; the removed fast path only executes on the last reference, where the reference-count invariant makes the non-atomic zero store safe. No concurrency scenario that underflows the count via this routine was shown.
- The stream-length clamp in `StreamNormalizeClassifyOut` is present in both builds. The patched addition on the zero-permit path is verifier/telemetry plus a forced block verdict; it does not gate a copy that would otherwise read or write out of bounds. `StreamVerifierBreak` only takes effect when the WFP stream verifier is enabled.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive is supported by the two binaries.

- There is no use-after-free primitive: the decrement was already interlocked in the unpatched build, and the patch's `RtlFailFast(0x0E)` on underflow makes any refcount corruption fail closed rather than continue into freed memory.
- There is no out-of-bounds primitive from the stream-length path: the length clamp exists in both builds, and the new path is diagnostic/verdict-forcing, not a bounds check preceding a copy.

No arbitrary read/write, information-leak, pool-grooming, token-swap, or code-integrity-bypass chain is demonstrable from these changes. Claims of such primitives are not included because they are not supported by the binaries.

---

## 7. Debugger Anchors

Real, verified addresses and offsets for anyone reviewing the diff (no proof-of-concept is implied; the changes are hardening/instrumentation):

| Offset | Instruction / string | Meaning |
|---|---|---|
| `0x1C00041D7` | `cmp dword ptr [rbx+40h], 1` | Unpatched last-reference fast-path test. |
| `0x1C00041E1` | `mov [rbx+40h], r12d` | Unpatched non-atomic zero store (last-reference case only). |
| `0x1C00043A7` | `lock xadd [rbx+40h], eax` | Unpatched atomic decrement (already interlocked). |
| `0x140011D45` | `lock xadd [rbx+40h], rax` | Patched atomic decrement (widened to 64-bit). |
| `0x140011DA0` | `mov ecx, 0Eh; int 29h` | Patched `RtlFailFast` on reference-count underflow. |
| `0x1C00305C5` | `call NetioDereferenceNetBufferListChain` | Real delegation site in unpatched `WfpStreamInspectReceive`. |
| `0x140023CDE` | `mov ecx, 5003h; call StreamVerifierBreak` | Patched stream-length verifier gate. |

NBL field offsets consistent with both builds: `+0x40` reference count, `+0x48` info flag selecting the alternate dereference path, `+0x50`/`+0x58` stream context callback / parameter, `+0x88` flags (bit `0x200000` clears status on free). These are used identically in both builds.

---

## 8. Changed Functions — Full Triage

| Function | Sim. | Change Type | Note |
|---|---|---|---|
| `NetioDereferenceNetBufferListChain` | 0.183 | hardening | Both builds decrement atomically. Patch removes the non-atomic last-reference fast path, widens the `lock xadd` to 64-bit, adds `RtlFailFast(0x0E)` on underflow, and extracts cleanup to `NetiopCleanupNetBufferListInformation` (`0x140015880`). No demonstrable reachable race. |
| `WfpStreamInspectReceive` | 0.641 | behavioral | Patch inlines the NBL cleanup that the unpatched build delegated (real call at `0x1C00305C5`) via `NetiopCleanupNetBufferListInformation` + `RtlFailFast`. The `v12 != 23 && v12 != 2` test is a WPP trace guard, not a protocol whitelist. |
| `WfpStreamInspectSend` | 0.467 | behavioral | Mirrors the receive-path cleanup restructuring; part of the same stream-inspection pipeline. No new bounds check. |
| `StreamNormalizeClassifyOut` | — | instrumentation | Adds the `StreamInvalidDataLength-*` verifier/telemetry gate (code `0x5003`) and a forced block verdict on the zero-permit inconsistency. The length clamp (`0x5000`) already exists in both builds. |
| `FwppStreamInject` | 0.527 | behavioral | Adds WPP/ETW tracing around the NBL chain walk and endpoint-context acquire; core inject logic preserved. Not security-relevant. |
| `WfpNblInfoCleanup` | 0.000 | instrumentation | Adds a `WFP_NBL_INFO_CONTAINER` signature check (magic `0x6E706657` = `"Wfpn"`, written by `WfpNblInfoAlloc` in both builds). The check bugchecks only under Driver Verifier (`KeBugCheckEx(0xC4)` gated on `gVerifierFlags & 0x2000000` / `gWfpVerifierEnabled`) and emits `MicrosoftTelemetryAssert…` behind the feature flag `gWFPFeature_Firewall_042024_IsEnabled`, with the old path retained. Diagnostic, not production enforcement. |
| `NetioPhParseIpv6TlvNdOption` | 0.585 | cosmetic | Wraps a contiguity check then calls the pre-existing helper `NetioPhParseIpv6TlvNdOptionContiguous` (`0x1C003F688` unpatched / `0x140040B88` patched). The `DataLength >= 2` bounds check is present in both builds. |
| `FwppCopyStreamDataToBuffer` | 0.645 | behavioral | MDL-walk restructured; the patch inlines `RtlCopyMdlToBuffer` with the same `ByteCount - offset` clamp present in both builds. No bounds change. |

An independent full diff of both builds was performed (matching by content across relocations, not reused addresses). Every packet/record parser — `NetioPhFindTcpOption`, `NetioPhSkipAllIpv6Options(Contiguous)`, `NetioPhGetNdLinkLayerOptionAddress`, `NetioPhIsIcmpErrorForIcmpMessage`, `NetioParseIpFieldsFromNetBufferAndAdvance`, the `RtlCopyMdl*` family, and the `Nsip*`/`Bfe*` request validators — carries identical bounds/length checks in both builds. No omitted minimum-length or bounds fix was found. netio.sys contains no TLS/DTLS/SSL/record parser symbol in either build.

---

## 9. Unmatched Functions

None. Both `unmatched_unpatched` and `unmatched_patched` are zero — all changes are intra-function. The extracted cleanup body appears as the real named helper `NetiopCleanupNetBufferListInformation` (`0x140015880`), reachable from already-existing functions, so it does not appear in the unmatched lists.

Implication: no removed sanitizer, no removed bounds check, and no new exported attack surface. The patch is additive: an always-atomic decrement with underflow fail-fast, verifier/telemetry instrumentation, and tracing.

---

## 10. Confidence & Caveats

**Confidence: High.**

- **Strongly evidenced:**
  - The unpatched `NetioDereferenceNetBufferListChain` already uses `lock xadd [rbx+40h], eax`; the patch's change is removal of the non-atomic last-reference fast path plus a 64-bit widening and an `RtlFailFast` underflow guard. This is concrete in both disassemblies.
  - The stream length clamp exists in both builds' `StreamNormalizeClassifyOut`; the patched additions on the zero-permit path are `StreamVerifierBreak` (verifier-gated `KeBugCheckEx(0xC4)`), `MicrosoftTelemetryAssert…`, and WPP tracing.
  - The two `"StreamInvalidDataLength-*"` strings exist only in the patched build; the `"InvalidStreamDataLength"` string does not exist in either build.
  - An independent content-matched diff found no omitted bounds/length fix in any parser, and no TLS/DTLS/record parser exists in netio.sys.

- **Net assessment:** The patch delivers defensive hardening (always-atomic NBL refcount decrement with underflow fail-fast) and WFP stream-inspection verifier/telemetry instrumentation. No demonstrable reachable memory-safety vulnerability is fixed or introduced, and the direction of every change is toward stricter behavior in the patched build.
