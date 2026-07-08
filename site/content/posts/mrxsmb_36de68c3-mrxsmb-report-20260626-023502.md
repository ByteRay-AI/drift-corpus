Title: mrxsmb.sys — Use-after-free via missing zero-check on VcEndpoint reference during SMB negotiate handling (CWE-416) fixed
Date: 2026-06-26
Slug: mrxsmb_36de68c3-mrxsmb-report-20260626-023502
Category: Corpus
Author: Argus
Summary: KB5075912
Severity: Medium

---

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | `mrxsmb_unpatched.sys` |
| Patched binary | `mrxsmb_patched.sys` |
| Overall similarity | 0.9907 |
| Matched functions | 1059 |
| Changed functions | 3 |
| Identical functions | 1056 |
| Unmatched (unpatched-only / patched-only) | 5 / 0 |

**Verdict:** The patch removes a staged feature gate in the SMB client (`mrxsmb.sys`) that, when the feature was disabled, deferred taking a reference on the per-connection `VcEndpoint` until *after* the attacker-controlled SMB negotiate response was parsed, and then took that reference with a variant that does **not** reject a zero (torn-down) reference count. The patched build always takes the zero-checked reference *before* any negotiate bytes are parsed. The reachable impact is a use-after-free / object-resurrection race (CWE-416) of Medium severity. There is no demonstrable arbitrary read/write or code-execution primitive in the diff; earlier such claims are not supported by the binaries and have been removed.

---

## 2. Vulnerability Summary

### Finding #1 — Medium: Object-resurrection UAF in VcEndpoint reference (`SmbCeCompleteSrvCallConstructionPhase2`)

- **Severity:** Medium (feature-gated, network-adjacent kernel object-lifetime race)
- **Class:** Use-After-Free (CWE-416) — resurrection of a reference-count-zero object
- **Affected function:** `SmbCeCompleteSrvCallConstructionPhase2 @ 0x1C0011E10`
- **Reference primitive at issue:** `VctReferenceEndpoint @ 0x1C000EE90` (called late from `0x1C001207E` in the feature-disabled path)

**Root cause:**
`SmbCeCompleteSrvCallConstructionPhase2` finishes constructing an SMB server call after the negotiate response arrives. To operate on the per-connection `VcEndpoint` object safely it must hold a reference so the endpoint cannot be freed underneath it.

In the unpatched build a WIL feature-staging flag (`Feature_84197691__private_IsEnabledDeviceUsage`) selects between two orderings:

1. **Feature enabled:** acquire spinlock → `SmbCeGetFirstVcEndpoint` → `VctReferenceEndpointSafe` (which reads the reference count and refuses to increment if it is already zero) → hold the reference across the negotiate parse.
2. **Feature disabled:** parse the negotiate response via `GetDialectInfoFromNegotiateResponse` (which reads attacker-controlled data) **first**, then late-acquire the endpoint via `SmbCeGetFirstVcEndpoint` + `VctReferenceEndpoint`.

The two reference helpers are both atomic. The difference is the **zero-check**:

- `VctReferenceEndpointSafe @ 0x1C00168E4` reads the count, returns failure (0) if it is 0, otherwise increments with `lock cmpxchg`.
- `VctReferenceEndpoint @ 0x1C000EE90` increments unconditionally with `lock xadd` and always returns the (non-zero) new count. It cannot detect that the object is already at reference count 0 (mid-teardown).

Because the feature-disabled path parses the negotiate response before referencing the endpoint, the endpoint is held by no reference from this path during the parse. If a concurrent teardown drops the endpoint's reference count to 0 during that window, the late `VctReferenceEndpoint` resurrects a zero-count object instead of failing, and the code then dereferences it (`and [rbx+0x148], r12`, and later field accesses). The zero-checked variant used everywhere else in the receive path (`SmbWskReceiveEvent`, `SmbQuicReceiveEvent`, and the enabled path here all call `VctReferenceEndpointSafe`) exists precisely to reject that case, which indicates the object can be observed at reference count 0 while still enumerable.

**The patch** removes the feature flag and always takes the zero-checked reference (`VctReferenceEndpointSafe`) before any negotiate-response bytes are consumed. The late `VctReferenceEndpoint` call is gone.

**Attacker-adjacent entry point:** A malicious or compromised SMB server responding to a client-initiated SMB2 NEGOTIATE, combined with a concurrent teardown of that connection during negotiate processing.

**Call chain:**
1. `MRxSmbCreateSrvCall @ 0x1C0062520` — RDBSS mini-redirector callback invoked when the client opens `\\server\share`.
2. `SmbCeCreateSrvCall @ 0x1C006254C` — drives server-call construction; posts the Phase 2 completion (`SmbCeCompleteSrvCallConstructionPhase2` is taken by address at `0x1C006292F`).
3. `SmbCeCompleteSrvCallConstructionPhase2 @ 0x1C0011E10` — when `Feature_84197691` is disabled, references the endpoint only after negotiate parsing.
4. `GetDialectInfoFromNegotiateResponse @ 0x1C00158DC` — parses attacker-controlled negotiate bytes.
5. `VctReferenceEndpoint @ 0x1C000EE90` — late reference with no zero-check.

---

## 3. Pseudocode Diff

```c
// ============= UNPATCHED SmbCeCompleteSrvCallConstructionPhase2 =============
if (Feature_84197691__private_IsEnabledDeviceUsage()) {
    // ----- EARLY, ZERO-CHECKED PATH (feature enabled) -----
    r15 = SmbCeAcquireSpinLock(connection);
    rbx = SmbCeGetFirstVcEndpoint(serverEntry);
    if (rbx && VctReferenceEndpointSafe(rbx)) {   // fails if refcount == 0
        rbx[0x148] = 0;
        SmbCeReleaseSpinLock(connection, r15);
    } else { rbx = NULL; status = 0xC000020C; goto err; }
}
// If feature disabled: endpoint NOT referenced here.

// Negotiate response parsed in BOTH paths (attacker-controlled bytes):
edi = GetDialectInfoFromNegotiateResponse(serverEntry->connection, negBuf, size, ...);

// Late reference, only when the flag was OFF:
if (!Feature_84197691__private_IsEnabledDeviceUsage()) {
    r13 = SmbCeAcquireSpinLock(connection);
    rbx = SmbCeGetFirstVcEndpoint(serverEntry);
    VctReferenceEndpoint(rbx);   // atomic increment, NO zero-check -> resurrects refcount-0 object
    rbx[0x148] = 0;
    SmbCeReleaseSpinLock(connection, r13);
}
```

```c
// ============= PATCHED SmbCeCompleteSrvCallConstructionPhase2 =============
// Feature flag removed.
sil = ExAcquireSpinLockExclusive(connection + 0x784);
*(connection + 0x782) = 1;
rbx = SmbCeGetFirstVcEndpoint(serverEntry);
if (rbx) {
    if (!VctReferenceEndpointSafe(rbx)) {         // always zero-checked, early
        rbx = NULL; status = 0xC000020C; goto err;
    }
    rbx[0x148] = 0;
    SmbCeReleaseSpinLock(connection, sil);

    // Negotiate parsed ONLY AFTER the endpoint is safely referenced:
    edi = GetDialectInfoFromNegotiateResponse(...);
}
// The late VctReferenceEndpoint call is removed entirely.
```

```c
// ============= VctReferenceEndpoint @ 0x1C000EE90 (no zero-check) =============
// ebx = 1; lock xadd [obj+8], ebx    -> atomic increment, returns previous count
// return previous + 1                -> always non-zero; cannot fail on a torn-down object
```

```c
// ============= VctReferenceEndpointSafe @ 0x1C00168E4 (zero-checked) =============
// old = [obj+8];
// if (old == 0) return 0;            -> refuse to reference a torn-down object
// lock cmpxchg [obj+8], old+1 loop;
// return 1;
```

---

## 4. Assembly Analysis

### Vulnerable region of `SmbCeCompleteSrvCallConstructionPhase2` (unpatched)

```asm
; ---- setup ----
00000001C0011E10  mov     [rsp-40h+P], rcx
00000001C0011E28  mov     r13, [rcx+18h]            ; r13 = ServerEntry
00000001C0011E2E  mov     r14, [rcx+20h]            ; r14 = negotiate response buffer
00000001C0011E34  mov     edi, [rcx+8]              ; edi = NTSTATUS
00000001C0011E3E  mov     rsi, [r13+18h]            ; rsi = connection object
00000001C0011E55  mov     r15, [rax+108h]           ; r15 = SrvCall

; ---- feature gate ----
00000001C0011E60  call    Feature_84197691__private_IsEnabledDeviceUsage
00000001C0011E6A  test    eax, eax
00000001C0011E6C  jz      loc_1C0011EE2             ; disabled -> deferred path

; ---- early zero-checked path (feature enabled) ----
00000001C0011E71  call    SmbCeAcquireSpinLock      ; (rsi)
00000001C0011E7C  call    SmbCeGetFirstVcEndpoint   ; (r13) -> rbx
00000001C0011EAA  call    VctReferenceEndpointSafe  ; zero-checked
00000001C0011EB5  test    al, al
00000001C0011EB7  jnz     loc_1C0011ECC             ; success
00000001C0011ECC  and     [rbx+148h], r12
00000001C0011ED3  call    SmbCeReleaseSpinLock

; ---- negotiate parse (both paths) ----
00000001C0011FC3  mov     rcx, [r13+18h]            ; serverEntry->connection
00000001C0011FCC  call    GetDialectInfoFromNegotiateResponse
00000001C0011FD1  mov     edi, eax

; ---- second gate: decide whether to late-acquire ----
00000001C0012038  call    Feature_84197691__private_IsEnabledDeviceUsage
00000001C001203D  test    eax, eax
00000001C001203F  jnz     loc_1C0012099            ; enabled -> already referenced, skip

; ---- late reference (feature disabled) ----
00000001C0012044  call    SmbCeAcquireSpinLock
00000001C0012050  call    SmbCeGetFirstVcEndpoint  ; rbx = endpoint (may be mid-teardown)
00000001C001207B  mov     rcx, rbx
00000001C001207E  call    VctReferenceEndpoint     ; no zero-check
00000001C0012083  and     [rbx+148h], r12
00000001C0012090  call    SmbCeReleaseSpinLock
```

### `VctReferenceEndpoint @ 0x1C000EE90` (no zero-check)

```asm
00000001C000EE9D  mov     ebx, 1
00000001C000EEA2  lock xadd [rcx+8], ebx            ; atomic increment, no zero-check
00000001C000EEB2  inc     ebx
00000001C000EEC1  call    cs:__imp_RxDiagnosticTrace
00000001C000EEEB  mov     eax, ebx                  ; return new (non-zero) count
00000001C000EEF7  retn
```

### `VctReferenceEndpointSafe @ 0x1C00168E4` (zero-checked)

```asm
00000001C00168F3  mov     ebx, [rcx+8]
00000001C00168F9  test    ebx, ebx
00000001C00168FB  jz      loc_1C0016964            ; refcount 0 -> fail (return 0)
00000001C00168FD  lea     edx, [rbx+1]
00000001C0016900  mov     eax, ebx
00000001C0016902  lock cmpxchg [rcx+8], edx         ; atomic compare-exchange
00000001C0016951  mov     al, 1                     ; success
00000001C0016962  retn
00000001C0016964  xor     al, al                    ; failure
```

### Patched `SmbCeCompleteSrvCallConstructionPhase2` (key region)

```asm
; No Feature_84197691 call — always zero-checked, early
00000001C0011E4B  lea     rcx, [r13+784h]           ; SpinLock
00000001C0011E61  call    cs:__imp_ExAcquireSpinLockExclusive
00000001C0011E6D  mov     sil, al
00000001C0011E78  mov     [r13+782h], al            ; construction flag = 1
00000001C0011E7F  call    SmbCeGetFirstVcEndpoint
00000001C0011EA9  call    VctReferenceEndpointSafe  ; always zero-checked
00000001C0011EB6  jnz     loc_1C0011ECE             ; success
00000001C0011ECE  and     [rdi+148h], r12
00000001C0011ED5  call    SmbCeReleaseSpinLock
00000001C0011FBB  call    GetDialectInfoFromNegotiateResponse  ; parsed AFTER safe reference
; No VctReferenceEndpoint call anywhere in this function.
```

The security-relevant diff is: removal of the `Feature_84197691` gates (`0x1C0011E60`, `0x1C0012038`, and the error-path gates), removal of the late `VctReferenceEndpoint` call at `0x1C001207E`, and the negotiate parse being moved to run only after the zero-checked reference is held. The lock primitive also changes from `SmbCeAcquireSpinLock` to `ExAcquireSpinLockExclusive(connection+0x784)`, and `SmbCeGetFirstBindingObject` to `SmbCeGetFirstBindingObjectEx(rdi, 0)`.

---

## 5. Trigger Conditions

1. **Client initiates SMB:** a user-mode application or system component on the victim opens a UNC path (`net use \\attacker\share`, Explorer, scripted `CreateFile`, etc.), causing `MRxSmbCreateSrvCall` → `SmbCeCreateSrvCall`.
2. **Negotiate exchange:** the client sends SMB2 NEGOTIATE and the server replies with a negotiate response. `GetDialectInfoFromNegotiateResponse` validates SMB magic (`424D53FF` SMB1 / `424D53FE` SMB2) and response size (`>= 0x20 / 0x23 / 0x40 / 0x46` depending on path) — these size checks are identical in both builds.
3. **Feature disabled:** `Feature_84197691__private_IsEnabledDeviceUsage()` returns 0, selecting the deferred path. This is a WIL feature-staging flag; its default cannot be determined from the binary alone (it is resolved at runtime by the feature-configuration system).
4. **Teardown races the parse:** while `GetDialectInfoFromNegotiateResponse` is executing (i.e., after the negotiate response is delivered but before `VctReferenceEndpoint` at `0x1C001207E` runs), a concurrent teardown drops the endpoint reference count to 0 (`VctDereferenceEndpoint` path). The late `VctReferenceEndpoint` then increments a zero count instead of failing, and the endpoint is subsequently dereferenced.

The race window is narrow (a single function body) and requires the endpoint to be observable at reference count 0 while still enumerable by `SmbCeGetFirstVcEndpoint`. No further primitive (info leak, controlled reclaim) is demonstrable from the diff.

---

## 6. Impact Assessment

**Primitive:** A kernel object-lifetime race (use-after-free / resurrection) on a `VcEndpoint`. In the deferred path the endpoint's reference count can reach 0 during negotiate processing; `VctReferenceEndpoint` then resurrects it and the function dereferences endpoint fields (`+0x148`, and via later cleanup `+0x1C8`).

What the binary supports:
- The two reference helpers differ only by the zero-check; `VctReferenceEndpoint` uses `lock xadd` (atomic) and cannot fail on a torn-down object.
- The receive/disconnect paths elsewhere use the zero-checked `VctReferenceEndpointSafe`, consistent with the object being observable at reference count 0.
- The patch makes the zero-checked, early reference mandatory.

What the binary does **not** support (and is therefore not claimed): any arbitrary kernel read/write, pool-spray reclaim strategy, KASLR/info-leak, control-flow hijack, or SMEP/CFG/HVCI-bypass chain. Reaching a corrupted or freed `VcEndpoint` dereference would most plausibly manifest as a bug check rather than a controlled primitive; weaponization is not demonstrated by this diff.

---

## 7. Debugger Notes

Real, verifiable addresses for confirming the code path on the unpatched image (`mrxsmb.sys` image base is the module load address; the constants below are file-relative to `0x1C0000000`):

```text
bp mrxsmb!SmbCeCompleteSrvCallConstructionPhase2   ; 0x1C0011E10 entry
bp mrxsmb+0x11E60                                   ; Feature_84197691 gate #1
bp mrxsmb+0x12038                                   ; Feature_84197691 gate #2 (late)
bp mrxsmb+0x1207E                                   ; late VctReferenceEndpoint call
bp mrxsmb!VctReferenceEndpoint                      ; 0x1C000EE90 (no zero-check)
bp mrxsmb!VctReferenceEndpointSafe                  ; 0x1C00168E4 (zero-checked)
bp mrxsmb!GetDialectInfoFromNegotiateResponse       ; 0x1C00158DC (negotiate parser)
```

At function entry, `RCX` is the work-item context: `[RCX+0x18]` = ServerEntry, `[RCX+0x20]` = negotiate buffer, `[RCX+0x8]` = NTSTATUS, `[RCX+0x10]` = RDBSS context. After the `mrxsmb+0x11E60` call, `EAX == 0` indicates the deferred path is selected on this build. At `mrxsmb+0x1207E`, `RCX` is the `VcEndpoint`; `[RCX+0x8]` is its reference count — a value of 0 there before the `lock xadd` is the resurrection condition.

Relevant offsets:

```text
VcEndpoint
  +0x008  ReferenceCount (LONG)        ; incremented by VctReferenceEndpoint / VctReferenceEndpointSafe
  +0x148  ServerCall claim field       ; cleared (and [rbx+148h], r12) after the reference
  +0x1C8  sliding-window field         ; xchg'd during teardown/cleanup
ServerEntry
  +0x018  Connection*
Connection
  +0x782  BYTE construction flag       ; set to 1 in patched
  +0x784  spin lock                    ; ExAcquireSpinLockExclusive in patched
```

---

## 8. Changed Functions — Full Triage

### `SmbCeCompleteSrvCallConstructionPhase2` — similarity 0.7001 — security-relevant
- Removed: the `Feature_84197691__private_IsEnabledDeviceUsage` gates (`0x1C0011E60`, `0x1C0012038`, and the error-path checks at `0x1C0011EFD`, `0x1C0011FD7`, `0x1C0012107`, `0x1C0012152`, `0x1C00122CA`).
- Removed: the late `VctReferenceEndpoint` call at `0x1C001207E` and its deferred `SmbCeGetFirstVcEndpoint` acquisition block.
- Always-on: early `VctReferenceEndpointSafe` reference (`0x1C0011EA9`) before `GetDialectInfoFromNegotiateResponse` (`0x1C0011FBB`).
- Changed lock primitive: `SmbCeAcquireSpinLock` → `ExAcquireSpinLockExclusive(connection+0x784)`, with the construction flag at `connection+0x782`.
- Changed binding helper: `SmbCeGetFirstBindingObject` → `SmbCeGetFirstBindingObjectEx(rdi, 0)` (`0x1C00120D9`).
- Error status on the reference-failure path is `0xC000020C` in both builds.

### `GetDialectInfoFromNegotiateResponse` — similarity 0.9548 — behavioral (not security-relevant)
- Removed: the `Feature_84197691` checks on the unknown-dialect error path. In the unpatched build the unknown-dialect status `0xC000A013` was applied conditionally via `cmovnz` gated on the feature (`0x1C0015BDA`/`0x1C0015C25`); in the patched build it is applied unconditionally (`mov ebx, 0xC000A013` at `0x1C0015AB0`).
- Unchanged: the SMB magic checks (`424D53FF`/`424D53FE`) and the response-size checks (`0x20`/`0x23`/`0x40`/`0x46`) are byte-identical in both builds — no bounds check was added or removed. Both builds contain the same `0xC0000016` and `0xC000022D` status comparisons; there is no status-code swap.
- Cosmetic: data-address and WPP GUID relocations from the different image layout.

### `DriverEntry` — similarity 0.9865 — not security-relevant
- Removed: a `Feature_Servicing_EnableSMBHardeningTelemetry__private_IsEnabledDeviceUsage` gate (`0x1C00650B7` in the unpatched build) — a telemetry feature check.
- Otherwise: global/data address relocations and WPP GUID changes from the different image layout. No behavioral security change.

---

## 9. Unmatched Functions

No functions were added. Five functions present only in the unpatched build were removed because their feature flags were retired: `Feature_84197691__private_IsEnabledDeviceUsage`, `Feature_84197691__private_IsEnabledFallback`, `Feature_Servicing_EnableSMBHardeningTelemetry__private_IsEnabledDeviceUsage`, `Feature_Servicing_EnableSMBHardeningTelemetry__private_IsEnabledFallback`, and the `SmbCeGetFirstBindingObject` wrapper (superseded by `SmbCeGetFirstBindingObjectEx`, which exists in both builds). None of these removals is an omitted security fix. `VctReferenceEndpoint` itself is **not** removed — it still exists and is still called from other functions; only its late call from `SmbCeCompleteSrvCallConstructionPhase2` is removed.

---

## 10. Confidence & Caveats

**Confidence: High on the mechanics, Medium on impact.** The diff is unambiguous: a feature-gated, deferred reference taken with a non-zero-checked helper is replaced by an unconditional, zero-checked reference taken before any attacker-controlled data is parsed. Both reference helpers are atomic; the only functional difference is the zero-check, so the correct framing is object resurrection (referencing a reference-count-0 object), not a non-atomic increment.

**Caveats:**
- `Feature_84197691` is a WIL feature-staging flag; whether the deferred (unsafe) path is the default on a given build cannot be determined from the binary. Regardless of the default, the patch closes the window whenever the flag is disabled.
- The race requires a concurrent teardown to drive the endpoint's reference count to 0 while it is still enumerable during the negotiate-processing window. The presence and use of `VctReferenceEndpointSafe` in the receive/disconnect paths is consistent with this being reachable, but no controlled exploitation primitive is demonstrable from the diff.
- Severity is assessed as Medium: a network-adjacent kernel object-lifetime race with no demonstrated escalation primitive.
