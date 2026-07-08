Title: hvsocket.sys — VMBus loopback endpoint spinlock conditionally skipped behind a feature gate, allowing an unsynchronized access race (CWE-362) — fixed by making locking unconditional
Date: 2026-06-29
Slug: hvsocket_b903f3ca-hvsocket-report-20260629-003328
Category: Corpus
Author: Argus
Summary: KB5082123

### 1. Overview
- **Unpatched Binary:** `hvsocket_unpatched.sys`
- **Patched Binary:** `hvsocket_patched.sys`
- **Overall Similarity Score:** 0.9678
- **Diff Statistics (as reported by the diff tooling):** 269 matched functions (260 identical, 9 changed). 0 unmatched functions added or removed. An independent content diff (matching by name across relocations) confirms the same nine loopback/connection functions changed, plus the feature-staging initializer `rbc_InitializeFeatureStaging` and the deletion of the gate helper `EvaluateCurrentState`; no other function changed in a security-relevant way.
- **Verdict:** The patch removes a runtime feature gate (`EvaluateCurrentState`, a Windows feature-staging / Velocity check) that in the unpatched build conditionally skipped acquisition of the spinlock at `object+0x48` protecting the VMBus TL loopback endpoint pointer at `object+0x2b8`. In the patched build the spinlock is acquired unconditionally, and the feature-descriptor table is emptied so the gate can no longer take the lock-skipping path. This is a synchronization hardening: when the gate resolved to the lock-skipping path, the endpoint pointer and its reference count were read, cleared, and referenced without the spinlock, creating a data race with the loopback reference/set paths that legitimately hold that spinlock (potentially at DISPATCH_LEVEL).

### 2. Vulnerability Summary
- **Severity:** Medium
- **Vulnerability Class:** Race condition from improper synchronization (CWE-362), with a potential use-after-free consequence (CWE-416). This is not a classic check-then-use TOCTOU (CWE-367): there is no re-validated condition, only unsynchronized shared-state access.
- **Affected Functions:** `VmbusTlLoopbackDisconnect` (unpatched `0x1C0006C30`), `VmbusTlLoopbackSend` (unpatched `0x1C00065EC`), and seven other loopback/connection functions listed in section 8.
- **Root Cause:** In the unpatched driver the loopback endpoint operations call `EvaluateCurrentState` (`0x1C0001D78`) to decide whether to acquire the spinlock at `object+0x48` before reading/clearing/referencing the loopback endpoint pointer at `object+0x2b8`. `EvaluateCurrentState` is a feature-staging check: it calls `EvaluateFeature` on the WIL feature descriptor `reg_FeatureDescriptors_a` and returns `(cached_state != 1)` (non-zero when the feature is enabled, zero when disabled). When it returns zero, the spinlock is bypassed and the endpoint pointer at `object+0x2b8` is read and cleared without the spinlock. The spinlock at `object+0x48` is the genuine synchronization primitive for this pointer: `VmbusTlLoopbackReferenceEndpointDeliveryQueue` and `VmbusTlLoopbackSetEndpointDeliveryQueue` acquire it unconditionally (in both builds) while reading `object+0x2b8` and adjusting the endpoint reference count. Skipping it in the disconnect/send/notify paths therefore removes the mutual exclusion that keeps the endpoint pointer and reference count consistent across concurrent access. The patch removes the gate and acquires the spinlock unconditionally.
- **Attacker-Reachable Entry Point:** Hyper-V socket (`AF_HYPERV` / `HVSOCKET`) user-mode operations. Send/disconnect operations on a loopback (same-partition) connection reach `VmbusTlLoopbackSend` / `VmbusTlLoopbackDisconnect`.
- **Reachability Caveat:** Whether the lock-skipping path is actually taken depends on the runtime state of the WIL/Velocity feature descriptor, which is controlled by the OS/servicing configuration, **not** by the attacker. The unlocked path is reachable only in configurations where that feature resolves to the disabled state. The patch removes this dependency entirely.

### 3. Pseudocode Diff
Below is the read/clear sequence for the primary function, `VmbusTlLoopbackDisconnect`, showing the conditional-versus-unconditional spinlock. Note that the later reference-count drop and free of the endpoint/connection objects (via `lock xadd`, a CFG-checked cleanup callback, and `ExFreePoolWithTag`) occur **outside** the spinlock in **both** builds; the spinlock’s role is to make the read-and-clear of `object+0x2b8` (and the back-pointer at `endpoint+0x68`) atomic against concurrent holders of that spinlock.

```c
// UNPATCHED VmbusTlLoopbackDisconnect (0x1C0006C30)
void* VmbusTlLoopbackDisconnect(void* arg1) {
    KeEnterCriticalRegion();
    ExAcquireFastMutexUnsafe(arg1 + 0x10);

    // Feature gate: spinlock acquired only when EvaluateCurrentState() != 0
    char irql = 0;
    if (EvaluateCurrentState() != 0)
        irql = KeAcquireSpinLockRaiseToDpc(arg1 + 0x48);

    // When EvaluateCurrentState() == 0, this read/clear runs WITHOUT the spinlock:
    void* ep = *(arg1 + 0x2b8);
    *(arg1 + 0x2b8) = 0;
    void* conn = 0;
    if (ep) {
        conn = *(ep + 0x68);
        if (EvaluateCurrentState() != 0)
            *(ep + 0x68) = 0;
    }

    if (EvaluateCurrentState() != 0)              // conditional release
        KeReleaseSpinLock(arg1 + 0x48, irql);

    ExReleaseFastMutexUnsafe(arg1 + 0x10);
    KeLeaveCriticalRegion();
    // ... reference-count drop / free of conn and ep (outside any lock, same in both builds)
}

// PATCHED VmbusTlLoopbackDisconnect (0x1C00068B0)
void* VmbusTlLoopbackDisconnect(void* arg1) {
    KeEnterCriticalRegion();
    ExAcquireFastMutexUnsafe(arg1 + 0x10);

    char irql = KeAcquireSpinLockRaiseToDpc(arg1 + 0x48);  // unconditional
    void* ep = *(arg1 + 0x2b8);                            // read under spinlock
    *(arg1 + 0x2b8) = 0;                                   // clear under spinlock
    void* conn = 0;
    if (ep) { conn = *(ep + 0x68); *(ep + 0x68) = 0; }
    KeReleaseSpinLock(arg1 + 0x48, irql);                  // unconditional

    ExReleaseFastMutexUnsafe(arg1 + 0x10);
    KeLeaveCriticalRegion();
    // ... reference-count drop / free of conn and ep (unchanged from unpatched)
}
```

### 4. Assembly Analysis
**Unpatched `VmbusTlLoopbackDisconnect` (`0x1C0006C30`)** — the conditional spinlock and the unsynchronized read/clear (real disassembly):

```assembly
00000001C0006C6F  call    EvaluateCurrentState                 ; feature-staging check
00000001C0006C74  test    eax, eax
00000001C0006C76  jz      loc_1C0006C8B                        ; skip spinlock when feature disabled
00000001C0006C78  lea     rcx, [rbx+48h]                       ; SpinLock (only if eax != 0)
00000001C0006C7C  call    cs:__imp_KeAcquireSpinLockRaiseToDpc
00000001C0006C88  mov     dil, al                              ; save IRQL
00000001C0006C8B  mov     rsi, [rbx+2B8h]                      ; read endpoint ptr (unlocked if je taken)
00000001C0006C92  and     qword ptr [rbx+2B8h], 0              ; clear endpoint ptr (unlocked if je taken)
00000001C0006C9A  test    rsi, rsi
00000001C0006C9D  jz      loc_1C0006CB3
00000001C0006C9F  mov     rbp, [rsi+68h]                       ; back-pointer to connection object
00000001C0006CA3  call    EvaluateCurrentState                 ; second gate (clear of [rsi+68h])
00000001C0006CB5  call    EvaluateCurrentState                 ; third gate (spinlock release)
```

The subsequent reference-count drop / free block operates on `rbp` and `rsi` after the fast mutex and (conditional) spinlock are released — the same code exists in the patched build:

```assembly
00000001C0006D6A  lock xadd [rbp+8], rax                       ; reference-count decrement (connection object)
00000001C0006D88  mov     rax, [rbp+50h]                       ; cleanup callback pointer
00000001C0006D94  call    cs:__guard_dispatch_icall_fptr       ; CFG-checked indirect call
00000001C0006DF1  call    cs:__imp_ExFreePoolWithTag           ; free (tag 'Vnpi' = 0x69706E56)
```

**Patched `VmbusTlLoopbackDisconnect` (`0x1C00068B0`)** — the gate is gone; the spinlock is acquired unconditionally before touching `rbx+0x2b8`:

```assembly
00000001C00068E7  lea     rcx, [rbx+48h]                       ; SpinLock
00000001C00068EB  call    cs:__imp_KeAcquireSpinLockRaiseToDpc ; unconditional
00000001C00068F7  mov     rsi, [rbx+2B8h]                      ; read under spinlock
00000001C00068FE  and     qword ptr [rbx+2B8h], 0              ; clear under spinlock
00000001C0006918  mov     dl, al
00000001C000691E  call    cs:__imp_KeReleaseSpinLock           ; unconditional
```

**Gate helper `EvaluateCurrentState` (`0x1C0001D78`, unpatched only)** — confirms this is a feature-staging check, not a runtime state variable:

```assembly
00000001C0001D7C  lea     rcx, reg_FeatureDescriptors_a
00000001C0001D83  call    EvaluateFeature
00000001C0001D88  mov     rax, cs:reg_FeatureDescriptors_a
00000001C0001D8F  mov     ecx, [rax]
00000001C0001D93  cmp     ecx, 1
00000001C0001D96  setnz   al                                   ; returns (cached_state != 1)
```

### 5. Trigger Conditions
1. **Environment:** A system with Hyper-V sockets loaded (`hvsocket.sys`).
2. **Feature state:** The WIL feature checked by `EvaluateCurrentState` must resolve to the disabled state so the lock-skipping path is taken. This is governed by servicing/feature configuration, not by the attacker.
3. **Loopback connection:** Establish an `AF_HYPERV` loopback (same-partition) connection, creating the VMBus TL loopback endpoint.
4. **Concurrency:** Issue disconnect (`VmbusTlLoopbackDisconnect`) concurrently with send/notify (`VmbusTlLoopbackSend`, `VmbusTlLoopbackNotifyReceiveConsumed`) on the same endpoint. Because the disconnect/send/notify paths skip the spinlock while `VmbusTlLoopbackReferenceEndpointDeliveryQueue` / `VmbusTlLoopbackSetEndpointDeliveryQueue` hold it, the read/clear/reference of the endpoint pointer and its reference count are not mutually exclusive.

### 6. Impact
- **Demonstrable change:** The spinlock at `object+0x48` that guards the loopback endpoint pointer at `object+0x2b8` is made unconditional; the feature gate and the feature-descriptor table that enabled the lock-skipping path are removed.
- **Realistic consequence:** When the lock-skipping path was active, the endpoint pointer and reference count could be manipulated concurrently with the spinlock-holding reference/set paths. The plausible outcome is an inconsistent reference count on the `'Vnpi'` NonPagedPool connection/endpoint object, which can lead to a premature reference drop and use-after-free of that object. The object is dereferenced afterward for a reference-count decrement (`lock xadd`), a CFG-checked cleanup callback, and `ExFreePoolWithTag`.
- **Not demonstrated by the binaries:** A concrete arbitrary-read/write primitive, function-pointer hijack (the callback dereference is a CFG-guarded indirect call), pool-spray reclamation layout, or code-execution chain. Those are not evidenced here and are not claimed.

### 7. Observability Notes (unpatched target)
The race window is between the unlocked read of the endpoint pointer at `0x1C0006C8B` and the later reference-count drop of that object. Useful observation points on the unpatched build:
- `0x1C0006C6F` — `call EvaluateCurrentState`; if the return value in `eax` is zero, the spinlock is skipped (unlocked path).
- `0x1C0006C8B` — `mov rsi, [rbx+2B8h]`; the endpoint pointer read, unlocked when arriving via the `je` at `0x1C0006C76`.
- `0x1C0006D6A` — `lock xadd [rbp+8], rax`; reference-count decrement on the connection object.
Racing partner: `VmbusTlLoopbackSend` (`0x1C00065EC`), which likewise consults `EvaluateCurrentState` before referencing the same endpoint. Instability of the endpoint reference count under concurrent disconnect/send on the same loopback endpoint (when the feature is disabled) is the observable symptom; a bad reference count typically surfaces as a `RtlFailFast` (`int 29h`) reference-count assertion or a pool bugcheck.

### 8. Changed Functions — Full Triage
All nine functions below drop one or more `EvaluateCurrentState` gates; the patched build contains zero calls to that helper. The two functions whose change is literally "the `KeAcquireSpinLockRaiseToDpc` at `object+0x48` becomes unconditional" are `VmbusTlLoopbackDisconnect` and `VmbusTlLoopbackNotifyReceiveConsumed`; the others remove the gate around a fast mutex (`object+0x10`) or around the delivery-queue reference/set helpers, which themselves lock `object+0x48` unconditionally.
- **`VmbusTlLoopbackDisconnect`** (unpatched `0x1C0006C30` → patched `0x1C00068B0`, Sim 0.9128): conditional spinlock at `+0x48` removed; endpoint pointer at `+0x2b8` now read/cleared under an unconditional spinlock.
- **`VmbusTlLoopbackSend`** (unpatched `0x1C00065EC` → patched `0x1C00062A4`, Sim 0.8832): gate removed; `VmbusTlLoopbackReferenceEndpointDeliveryQueue` (the spinlock-protected endpoint-reference helper) is now always called instead of the unlocked `[arg1+0x2b8]` fast path.
- **`VmbusTlLoopbackNotifyReceiveConsumed`** (unpatched `0x1C0006F50` → patched `0x1C0006BB0`, Sim 0.8389): the `!EvaluateCurrentState()` fallback that took the spinlock directly is removed; only the delivery-queue-reference path remains.
- **`VmbusTlNotifyListenerAccept`** (unpatched `0x1C0005F18` → patched `0x1C0005C68`, Sim 0.8043): the `if (EvaluateCurrentState())` wrapper around the endpoint-reference / connect-dispatch path is removed; that path now runs unconditionally.
- **`VmbusTlLoopbackSetupConnection`** (unpatched `0x1C001B1D0` → patched `0x1C001B100`, Sim 0.4819): gate removed; the critical-region / fast-mutex release path around loopback endpoint setup is now unconditional (the non-feature `[arg2+0x2b8]=0` branch dropped). Larger rewrite / signature change.
- **`VmbusTlLoopbackAcceptConnection`** (unpatched `0x1C001B630` → patched `0x1C001B530`, Sim 0.6072): gate removed; always references the delivery queue and calls `VmbusTlLoopbackSetEndpointDeliveryQueue` (the non-feature mutex branch dropped).
- **`VmbusTlCommonConnectCompletion`** (unpatched `0x1C0002670` → patched `0x1C00023D0`, Sim 0.9609): gate removed from a compound condition — `if (EvaluateCurrentState() && (flags & 0x80))` becomes `if (flags & 0x80)`.
- **`VmbusTlProviderListen`** (unpatched `0x1C001E420` → patched `0x1C001E290`, Sim 0.5765): top-level gate removed, collapsing two near-duplicate silo/partition-resolution paths into one; the former `VmbusTlCreateListenEndpoint` wrapper is inlined here.
- **`VmbusTlProcessNewConnectionForListener`** (unpatched `0x1C0019E60` → patched `0x1C0019DB0`, Sim 0.9756): two `EvaluateCurrentState` gates removed; the fast-mutex-guarded partition lookup / state check now runs unconditionally.

Additionally, the enabling mechanism (not a separate vulnerability):
- **`rbc_InitializeFeatureStaging`** (unpatched `0x1C000C694` → patched `0x1C000C4F8`): the feature-descriptor registration loop is neutered to an empty range (`&reg_FeatureDescriptors_z .. &reg_FeatureDescriptors_z`), i.e., the feature-staging table is emptied.
- **`EvaluateCurrentState`** (`0x1C0001D78`, unpatched only): the gate helper itself is deleted in the patched build.

### 9. Unmatched Functions
No security-relevant functions were added or removed. `EvaluateCurrentState` is deleted and `VmbusTlCreateListenEndpoint` disappears through inlining into `VmbusTlProviderListen`; both are consequences of the feature-gate removal, not independent changes. An independent content diff found no security-relevant change outside the feature-staging removal theme (authentication, address validation, bounds checks, and parsing paths are unchanged).

### 10. Confidence & Caveats
- **Confidence in the mechanism:** High. The conditional spinlock and its removal are directly visible in the disassembly of both builds, and `EvaluateCurrentState` is unambiguously a feature-staging check over `reg_FeatureDescriptors_a` via `EvaluateFeature`.
- **Confidence in impact:** Moderate. The spinlock is the real synchronization primitive for `object+0x2b8` (the reference/set helpers lock it unconditionally in both builds), so skipping it is a genuine data race, and a premature-reference-drop / use-after-free of the `'Vnpi'` object is a plausible consequence. However, the binaries do not demonstrate a concrete exploit primitive or code-execution path, and the reference-count drop/free operations occur outside the spinlock in both builds.
- **Reachability:** The unlocked path is gated by a WIL/Velocity feature flag controlled by the OS/servicing configuration, not by the attacker. Exploitability is constrained to configurations where that feature resolves to disabled.
- **CWE:** Primary CWE-362 (improper synchronization / race condition); potential consequence CWE-416 (use-after-free). CWE-367 (TOCTOU) is not an accurate fit — there is no re-checked condition, only unsynchronized shared-state access.
