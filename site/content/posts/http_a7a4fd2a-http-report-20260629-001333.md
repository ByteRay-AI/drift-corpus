Title: http.sys — WIL feature-staging cache bookkeeping bit in wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState
Date: 2026-06-29
Slug: http_a7a4fd2a-http-report-20260629-001333
Category: Corpus
Author: Argus
Summary: KB5095051
Severity: Informational
KBDate: 2026-06-09

## 1. Overview

| Field | Value |
|---|---|
| Title | http.sys WIL feature-state cache bookkeeping bit (0x40000) |
| Unpatched binary | `http_unpatched.sys` |
| Patched binary | `http_patched.sys` |
| Overall similarity | **0.9925** |
| Matched functions | 4354 |
| Changed functions | **2** |
| Identical functions | 4352 |
| Unmatched (unpatched→patched) | 0 / 0 |
| Unmatched (patched→unpatched) | 0 / 0 |

**Verdict:** The two changed functions are both part of the Windows Implementation Library (WIL) feature-staging machinery that http.sys links in, not the HTTP connection/timer path. The patched build of `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState (sub_1400BF5E8)` forces bit `0x40000` into the value it publishes through its interlocked compare-exchange loop that maintains the WIL cached feature-enabled state; the second function, `wil_details_RegisterFeatureUsageProvider (sub_1401C368C)`, has updated feature-usage provider GUID/config pointers. Both are WIL feature-staging library bookkeeping churn from a library version bump. There is no timer state machine, no DPC, no connection lifecycle, and no use-after-free. No security-relevant change.

---

## 2. Change Summary

### Finding #1 — Added cache bookkeeping bit in WIL feature-state reevaluation

| Attribute | Value |
|---|---|
| **Severity** | None (informational) |
| **Class** | Library feature-staging bookkeeping (not a vulnerability) |
| **Affected function** | `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState (sub_1400BF5E8)` |
| **Site** | `0x1400bf68e: lock cmpxchg dword [r15], ebx` (unpatched) / `0x1400bf69e: lock cmpxchg dword [r12], esi` (patched) |
| **Reachable via** | Internal WIL feature-flag evaluation, invoked when http.sys code queries a staged feature |

**What the function does.** `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` is a WIL helper that recomputes and republishes the cached "feature enabled state" for a staged feature. It reads the current feature-enabled state via `wil_details_GetCurrentFeatureEnabledState (sub_1400BF74C)`, optionally ensures a subscription to feature-configuration changes, then atomically stores the recomputed packed cache word into the caller-supplied cache location using an `_InterlockedCompareExchange` retry loop. The packed 32-bit value encodes the WIL feature-enabled state plus cache/reporting bookkeeping bits (the `& 0x9C1`, `& 0x400`, bit `0x2`, bit `0x4` manipulations seen in the loop).

**What changed.** In the patched build every candidate value written by the loop is OR-ed with `0x40000` (bit 18) before the compare-exchange:

```c
LODWORD(v14) = v9 | 0x40000;   // patched: bit 0x40000 forced on
v11 = v9 | 0x40000;
```

The unpatched build publishes the same recomputed value without that bit. This is a WIL cache-state bookkeeping bit introduced by a newer WIL library revision. It is a per-feature cache word private to the WIL feature-staging subsystem; it is not a timer state, a connection-object field, or a lifetime/ownership flag, and nothing in the HTTP request or connection-teardown paths consumes it as a "dirty" sentinel.

**Why it is not a security issue.** The value lives entirely inside WIL's feature-state cache. The functions the analysis chain would need for a use-after-free do not exist as described: the addresses cited as a "timer DPC" and "state dispatcher" resolve to unrelated WIL/settings helpers (see Section 8). There is no connection object, no `KeSetTimer`/`KeInitializeDpc` timer, and no freed-pool dereference on this path. Toggling a WIL feature-cache bookkeeping bit cannot free or dangle a kernel object.

---

## 3. Pseudocode Diff

```c
// ===== UNPATCHED  wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState =====
for ( i = v5; ; i = v10 )
{
    LODWORD(v13) = v5;                              // publish current value, no 0x40000
    if ( v8 != 0 && (i & 2) == 0 )
        v5 = CurrentFeatureEnabledState & 0x9C1 | i & 0xFFFFF63E | 2;
    if ( (i & 4) == 0 )
        v5 = v5 & 0xFFFFFBFF | CurrentFeatureEnabledState & 0x400 | 4;
    v10 = _InterlockedCompareExchange(a1, v5, i);
    if ( i == v10 ) break;
    v5 = v10;
}

// ===== PATCHED  wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState =====
for ( i = v5; ; i = v9 )
{
    LODWORD(v14) = v9 | 0x40000;                    // ADDED: bit 0x40000 forced on
    v11 = v9 | 0x40000;
    if ( v8 != 0 && (i & 2) == 0 )
        v11 = CurrentFeatureEnabledState & 0x9C1 | v9 & 0xFFFBF63E | 0x40000 | 2;
    if ( (v5 & 4) == 0 )
        v11 = v11 & 0xFFFFFBFF | CurrentFeatureEnabledState & 0x400 | 4;
    v9 = _InterlockedCompareExchange(a1, v11, v5);
    if ( v5 == v9 ) break;
    v5 = v9;
}
```

The only behavioral difference is the unconditional `| 0x40000`. The remaining deltas (`rbx→rdi`, `r15→r12`, an extra `push`) are register-allocation side effects of the added instruction.

---

## 4. Assembly Analysis

### 4.1 Unpatched `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState (sub_1400BF5E8)` — annotated

```nasm
0x1400bf5e8: mov     qword [rsp+0x18], rbx
0x1400bf5ed: push    rbp
0x1400bf5ee: push    rsi
0x1400bf5ef: push    rdi
0x1400bf5f0: push    r14
0x1400bf5f2: push    r15
0x1400bf5f4: sub     rsp, 0x20
0x1400bf5f8: mov     rax, qword [rel 0x1401a4c98]   ; g_wil_details_ensureSubscribedToFeatureConfigurationChanges
0x1400bf5ff: xor     ebp, ebp
0x1400bf601: mov     dword [rsp+0x50], ebp
0x1400bf605: mov     r14, r8                          ; r14 = a3 = feature-state descriptor ptr
0x1400bf608: mov     qword [rsp+0x58], rdx
0x1400bf60d: mov     rbx, rdx                         ; rbx = current cache word
0x1400bf610: mov     r15, rcx                         ; r15 = a1 = cache location ptr
0x1400bf613: test    rax, rax
0x1400bf616: je      0x1400bf61f
0x1400bf618: call    0x1401620e0                      ; _guard_dispatch_icall -> ensureSubscribed...
0x1400bf61d: mov     ebp, eax
0x1400bf61f: lea     rdx, [rsp+0x50]
0x1400bf624: mov     rcx, r14
0x1400bf627: call    0x1400bf74c                      ; wil_details_GetCurrentFeatureEnabledState
0x1400bf62c: cmp     byte [r14+0x1c], 0x0             ; a3+28 descriptor byte
0x1400bf631: mov     rdi, rax                         ; rdi = CurrentFeatureEnabledState
0x1400bf634: jne     0x1400bf642
0x1400bf636: mov     ecx, ebp
0x1400bf638: neg     ecx
0x1400bf63a: sbb     esi, esi
0x1400bf63c: and     esi, dword [rsp+0x50]
0x1400bf640: jmp     0x1400bf646
0x1400bf642: mov     esi, dword [rsp+0x50]

; === interlocked compare-exchange loop ===
0x1400bf646: mov     ecx, ebx
0x1400bf648: mov     dword [rsp+0x58], ebx            ; publish current value (no 0x40000)
0x1400bf64c: test    esi, esi
0x1400bf64e: je      0x1400bf671
0x1400bf650: mov     dword [rsp+0x58], ebx
0x1400bf654: test    cl, 0x2
0x1400bf657: jne     0x1400bf671
0x1400bf659: mov     ebx, ecx
0x1400bf65b: mov     eax, edi
0x1400bf65d: and     ebx, 0xfffff63e
0x1400bf663: and     eax, 0x9c1
0x1400bf668: or      ebx, eax
0x1400bf66a: or      ebx, 0x2
0x1400bf66d: mov     dword [rsp+0x58], ebx
0x1400bf671: test    cl, 0x4
0x1400bf674: jne     0x1400bf68c
0x1400bf676: btr     ebx, 0xa
0x1400bf67a: mov     eax, edi
0x1400bf67c: and     eax, 0x400
0x1400bf681: or      eax, ebx
0x1400bf683: or      eax, 0x4
0x1400bf686: mov     ebx, eax
0x1400bf688: mov     dword [rsp+0x58], eax
0x1400bf68c: mov     eax, ecx                         ; eax = expected old cache word
0x1400bf68e: lock cmpxchg dword [r15], ebx            ; publish recomputed cache word
0x1400bf693: je      0x1400bf69b
0x1400bf695: mov     ebx, eax                         ; lost race, reload
0x1400bf697: mov     ecx, eax
0x1400bf699: jmp     0x1400bf648                      ; retry
0x1400bf69b: test    cl, 0x4
0x1400bf69e: jne     0x1400bf6bc
0x1400bf6a0: mov     rax, qword [rel 0x1401a4c58]     ; g_wil_details_subscribeFeatureStateCache...
0x1400bf6a7: test    rax, rax
0x1400bf6aa: je      0x1400bf6bc
0x1400bf6ac: movzx   edx, byte [r14+0x1c]
0x1400bf6b1: mov     r8d, ebp
0x1400bf6b4: mov     rcx, r15
0x1400bf6b7: call    0x1401620e0                      ; _guard_dispatch_icall -> subscribe...
0x1400bf6bc: test    esi, esi
0x1400bf6be: jne     0x1400bf6d2
0x1400bf6c0: and     edi, 0x9c1
0x1400bf6c6: and     ebx, 0xfffff63e
0x1400bf6cc: or      edi, ebx
0x1400bf6ce: mov     dword [rsp+0x58], edi
0x1400bf6d2: mov     rax, qword [rsp+0x58]
0x1400bf6d7: mov     rbx, qword [rsp+0x60]
0x1400bf6dc: add     rsp, 0x20
0x1400bf6e0: pop     r15
0x1400bf6e2: pop     r14
0x1400bf6e4: pop     rdi
0x1400bf6e5: pop     rsi
0x1400bf6e6: pop     rbp
0x1400bf6e7: retn
```

### 4.2 Patched variant — loop-entry block

```nasm
; === PATCHED wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState (loop region) ===
0x1400bf650: mov     eax, edi
0x1400bf652: mov     ecx, edi
0x1400bf654: bts     eax, 0x12         ; ADDED: set bit 0x40000 (bit 18) in candidate cache word
0x1400bf658: mov     dword [rsp+0x58], eax
0x1400bf65c: mov     esi, eax
0x1400bf65e: test    ebp, ebp
0x1400bf660: je      0x1400bf67d
0x1400bf662: test    cl, 0x2
0x1400bf665: jne     0x1400bf67d
0x1400bf667: and     esi, 0xfffff63e
0x1400bf66d: mov     eax, ebx
0x1400bf66f: and     eax, 0x9c1
0x1400bf674: or      esi, eax
0x1400bf676: or      esi, 0x2
0x1400bf679: mov     dword [rsp+0x58], esi
0x1400bf67d: test    dil, 0x4
0x1400bf681: jne     0x1400bf69c
0x1400bf683: mov     eax, esi
0x1400bf685: mov     ecx, ebx
0x1400bf687: and     ecx, 0x400
0x1400bf68d: btr     eax, 0xa
0x1400bf691: mov     esi, ecx
0x1400bf693: or      esi, eax
0x1400bf695: or      esi, 0x4
0x1400bf698: mov     dword [rsp+0x58], esi
0x1400bf69c: mov     eax, edi                          ; expected old cache word
0x1400bf69e: lock cmpxchg dword [r12], esi             ; publishes value WITH 0x40000
0x1400bf6a4: je      0x1400bf6ac
```

**Diff summary:**

- Inserted `bts eax, 0x12` at `0x1400bf654` — sets bit 18 in the candidate cache word before the interlocked store.
- The `lock cmpxchg` source register changes from `ebx` to `esi` (which carries `0x40000` because it derives from the `bts`-ed `eax`).
- Cache-pointer register `r15` → `r12` (register realloc from the added instruction).

---

## 5. Reachability

`wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` runs when http.sys evaluates a WIL staged feature flag whose cached state needs recomputation (first evaluation or after a feature-configuration change notification). It operates only on the WIL per-feature cache word. It is not driven by remote HTTP input, does not touch connection or timer objects, and its output bit is consumed only by other WIL feature-staging helpers. There is no attacker-controllable data flow into or out of the changed bit.

---

## 6. Exploitability

None. The change toggles a bookkeeping bit inside WIL's feature-state cache. It cannot free, dangle, or corrupt any kernel object, and there is no primitive to develop. The interlocked compare-exchange loop is already race-safe in both builds; the added bit does not alter memory lifetime or ownership.

---

## 7. Verification Notes

To observe the difference in a debugger:

- Break at `0x1400bf68e` (unpatched) / `0x1400bf69e` (patched), the `lock cmpxchg` that publishes the WIL feature-state cache word.
- Unpatched: the stored value never has bit `0x40000`. Patched: every stored value has bit `0x40000`.
- The pointer in `r15` (unpatched) / `r12` (patched) is the WIL per-feature cache location, not a connection or timer object.

Supporting facts:

- `sub_1400BF5E8` = `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` (function header present at this exact address in both builds).
- `sub_1400BF74C` = `wil_details_GetCurrentFeatureEnabledState` (the "status helper" called at `0x1400bf627`).
- `0x1401620E0` = `_guard_dispatch_icall` (CFG-guarded indirect call, used for the two WIL subscription callbacks; it is not a tracing/ETW enter/exit routine).
- The cache word bits: `0x2`, `0x4`, `0x400`, and the `0x9C1`/`0xFFFFF63E` masks are WIL feature-enabled-state packing fields, not timer flags.

---

## 8. Changed Functions — Full Triage

### `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState (sub_1400BF5E8)` — informational, similarity **0.9726**

- **Change type:** behavioral, but confined to WIL feature-staging bookkeeping.
- **What changed:** every candidate cache word is OR-ed with `0x40000` (`bts eax, 0x12`) before the interlocked store. Prologue gains a `push`; registers reallocated (`rbx→rdi`, `r15→r12`).
- **Why it matters:** it does not. The bit is private to WIL's feature-state cache; no HTTP/timer/connection code consumes it as a lifetime sentinel. This is a WIL library revision, not a fix.

### `wil_details_RegisterFeatureUsageProvider (sub_1401C368C)` — cosmetic, similarity **0.9853**

- **Change type:** feature-usage provider registration churn.
- **What changed:**
  - Provider-GUID pointer: `0x1401a17f8 → 0x1401a1818`.
  - Configuration-data pointer: `0x1401a1de0 → 0x1401a1dc8`.
  - Two new stack locals passed as additional parameters to the registration call.
  - A WIL usage-reporting callback table entry moved from `wil_details_RecordFeatureUsageReporting (sub_1400BFB00)` to the same function at its shifted address `sub_1400BFB10` — a rebuild address shift; the target function is identical in both builds.
- **Why it matters:** not security-relevant. Standard WIL feature-usage provider registration churn from a rebuild with updated feature GUIDs.

### Collapsed: cosmetic / register-allocation deltas

All non-instruction deltas (the extra `push`, the `rbx→rdi / r15→r12` swaps in `sub_1400BF5E8`, and the pointer-table address shift in `sub_1401C368C`) are compiler side effects of the added `bts` and the bumped feature GUIDs.

### Cited helper addresses (for the record)

The following addresses were part of the analysis chain; each resolves to a WIL/settings helper unrelated to any HTTP timer or connection lifecycle:

- `sub_1400BE740` = `UxStartEnvironmentModule` (environment/settings module startup — not a timer DPC).
- `sub_1400BF2E4` = `wil_details_FeatureReporting_RecordUsageInCache`.
- `sub_1400BF868` = `wil_details_IsEnabledFallback`.
- `sub_1400BD624` = `UxReadBooleanSetting`; `sub_1400BD680` = `UxReadBoundedULongSetting` (registry/settings readers).
- `0x140181218` is a WIL/data table entry, not a `KeInitializeDpc` callback registration.

---

## 9. Unmatched Functions

```
Added (patched only):    none
Removed (unpatched only): none
```

No sanitizers added and no mitigations removed. The delta is confined to two WIL feature-staging functions.

---

## 10. Confidence & Caveats

### Confidence: **High**

Rationale:

- Only two functions differ, and both are WIL feature-staging library code (`wil_details_*`), confirmed by function symbols present at the exact cited addresses in both builds.
- The single behavioral change is an added `| 0x40000` bookkeeping bit in the WIL feature-state cache word; the value is private to WIL's feature-staging subsystem and is not consumed by any HTTP request, timer, or connection-teardown path.
- The addresses that would be required for a use-after-free (a "timer DPC", a "state dispatcher", freed-connection dereference) resolve to unrelated WIL/settings helpers, so no such call chain exists.

### Notes

1. **Bit `0x40000` semantics.** It is a WIL cache-state bookkeeping bit added by a newer WIL revision. It does not gate object lifetime.
2. **No remote surface.** This code path is internal feature-flag evaluation; it is not reached with attacker-controlled HTTP data.
3. **No pool/UAF interaction.** No connection object, pool tag, or timer is involved on this path.
