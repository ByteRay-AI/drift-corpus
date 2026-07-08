Title: mrxsmb.sys — No security-relevant change (WIL feature-staging library churn)
Date: 2026-06-29
Slug: mrxsmb_1bf547b7-mrxsmb-report-20260629-131146
Category: Corpus
Author: Argus
Summary: KB5095051
Severity: None
KBDate: 2026-06-09

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `mrxsmb_unpatched.sys` |
| **Patched binary** | `mrxsmb_patched.sys` |
| **Overall similarity** | 0.9922 |
| **Matched functions** | 1279 |
| **Changed functions** | 2 |
| **Identical functions** | 1277 |
| **Unmatched (unpatched)** | 0 |
| **Unmatched (patched)** | 0 |

**Verdict:** The only two functions that changed between the builds both belong to the statically-linked Windows Implementation Library (WIL) feature-staging framework: `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` (at `0x14003AD00`) and `wil_details_RegisterFeatureUsageProvider` (at `0x140083A7C`). The patched build unconditionally OR-es bit `0x40000` into the cached feature-enabled-state value before the interlocked compare-exchange that publishes it, and adds two local-field initializers to the feature-usage provider registration routine. Both changes are internal WIL bookkeeping and are not driven by attacker-controlled SMB input. There is no VNetRoot lifecycle bug, no use-after-free, no race with demonstrable security impact, and no reachable exploit primitive. This is a WIL library rebuild, not a security fix.

---

## 2. Change Summary

### Finding 1 — Cached feature-enabled-state now carries an extra WIL bookkeeping bit

- **Severity:** None (informational)
- **Class:** WIL feature-staging library churn — no security relevance
- **Function:** `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` at `0x14003AD00`

**What this function actually is:**

This is the WIL feature-staging helper that recomputes and caches whether a compile-time-registered feature flag is enabled. Its first argument (`rcx`, the target of the atomic compare-exchange) points at a per-feature 32-bit cache cell in the module's WIL feature-state cache — a global bookkeeping variable, not a per-connection object. It reads the current desired state via `wil_details_GetCurrentFeatureEnabledState`, folds it into a packed state word, and publishes the result with `lock cmpxchg` in a standard lock-free update loop. The neighbouring functions in the same region (`wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath`, `wil_details_GetCurrentFeatureEnabledState`, `wil_details_RegisterFeatureUsageProvider`) confirm this is the WIL feature-cache machinery.

**What changed:**

The patched build unconditionally sets bit `0x40000` (bit 18) in the packed cache value before every compare-exchange. In the decompilation this appears as `v9 | 0x40000` at the top of the loop; in assembly it is the single added instruction `bts eax, 0x12`. A companion constant also changed in one branch, from mask `0xFFFFF63E` to `0xFFFBF63E` (the same mask with bit `0x40000` cleared, so the subsequent OR re-adds it consistently). Bit `0x40000` is an internal WIL cache-state flag; it does not gate the lifetime, freeing, or teardown of any SMB object.

**Why this is not a security issue:**

- The cache cell is WIL-internal feature-flag state, not a VNetRoot, connection, session, or exchange object. Nothing about an object's lifetime is decided by this bit.
- The value is not attacker-controlled: the desired feature state comes from the compile-time feature descriptors and the WIL configuration provider, not from SMB request data.
- The compare-exchange loop is unchanged in structure; the patch only alters which constant bit is present in the published value. There is no removed bounds check, no removed lock, and no direction reversal.
- No consumer in either build was found to gate a free/dereference on bit `0x40000` in a way an attacker could race.

This is a straightforward rebuild of the statically-linked WIL feature-staging library with a newer internal cache representation.

---

## 3. Pseudocode Diff

### `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` (`0x14003AD00`) — cache update loop

```c
// ============================================================
// UNPATCHED
// ============================================================
for ( i = v5; ; i = v10 )
{
    LODWORD(v13) = v5;                         // publish raw computed state
    if ( v8 != 0 )
    {
        LODWORD(v13) = v5;
        if ( (i & 2) == 0 )
        {
            v5 = CurrentFeatureEnabledState & 0x9C1 | i & 0xFFFFF63E | 2;
            LODWORD(v13) = v5;
        }
    }
    if ( (i & 4) == 0 )
    {
        v5 = v5 & 0xFFFFFBFF | CurrentFeatureEnabledState & 0x400 | 4;
        LODWORD(v13) = v5;
    }
    v10 = _InterlockedCompareExchange(a1, v5, i);
    if ( i == v10 ) break;
    v5 = v10;
}

// ============================================================
// PATCHED
// ============================================================
v9 = v5;
for ( i = v5; ; i = v9 )
{
    LODWORD(v14) = v9 | 0x40000;              // NEW: bit 0x40000 always set
    v11 = v9 | 0x40000;
    if ( v8 != 0 && (i & 2) == 0 )
    {
        v11 = CurrentFeatureEnabledState & 0x9C1 | v9 & 0xFFFBF63E | 0x40000 | 2;
        LODWORD(v14) = v11;                    // mask 0xFFFFF63E -> 0xFFFBF63E, then re-OR 0x40000
    }
    if ( (v5 & 4) == 0 )
    {
        v11 = v11 & 0xFFFFFBFF | CurrentFeatureEnabledState & 0x400 | 4;
        LODWORD(v14) = v11;
    }
    v9 = _InterlockedCompareExchange(a1, v11, v5);
    if ( v5 == v9 ) break;
    v5 = v9;
}
```

**Key difference:** the published cache value now always carries bit `0x40000`. Everything else is register renaming from the extra instruction shifting register allocation.

---

## 4. Assembly Analysis

The instruction addresses and opcodes below are copied from the two builds. The change is the single `bts eax, 0x12` inserted in the patched loop.

### UNPATCHED — `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` loop body

```asm
000000014003AD5E  mov     ecx, ebx                 ; ecx = current computed state
000000014003AD60  mov     dword ptr [rsp+48h+arg_8], ebx
000000014003AD64  test    esi, esi
000000014003AD66  jz      short 0x14003AD89
...
000000014003ADA4  mov     eax, ecx                 ; eax = expected old state
000000014003ADA6  lock cmpxchg [r15], ebx          ; publish cached state (no 0x40000)
```

### PATCHED — same function, loop body

```asm
000000014003AD68  mov     eax, edi
000000014003AD6A  mov     ecx, edi
000000014003AD6C  bts     eax, 12h                 ; ADDED: set bit 18 (0x40000)
000000014003AD70  mov     dword ptr [rsp+48h+arg_8], eax
000000014003AD74  mov     esi, eax
000000014003AD76  test    ebp, ebp
000000014003AD78  jz      short 0x14003AD95
...
000000014003ADB6  lock cmpxchg [r12], esi          ; publish cached state (with 0x40000)
```

**Annotations:**

- `0x14003AD6C` (patched only) — `bts eax, 0x12` is the entire behavioural change: it sets bit `0x40000` in the WIL feature-state cache value before the compare-exchange.
- `r15` (unpatched) / `r12` (patched) — holds the pointer passed in `rcx`, i.e. the address of the per-feature cache cell. This is WIL feature-flag state, not an SMB object field.
- `ebx` (unpatched) / `esi` (patched) — the packed cache value being published.

---

## 5. Reachability

`wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` is invoked by the WIL feature-flag evaluation path (through `wil_details_GetFeatureEnabledState` / the feature-cache readers) whenever a compile-time-registered feature flag is queried. The state it computes comes from the module's static feature descriptors and the WIL configuration provider. It is not reached with attacker-controlled data through SMB request handling, and the cache cell it updates is a global bookkeeping variable rather than a per-request or per-connection object. There is no SMB-triggerable path that turns the bit-set change into a security-relevant event.

---

## 6. Exploit Primitive & Development Notes

There is no exploit primitive. The change is confined to the internal representation of a WIL feature-state cache value; it does not create or remove a bounds check, a reference-count operation, a lock, or a lifetime decision on any SMB object. No use-after-free, double-free, information leak, or memory-corruption primitive follows from it. No proof-of-concept is applicable.

---

## 7. PoC / Trigger Notes

Not applicable. There is no reachable security-relevant behaviour to trigger. The `bts eax, 0x12` insertion changes only which constant bit is present in a WIL feature-flag cache word, and that value is derived from compile-time feature descriptors, not from SMB traffic.

---

## 8. Changed Functions — Full Triage

### `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` — `0x14003AD00` (not security-relevant)

- **Similarity:** 0.9726
- **Change type:** WIL feature-staging library churn
- **What changed:** A single `bts eax, 0x12` is inserted so the published feature-state cache value always carries bit `0x40000`; one branch mask changed `0xFFFFF63E` → `0xFFFBF63E` to keep that bit consistent. The remaining diff is register renaming caused by the extra instruction. No security impact.

### `wil_details_RegisterFeatureUsageProvider` — `0x140083A7C` (not security-relevant)

- **Similarity:** 0.976
- **Change type:** WIL feature-staging library churn
- **What changed:** The patched build adds two local initializers (`v2 = 1`, `v3 = 0`) in the registration structure passed to `RtlRegisterFeatureUsageProvider`. This reflects a newer WIL provider-registration layout. No behavioural change relevant to security.

Both changed functions are part of the statically-linked WIL feature-staging library. No other function differs beyond relocation/tracing-symbol churn.

---

## 9. Unmatched Functions

None. Both `removed` and `added` lists are empty. An independent content-based diff of the two builds (matching functions across relocations rather than by reused address) confirms exactly two functions changed in substance — the two WIL functions above. All other apparent differences are branch-target relocation shifts (`locret_` labels moving by the size of the inserted instructions) and WPP tracing thunk renames, neither of which is a behavioural change.

---

## 10. Confidence & Caveats

**Confidence:** **High** that this is not a security-relevant change. The two changed functions were identified by exact symbol name in both builds (`wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` and `wil_details_RegisterFeatureUsageProvider`), the instruction- and decompiler-level diffs were confirmed in both directions, and an independent whole-module diff found no other substantive change.

**Notes:**

- The atomic compare-exchange target in the reevaluate function is a WIL per-feature cache cell, established by the surrounding WIL feature-staging functions, not an SMB VNetRoot, connection, session, or exchange object.
- Bit `0x40000` is an internal WIL cache flag; no consumer was found that gates object lifetime or freeing on it.
- The feature-usage provider registration change is a struct-initialization update consistent with a WIL library version bump.
