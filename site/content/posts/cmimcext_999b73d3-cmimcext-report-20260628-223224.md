Title: cmimcext.sys — No security-relevant change (WIL feature-staging library rebuild and IMC feature-flag rollout)
Date: 2026-06-28
Slug: cmimcext_999b73d3-cmimcext-report-20260628-223224
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: None
KBDate: 2026-06-09

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `cmimcext_unpatched.sys` |
| **Patched binary** | `cmimcext_patched.sys` |
| **Overall similarity** | 0.7993 |
| **Matched functions** | 55 |
| **Changed functions** | 34 |
| **Identical functions** | 21 |
| **Unmatched (unpatched)** | 0 |
| **Unmatched (patched)** | 0 |

**Verdict:** No demonstrable, reachable security fix is present in this patch. The churn is dominated by three benign categories:

1. **A Windows Implementation Library (WIL) feature-staging rebuild.** The patched `wil_InitializeFeatureStaging` gains the standard WIL one-time-init guard `g_wil_details_isFeatureStagingInitialized`, registers a feature usage provider (`RtlRegisterFeatureUsageProvider`), and sets `g_wil_details_recordFeatureUsage`. The paired teardown reset appears in `CmCompleteInitMachineConfig`. These are library-version characteristics of the WIL feature-staging subsystem (also visible in the many refactored `wil_details_FeatureReporting_*` / `wil_details_FeatureStateCache_*` helpers), not a targeted cmimcext fix.
2. **A `Feature_ImcL` staged rollout.** `CmSetInitMachineConfig` and `CmCompleteInitMachineConfig` add `Feature_ImcL__private_IsEnabledDeviceUsageNoInline` checks that select between a legacy IMC configuration path and a new one. The legacy path is retained in the else branch, i.e. this is a staged feature flag, not a delivered enforcement change. There is no VBS/HVCI/secure-kernel state anywhere in either binary.
3. **A pool-allocation API modernization.** Numerous `Imp*` functions migrate `ExAllocatePoolWithTag(NonPagedPoolNx, …)` to `ExAllocatePool2(0x40, …)`. This is a uniform API modernization / defense-in-depth pattern, not a fix for a specific reachable defect.

Two additional points settle the earlier over-claims:

- The one-time-init guard in `wil_InitializeFeatureStaging` does not close a reachable use-after-free or attacker-controlled leak. The function has a single call site (`CmSetInitMachineConfig`, reached during boot-time machine-config initialization), and its notification callback `wil_details_ReevaluateOnFeatureConfigurationChange` re-evaluates the module-global feature descriptor table (`wil_details_featureDescriptors_a..z`), which persists for the driver's lifetime and is not the IMCP-tagged pool freed during teardown. There is no freed state for a stale callback to touch and no attacker-controlled input.
- `Feature_Servicing_IMCMemoryCorruptionFix` — a feature whose name suggests a memory-safety fix — is present and **behaviorally identical in both builds**. Its gate in `CmCompleteInitMachineConfig` halves two length words on the enabled path in each build; this patch does not change it. Whatever that feature does was already staged before this patch and is not delivered by it.

The `McGenControlCallbackV2` change is a cosmetic re-expression of the standard ETW enable-bit computation with no behavioral difference.

---

## 2. Change Summary

### Finding 1: Feature-Staging Gate in `CmSetInitMachineConfig`

| Attribute | Detail |
|---|---|
| **Severity** | Informational (no security relevance) |
| **Change class** | WIL feature-staging rollout gate (not a security boundary) |
| **Affected function** | `CmSetInitMachineConfig` (sub_1C000B220 unpatched / sub_14000C080 patched) |

`CmSetInitMachineConfig` decides whether to perform the machine-configuration registry operations (`ZwOpenKey`, `ZwSetValueKey`) based on a value (`v10`/`v12`) derived from `HviIsHypervisorMicrosoftCompatible()`, CPUID leaf `0x40000003` bit 54, and CPUID leaf `0x4000000c` (`_RBX & 0xF`). This is ordinary hypervisor detection, not a VBS/HVCI secure-kernel check. There is no VBS/HVCI/secure-kernel flag anywhere in this binary. This hypervisor-detection logic is unchanged between the two builds.

The patched version adds calls to `Feature_ImcL__private_IsEnabledDeviceUsageNoInline (sub_140001020)`, a WIL feature-staging flag check. It reads the global `Feature_ImcL__private_featureState` (bit `0x10` = feature state already resolved/cached, bit `0` = feature enabled); when the cache bit is clear it falls back to `Feature_ImcL__private_IsEnabledFallback (sub_14000105C)`. The added conditions such as:

```c
if (Feature_ImcL__private_IsEnabledDeviceUsageNoInline() == 0 && v10 != 0)
    goto legacy;   // Feature_ImcL disabled -> use legacy path
```

select between the legacy IMC path (`ImpApplyMachineConfiguration`, `ImpReadWriteSequence`, `ImpQueryForceImcUpdate`) and the new IMC path (`ImpProcessImc`, `ImpReadImcHiveDword (sub_14000C960)`, direct `ZwSetValueKey`). Because the legacy path is retained in the else branch, this is a staged feature rollout, not a trust-boundary enforcement, and it grants no cross-context isolation. There are seven such `Feature_ImcL` call sites in the patched function.

`CmSetInitMachineConfig` is also the single call site of `wil_InitializeFeatureStaging (sub_1C000B008)` (see Finding 3).

---

### Finding 2: Feature-Staging Teardown Bookkeeping in `CmCompleteInitMachineConfig`

| Attribute | Detail |
|---|---|
| **Severity** | Informational (no security relevance) |
| **Change class** | WIL lifecycle bookkeeping + feature-staging gate |
| **Affected function** | `CmCompleteInitMachineConfig` (sub_1C0008320 unpatched / sub_140009010 patched) |

`CmCompleteInitMachineConfig` walks the `CmpImcAllowEventQueueHead` list and calls `ExFreePoolWithTag` on the allocations at node offsets `+0x20` (`v14[4]`), `+0x30` (`v14[6]`), and the node itself, using pool tag `0x50434d49` (`"IMCP"`). This free loop is present in **both** versions and drains the list exactly once. There is no double-free or cross-context free here. In the patched build the loop is wrapped in `if (Feature_ImcL__private_IsEnabledDeviceUsageNoInline (sub_140001020))`, so the list is drained only on the new IMC path — a feature-staging gate, not a bounds or double-free fix.

The genuine additions in the patched build are WIL teardown bookkeeping that pairs with the `wil_InitializeFeatureStaging` one-time-init guard:

```c
if (g_wil_details_featureChangeNotification != 0) { RtlUnregisterFeatureConfigurationChangeNotification(); g_wil_details_featureChangeNotification = 0; }
if (g_wil_details_featureUsageProvider != 0)      { RtlUnregisterFeatureUsageProvider();               g_wil_details_featureUsageProvider = 0; }
g_wil_details_isFeatureStagingInitialized = 0;    // reset init flag
```

The unpatched version unregisters only `wil_details_featureChangeNotification`; it never registers or unregisters a usage provider and has no init flag to reset. These are all attributes of the newer WIL feature-staging library linked into the patched build (see Finding 3), not a security fix.

The ETW-emit loop earlier in this function is gated by `Feature_Servicing_IMCMemoryCorruptionFix__private_IsEnabledDeviceUsageNoInline (sub_140001078)` in the patched build (and by `Feature_Servicing_IMCMemoryCorruptionFix__private_IsEnabledDeviceUsage (sub_1C0001C18)` in the unpatched build). The behavior of that gate — halving the two length words `[rbx+18h]` and `[rbx+28h]` on the enabled path before they are passed to the ETW template — is identical in both builds. This patch does not change it.

---

### Finding 3: WIL One-Time-Init Guard Added to `wil_InitializeFeatureStaging`

| Attribute | Detail |
|---|---|
| **Severity** | Informational (no security relevance) |
| **Change class** | WIL feature-staging library boilerplate (one-time init + usage-provider registration) |
| **Affected function** | `wil_InitializeFeatureStaging` (sub_1C000B008 unpatched / sub_14000CB94 patched) |

The unpatched `wil_InitializeFeatureStaging` has no init flag: each call runs the full body, which registers the callback `wil_details_ReevaluateOnFeatureConfigurationChange (sub_1C0008010)` via `RtlRegisterFeatureConfigurationChangeNotification` and stores the handle in `wil_details_featureChangeNotification`. The patched build adds the WIL one-time-init flag at the top of the function:

```c
if (g_wil_details_isFeatureStagingInitialized != 0)
    return 0;
g_wil_details_isFeatureStagingInitialized = 1;
```

and the complementary `g_wil_details_isFeatureStagingInitialized = 0` reset in `CmCompleteInitMachineConfig`. The patched build additionally registers a feature usage provider via `RtlRegisterFeatureUsageProvider` (callback `wil_details_OnFeatureUsageProviderFlushNotification (sub_14000A320)`, handle `g_wil_details_featureUsageProvider`) and sets `g_wil_details_recordFeatureUsage = wil_details_RecordFeatureUsageReporting (sub_140002010)` — neither exists in the unpatched build.

**Why this is not a security fix:**

- These are stock characteristics of the WIL feature-staging subsystem in the newer library version linked into the patched binary. The same subsystem accounts for the many other refactored `wil_details_*` helpers in this patch (feature-reporting cache, feature-state cache, dependency evaluation). It is a library rebuild, not a cmimcext-specific patch.
- `wil_InitializeFeatureStaging` has exactly one call site in both builds: `CmSetInitMachineConfig`, reached during boot-time machine-config initialization. cmimcext.sys exposes no IOCTL handlers or device objects, so there is no attacker-controlled path to drive repeated re-initialization.
- The notification callback `wil_details_ReevaluateOnFeatureConfigurationChange` re-evaluates the module-global feature descriptor table (`wil_details_featureDescriptors_a..z`) via `wil_details_EvaluateFeatureDependencies`. That state persists for the driver's lifetime and is distinct from the IMCP-tagged pool nodes freed during teardown. There is therefore no freed state for a re-registered or stale callback to dereference, i.e. no use-after-free.

At most, the missing flag in the unpatched build could allow a redundant re-registration of a single boot-time notification object if the init path ever ran twice; this is a bounded, non-attacker-controlled bookkeeping matter, not a reachable primitive.

---

### Finding 4: ETW Enable-Bit Computation in `McGenControlCallbackV2` (No Behavioral Change)

| Attribute | Detail |
|---|---|
| **Severity** | None (cosmetic) |
| **Change class** | None — semantically identical ETW enable-bit computation |
| **Affected function** | `McGenControlCallbackV2` (sub_1C0001010 unpatched / sub_1400011E0 patched) |

`McGenControlCallbackV2` is the standard compiler/WIL-generated ETW provider control callback (registered via `EtwRegister` in `McGenEventRegister_EtwRegister`). It is not a feature-bitmap evaluator and there is no threshold inversion.

For `ControlCode == 1` (enable) it computes, per event descriptor, the enable bit:

```
enabled = (perEventLevel <= Level || Level == 0)
       && (MatchAnyKeyword == 0
           || ((keyword & MatchAnyKeyword) != 0 && (keyword & MatchAllKeyword) == MatchAllKeyword));
```

Here `Level` is the ETW trace level (`Level == 0` means "all levels") and the keyword test is the standard MatchAny/MatchAll rule. This condition is **identical** in both versions — the `perEventLevel <= Level || Level == 0` comparison is present unchanged in each. The only difference is expression form: the unpatched build uses nested `if` statements setting a boolean, the patched build uses one combined boolean expression and slightly different register allocation. There is no enable/disable inversion and no security impact.

---

## 3. Pseudocode Diff

### Finding 1: `CmSetInitMachineConfig` — Feature-Staging Gate

```c
// ── UNPATCHED: CmSetInitMachineConfig (sub_1C000B220) ──────────
void CmSetInitMachineConfig(...) {
    v12 = 0;
    if (HviIsHypervisorMicrosoftCompatible()) {
        cpuid(0x40000003);
        if (result & 0x40000000000000) {   // leaf 0x40000003 bit 54
            cpuid(0x4000000c);
            v12 = _RBX & 0xF;              // hypervisor partition count
        }
    }
    wil_InitializeFeatureStaging();        // single call site (see Finding 3)
    // registry ops selected by v12 only; ImpReadImcHiveDword path
    if (v12 != 0) { ZwSetValueKey(Handle, ...); }
    ...
}

// ── PATCHED: CmSetInitMachineConfig (sub_14000C080) ────────────
void CmSetInitMachineConfig(...) {
    // v10 computed identically (hypervisor detection, NOT VBS)
    wil_InitializeFeatureStaging(_RCX, _RDX);   // now has WIL init flag (Finding 3)

    // ADDED: WIL feature-staging flag selects legacy vs new IMC path
    if (Feature_ImcL__private_IsEnabledDeviceUsageNoInline() == 0 && v10 != 0)
        goto legacy;                       // Feature_ImcL disabled -> legacy retained
    ...
    if (Feature_ImcL__private_IsEnabledDeviceUsageNoInline() != 0)
        v15 = ImpReadImcHiveDword(Handle, &ImpSequenceValueName, &v22);  // new path
    else
        v15 = ImpReadWriteSequence(Handle);                             // legacy path
    ...
}

// Feature_ImcL__private_IsEnabledDeviceUsageNoInline (sub_140001020) — WIL feature-flag check
__int64 Feature_ImcL__private_IsEnabledDeviceUsageNoInline() {
    // Feature_ImcL__private_featureState: bit 0x10 = state resolved/cached, bit 0 = feature enabled
    if (Feature_ImcL__private_featureState & 0x10)
        return Feature_ImcL__private_featureState & 1;   // cached enabled state
    return Feature_ImcL__private_IsEnabledFallback(Feature_ImcL__private_featureState, 3);
}
```

### Finding 2: `CmCompleteInitMachineConfig` — Feature-Staging Teardown Bookkeeping

```c
// ── UNPATCHED: CmCompleteInitMachineConfig (sub_1C0008320) ─────
void CmCompleteInitMachineConfig(a1) {
    // IMCP-tagged list drained exactly once (present in BOTH versions)
    while ((v19 = CmpImcAllowEventQueueHead) != &CmpImcAllowEventQueueHead) {
        CmpImcAllowEventQueueHead = *v19;
        ExFreePoolWithTag(v19[4], 0x50434D49);   // node+0x20
        ExFreePoolWithTag(v19[6], 0x50434D49);   // node+0x30
        ExFreePoolWithTag(v19,    0x50434D49);   // node
    }
    if (wil_details_featureChangeNotification != 0) {
        RtlUnregisterFeatureConfigurationChangeNotification();
        wil_details_featureChangeNotification = 0;
    }
    // older WIL: no usage-provider unregister, no init flag (the library has neither)
}

// ── PATCHED: CmCompleteInitMachineConfig (sub_140009010) ───────
void CmCompleteInitMachineConfig(a1) {
    if (Feature_ImcL__private_IsEnabledDeviceUsageNoInline()) {   // feature gate, NOT VBS
        while ((v14 = CmpImcAllowEventQueueHead) != &CmpImcAllowEventQueueHead) {
            CmpImcAllowEventQueueHead = *v14;
            ExFreePoolWithTag(v14[4], 0x50434D49);
            ExFreePoolWithTag(v14[6], 0x50434D49);
            ExFreePoolWithTag(v14,    0x50434D49);
        }
    }
    if (g_wil_details_featureChangeNotification != 0) {
        RtlUnregisterFeatureConfigurationChangeNotification();
        g_wil_details_featureChangeNotification = 0;
    }
    if (g_wil_details_featureUsageProvider != 0) {          // ← ADDED (newer WIL)
        RtlUnregisterFeatureUsageProvider();
        g_wil_details_featureUsageProvider = 0;
    }
    g_wil_details_isFeatureStagingInitialized = 0;          // ← ADDED (newer WIL)
}
```

### Finding 3: `wil_InitializeFeatureStaging` — WIL One-Time-Init Flag

```c
// ── UNPATCHED: wil_InitializeFeatureStaging (sub_1C000B008) ────
__int64 wil_InitializeFeatureStaging() {
    // older WIL: no init flag
    v4 = RtlQueryFeatureConfigurationChangeStamp();
    wil_details_PopulateInitialConfiguredFeatureStates();
    wil_details_EvaluateFeatureDependencies();
    // ... iterate descriptors ...
    v3 = RtlRegisterFeatureConfigurationChangeNotification(
        wil_details_ReevaluateOnFeatureConfigurationChange,   // callback
        0, &v4,
        &wil_details_featureChangeNotification);              // handle
}

// ── PATCHED: wil_InitializeFeatureStaging (sub_14000CB94) ──────
__int64 wil_InitializeFeatureStaging() {
    if (g_wil_details_isFeatureStagingInitialized != 0)      // ← ADDED WIL init flag
        return 0;
    g_wil_details_isFeatureStagingInitialized = 1;           // ← mark initialized
    v7 = RtlQueryFeatureConfigurationChangeStamp();
    wil_details_PopulateInitialConfiguredFeatureStates();
    wil_details_EvaluateFeatureDependencies();
    // ... iterate descriptors ...
    RtlRegisterFeatureConfigurationChangeNotification(
        wil_details_ReevaluateOnFeatureConfigurationChange, 0, &v7,
        &g_wil_details_featureChangeNotification);
    g_wil_details_recordFeatureUsage = wil_details_RecordFeatureUsageReporting;   // ← ADDED (sub_140002010)
    RtlRegisterFeatureUsageProvider(                          // ← ADDED
        wil_details_OnFeatureUsageProviderFlushNotification,  // callback (sub_14000A320)
        v4, &g_wil_details_featureUsageProvider);
}
```

### Finding 4: `McGenControlCallbackV2` — Identical ETW Enable-Bit Computation

```c
// ── UNPATCHED: McGenControlCallbackV2 (sub_1C0001010) ─────────
void McGenControlCallbackV2(SourceId, ControlCode, Level, MatchAnyKeyword,
                            MatchAllKeyword, FilterData, CallbackContext) {
    if (ControlCode == 1) {                         // ENABLE
        ctx->Level = Level; ctx->MatchAny = MatchAnyKeyword; ctx->MatchAll = MatchAllKeyword;
        for (v7 = 0; v7 < ctx->count; ++v7) {
            v10 = false;
            if (ctx->levels[v7] <= Level || Level == 0) {     // enable-level test
                v9 = ctx->keywords[v7];
                if (v9 == 0 || ((v9 & MatchAny) && (v9 & MatchAll) == MatchAll))
                    v10 = true;
            }
            if (v10) ctx->bits[v7>>5] |=  (1 << (v7 & 0x1F));
            else     ctx->bits[v7>>5] &= ~(1 << (v7 & 0x1F));
        }
    }
}

// ── PATCHED: McGenControlCallbackV2 (sub_1400011E0) ───────────
void McGenControlCallbackV2(...) {
    if (ControlCode == 1) {                         // ENABLE
        ctx->Level = Level; ctx->MatchAll = MatchAllKeyword; ctx->MatchAny = MatchAnyKeyword;
        for (v7 = 0; v7 < ctx->count; ++v7) {
            // SAME predicate, expressed as one combined boolean:
            v10 = (ctx->levels[v7] <= Level || Level == 0)
               && (ctx->keywords[v7] == 0
                   || ((ctx->keywords[v7] & MatchAny) && (ctx->keywords[v7] & MatchAll) == MatchAll));
            if (v10) ctx->bits[v7>>5] |=  (1 << v7);
            else     ctx->bits[v7>>5] &= ~(1 << v7);
        }
    }
}
// The `levels[v7] <= Level || Level == 0` test is IDENTICAL in both. No inversion.
```

---

## 4. Assembly Analysis

### Finding 1: `CmSetInitMachineConfig` — Feature-Staging Gate

**Feature flag helper (patched, verbatim at 0x140001020):**

```asm
; ── Feature_ImcL__private_IsEnabledDeviceUsageNoInline @ 0x140001020 ──
0x140001020  sub     rsp, 28h
0x140001024  mov     eax, cs:Feature_ImcL__private_featureState  ; NOT VBS state
0x14000102A  mov     [rsp+28h+arg_0], 0
0x140001033  mov     dword ptr [rsp+28h+arg_0], eax
0x140001037  test    al, 10h                                     ; state resolved/cached?
0x140001039  jz      short loc_140001040
0x14000103B  and     eax, 1                                      ; return enabled bit
0x14000103E  jmp     short loc_14000104F
0x140001040  mov     rcx, [rsp+28h+arg_0]
0x140001045  mov     edx, 3
0x14000104A  call    Feature_ImcL__private_IsEnabledFallback     ; Feature_ImcL__private_IsEnabledFallback (sub_14000105C)
0x14000104F  add     rsp, 28h
0x140001053  retn
```

**What changed:** The unpatched `CmSetInitMachineConfig` selects the IMC registry path on the hypervisor-partition value alone. The patched version inserts `call Feature_ImcL__private_IsEnabledDeviceUsageNoInline` + `test eax, eax` at seven decision points to choose between the legacy IMC path (`ImpApplyMachineConfiguration`, `ImpReadWriteSequence`) and the new IMC path (`ImpProcessImc`, `ImpReadImcHiveDword (sub_14000C960)`). This is a WIL feature-staging flag, not a VBS/HVCI gate; the global read is `Feature_ImcL__private_featureState`, not a secure-kernel flag.

---

### Finding 2: `CmCompleteInitMachineConfig` — Feature-Staging Teardown

**Unpatched teardown tail (verbatim, 0x1C00085D4):**

```asm
; ── UNPATCHED: CmCompleteInitMachineConfig (sub_1C0008320) ──
; free loop above drains CmpImcAllowEventQueueHead once with tag 0x50434D49
0x1C00085D4  mov     rcx, cs:wil_details_featureChangeNotification
0x1C00085DB  test    rcx, rcx
0x1C00085DE  jz      short loc_1C00085F3
0x1C00085E0  call    cs:__imp_RtlUnregisterFeatureConfigurationChangeNotification
0x1C00085EC  mov     cs:wil_details_featureChangeNotification, rdi   ; = 0
0x1C00085F3  ...                                                     ; return
; older WIL: no usage-provider unregister, no init-flag reset
```

**Patched teardown tail (verbatim, 0x1400092DB):**

```asm
; ── PATCHED: CmCompleteInitMachineConfig (sub_140009010) ──
; free loop above is gated at 0x140009197 by Feature_ImcL__private_IsEnabledDeviceUsageNoInline
0x1400092DB  mov     rcx, cs:g_wil_details_featureChangeNotification
0x1400092E2  test    rcx, rcx
0x1400092E5  jz      short loc_1400092FA
0x1400092E7  call    cs:__imp_RtlUnregisterFeatureConfigurationChangeNotification
0x1400092F3  mov     cs:g_wil_details_featureChangeNotification, rdi ; = 0
0x1400092FA  mov     rcx, cs:g_wil_details_featureUsageProvider      ; ← ADDED (newer WIL)
0x140009301  test    rcx, rcx
0x140009304  jz      short loc_140009319
0x140009306  call    cs:__imp_RtlUnregisterFeatureUsageProvider
0x140009312  mov     cs:g_wil_details_featureUsageProvider, rdi      ; = 0
0x140009319  mov     rbx, [rsp+48h+arg_0]
0x140009323  mov     cs:g_wil_details_isFeatureStagingInitialized, edi ; ← ADDED reset = 0
0x14000932E  retn
```

---

### Finding 3: `wil_InitializeFeatureStaging` — WIL One-Time-Init Flag

**Patched entry (verbatim, 0x14000CB94):**

```asm
; ── PATCHED: wil_InitializeFeatureStaging (sub_14000CB94) ──
0x14000CBA8  xor     esi, esi
0x14000CBAA  cmp     cs:g_wil_details_isFeatureStagingInitialized, esi  ; esi = 0
0x14000CBB0  mov     edi, esi
0x14000CBB2  jnz     loc_14000CCD2                                       ; already init -> return 0
0x14000CBB8  mov     cs:g_wil_details_isFeatureStagingInitialized, 1     ; ← ADDED WIL init flag
0x14000CBC2  call    cs:__imp_RtlQueryFeatureConfigurationChangeStamp
...
0x14000CC47  call    cs:__imp_RtlRegisterFeatureConfigurationChangeNotification
...
0x14000CC65  lea     rax, wil_details_RecordFeatureUsageReporting
0x14000CC70  mov     cs:g_wil_details_recordFeatureUsage, rax            ; ← ADDED
...
0x14000CCB4  call    cs:__imp_RtlRegisterFeatureUsageProvider            ; ← ADDED
```

The unpatched `wil_InitializeFeatureStaging (sub_1C000B008)` has no such flag test at entry: its body begins directly with `xor ebx, ebx` / `call RtlQueryFeatureConfigurationChangeStamp` and it never registers a usage provider. Both differences are attributes of the newer WIL feature-staging library, matching the reset added in `CmCompleteInitMachineConfig` (0x140009323).

---

### Finding 4: `McGenControlCallbackV2` — Identical Enable-Level Test

**Both versions compute the same ETW enable predicate.** The per-event enable-level comparison `perEventLevel <= Level` (with `Level == 0` meaning all levels) is present unchanged in each:

```asm
; ── UNPATCHED: McGenControlCallbackV2 (sub_1C0001010) ──
; cl = Level, byte [rax+r9] = perEventLevel
cmp     [rax+r9], cl        ; perEventLevel vs Level
jbe     keyword_test        ; perEventLevel <= Level → keyword test
test    cl, cl
jz      keyword_test        ; Level == 0 → keyword test (all levels)
; else enabled = false
...
    or      dword ptr [r11+4*rdx], r8d    ; set enable bit
    ; else
    and     dword ptr [r11+4*rdx], ...    ; clear enable bit

; ── PATCHED: McGenControlCallbackV2 (sub_1400011E0) ──
; same predicate, combined into one boolean before the bit write;
; only register allocation and expression form differ. No inversion.
```

There is no `jg`/`ja` threshold inversion; this is the stock ETW control-callback enable-bit computation and is behaviorally identical across the two builds.

---

## 5. Reachability / Trigger Analysis

### Finding 1 & 3: Feature-Staging Init Path

1. **Driver loaded:** `cmimcext.sys` is a Configuration Manager extension loaded during system initialization. It has no IOCTL handlers and no device objects, so there is no user-mode attack surface.
2. **`CmSetInitMachineConfig`** runs on the boot machine-config path and is the sole caller of `wil_InitializeFeatureStaging (sub_1C000B008)`.
3. **No reachable re-entry primitive:** There is no attacker-controlled way to force repeated re-initialization. Even if the init path ran more than once in the unpatched build, the only consequence would be a redundant registration of a boot-time notification object.
4. **No stale-callback use-after-free:** The notification callback `wil_details_ReevaluateOnFeatureConfigurationChange (sub_1C0008010)` re-evaluates the module-global feature descriptor table, which lives for the driver's lifetime and is not the IMCP-tagged pool freed at teardown. There is no freed memory for it to touch.

### Finding 2: Teardown Bookkeeping

1. **`CmCompleteInitMachineConfig`** runs on the configuration completion/teardown path.
2. The IMCP-tagged free loop drains `CmpImcAllowEventQueueHead` exactly once in both builds — not a double-free. In the patched build it is gated by `Feature_ImcL`.
3. The added `RtlUnregisterFeatureUsageProvider` and `g_wil_details_isFeatureStagingInitialized = 0` are WIL lifecycle bookkeeping matching the newer library's init path.

### Finding 4: ETW Control Callback

1. **`McGenControlCallbackV2 (sub_1C0001010)`** is invoked by ETW when a session enables/disables the provider (`ControlCode` 0 or 1).
2. The enable-bit computation is identical across builds; enabling the provider at any level/keyword yields the same per-event enable bitmap in both versions.

---

## 6. Impact Assessment

- **Finding 1 (Feature_ImcL gate):** No primitive. The flag selects between two functionally-equivalent IMC configuration implementations with the legacy path retained; it is not a trust boundary and grants no cross-context capability. There is no VBS/HVCI/secure-kernel path in this binary; the CPUID work is ordinary hypervisor detection.
- **Finding 2 (teardown bookkeeping):** No primitive. The IMCP-tagged list is drained exactly once per teardown in both builds; there is no double-free or cross-context free. The added unregister/reset are WIL lifecycle bookkeeping.
- **Finding 3 (WIL init flag):** No reachable primitive. Single boot-time call site, no attacker-controlled re-entry, and the notification callback operates on persistent module-global state, so there is no use-after-free and no attacker-controlled resource-exhaustion primitive.
- **Finding 4 (ETW control callback):** No primitive. Behaviorally identical across builds.
- **Pool API migration (`ExAllocatePoolWithTag` → `ExAllocatePool2`) across `Imp*` functions:** Defense-in-depth API modernization applied uniformly, not a fix for a specific reachable defect.
- **`Feature_Servicing_IMCMemoryCorruptionFix`:** Present and behaviorally identical in both builds; this patch does not change it.

No finding yields a reachable exploitation primitive in either build.

---

## 7. Debugger Observation Notes

> The following assumes WinDbg/KD attached to `cmimcext.sys` during system boot or configuration change. These steps confirm the changes are benign WIL feature-staging / feature-flag churn; none exercises a vulnerability.

### Finding 1: `CmSetInitMachineConfig` Feature-Staging Gate

**Breakpoints:**

```
bp cmimcext!CmSetInitMachineConfig
bp cmimcext!wil_InitializeFeatureStaging
```

**What to inspect:**

- **`v10`/`v12`:** the hypervisor-partition value from CPUID leaf `0x40000003` bit 54 + leaf `0x4000000c` (`_RBX & 0xF`). This is hypervisor detection, not a VBS/secure-kernel flag, and is unchanged between builds.
- **Patched only:** a `call Feature_ImcL__private_IsEnabledDeviceUsageNoInline (sub_140001020)` appears at each path-selection point. This helper reads `Feature_ImcL__private_featureState` (bit `0x10` = resolved/cached, bit `0` = enabled) — a WIL feature-staging flag, not a security boundary.
- **`wil_InitializeFeatureStaging`:** in the unpatched build the body runs from entry; in the patched build it returns early once `g_wil_details_isFeatureStagingInitialized` is set.

| Global | Unpatched | Patched | Purpose |
|---|---|---|---|
| Feature-staging flag | (n/a) | `Feature_ImcL__private_featureState` | bit 0x10=resolved, bit 0=enabled |
| Init flag | (none) | `g_wil_details_isFeatureStagingInitialized` | 0=uninit, 1=initialized |
| Hypervisor partition | `v12` (local) | `v10` (local) | CPUID leaf 0x4000000c count |

---

### Finding 2: `CmCompleteInitMachineConfig` Teardown Bookkeeping

**Breakpoints:**

```
bp cmimcext!CmCompleteInitMachineConfig
bp nt!RtlUnregisterFeatureUsageProvider
```

**What to inspect:**

- **`rcx`/`rdx` at each `ExFreePoolWithTag`:** the freed pointer (`v14[4]` at node+0x20, `v14[6]` at node+0x30, or the node) and the pool tag `0x50434d49` (`"IMCP"`). The list is drained exactly once — not a double-free.
- **Feature gate (patched only):** the free loop is wrapped in `if (Feature_ImcL__private_IsEnabledDeviceUsageNoInline())` at 0x140009197 — a feature-staging gate.
- **Teardown bookkeeping (patched only):** after the loop, `RtlUnregisterFeatureUsageProvider` is called and `g_wil_details_isFeatureStagingInitialized` is set to 0 (0x140009323). Both are absent in the unpatched build's older WIL.

---

### Finding 3: `wil_InitializeFeatureStaging` Init Flag

**Breakpoints:**

```
bp cmimcext!wil_InitializeFeatureStaging
bp nt!RtlRegisterFeatureConfigurationChangeNotification
```

**What to inspect:**

- **On entry:** in the unpatched build execution falls directly to `RtlQueryFeatureConfigurationChangeStamp`. In the patched build the first instructions test and set `g_wil_details_isFeatureStagingInitialized` (0x14000CBAA / 0x14000CBB8).
- **At `RtlRegisterFeatureConfigurationChangeNotification`:** the output handle pointer is `&wil_details_featureChangeNotification` (unpatched) / `&g_wil_details_featureChangeNotification` (patched). The callback registered, `wil_details_ReevaluateOnFeatureConfigurationChange`, re-evaluates module-global feature state — not freed pool.
- **Read the flag (patched):** `dd cmimcext!g_wil_details_isFeatureStagingInitialized L1` — 0 on first call, 1 afterward. This global does not exist in the unpatched build.

---

### Finding 4: `McGenControlCallbackV2` ETW Control Callback

**Breakpoints:**

```
bp cmimcext!McGenControlCallbackV2
```

**What to inspect:**

- **On entry:** ETW-supplied args (`SourceId`, `ControlCode`, `Level`, `MatchAnyKeyword`, `MatchAllKeyword`, `FilterData`, `CallbackContext`). This is the ETW provider control callback, not a feature-bitmap evaluator with a threshold.
- **At the enable-level test:** both builds compute `perEventLevel <= Level || Level == 0` (plus the MatchAny/MatchAll keyword test) identically. There is no `jg`/`ja` inversion.

**Expected observation:** for the same `Level`/keyword inputs, the per-event enable bitmap in `CallbackContext` is identical between the two builds.

---

## 8. Changed Functions — Full Triage

### WIL Feature-Staging / Feature-Flag Churn (non-security)

| Function | Similarity | Note |
|---|---|---|
| `wil_InitializeFeatureStaging (sub_1C000B008)` / `(sub_14000CB94)` | 0.6982 | WIL one-time-init flag `g_wil_details_isFeatureStagingInitialized` added; also registers a feature usage provider and sets the record-usage callback. Newer WIL library boilerplate, not a security fix. |
| `CmCompleteInitMachineConfig` | 0.9116 | WIL teardown bookkeeping added (`RtlUnregisterFeatureUsageProvider` + init-flag reset); IMCP free loop wrapped in a `Feature_ImcL` gate. Free loop runs once — not a double-free. |
| `CmSetInitMachineConfig` | 0.8146 | Seven `Feature_ImcL` gate sites select legacy vs new IMC path (legacy retained). Not a VBS boundary. Hypervisor detection unchanged. |
| `wil_details_FeatureReporting_RecordUsageInCache (sub_1C00013FC)` / `wil_details_FeatureReporting_IncrementUsageInCache (sub_1400016BC)` | 0.2144 | Feature-usage state machine refactored to a single `lock cmpxchg` path with `0x1FF` mask; signature takes a context pointer. WIL rebuild. |
| `wil_details_FeatureReporting_ReportUsageToServiceDirect (sub_1C00016D4)` / `(sub_1400018DC)` | 0.4212 | Feature-usage reporting refactored to context pointer from `arg1+8`; calls via `_guard_dispatch_icall`. WIL rebuild. |
| `Feature_Servicing_IMCMemoryCorruptionFix__private_IsEnabledFallback (sub_1C0001C00)` / `(sub_1400010B4)` | 0.5239 | Thunk updated to pass explicit context pointer. WIL feature-flag rebuild. Feature behavior unchanged across builds. |
| `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState (sub_1C00018E0)` / `(sub_140001B04)` | 0.6309 | New `0xC00`/`0x800` bit-field handling for variant selection. WIL rebuild. |
| `wil_details_EvaluateFeatureDependencies_GetCachedFeatureEnabledState (sub_1C0008224)` / `wil_details_EvaluateFeatureDependencies_ReevaluateCachedFeatureEnabledState (sub_14000A204)` | 0.6561 | Signature takes explicit value; adds `0xC00` handling. WIL rebuild. |
| `wil_details_PopulateInitialConfiguredFeatureStates (sub_1C000B0B4)` / `(sub_14000CCF0)` | 0.7443 | Condition refactored from unsigned range check to explicit `== 2 || == 3`. WIL rebuild. |
| `wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath (sub_1C0001BBC)` / `(sub_140001DBC)` | 0.7582 | Takes explicit context pointer; adds short-circuit for `*(arg3+0x1e) || *(arg3+0x1d)`. WIL rebuild. |
| `wil_details_EvaluateFeatureDependencies (sub_1C0008138)` / `(sub_14000A0B4)` | 0.8654 | Calls 3-arg variant of propagation helper. WIL rebuild. |
| `Feature_Servicing_IMCMemoryCorruptionFix__private_IsEnabledDeviceUsage (sub_1C0001C18)` / `wil_details_EvaluateFeatureDependencies_GetCachedFeatureEnabledState (sub_14000A1C8)` | 0.9094 | Bit check `0x10` → bit 9; recursion path changed. WIL feature-state semantics rebuild. |
| `wil_details_IsEnabledFallback (sub_1C0001B30)` / `(sub_140001E18)` | 0.9555 | Takes explicit context pointer instead of a global. WIL rebuild. |
| `wil_details_ReevaluateOnFeatureConfigurationChange (sub_1C0008010)` / `(sub_14000A3A0)` | 0.9657 | Notification callback: address relocations; commutative XOR operand swap. WIL rebuild. |
| `wil_details_FeatureReporting_ReportUsageToService (sub_1C00017C4)` / `(sub_1400017B0)` | 0.9874 | Switch-case flattened to if-else chain; call via `_guard_dispatch_icall`. WIL rebuild. |

### Pool-API Modernization / Registry Helpers (non-security)

| Function | Similarity | Note |
|---|---|---|
| `ImpGetSubkeyByIndex (sub_1C00091CC)` / `(sub_140009D68)` | 0.9519 | `ExAllocatePoolWithTag(NonPagedPoolNx, …)` → `ExAllocatePool2(0x40, …)`; symbolic STATUS constants. |
| `ImpEstablishNamedSubkey (sub_1C0008DD0)` / `(sub_140009954)` | 0.9610 | Bounds check refactored (semantically equivalent); pool API migrated. |
| `ImpGetObjectSecurityDescriptorByHandle (sub_1C0009090)` / `(sub_140009C20)` | 0.9751 | Pool API migration for the `ZwQuerySecurityObject` buffer. |
| `ImpUnloadImcHive (sub_1C0008614)` / `(sub_140009EF0)` | 0.9777 | Pool API migration; condition caching restructured. |
| `ImpApplyMachineConfiguration (sub_1C00087E4)` / `(sub_14000935C)` | 0.9890 | Pool API migration; register renaming; `< 0` → `< STATUS_SUCCESS`. |
| `ImpCopyKeyValues (sub_1C0008B7C)` / `(sub_1400096F4)` | 0.9856 | Pool API migration; explicit STATUS assignment on error path. |
| `ImpSetRegValue (sub_1C000BEB4)` / `(sub_14000D45C)` | 0.9787 | Object attributes init reordered. |
| `ImpGetRegValueSz (sub_1C000BCE0)` / `(sub_14000D000)` | 0.9828 | Object attributes init reordered; relocations. |
| `ImpReadImcHiveDword (sub_1C000BAE4)` / `(sub_14000C960)` | 0.9832 | Address relocations only. |
| `ImpAddAllowListEvent (sub_1C000BB74)` / `(sub_14000CE80)` | 0.7397 | Error-handling if/else swapped; logically equivalent. |
| `ImpValidatePagingFiles (sub_1C000C128)` / `(sub_14000D5E4)` | 0.9646 | GUID/string validation loop branches swapped. |
| `ImpEstablishIMCPolicies (sub_1C000B7E8)` / `(sub_14000C66C)` | 0.9906 | Minor address relocations. |

### Cosmetic / Register-Allocation / Compiler Changes (non-security)

- `McGenControlCallbackV2 (sub_1C0001010)` / `(sub_1400011E0)` (0.9791) — stock ETW control callback; enable-bit computation identical.
- `McTemplateK0hzr0_EtwWriteTransfer (sub_1C0001220)` / `(sub_1400013F0)` (0.6966) — address relocation.
- `McTemplateK0d_EtwWriteTransfer (sub_1C00011BC)` / `(sub_140001390)` (0.7019) — address relocation.
- `__cpu_features_init (sub_1C0001E10)` / `(sub_1400021E0)` (0.3933) — CPUID detection reordered; semantically equivalent.
- `HviIsHypervisorMicrosoftCompatible (sub_1C0001CAC)` / `(sub_1400020D4)` (0.9500) — security cookie removed, stack reduced.
- `HviIsAnyHypervisorPresent (sub_1C0001C50)` / `(sub_140002094)` (0.9608) — security cookie removed.
- `__GSHandlerCheckCommon (sub_1C0001D9C)` / `(sub_14000215C)` (0.9878) — security cookie removed.

> **Note on security cookie removal:** Several functions had `__security_cookie` XOR stack guards removed in the patched version (`HviIsHypervisorMicrosoftCompatible`, `HviIsAnyHypervisorPresent`, `__GSHandlerCheckCommon`). This is a compiler decision made when a function has no stack buffer overrun risk (e.g. no local arrays). It is not a security regression or fix.

> **Note on `Feature_Servicing_IMCMemoryCorruptionFix`:** Despite its name, this feature's gate in `CmCompleteInitMachineConfig` is behaviorally identical in both builds (it halves the two length words `[rbx+18h]` and `[rbx+28h]` on the enabled path before ETW emission). This patch does not alter it; whatever it fixes was already staged in the unpatched build.

---

## 9. Unmatched Functions

No functions were added or removed between versions. All 55 matched functions are present in both binaries; 34 changed and 21 are byte-identical.

**Implication:** The patch is a pure in-place modification. The patched build exposes additional WIL feature-staging helper symbols not present in the unpatched listing (`Feature_ImcL__private_IsEnabledDeviceUsageNoInline (sub_140001020)`, `Feature_ImcL__private_IsEnabledFallback (sub_14000105C)`, `wil_details_OnFeatureUsageProviderFlushNotification (sub_14000A320)`, `wil_details_RecordFeatureUsageReporting (sub_140002010)`, `ImpReadWriteSequence (sub_14000C9F0)`), and the init flag `g_wil_details_isFeatureStagingInitialized` is a new global. The `RtlRegisterFeatureUsageProvider` / `RtlUnregisterFeatureUsageProvider` calls are new invocations of existing NT API imports. These are consistent with a newer WIL library and a `Feature_ImcL` staged rollout.

---

## 10. Confidence & Caveats

**Overall confidence: High that there is no security-relevant change.**

The findings are verified against the decompilation and disassembly of both binaries.

- The `wil_InitializeFeatureStaging` init flag, usage-provider registration, and the many refactored `wil_details_*` helpers are consistent with a WIL feature-staging library version update. They are not a cmimcext-specific security fix.
- The `Feature_ImcL` gates in `CmSetInitMachineConfig` and `CmCompleteInitMachineConfig` are a staged rollout that retains the legacy path; no enforcement is delivered.
- The `ExAllocatePoolWithTag` → `ExAllocatePool2` migration is a uniform API modernization.
- `Feature_Servicing_IMCMemoryCorruptionFix` is identical in both builds and is not delivered by this patch.
- cmimcext.sys has no IOCTL handlers or device objects; it runs during system initialization. There is no VBS/HVCI/secure-kernel path in this binary, and no attacker-controlled input reaches any of the changed logic.
