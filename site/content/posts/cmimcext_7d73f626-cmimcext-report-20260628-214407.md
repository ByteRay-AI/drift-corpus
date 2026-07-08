Title: cmimcext.sys — WIL feature-staging library churn, pool-API modernization, and a feature-gated rollout
Date: 2026-06-28
Slug: cmimcext_7d73f626-cmimcext-report-20260628-214407
Category: Corpus
Author: Argus
Summary: KB5082142
Severity: Unknown
KBDate: 2026-04-14

### 1. Overview

- **Unpatched Binary:** `cmimcext_unpatched.sys`
- **Patched Binary:** `cmimcext_patched.sys`
- **Overall Similarity Score:** `0.7993`
- **Diff Statistics:** 55 matched functions (21 identical, 34 changed), 0 unmatched functions in either direction.
- **Verdict:** The diff is dominated by a rebuild against a newer Windows feature-staging (WIL) library plus routine pool-API modernization. The feature-usage/reporting helpers changed from reading module-global state to receiving a context pointer, the one-time staging initializer gained a standard init guard and a new usage-provider registration, and every `ExAllocatePoolWithTag` was replaced by `ExAllocatePool2`. The only Configuration-Manager behavioral change is a new runtime feature-staging killswitch (`Feature_ImcL`) that gates pre-existing migration paths; the old paths remain in the binary. None of these is an unconditionally-delivered, attacker-reachable security fix. There is no genuine race-condition fix and no re-entrancy/pool-corruption fix.

---

### 2. Vulnerability Summary

#### Finding 1: Feature-usage reporting refactored from module-global state to a context pointer
- **Severity:** None (No security-relevant change)
- **Vulnerability Class:** Not applicable (library refactor / WIL feature-staging churn)
- **Affected Function:** `wil_details_FeatureReporting_ReportUsageToServiceDirect` (unpatched `0x1C00016D4` → patched `0x1400018DC`) and `wil_details_FeatureReporting_RecordUsageInCache` (`0x1C00013FC`) → `wil_details_FeatureReporting_IncrementUsageInCache` (`0x1400016BC`).

**What actually changed:**
These are Windows Implementation Library (WIL) feature-usage-reporting helpers. In the unpatched build, `wil_details_FeatureReporting_ReportUsageToServiceDirect` reads the WIL feature-property cache through the module-global `off_1C00038F8` and reads the set-once reporting callback `g_wil_details_recordFeatureUsage` (`0x1C0001728`) before dispatching through `__guard_dispatch_icall_fptr` and calling `RtlNotifyFeatureUsage`. In the patched build the equivalent helper receives its state through a caller-supplied context pointer (`[rcx+8]`) instead of reading `off_1C00038F8`.

This is a WIL library-version difference, not a synchronization fix. Several observations rule out the claimed race:

- The reporting path is WIL feature-usage telemetry that runs at `PASSIVE_LEVEL`; there is no demonstrated attacker-controlled concurrency between two writers of the same state.
- `g_wil_details_recordFeatureUsage` is a function pointer initialized once during staging init (the patched `wil_InitializeFeatureStaging` sets it at `0x14000CC70` to `wil_details_RecordFeatureUsageReporting`) and it is still read as a module-global in the patched build. A "fix" that eliminated a racing global would not leave the same global read in place.
- The per-dword `lock cmpxchg` in the cache helper is WIL's normal in-place feature-state update, present in both builds.

There is no demonstrable reachable impact from this refactor.

#### Finding 2: One-time staging-init guard and a new usage-provider registration
- **Severity:** None (No security-relevant change)
- **Vulnerability Class:** Not applicable (WIL one-time-init pattern / library churn)
- **Affected Function:** `wil_InitializeFeatureStaging` (unpatched `0x1C000B008` → patched `0x14000CB94`).

**What actually changed:**
The patched `wil_InitializeFeatureStaging` adds a standard one-time-init guard (`g_wil_details_isFeatureStagingInitialized`, checked at `0x14000CBAA` and set at `0x14000CBB8`) and, when it runs, additionally calls `RtlRegisterFeatureUsageProvider` (`0x14000CCB4`) - a new WIL telemetry surface that did not exist in the unpatched library. `CmCompleteInitMachineConfig` in the patched build adds the symmetric `RtlUnregisterFeatureUsageProvider` teardown and clears the init flag.

This is the newer WIL library's standard initialization shape, not a security fix. In both builds the function only calls `RtlQueryFeatureConfigurationChangeStamp`, `wil_details_PopulateInitialConfiguredFeatureStates`, `wil_details_EvaluateFeatureDependencies`, and conditionally `RtlRegisterFeatureConfigurationChangeNotification` (registration is skipped when no feature descriptor requests change notification). It allocates nothing and touches no linked list. There is no `ImpAddAllowListEvent` call and no notification-node list in this function in either build, so there is no double-registration pool-corruption primitive.

---

### 3. Pseudocode Diff

Below is the observed structure of the reporting helper and the staging initializer.

```c
// --- UNPATCHED wil_details_FeatureReporting_ReportUsageToServiceDirect @ 0x1C00016D4 ---
// Reads the WIL feature-property cache via a module-global; runs at PASSIVE_LEVEL telemetry.
void ReportUsageToServiceDirect(uint64_t feature_config_val, uint32_t subtype) {
    uint32_t change_type = feature_config_val >> 32;
    void* feature_cache = off_1C00038F8;                       // module-global WIL cache
    result = RecordUsageInCache(&local, feature_cache, subtype, change_type);
    void* record = g_wil_details_recordFeatureUsage;           // set-once callback pointer
    if (record)
        __guard_dispatch_icall(record, 0x3A6CBA9, subtype, 1, feature_cache, &local);
    // RtlNotifyFeatureUsage(...) path for certain flag bits
}

// --- PATCHED wil_details_FeatureReporting_ReportUsageToServiceDirect @ 0x1400018DC ---
// Newer WIL: state arrives through a caller-supplied context pointer instead of the global.
void ReportUsageToServiceDirect(void* ctx, ...) {
    void* state = *(ctx + 8);                                  // context-supplied, not off_1C00038F8
    IncrementUsageInCache(state, ...);
    // g_wil_details_recordFeatureUsage is STILL read as a module-global in this build
}
```

```c
// --- UNPATCHED wil_InitializeFeatureStaging @ 0x1C000B008 ---
void wil_InitializeFeatureStaging() {
    stamp = RtlQueryFeatureConfigurationChangeStamp();
    wil_details_PopulateInitialConfiguredFeatureStates();
    wil_details_EvaluateFeatureDependencies();
    // registers ONLY if a feature descriptor requests change notification
    if (any_descriptor_wants_notification)
        RtlRegisterFeatureConfigurationChangeNotification(
            wil_details_ReevaluateOnFeatureConfigurationChange, 0, &stamp,
            &wil_details_featureChangeNotification);
}

// --- PATCHED wil_InitializeFeatureStaging @ 0x14000CB94 ---
void wil_InitializeFeatureStaging() {
    if (g_wil_details_isFeatureStagingInitialized)             // standard one-time-init guard
        return;
    g_wil_details_isFeatureStagingInitialized = 1;
    stamp = RtlQueryFeatureConfigurationChangeStamp();
    wil_details_PopulateInitialConfiguredFeatureStates();
    wil_details_EvaluateFeatureDependencies();
    if (any_descriptor_wants_notification)
        RtlRegisterFeatureConfigurationChangeNotification(...);
    g_wil_details_recordFeatureUsage = wil_details_RecordFeatureUsageReporting;
    RtlRegisterFeatureUsageProvider(...);                      // new WIL telemetry surface
}
```

---

### 4. Assembly Analysis

The unpatched reporting helper, showing the module-global reads that the newer library replaces with a context pointer. These are real instructions from `wil_details_FeatureReporting_ReportUsageToServiceDirect @ 0x1C00016D4` in `cmimcext_unpatched.asm`.

```assembly
; ---- wil_details_FeatureReporting_ReportUsageToServiceDirect @ 0x1C00016D4 (unpatched) ----
00000001C00016F7  mov     r9, rdx
00000001C00016FA  lea     rcx, [rbp+var_38]
00000001C00016FE  mov     rbx, rdx
00000001C0001701  shr     r9, 20h
00000001C0001705  mov     rdx, cs:off_1C00038F8            ; module-global WIL feature cache
00000001C000170C  mov     esi, r8d
00000001C000170F  call    wil_details_FeatureReporting_RecordUsageInCache
00000001C0001714  xor     edi, edi
00000001C0001716  mov     r14d, 1
00000001C000171C  movups  xmm1, xmmword ptr [rax]
00000001C000171F  movups  [rbp+var_20], xmm1
00000001C0001723  movsd   xmm0, qword ptr [rax+10h]
00000001C0001728  mov     rax, cs:g_wil_details_recordFeatureUsage  ; set-once callback pointer
00000001C000172F  movsd   [rbp+var_10], xmm0
00000001C0001734  test    rax, rax
00000001C0001737  jz      short loc_1C0001759
00000001C0001739  mov     r9, cs:off_1C00038F8            ; same module-global cache
00000001C0001740  lea     rcx, [rbp+var_20]
00000001C000174C  mov     ecx, 3A6CBA9h
00000001C0001751  mov     edx, esi
00000001C0001753  call    cs:__guard_dispatch_icall_fptr  ; CFG-checked dispatch of set-once callback
```

The patched staging initializer, showing the one-time-init guard and the new usage-provider registration. Real instructions from `wil_InitializeFeatureStaging @ 0x14000CB94` in `cmimcext_patched.asm`.

```assembly
; ---- wil_InitializeFeatureStaging @ 0x14000CB94 (patched) ----
000000014000CBAA  cmp     cs:g_wil_details_isFeatureStagingInitialized, esi   ; esi = 0
000000014000CBB2  jnz     loc_14000CCD2                                       ; already initialized -> return
000000014000CBB8  mov     cs:g_wil_details_isFeatureStagingInitialized, 1
...
000000014000CC47  call    cs:__imp_RtlRegisterFeatureConfigurationChangeNotification
000000014000CC70  mov     cs:g_wil_details_recordFeatureUsage, rax            ; set-once callback pointer
000000014000CCB4  call    cs:__imp_RtlRegisterFeatureUsageProvider            ; new WIL telemetry surface
```

The new Configuration-Manager feature gate. Real instructions from `CmSetInitMachineConfig @ 0x14000C080` in `cmimcext_patched.asm`.

```assembly
000000014000C11B  call    wil_InitializeFeatureStaging
000000014000C120  call    Feature_ImcL__private_IsEnabledDeviceUsageNoInline  ; new runtime feature gate
000000014000C125  test    eax, eax
000000014000C127  jnz     short loc_14000C131                                 ; feature ON -> take path directly
000000014000C129  test    esi, esi                                           ; feature OFF -> pre-existing Hyper-V-count gate
000000014000C12B  jnz     loc_14000C314
```

---

### 5. Trigger Conditions

`cmimcext.sys` (Configuration Manager Initial Machine Config extension) is a boot-time driver. `CmSetInitMachineConfig` runs once during system initialization to migrate content from `\REGISTRY\MACHINE\INITIALMACHINECONFIG`; `CmCompleteInitMachineConfig` performs the matching teardown. The feature-usage-reporting and staging-init code examined above is WIL library plumbing invoked from that single boot-time path.

No attacker-reachable trigger for a race, double-registration, or pool corruption was identified:

- The reporting helpers run at `PASSIVE_LEVEL` and the touched globals are a feature-property cache and a set-once callback pointer, not a two-writer shared structure with demonstrated concurrent mutation.
- `wil_InitializeFeatureStaging` is guarded by `g_wil_details_isFeatureStagingInitialized` in the patched build, but the unpatched function still performs no allocation and no list insertion, so there is nothing to corrupt on re-entry.
- The `Feature_ImcL` gate only selects between an already-present code path and the pre-existing Hyper-V-partition-count gate; both paths exist in the binary and are chosen at runtime by the feature-configuration state.

---

### 6. Exploit Primitive & Development Notes

No exploit primitive is supported by the binaries.

- There is no linked-list insertion in `wil_InitializeFeatureStaging`, so no notification-node list-corruption or write-what-where primitive exists. `ImpAddAllowListEvent` is not called from that function in either build.
- `g_wil_details_recordFeatureUsage` is initialized once and is dispatched through `__guard_dispatch_icall_fptr` (CFG-checked); it is not an attacker-mutated pointer and it remains a module-global in the patched build.
- The `ExAllocatePoolWithTag → ExAllocatePool2` migration (all 7 tagged allocations in the unpatched build replaced; the patched build has 0 `ExAllocatePoolWithTag` and 12 `ExAllocatePool2` sites) is routine pool-API modernization that yields zeroed non-paged pool. It changes no size or bounds logic.

---

### 7. Debugger Notes

For anyone wishing to observe the WIL staging flow in a kernel debugger attached to the unpatched build, the relevant single-boot entry points are:

```text
bp cmimcext_unpatched!wil_InitializeFeatureStaging                 // 0x1C000B008 - one-time staging init
bp cmimcext_unpatched!wil_details_FeatureReporting_ReportUsageToServiceDirect  // 0x1C00016D4 - usage reporting helper
```

Observations expected on this path:

- `wil_InitializeFeatureStaging` is reached from the single boot-time `CmSetInitMachineConfig` call site; it performs no allocation and inserts nothing into a list.
- `off_1C00038F8` and `g_wil_details_recordFeatureUsage` are read on the reporting path; the callback pointer is written once during init and dispatched via CFG.

#### Key Instructions/Offsets
- `0x1C0001705: mov rdx, cs:off_1C00038F8` - read of the WIL feature-property cache (module-global in unpatched; context-supplied in patched).
- `0x1C0001728: mov rax, cs:g_wil_details_recordFeatureUsage` - read of the set-once reporting callback pointer.
- `0x14000CBAA: cmp cs:g_wil_details_isFeatureStagingInitialized, esi` - patched one-time-init guard.
- `0x14000C120: call Feature_ImcL__private_IsEnabledDeviceUsageNoInline` - new runtime feature gate in `CmSetInitMachineConfig`.

---

### 8. Changed Functions - Full Triage

The patch is dominated by WIL library churn and pool-API modernization. No changed function delivers an unconditional, attacker-reachable security fix.

**Behavioral (library refactor / feature-staging, not security fixes):**
- `wil_details_FeatureReporting_RecordUsageInCache (0x1C00013FC) → wil_details_FeatureReporting_IncrementUsageInCache (0x1400016BC)`: WIL usage-cache helper; state source changed from a module-global to a caller-supplied pointer. Newer library shape.
- `wil_details_FeatureReporting_ReportUsageToServiceDirect (0x1C00016D4) → (0x1400018DC)`: reads state from context instead of `off_1C00038F8`; `g_wil_details_recordFeatureUsage` remains a module-global read.
- `wil_InitializeFeatureStaging (0x1C000B008) → (0x14000CB94)`: adds one-time-init guard `g_wil_details_isFeatureStagingInitialized` and a new `RtlRegisterFeatureUsageProvider` registration. No allocation, no list insertion in either build.
- `wil_details_EvaluateFeatureDependencies (0x1C0008138) → (0x14000A0B4)`, `wil_details_EvaluateFeatureDependencies_GetCachedFeatureEnabledState (0x1C0008224) → wil_details_EvaluateFeatureDependencies_ReevaluateCachedFeatureEnabledState (0x14000A204)`, `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState (0x1C00018E0) → (0x140001B04)`, `wil_details_IsEnabledFallback (0x1C0001B30) → (0x140001E18)`, `wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath (0x1C0001BBC) → (0x140001DBC)`, `wil_details_FeatureReporting_ReportUsageToService (0x1C00017C4) → (0x1400017B0)`: the same context-pointer threading through the WIL feature-evaluation/reporting tree.
- `CmSetInitMachineConfig (0x1C000B220 → 0x14000C080)`: adds the `Feature_ImcL__private_IsEnabledDeviceUsageNoInline` runtime gate at multiple branch points (`0x14000C120`, `0x14000C2BF`, `0x14000C469`, `0x14000C4AC`, `0x14000C51A`, `0x14000C58D`, `0x14000C5E1`) that select between a code path and the pre-existing Hyper-V-partition-count gate. Feature-staged rollout; old paths retained. The core registry open/query/set logic is preserved.
- `CmCompleteInitMachineConfig (0x1C0008320 → 0x140009010)`: adds `RtlUnregisterFeatureUsageProvider` teardown and clears `g_wil_details_isFeatureStagingInitialized`, balancing the new registration; also gates its cleanup loop behind `Feature_ImcL`. The `Feature_Servicing_IMCMemoryCorruptionFix` gate is called here in BOTH builds (unpatched `0x1C0008358`, patched `0x140009055`) and is unchanged between them.

**Cosmetic / modernization / register allocation:**
- Pool-API migration `ExAllocatePoolWithTag(NonPagedPoolNx) → ExAllocatePool2(POOL_FLAG_NON_PAGED)` across `ImpCopyKeyValues (0x1C0008B7C → 0x1400096F4)`, `ImpEstablishNamedSubkey (0x1C0008DD0 → 0x140009954)`, `ImpUnloadImcHive (0x1C0008614 → 0x140009EF0)`, `ImpGetObjectSecurityDescriptorByHandle (0x1C0009090 → 0x140009C20)`, `ImpGetSubkeyByIndex (0x1C00091CC → 0x140009D68)`, `ImpAddAllowListEvent (0x1C000BB74 → 0x14000CE80)`, `ImpEstablishIMCPolicies (0x1C000B7E8 → 0x14000C66C)`, `ImpApplyMachineConfiguration (0x1C00087E4 → 0x14000935C)`. Buffer-growth, bounds, and copy logic are unchanged (e.g. `ImpEstablishNamedSubkey`'s `rdx-1 > 0xFFFFFFFD` is the same test as `!rdx || rdx == 0xFFFFFFFF`).
- `__cpu_features_init (0x1C0001E10 → 0x1400021E0)`: CPUID detection reordered; logic equivalent.
- `HviIsAnyHypervisorPresent (0x1C0001C50 → 0x140002094)`, `HviIsHypervisorMicrosoftCompatible (0x1C0001CAC → 0x1400020D4)`: `__security_cookie` removed from leaf functions with no local buffer.
- `ImpReadImcHiveDword (0x1C000BAE4 → 0x14000C960)`, `ImpGetRegValueSz (0x1C000BCE0 → 0x14000D000)`, `ImpSetRegValue (0x1C000BEB4 → 0x14000D45C)`, `ImpValidatePagingFiles (0x1C000C128 → 0x14000D5E4)`, `McGenControlCallbackV2 (0x1C0001010 → 0x1400011E0)`, `wil_details_ReevaluateOnFeatureConfigurationChange (0x1C0008010 → 0x14000A3A0)`, `wil_details_PopulateInitialConfiguredFeatureStates (0x1C000B0B4 → 0x14000CCF0)`, `__GSHandlerCheckCommon (0x1C0001D9C → 0x14000215C)`: register allocation / structure-init reordering; validation logic preserved.

---

### 9. Unmatched Functions

**Removed:** `0`
**Added:** `0`

The patch is entirely in-place modernization and feature-staging; no functional module was added or removed.

---

### 10. Confidence & Caveats

- **Confidence Level:** **High** that there is no delivered, attacker-reachable security fix in this diff. The reporting-helper change is a WIL context-pointer refactor with the reporting callback still read as a global in the patched build; the staging-init change is a standard one-time-init guard plus a new usage-provider registration; the Configuration-Manager change is a runtime feature-staging killswitch (`Feature_ImcL`) selecting among paths that all remain present.
- **Notable:** The presence of a WIL feature flag named `Feature_Servicing_IMCMemoryCorruptionFix` (in BOTH builds, with an unchanged call site in `CmCompleteInitMachineConfig`) indicates a memory-corruption servicing fix exists somewhere in the servicing pipeline, but it is not delivered unconditionally in this binary diff - it is gated by runtime feature-configuration state, and its gated behavior does not differ between the two builds examined here.
- **Caveat:** Because `Feature_ImcL` and `IMCMemoryCorruptionFix` are runtime feature-staging gates, the effective behavior depends on feature-configuration state that is not visible in the static binaries. If a future rollout hard-enables one of these gates, the gated path should be re-examined at that time.
