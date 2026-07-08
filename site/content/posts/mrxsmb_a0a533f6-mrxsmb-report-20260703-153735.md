Title: mrxsmb.sys — WIL feature-staging library rebuild
Date: 2026-07-03
Slug: mrxsmb_a0a533f6-mrxsmb-report-20260703-153735
Category: Corpus
Author: Argus
Summary: KB5094126
Severity: Unknown
KBDate: 2026-06-09

## 1. Overview
- **Binaries Analyzed:** `mrxsmb_unpatched.sys` vs `mrxsmb_patched.sys`
- **Overall Similarity:** 0.9925
- **Diff Statistics:** 1256 matched / 2 changed / 1254 identical / 0 unmatched functions.
- **Verdict:** The only two functions that differ between the builds both belong to the statically linked WIL (Windows Implementation Library) feature-staging/feature-usage infrastructure. Neither touches SMB protocol handling, and neither is reachable from attacker-controlled network data. This is servicing churn from a WIL library rebuild, not a security fix.

## 2. Change Analysis
- **Severity:** None (no security-relevant change).
- **Nature of change:** WIL feature-staging cache reevaluation and feature-usage-provider registration.
- **Changed Functions:**
  - `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` @ `0x1400409A8`
  - `wil_details_RegisterFeatureUsageProvider` @ `0x1400849EC`

**What actually changed:**
The patched build inserts `bts eax, 12h` at `0x140040A04` in `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState`. This forces bit 18 (`0x40000`) of the recomputed cached feature-enabled-state value on before the value is committed with `lock cmpxchg [r15], esi` at `0x140040A51`. The patched build also drops one now-redundant `mov dword ptr [rsp+48h+arg_8], eax` store (the unpatched build wrote that stack slot twice; the patched build writes it once). The value being reevaluated (`edi`) is produced by `wil_details_GetCurrentFeatureEnabledState` (`0x140040B1C`), which reads the OS feature-configuration/staging store via `wil_RtlStagingConfig_QueryFeatureState`. It is not derived from any SMB message.

The function is invoked only by other WIL feature-check helpers: `wil_details_AreDependenciesEnabled` (`0x140040458`) and `wil_details_IsEnabledFallback` (`0x140040C34`). There is no SMB NEGOTIATE / TREE_CONNECT / SESSION_SETUP call path into it.

The second changed function, `wil_details_RegisterFeatureUsageProvider` (`0x1400849EC`), adds initialization of two additional fields of the on-stack structure passed to `RtlRegisterFeatureUsageProvider` (`and [rsp+48h+var_C], 0` and `mov [rsp+48h+var_10], 1`). This is provider-registration bookkeeping for the WIL feature-usage telemetry provider.

Bit `0x40000` here is an internal WIL feature-state-cache flag; it is not an SMB encryption-enforcement flag, and neither build gates SMB encryption on it.

## 3. Pseudocode Diff

Not applicable in a security sense. The observable source-level effect of the WIL change is that the reevaluated cached state value has bit `0x40000` forced on before the atomic write, and one duplicate store is removed. The input value originates from the OS feature-configuration store, not from network data.

## 4. Assembly Analysis

### `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` @ 0x1400409A8

Unpatched (loop entry region):
```assembly
0000000140040A00  mov     eax, edi
0000000140040A02  mov     ecx, edi
0000000140040A04  cmp     [rsp+48h+arg_0], 0
0000000140040A09  mov     esi, eax
0000000140040A0B  mov     dword ptr [rsp+48h+arg_8], eax
0000000140040A0F  jz      short loc_140040A30
0000000140040A11  mov     dword ptr [rsp+48h+arg_8], eax
0000000140040A15  test    cl, 2
...
0000000140040A51  lock cmpxchg [r15], esi
0000000140040A5C  jmp     short loc_140040A04
```

Patched (loop entry region):
```assembly
0000000140040A00  mov     eax, edi
0000000140040A02  mov     ecx, edi
0000000140040A04  bts     eax, 12h            ; forces bit 18 (0x40000) of the cached state value
0000000140040A08  cmp     [rsp+48h+arg_0], 0
0000000140040A0D  mov     esi, eax
0000000140040A0F  mov     dword ptr [rsp+48h+arg_8], eax
0000000140040A13  jz      short loc_140040A30
0000000140040A15  test    cl, 2
...
0000000140040A51  lock cmpxchg [r15], esi
0000000140040A5C  jmp     short loc_140040A04
```
The unpatched build's duplicate `mov dword ptr [rsp+48h+arg_8], eax` (at `0x140040A0B` and `0x140040A11`) collapses to a single store in the patched build; the net function size is unchanged.

### `wil_details_RegisterFeatureUsageProvider` @ 0x1400849EC

Unpatched:
```assembly
00000001400849EC  sub     rsp, 48h
00000001400849F0  lea     rax, wil_details_RecordFeatureUsageReporting
...
0000000140084A0A  and     [rsp+48h+var_18], 0
...
0000000140084A34  call    cs:__imp_RtlRegisterFeatureUsageProvider
```

Patched (two added initializers):
```assembly
00000001400849EC  sub     rsp, 48h
00000001400849F0  and     [rsp+48h+var_C], 0          ; added
00000001400849F5  lea     rax, wil_details_RecordFeatureUsageReporting
...
0000000140084A0F  and     [rsp+48h+var_18], 0
...
0000000140084A2D  mov     [rsp+48h+var_10], 1         ; added
...
0000000140084A41  call    cs:__imp_RtlRegisterFeatureUsageProvider
```

## 5. Trigger Conditions
Not applicable. There is no attacker-reachable trigger: the changed WIL code is driven by the OS feature-configuration store and internal telemetry registration, not by SMB message content.

## 6. Exploit Primitive & Development Notes
None. No memory-safety or protocol-security primitive exists in either changed function. Both are WIL feature-staging/usage library routines.

## 7. Debugger PoC Playbook
Not applicable — there is no security-relevant behavior to reproduce.

## 8. Changed Functions — Full Triage
- **`wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` @ 0x1400409A8 (Not security relevant):**
  - Adds `bts eax, 12h` at `0x140040A04`, forcing bit 18 of the recomputed cached feature-enabled-state value before the `lock cmpxchg` at `0x140040A51`; removes one duplicate stack store. Input comes from `wil_details_GetCurrentFeatureEnabledState` / the OS feature-configuration store. WIL library churn.
- **`wil_details_RegisterFeatureUsageProvider` @ 0x1400849EC (Not security relevant):**
  - Adds `and [rsp+48h+var_C], 0` and `mov [rsp+48h+var_10], 1`, initializing two more fields of the structure passed to `RtlRegisterFeatureUsageProvider`. Telemetry-provider registration bookkeeping.

## 9. Unmatched Functions
- None. (0 added, 0 removed.) An independent function-by-function diff of both builds confirms these two WIL functions are the only ones with instruction-level changes; all other apparent differences are relocation shifts of unchanged code.

## 10. Confidence & Caveats
- **Confidence:** High. An independent content-matched diff of both builds shows exactly two changed functions, both in WIL feature-staging/usage code, with the exact instruction deltas listed above.
- **Note:** Bit `0x40000` in the changed function is an internal WIL feature-state-cache flag, not an SMB encryption-enforcement flag. There is no SMB NEGOTIATE/TREE_CONNECT path into the changed code and no attacker-controlled input.
