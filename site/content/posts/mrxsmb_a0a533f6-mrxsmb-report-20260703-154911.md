Title: mrxsmb.sys — No security-relevant change (WIL feature-staging library rebuild)
Date: 2026-07-03
Slug: mrxsmb_a0a533f6-mrxsmb-report-20260703-154911
Category: Corpus
Author: Argus
Summary: KB5094126
Severity: None

## 1. Overview
- **Unpatched Binary:** `mrxsmb_unpatched.sys`
- **Patched Binary:** `mrxsmb_patched.sys`
- **Overall Similarity Score:** 0.9925
- **Diff Statistics:** 1254 identical, 2 changed, 0 unmatched functions in both directions.
- **Verdict:** The two functions that differ both belong to the statically linked WIL (Windows Implementation Library) feature-staging/feature-usage infrastructure. Neither is part of SMB protocol handling and neither is reachable from attacker-controlled network input. This is a WIL library rebuild (servicing churn), not a security fix.

## 2. Change Analysis

### Changed code: WIL feature-staging infrastructure
- **Severity:** None (no security-relevant change).
- **Change Class:** Library rebuild / servicing churn (WIL feature-state cache + feature-usage provider registration).
- **Affected Functions:**
  - `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` @ `0x1400409A8`
  - `wil_details_RegisterFeatureUsageProvider` @ `0x1400849EC`
- **What changed:** In `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState`, the patched build inserts `bts eax, 12h` at `0x140040A04`, forcing bit 18 (`0x40000`) of the recomputed cached feature-enabled-state value on before the value is committed with `lock cmpxchg [r15], esi` at `0x140040A51`. A now-duplicate `mov dword ptr [rsp+48h+arg_8], eax` store is removed. The value being reevaluated (`edi`) is produced by `wil_details_GetCurrentFeatureEnabledState` (`0x140040B1C`), which reads the OS feature-configuration store via `wil_RtlStagingConfig_QueryFeatureState`; it is not derived from any SMB message. In `wil_details_RegisterFeatureUsageProvider`, the patched build adds two field initializers (`and [rsp+48h+var_C], 0` and `mov [rsp+48h+var_10], 1`) to the on-stack structure handed to `RtlRegisterFeatureUsageProvider`.
- **Reachability:** `wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` is called only by `wil_details_AreDependenciesEnabled` (`0x140040458`) and `wil_details_IsEnabledFallback` (`0x140040C34`) — WIL feature-check helpers. There is no SMB NEGOTIATE / SESSION_SETUP / TREE_CONNECT path into it.
- **Note:** Bit `0x40000` here is an internal WIL feature-state-cache flag; it is not an SMB encryption-enforcement flag, and neither build gates SMB encryption on it.

## 3. Pseudocode Diff

Not applicable in a security sense. The only source-level effect is that the reevaluated cached feature-state value has bit `0x40000` forced on before the atomic write, and one duplicate store is removed. The input value originates from the OS feature-configuration store, not the network.

## 4. Assembly Analysis

`wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState` @ `0x1400409A8`, loop-entry region.

Unpatched:
```assembly
0000000140040A00  mov     eax, edi
0000000140040A02  mov     ecx, edi
0000000140040A04  cmp     [rsp+48h+arg_0], 0
0000000140040A09  mov     esi, eax
0000000140040A0B  mov     dword ptr [rsp+48h+arg_8], eax
0000000140040A0F  jz      short loc_140040A30
0000000140040A11  mov     dword ptr [rsp+48h+arg_8], eax
0000000140040A15  test    cl, 2
0000000140040A1A  and     esi, 0FFFFF63Eh
0000000140040A20  mov     eax, ebx
0000000140040A22  and     eax, 9C1h
0000000140040A27  or      esi, eax
0000000140040A29  or      esi, 2
0000000140040A2C  mov     dword ptr [rsp+48h+arg_8], esi
0000000140040A30  test    dil, 4
...
0000000140040A51  lock cmpxchg [r15], esi
0000000140040A56  jz      short loc_140040A5E
0000000140040A5C  jmp     short loc_140040A04
```

Patched (adds `bts eax, 12h`, drops the duplicate store at former `0x140040A11`):
```assembly
0000000140040A00  mov     eax, edi
0000000140040A02  mov     ecx, edi
0000000140040A04  bts     eax, 12h            ; forces bit 18 (0x40000) of the cached state value
0000000140040A08  cmp     [rsp+48h+arg_0], 0
0000000140040A0D  mov     esi, eax
0000000140040A0F  mov     dword ptr [rsp+48h+arg_8], eax
0000000140040A13  jz      short loc_140040A30
0000000140040A15  test    cl, 2
0000000140040A1A  and     esi, 0FFFFF63Eh
0000000140040A20  mov     eax, ebx
0000000140040A22  and     eax, 9C1h
0000000140040A27  or      esi, eax
0000000140040A29  or      esi, 2
0000000140040A2C  mov     dword ptr [rsp+48h+arg_8], esi
0000000140040A30  test    dil, 4
...
0000000140040A51  lock cmpxchg [r15], esi
0000000140040A56  jz      short loc_140040A5E
0000000140040A5C  jmp     short loc_140040A04
```

`wil_details_RegisterFeatureUsageProvider` @ `0x1400849EC` — two added stack-field initializers:
```assembly
; PATCHED adds:
00000001400849F0  and     [rsp+48h+var_C], 0
0000000140084A2D  mov     [rsp+48h+var_10], 1
; before:
0000000140084A41  call    cs:__imp_RtlRegisterFeatureUsageProvider
```

## 5. Trigger Conditions
Not applicable. The changed WIL code is driven by the OS feature-configuration store and internal telemetry registration, not by SMB message content. There is no attacker-reachable trigger.

## 6. Exploit Primitive & Development Notes
None. Neither changed function exposes a memory-safety or protocol-security primitive.

## 7. Debugger PoC Playbook
Not applicable — there is no security-relevant behavior to reproduce.

## 8. Changed Functions — Full Triage
- **`wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState`** @ `0x1400409A8` (Similarity: 0.9887):
  - **Change:** Adds `bts eax, 12h` at `0x140040A04`, forcing bit 18 of the recomputed cached feature-enabled-state value before the `lock cmpxchg` at `0x140040A51`; removes one duplicate stack store.
  - **Note:** WIL feature-staging library churn. Input comes from the OS feature-configuration store, not the network. Not security relevant.
- **`wil_details_RegisterFeatureUsageProvider`** @ `0x1400849EC` (Similarity: 0.976):
  - **Change:** Adds `and [rsp+48h+var_C], 0` and `mov [rsp+48h+var_10], 1`, initializing two more fields of the structure passed to `RtlRegisterFeatureUsageProvider`.
  - **Note:** Feature-usage-provider registration bookkeeping. Not security relevant.

## 9. Unmatched Functions
- **None.** (0 added, 0 removed.) An independent function-by-function diff confirms these two WIL functions are the only ones with instruction-level changes; every other difference is a relocation shift of otherwise-identical code.

## 10. Confidence & Caveats
- **Confidence Level:** High. An independent content-matched diff of both builds shows exactly two changed functions, both WIL feature-staging/usage routines, with the instruction deltas listed above.
- **Note:** Bit `0x40000` in the changed function is an internal WIL feature-state-cache flag, not an SMB encryption-enforcement flag. No SMB NEGOTIATE/SESSION_SETUP/TREE_CONNECT path reaches the changed code, and there is no attacker-controlled input.
