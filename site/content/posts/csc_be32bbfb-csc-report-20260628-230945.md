Title: csc.sys — WIL feature-staging gate graduated to unconditional NULL check
Date: 2026-03-10
Slug: csc_be32bbfb-csc-report-20260628-230945
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Unknown
KBDate: 2026-03-10

## 1. Overview

| | |
|---|---|
| **Unpatched binary** | `csc_unpatched.sys` (Windows Offline Files / Client-Side Caching mini-redirector) |
| **Patched binary** | `csc_patched.sys` |
| **Overall similarity** | 0.992 |
| **Matched functions** | 1398 |
| **Changed functions** | 1 |
| **Identical functions** | 1397 |
| **Unmatched (either direction)** | 0 / 0 |

**Verdict:** The only functional change is in the transition handler `CscDclMRxTransition` (`0x1C005CBA4`, source file `base\fs\remotefs\rdr\csc\driver\dclmrx.c`). In the unpatched build a NULL check on a logical-view (LView) pointer is AND-gated behind a WIL feature-staging evaluation (`EvaluateCurrentState`, `0x1C0007440`); the patch removes that gate at both guard sites so the NULL check is unconditional. This is the graduation of a runtime feature flag into permanently-baked-in code (defense-in-depth), not a fix for an attacker-reachable vulnerability. The feature evaluation resolves to "skip the check" only when the WIL feature is in the **disabled** state, which is a vendor/cloud-flighting-controlled configuration, not the default and not attacker-controlled. In the default (feature-enabled) configuration both builds perform the NULL check identically. Even in the disabled-feature state the only possible outcome is a kernel NULL-pointer dereference bug check (local denial of service); NULL-page mapping is blocked on modern Windows, so there is no memory-corruption or code-execution primitive.

---

## 2. Change Summary

| Item | Value |
|---|---|
| **Severity** | None (defense-in-depth hardening; not attacker-reachable in default configuration) |
| **Weakness class touched** | NULL Pointer Dereference (CWE-476) — kernel-mode |
| **Affected function** | `CscDclMRxTransition` (`0x1C005CBA4`) |
| **Nature of change** | A feature-gated NULL check is made unconditional (WIL staging gate removed) |
| **Worst-case impact if feature disabled** | Kernel NULL dereference → bug check (local DoS). No controlled data, no escalation. |

### What actually changed

The handler loads a logical-view (LView) pointer that can legitimately be NULL:

```
v8 = a1->Header.FilterContexts.Flink[7].Flink     ; asm: mov rax,[rcx+38h]; mov rdi,[rax+70h]
```

A defensive NULL check on `v8` (`rdi`) exists in **both** builds. In the unpatched build it is AND-combined with a WIL feature-staging evaluation. The prologue error-exit guard reads:

```
if ( (a2 - 1) > 2 || EvaluateCurrentState() && v8 == 0 )   // take STATUS_INVALID_PARAMETER (0xC000000D) exit
```

where `EvaluateCurrentState()` (`0x1C0007440`) is a WIL feature helper:

```c
_BOOL8 EvaluateCurrentState()
{
  EvaluateFeature(&g_Feature_4283659579_58821281_FeatureDescriptorDetails);   // 0x1C00074EC
  return g_Feature_4283659579_58821281_cachedstate != 1;
}
```

The cached state is populated by the standard WIL flighting/registry-override machinery (`EvaluateFeature` → `EvaluateCurrentStateFromRegistry` → `QueryFeatureOverride`). `EvaluateFeature` stores `EvaluateCurrentStateFromRegistry(...) + 1` into the cached state, so the value is **2 when the feature resolves to enabled** and **1 when it resolves to disabled**. Therefore `EvaluateCurrentState()` returns:

- **true** when the feature is enabled (or default-resolves to enabled) — the NULL check runs.
- **false** only when the feature is explicitly **disabled** (cached state == 1) — the `v8 == 0` term is dropped and the NULL check is skipped.

Consequence in the unpatched build: only if the WIL feature is in the disabled state does execution fall through to `CscAcquireLViewLock(v8)` (`0x1C000BD78`) with `v8 == NULL`, causing a NULL dereference and a kernel bug check.

The patch removes the `EvaluateCurrentState()` gate at both guard sites, so the NULL check is unconditional:

```
if ( (a2 - 1) > 2 || v8 == 0 )   // prologue: v8 always checked
...
if ( v8 != 0 )                    // epilogue: v8 always checked
    CscFlushLViewWasPreviouslyOffline(v8);
```

This is a WIL feature-staging graduation: the NULL check already existed in the unpatched build and is active in the default configuration; the patch removes the runtime toggle so the check can no longer be turned off by feature flighting.

### Why this is not rated as a delivered security fix

- The feature state that skips the NULL check (disabled) is set by Microsoft's feature-flighting / registry-override infrastructure, not by an attacker. It is not the default configuration.
- In the default (feature-enabled) configuration the NULL check is present and active in **both** builds; there is no behavioral difference an attacker can reach.
- Even in the disabled-feature state, the only outcome is a NULL-pointer dereference bug check (local DoS). The dereferenced object's callees read fixed small offsets (`+0x30`, `+0x38`); there is no controlled data at address 0, no info leak, and no code-execution primitive on modern Windows where NULL-page mapping is blocked.

### Reachability of the handler

1. User-mode caller invokes `DeviceIoControl` / `NtDeviceIoControlFile` on the CSC device object (or via the Offline Files user-mode surface).
2. The FSCTL reaches the dispatch registered by `DriverEntry` → `CscInitializeDispatchTable` (`0x1C008E4E0`).
3. FSCTL router → `CscFsCtl` (`0x1C0049860`).
4. Internal FSCTL wrapper → `CscDclInternalFsControl` (`0x1C0049A10`).
5. Transition handler → `CscDclMRxTransition` (`0x1C005CBA4`).

The precise device DACL / non-admin reachability and the exact context state that yields `v8 == NULL` were not established from the binaries alone (see Section 10).

---

## 3. Pseudocode Diff

**Unpatched:**

```c
__int64 CscDclMRxTransition(struct _MRX_FCB_ *a1, int a2, ...)
{
    Flink = a1->Header.FilterContexts.Flink;
    v8 = Flink[7].Flink;                    // logical-view pointer, can be NULL
    CscGetContexts(a1, v39);

    // v8==0 check is AND-gated behind the WIL feature evaluation.
    // Skipped only when the feature is disabled (EvaluateCurrentState()==0).
    if ( (unsigned int)(a2 - 1) > 2 || EvaluateCurrentState() && v8 == 0 )
    {
        v9 = 0xC000000D; goto LABEL_70;     // STATUS_INVALID_PARAMETER
    }
    CscAcquireLViewLock(v8);                 // v8==NULL reachable only if feature disabled (0x1C000BD78)
    IsRootGhosted = CscLViewIsRootGhosted(v8);   // 0x1C00621B4
    CscReleaseLViewLock(v8);                 // 0x1C000BEEC
    ...
    // Second occurrence near epilogue, same gate:
    if ( !EvaluateCurrentState() || v8 != 0 )
        CscFlushLViewWasPreviouslyOffline(v8);   // 0x1C0061EEC
}
```

**Patched:**

```c
__int64 CscDclMRxTransition(struct _MRX_FCB_ *a1, int a2, ...)
{
    Flink = a1->Header.FilterContexts.Flink;
    v8 = Flink[7].Flink;
    CscGetContexts(a1, v39);

    if ( (unsigned int)(a2 - 1) > 2 || v8 == 0 )   // NULL check now unconditional
    {
        v9 = 0xC000000D; goto LABEL_69;
    }
    CscAcquireLViewLock(v8);                 // v8 guaranteed non-NULL
    ...
    if ( v8 != 0 )                           // epilogue: unconditional check
        CscFlushLViewWasPreviouslyOffline(v8);
}
```

Key point: the WIL feature helper `EvaluateCurrentState` (`0x1C0007440`, which reads `g_Feature_4283659579_58821281_cachedstate`) is removed from both guard sites, so the NULL check on `v8` is no longer gated by a runtime feature state.

---

## 4. Assembly Analysis

### Unpatched prologue

```asm
; rcx = a1 (RX_CONTEXT/FCB), r13d = a2 (sub-operation), rdi = v8 (logical-view pointer)
0x1C005CBFF:  lea     ecx, [r13-1]              ; ecx = a2 - 1
0x1C005CC0A:  cmp     ecx, 2
0x1C005CC0D:  jbe     loc_1C005CC19             ; a2 ∈ {1,2,3}?
0x1C005CC0F:  mov     esi, 0C000000Dh           ; STATUS_INVALID_PARAMETER
0x1C005CC14:  jmp     loc_1C005D174             ; error exit
0x1C005CC19:  call    EvaluateCurrentState      ; WIL feature-state evaluation (0x1C0007440)
0x1C005CC1E:  test    eax, eax                  ; eax = 0 only when feature disabled (cachedstate == 1)
0x1C005CC20:  jz      loc_1C005CC27             ; feature disabled → skip rdi NULL check
0x1C005CC22:  test    rdi, rdi                  ; NULL check, taken when feature enabled
0x1C005CC25:  jz      loc_1C005CC0F             ; NULL → error exit
0x1C005CC27:  mov     rcx, rdi                  ; rdi (v8) can be NULL here only if feature disabled
0x1C005CC2A:  call    CscAcquireLViewLock       ; 0x1C000BD78
0x1C005CC2F:  mov     rcx, rdi
0x1C005CC32:  call    CscLViewIsRootGhosted     ; 0x1C00621B4
```

### Unpatched epilogue (second gated NULL check)

```asm
0x1C005D181:  call    EvaluateCurrentState      ; same feature gate
0x1C005D186:  test    eax, eax
0x1C005D188:  jz      loc_1C005D18F             ; feature disabled → skip NULL check
0x1C005D18A:  test    rdi, rdi
0x1C005D18D:  jz      loc_1C005D197
0x1C005D18F:  mov     rcx, rdi
0x1C005D192:  call    CscFlushLViewWasPreviouslyOffline   ; 0x1C0061EEC
```

### Patched prologue

```asm
0x1C005CC0D:  jbe     loc_1C005CC19
0x1C005CC0F:  mov     esi, 0C000000Dh           ; STATUS_INVALID_PARAMETER
0x1C005CC14:  jmp     loc_1C005D16B
0x1C005CC19:  test    rdi, rdi                  ; UNCONDITIONAL NULL check (feature gate removed)
0x1C005CC1C:  jz      loc_1C005CC0F             ; NULL → error exit
0x1C005CC1E:  mov     rcx, rdi
0x1C005CC21:  call    CscAcquireLViewLock       ; rdi guaranteed non-NULL
```

### Patched epilogue

```asm
0x1C005D178:  test    rdi, rdi                  ; UNCONDITIONAL NULL check
0x1C005D17B:  jz      loc_1C005D185
0x1C005D17D:  mov     rcx, rdi
0x1C005D180:  call    CscFlushLViewWasPreviouslyOffline
```

### `EvaluateCurrentState` (`0x1C0007440`)

```asm
0x1C0007444:  lea     rcx, g_Feature_4283659579_58821281_FeatureDescriptorDetails
0x1C000744B:  call    EvaluateFeature           ; 0x1C00074EC (WIL flighting evaluation)
0x1C0007450:  mov     rax, cs:g_Feature_4283659579_58821281_FeatureDescriptorDetails
0x1C0007457:  mov     ecx, [rax]                ; cached state
0x1C000745B:  cmp     ecx, 1                    ; == 1 means feature disabled
0x1C000745E:  setnz   al                        ; return (cachedstate != 1)
0x1C0007465:  retn
```

`EvaluateFeature` (`0x1C00074EC`) stores `EvaluateCurrentStateFromRegistry(...) + 1` into the cached state (2 = enabled, 1 = disabled), confirming that `EvaluateCurrentState()` returns false only when the feature is disabled. The patch removes both call sites; combined with the unconditional `test rdi, rdi`, the NULL check no longer depends on any feature state.

---

## 5. Conditions for the (feature-disabled-only) crash

1. **The WIL feature must be disabled.** `g_Feature_4283659579_58821281_cachedstate` must equal `1`, which occurs only when the feature resolves to disabled through flighting/registry override. This is not the default configuration and is not attacker-controlled.
2. **Reach the handler.** Obtain a handle to the CSC device and issue the transition FSCTL sub-operation with `a2 ∈ {1, 2, 3}` (so `(a2 - 1) <= 2`).
3. **Drive the logical-view pointer to NULL.** `v8 = *(*(RX_CONTEXT + 0x38) + 0x70)` must be NULL, which requires the associated FCB/context to have no logical view allocated for the object being transitioned. The exact state that produces this was not confirmed from the binaries.
4. **Observable effect.** If all of the above hold, the unpatched build dereferences NULL at or inside `CscAcquireLViewLock` (faulting near address `0x0`, or small offsets like `+0x30`/`+0x38` inside the callees), producing a kernel bug check. In the patched build, or in the default (feature-enabled) configuration of the unpatched build, the NULL check returns `STATUS_INVALID_PARAMETER (0xC000000D)` instead.

None of these conditions are reachable in the default configuration, because with the feature enabled the NULL check is active in both builds.

---

## 6. Impact Assessment

- The only realizable effect, and only when the WIL feature is disabled, is a **kernel NULL-pointer dereference bug check** — a local denial of service.
- There is **no** controlled-data primitive: the callees (`CscAcquireLViewLock`, `CscLViewIsRootGhosted`) read fixed small offsets of the logical-view object; a NULL base yields a fault, not attacker-controlled reads/writes.
- On Windows 8 and later, user-mode processes cannot map the NULL page, so there is no path to place controlled data at address 0.
- There is no info leak, no KASLR defeat, no privilege escalation, and no code execution associated with this change. Claims of such would not be supported by the binaries.

| Mitigation | Relevance |
|---|---|
| NULL-page mapping prevention (Vista+) | Blocks any attempt to place data at address 0; confines the worst case to a bug check. |

In summary, this is a defense-in-depth hardening. Its maximum theoretical footprint is a local DoS confined to a non-default feature configuration.

---

## 7. Verification Playbook

Target: `csc_unpatched.sys`. Kernel debugger (WinDbg/KD) attached. These steps confirm the behavioral difference between the two builds and the feature-gated nature of the NULL check.

### Breakpoints

```text
bp csc_unpatched!CscDclMRxTransition          ; 0x1C005CBA4
bp csc_unpatched!EvaluateCurrentState         ; 0x1C0007440
bp 0x1C005CC19                 ; prologue call to the feature evaluation
bp 0x1C005CC27                 ; mov rcx, rdi (first use of rdi after the guard)
bp 0x1C005CC2A                 ; call CscAcquireLViewLock
bp 0x1C005D181                 ; epilogue feature gate
```

Why each:

- **`CscDclMRxTransition`** — confirm entry conditions. `rcx` = RX_CONTEXT/FCB, `edx` = sub-operation (must be 1–3). `rdi` is loaded as `*(*(rcx+0x38)+0x70)`.
- **`EvaluateCurrentState`** — inspect the return value: `eax = 0` ⇒ `cachedstate == 1` ⇒ feature disabled ⇒ NULL check skipped.
- **`0x1C005CC19`** — the prologue feature evaluation; trace `eax` after return.
- **`0x1C005CC27`** — first instruction that consumes `rdi` after the guard.
- **`0x1C005CC2A`** — passes `rdi` to `CscAcquireLViewLock`.
- **`0x1C005D181`** — second occurrence of the same feature gate (epilogue).

### What to inspect

| Stop | Register / memory to watch |
|---|---|
| `CscDclMRxTransition` entry | `rcx` = RX_CONTEXT/FCB; `edx` = sub-op (1/2/3). |
| post-load of rdi | `rdi` = `*(*(rcx+0x38)+0x70)` (= `Flink[7].Flink`). |
| After `EvaluateCurrentState` returns | `eax`. `0` means the feature is disabled and the NULL check is skipped. |
| `0x1C005CC27` | `rdi`. NULL here is only reached if `eax` was 0 at the gate. |
| `g_Feature_4283659579_58821281_cachedstate` | `1` = feature disabled (skip path), `2` = feature enabled (check active). |

### Key offsets

- `0x1C005CBA4` — function entry.
- `0x1C005CC19` — prologue call to `EvaluateCurrentState` (removed by patch).
- `0x1C005CC1E`–`0x1C005CC20` — `test eax,eax; jz 0x1C005CC27` (skip-NULL-check branch when feature disabled).
- `0x1C005CC22` — `test rdi, rdi` (the gated NULL check).
- `0x1C005CC27` — `mov rcx, rdi` (first use of `rdi`).
- `0x1C005CC2A` — `call CscAcquireLViewLock`.
- `0x1C005D181` — epilogue occurrence of the removed feature evaluation.
- `0x1C005D18A` — `test rdi, rdi` (the gated NULL check).

### Confirming the difference

- With the feature enabled (`cachedstate == 2`): `EvaluateCurrentState` returns non-zero, `test rdi,rdi` runs, and a NULL `rdi` takes the `STATUS_INVALID_PARAMETER` exit — identical to the patched build.
- With the feature disabled (`cachedstate == 1`): `EvaluateCurrentState` returns 0, the NULL check is skipped, and a NULL `rdi` faults in `CscAcquireLViewLock`. The patched build takes the `STATUS_INVALID_PARAMETER` exit regardless of feature state.

### Struct / offset notes

- `RX_CONTEXT + 0x38` → `Header.FilterContexts.Flink`.
- That pointer `+ 0x70` (= `Flink[7].Flink`) → logical-view (LView) pointer (the NULL-able `v8`/`rdi`).
- Within the LView object: fields at `+0x30`, `+0x38` are dereferenced by the callees.
- `g_Feature_4283659579_58821281_cachedstate` is the WIL feature cached state read by `EvaluateCurrentState`.

---

## 8. Changed Functions — Full Triage

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `CscDclMRxTransition` (`0x1C005CBA4`) | 0.9703 | **Defense-in-depth (feature-staging graduation)** | Transition handler. Two calls to `EvaluateCurrentState` (`0x1C0007440`) removed; at both guard sites the WIL feature gate is dropped so the `v8` (rdi) NULL check becomes unconditional (`test rdi, rdi`). In the default (feature-enabled) configuration the NULL check is active in both builds. Remaining diff hunks are cosmetic: WPP trace-GUID renames (`WPP_9227ea88...` → `WPP_9a6a71d2...`), `__LINE__` constant shifts (`0x2FB→0x2F6`, `0x305→0x300`), and branch/label target shifts from the removed `call/test/jz` sequences. |

**Cosmetic changes (grouped):**

- WPP trace-GUID symbol renames, differing `__LINE__` constants in `RxpTrackReference`/`RxpTrackDereference`, and `lea`/`call`/`jmp` target shifts resulting from removal of the two `call EvaluateCurrentState` sequences plus their `test/jz` pairs. No behavioral change beyond the feature-gate removal.

**Behavioral notes:**

- None beyond the feature-gate removal. The patched binary contains no new logic, no new mitigations, and no other control-flow changes.

---

## 9. Unmatched Functions

- **Removed:** none.
- **Added:** none.

No new sanitizers, helper routines, or mitigation logic were introduced. The patch is strictly the removal of the WIL feature gate around the existing NULL check in `CscDclMRxTransition` (`0x1C005CBA4`).

---

## 10. Confidence & Caveats

**Confidence:** High for the code delta; the security relevance is assessed as none/defense-in-depth.

**Rationale**

- The diff is tightly scoped (1 function, 2 changed guard sites); the assembly clearly shows the removed feature evaluation and the now-unconditional NULL check. The direction is correct (the patched build is stricter).
- `EvaluateCurrentState` (`0x1C0007440`) is a small self-contained WIL feature-staging helper; `EvaluateFeature` (`0x1C00074EC`) is the standard flighting/registry-override evaluator. The cached-state encoding (2 = enabled, 1 = disabled) is confirmed in both C and assembly.
- Because the NULL check is present and active in both builds under the default (feature-enabled) configuration, and the skip path exists only in the vendor-controlled disabled state, this change does not constitute a delivered fix for an attacker-reachable vulnerability. Its maximum theoretical impact is a local DoS bug check confined to a non-default configuration.

**Not established from the binaries**

- The default enablement state of feature `4283659579_58821281` (the `[descriptor+0xC]` value consumed by `EvaluateCurrentStateFromRegistry`) is not readable from the disassembly text and was not confirmed; the analysis holds regardless because the skip path requires the disabled state.
- Whether `\\.\CSC` is reachable from a non-admin context, and the exact RX_CONTEXT/FCB state that yields `v8 == NULL` (`*(*(RX_CONTEXT + 0x38) + 0x70) == 0`), were not confirmed.
- Source attribution to `base\fs\remotefs\rdr\csc\driver\dclmrx.c` is consistent with the function semantics (RDBSS mini-redirector FSCTL dispatch).
