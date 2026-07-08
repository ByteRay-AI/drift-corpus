Title: ntfs.sys — Negative file size/offset accepted in NtSetInformationFile handlers (CWE-839) fixed
Date: 2026-07-03
Slug: ntfs_15bc0fdb-ntfs-report-20260703-144115
Category: Corpus
Author: Argus
Summary: KB5078885

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `ntfs_unpatched.sys` |
| **Patched binary** | `ntfs_patched.sys` |
| **Overall similarity** | 0.9864 (98.64%) |
| **Matched functions** | 4,197 |
| **Security-relevant changed functions** | 4 (`NtfsSetEndOfFileInfo`, `NtfsSetAllocationInfo`, `NtfsSetPositionInfo`, and their dispatcher `NtfsCommonSetInformation`) |

**Verdict:** The patch adds a minimum-value (sign) check on the attacker-supplied 64-bit `LARGE_INTEGER` that several `NtSetInformationFile` handlers read from `Irp->AssociatedIrp.SystemBuffer`. Before the patch, the new end-of-file, allocation size, and file position were validated only against an upper bound using a **signed** comparison, so a negative value (bit 63 set) passed the check and was committed into the file's size/position bookkeeping. The added checks reject negative values with `STATUS_INVALID_PARAMETER`. Each check is gated behind the WIL feature flag `Feature_2681941305` (staged rollout): when the flag is off, the pre-patch behavior remains.

This is **not** an FSCTL / `IRP_MJ_FILE_SYSTEM_CONTROL` issue. The affected code is reached through `NtSetInformationFile` / `ZwSetInformationFile` (`IRP_MJ_SET_INFORMATION`).

---

## 2. Vulnerability Summary

The three findings below are one coordinated change: a missing lower-bound check on a user-controlled 64-bit size/offset field, added to three `NtfsCommonSetInformation` sub-handlers under the same feature flag.

### Finding #1 — Negative `EndOfFile` accepted (`NtfsSetEndOfFileInfo`)

| Field | Value |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-839 (Numeric Range Comparison Without Minimum Check) |
| **Affected function** | `NtfsSetEndOfFileInfo` @ `0x1C00E8EE0` (unpatched) / `0x1C00E8EB0` (patched) |
| **Entry point** | `NtSetInformationFile` / `ZwSetInformationFile`, `FileInformationClass = FileEndOfFileInformation` (20 / `0x14`), dispatched by `NtfsCommonSetInformation` @ `0x1C00E7C40` (unpatched) case `20` |
| **User-mode API** | `NtSetInformationFile` / `SetEndOfFile` |

**Root cause (plain English):**

`NtfsSetEndOfFileInfo` reads the caller's `FILE_END_OF_FILE_INFORMATION.EndOfFile` — a signed 64-bit value copied into `Irp->AssociatedIrp.SystemBuffer` (METHOD_BUFFERED). The unpatched code compares this value against the maximum file size with a **signed** comparison (`cmp rdi, [rax+1E90h]; jg`) and against the current sizes with `jl` / `jge`. A negative value is smaller than every positive bound, so it passes all of these checks and is then committed as the file's size (`mov [rbx+20h], rdi`, the SCB allocation-size field). There is no check that the value is `>= 0`.

**What the patch does:** Immediately after loading the value it calls `Feature_2681941305__private_IsEnabledDeviceUsage()`, and if the flag is enabled and the value is negative it returns `STATUS_INVALID_PARAMETER` (`0xC000000D`) before any size update.

### Finding #2 — Negative allocation size accepted (`NtfsSetAllocationInfo`)

| Field | Value |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-839 |
| **Affected function** | `NtfsSetAllocationInfo` @ `0x1C00E6864` (both builds) |
| **Entry point** | `NtSetInformationFile`, `FileInformationClass = FileAllocationInformation` (19 / `0x13`), `NtfsCommonSetInformation` case `19` |

**Root cause:** The handler reads `FILE_ALLOCATION_INFORMATION.AllocationSize` from `SystemBuffer`. The unpatched code only checks `NewFileSize <= MaximumFileSize` (signed), so a negative value passes. The patch adds the negative case: when the feature flag is enabled it rejects `NewFileSize > MaximumFileSize || NewFileSize < 0` with `STATUS_INVALID_PARAMETER`; when the flag is off the original max-only check remains.

### Finding #3 — Negative file position accepted (`NtfsSetPositionInfo`)

| Field | Value |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-839 |
| **Affected function** | `NtfsSetPositionInfo` @ `0x1C020DD74` (patched; inlined into `NtfsCommonSetInformation` in the unpatched build) |
| **Entry point** | `NtSetInformationFile`, `FileInformationClass = FilePositionInformation` (14 / `0x0E`), `NtfsCommonSetInformation` case `14` |

**Root cause:** In the unpatched build, case `14` was handled inline in `NtfsCommonSetInformation` as `FileObject->CurrentByteOffset.QuadPart = *(SystemBuffer)`, with no validation. The patch extracts this into `NtfsSetPositionInfo` and, when the feature flag is enabled, returns `STATUS_INVALID_PARAMETER` if the supplied `CurrentByteOffset` is negative.

---

## 3. Pseudocode Diff

Decompiled C, `NtfsSetEndOfFileInfo` (the load and the added check):

```c
// UNPATCHED  (@ 0x1C00E8EE0)
v12 = *(_QWORD *)(a3 + 24);       // a3 = IRP; +0x18 = Irp->AssociatedIrp.SystemBuffer
v13 = *(_QWORD *)v12;             // v13 = FILE_END_OF_FILE_INFORMATION.EndOfFile (signed)
...                               // no >= 0 check
if ( v13 > *(_QWORD *)(*(_QWORD *)(a4 + 176) + 7824LL) )  // signed max check; negative passes
    ...error...
...
*(_QWORD *)(a4 + 32) = v13;       // negative value committed as file size

// PATCHED  (@ 0x1C00E8EB0)
v13 = *(_QWORD *)v12;
IsEnabledDeviceUsage = Feature_2681941305__private_IsEnabledDeviceUsage();
if ( IsEnabledDeviceUsage != 0 && v13 < 0 )
{
    if ( NtfsStatusDebugFlags != 0 )
        NtfsStatusTraceAndDebugInternal(0, 3221225485LL, 998544);   // 3221225485 == 0xC000000D
    local_unwind_0(v122, &loc_1C00E9037);
    return 3221225485LL;          // STATUS_INVALID_PARAMETER
}
```

Decompiled C, `NtfsSetAllocationInfo`:

```c
// UNPATCHED  (@ 0x1C00E6864)
QuadPart = **(_QWORD **)(a3 + 24);        // FILE_ALLOCATION_INFORMATION.AllocationSize
if ( QuadPart <= *(_QWORD *)(*(_QWORD *)(a4 + 176) + 7824LL) )   // max-only, signed
    ... proceed ...

// PATCHED  (@ 0x1C00E6864)
NewFileSize = **(union _LARGE_INTEGER **)(a3 + 24);
IsEnabledDeviceUsage = Feature_2681941305__private_IsEnabledDeviceUsage();
if ( IsEnabledDeviceUsage != 0 )
{
    if ( NewFileSize.QuadPart > MaximumFileSize || NewFileSize.QuadPart < 0 )  // added < 0
        return 3221225485LL;      // STATUS_INVALID_PARAMETER
}
else if ( NewFileSize.QuadPart > MaximumFileSize )   // original max-only path retained
    ...
```

Decompiled C, `NtfsSetPositionInfo` (patched only):

```c
// PATCHED  (@ 0x1C020DD74)
v2 = *(__int64 **)(a2 + 24);              // SystemBuffer
v4 = Feature_2681941305__private_IsEnabledDeviceUsage() == 0;
v5 = *v2;                                 // FILE_POSITION_INFORMATION.CurrentByteOffset
if ( v4 || v5 >= 0 )
{
    *(_QWORD *)(a1 + 104) = v5;           // FileObject->CurrentByteOffset
    return 0;
}
return 3221225485LL;                      // STATUS_INVALID_PARAMETER
```

In the unpatched build the same case was inline in `NtfsCommonSetInformation`:

```c
case 14:
    v61->CurrentByteOffset.QuadPart = **(_QWORD **)(v40 + 24);   // no validation
```

---

## 4. Assembly Analysis

### `NtfsSetEndOfFileInfo` — load of the user value (identical in both builds)

```asm
; unpatched @ 0x1C00E8EE0 / patched @ 0x1C00E8EB0
00000001C00E8FEF  mov     rcx, [rdi+18h]     ; rcx = Irp->AssociatedIrp.SystemBuffer   (unpatched addr)
00000001C00E8FFB  mov     rdi, [rcx]         ; rdi = FILE_END_OF_FILE_INFORMATION.EndOfFile
```

### Unpatched — the only bound is a signed maximum check

```asm
00000001C00E9083  cmp     rdi, [rax+1E90h]   ; rax->+0x1E90 (7824) = maximum file size
00000001C00E908A  jg      loc_1C00EA058      ; signed 'greater' — a negative EndOfFile is NOT rejected
00000001C00E90B2  cmp     rdi, rax           ; rax = current allocation size ([rbx+20h])
00000001C00E90B5  jl      loc_1C00E9CAC      ; signed 'less'
...
00000001C00E920F  mov     [rbx+20h], rdi     ; negative value committed as the file size
```

There is no `test rdi, rdi; jns` (or equivalent `>= 0`) guard anywhere before these uses.

### Patched — the added feature-gated sign check (real disassembly)

```asm
00000001C00E8FD6  call    NtfsUpdateScbFromAttribute
00000001C00E8FDB  mov     rsi, [rdi+18h]                             ; SystemBuffer
00000001C00E8FDF  mov     [rsp+208h+var_68], rsi
00000001C00E8FE7  mov     rdi, [rsi]                                 ; EndOfFile value
00000001C00E8FEA  mov     qword ptr [rsp+208h+var_1A5+5], rdi
00000001C00E8FEF  call    Feature_2681941305__private_IsEnabledDeviceUsage
00000001C00E8FF4  mov     [rsp+208h+var_F8], eax
00000001C00E8FFB  test    eax, eax
00000001C00E8FFD  jz      short loc_1C00E9042                        ; flag off -> skip check (old behavior)
00000001C00E8FFF  test    rdi, rdi
00000001C00E9002  jns     short loc_1C00E9042                        ; non-negative -> proceed
00000001C00E9004  movzx   eax, cs:NtfsStatusDebugFlags
00000001C00E900B  test    al, al
00000001C00E900D  jz      short loc_1C00E9021
00000001C00E900F  mov     edx, 0C000000Dh
00000001C00E9014  xor     ecx, ecx
00000001C00E9016  mov     r8d, 0F3C90h
00000001C00E901C  call    NtfsStatusTraceAndDebugInternal
00000001C00E9021  lea     rdx, loc_1C00E9037
00000001C00E9028  mov     rcx, [rsp+208h+var_160]
00000001C00E9030  call    _local_unwind_0
00000001C00E9037  mov     eax, 0C000000Dh                            ; STATUS_INVALID_PARAMETER
00000001C00E903C  jmp     loc_1C00EA748                              ; return
00000001C00E9042  mov     rcx, [rbx+20h]                             ; normal path continues
```

### The feature gate

`Feature_2681941305__private_IsEnabledDeviceUsage` @ `0x1C0034380` (patched) is a Windows Feature Staging (WIL) gate. It reads the cached `Feature_2681941305__private_featureState`; if bit 4 (`0x10`) is set it returns bit 0, otherwise it calls `Feature_2681941305__private_IsEnabledFallback` → `wil_details_IsEnabledFallback`. The feature is new to the patched build (it has no references in the unpatched binary). Its runtime default cannot be determined from the static image.

| What | Unpatched | Patched |
|---|---|---|
| Load value from `SystemBuffer[0]` | `mov rdi, [rcx]` @ `0x1C00E8FFB` | `mov rdi, [rsi]` @ `0x1C00E8FE7` |
| Lower-bound (`>= 0`) check | **None** | `test rdi, rdi; jns` after feature gate |
| Upper-bound check | Signed `cmp; jg` against max file size | Same |
| Reject action | N/A | `STATUS_INVALID_PARAMETER` (`0xC000000D`) |

---

## 5. Trigger Conditions

1. **Open a file on an NTFS volume** with an access mask sufficient for the target information class (for `FileEndOfFileInformation` / `FileAllocationInformation`, write access such as `FILE_WRITE_DATA`; `SetEndOfFile` on a normally-opened writable file is enough). Any local user can do this on a file they create.

2. **Build the information buffer** for the class:
   - `FILE_END_OF_FILE_INFORMATION` — a single `LARGE_INTEGER EndOfFile`. Set it negative (bit 63 set), e.g. `0xFFFFFFFFFFFFFFFF` or `0x8000000000000000`.
   - `FILE_ALLOCATION_INFORMATION` — a single `LARGE_INTEGER AllocationSize`, set negative.
   - `FILE_POSITION_INFORMATION` — a single `LARGE_INTEGER CurrentByteOffset`, set negative.

3. **Call `NtSetInformationFile`** (or the Win32 `SetEndOfFile` / `SetFileInformationByHandle`) with the matching `FileInformationClass` (20, 19, or 14). The I/O manager copies the buffer into `Irp->AssociatedIrp.SystemBuffer` and issues `IRP_MJ_SET_INFORMATION`, which `NtfsCommonSetInformation` dispatches to the handler above.

4. **Observable difference:**
   - Unpatched: the negative value passes the signed max/current-size comparisons and is committed to the file's size or position fields.
   - Patched (feature flag enabled): the call returns `STATUS_INVALID_PARAMETER` (`0xC000000D`) and nothing is committed.

---

## 6. Impact Assessment

**What is demonstrable from the binaries:** the pre-patch handlers accept a negative, attacker-supplied 64-bit end-of-file, allocation size, or byte offset and commit it to NTFS size/position bookkeeping (e.g. the SCB allocation-size field at `[SCB+0x20]`, or `FileObject->CurrentByteOffset`). The only guard present in the unpatched code is a signed upper-bound comparison, which a negative value trivially passes; there is no lower-bound (`>= 0`) check.

**What is not demonstrable:** the diff does not show a concrete out-of-bounds read or write, an information leak, or a privilege-escalation primitive inside these functions. A negative value stored where a non-negative size is expected can be reinterpreted as a very large unsigned quantity by downstream size arithmetic (cache-manager, MDL, or zeroing paths), which is a plausible route to file-metadata corruption or a bugcheck (denial of service). None of those downstream faults are proven by this diff, so no memory-corruption or LPE claim is made here.

Because the fix is gated behind a WIL feature flag whose default state is not visible in the static image, the correction is a **staged rollout**: on builds where the flag is disabled, the pre-patch behavior is retained.

Reachability is broad (local, low privilege: any user who can set the corresponding information class on a file they own), but the demonstrable consequence is limited to committing an invalid negative size/offset. Severity is therefore assessed **Low**.

---

## 7. Debugger Notes

Addresses below are preferred virtual addresses at image base `0x1C0000000`; rebase against the loaded `ntfs.sys` (`lm vm ntfs`) at runtime.

| Location | Instruction | Purpose |
|---|---|---|
| `NtfsSetEndOfFileInfo` entry `0x1C00E8EE0` (unpatched) | prologue | `r8` = IRP, `r9` = SCB |
| `0x1C00E8FEF` (unpatched) | `mov rcx, [rdi+18h]` | `rcx` = `Irp->AssociatedIrp.SystemBuffer` |
| `0x1C00E8FFB` (unpatched) | `mov rdi, [rcx]` | `rdi` = the user `EndOfFile` value; inspect its sign |
| `0x1C00E9083` (unpatched) | `cmp rdi, [rax+1E90h]; jg` | signed maximum check; a negative `rdi` is not rejected |
| `0x1C00E920F` (unpatched) | `mov [rbx+20h], rdi` | the value is committed as the file size |
| `0x1C00E8FEF` (patched) | `call Feature_2681941305__private_IsEnabledDeviceUsage` | start of the added gate |
| `0x1C00E8FFF` / `0x1C00E9002` (patched) | `test rdi, rdi; jns` | the added lower-bound check |
| `0x1C00E7C40` (unpatched) | `NtfsCommonSetInformation` | dispatcher; break to confirm `FileInformationClass` 14/19/20 |

To confirm the behavioral difference: set `EndOfFile` (or `AllocationSize`, or `CurrentByteOffset`) to a negative value via `NtSetInformationFile`, break at the load, and observe that in the unpatched build execution falls through the signed comparisons and stores the value, whereas the patched build (with the feature enabled) returns `0xC000000D`.

---

## 8. Changed Functions — Full Triage

### Security-relevant

| Function | Change |
|---|---|
| `NtfsSetEndOfFileInfo` (`0x1C00E8EE0` → `0x1C00E8EB0`) | Added feature-gated `EndOfFile >= 0` check returning `STATUS_INVALID_PARAMETER`. |
| `NtfsSetAllocationInfo` (`0x1C00E6864`) | Added feature-gated `AllocationSize >= 0` check alongside the existing max-size check. |
| `NtfsSetPositionInfo` (`0x1C020DD74`, new) | Case-14 handler extracted from the dispatcher; adds feature-gated `CurrentByteOffset >= 0` check. |
| `NtfsCommonSetInformation` (`0x1C00E7C40` → `0x1C00E7C10`) | Case `14` inline position assignment replaced with a call to the new `NtfsSetPositionInfo`. Dispatch logic otherwise unchanged. |

### Feature-staging infrastructure (non-security)

`Feature_2681941305__private_IsEnabledDeviceUsage` / `IsEnabledFallback` and the `wil_*` feature-staging helpers (`wil_InitializeFeatureStaging`, `wil_details_EvaluateFeatureDependencies`, `wil_details_PopulateInitialConfiguredFeatureStates`, `wil_details_UpdateFeatureConfiguredStates`) reflect the addition of the new `Feature_2681941305` staging entry. This is Microsoft's standard feature-flag plumbing, not a security fix in itself.

### Diagnostic-only churn (non-security)

The remaining functions reported as "changed" differ **only** in the numeric source-line identifiers passed to `NtfsStatusTraceAndDebugInternal` / `NtfsRaiseStatusInternal` (and a few relocated string/call addresses). These constants shifted uniformly because the inserted checks added source lines upstream. Verified for: `NtfsSetValidDataLengthInfo`, `NtfsCheckScbForLinkRemoval`, `NtfsFileInfoExceptionFilter`, `NtfsFindTargetElements`, `NtfsGetSfioReservation`, `NtfsSetSfioReservation`, `NtfsMoveLinkToNewDir`, `NtfsRenameLinkInDir`, `NtfsProcessTreeForRename`, `NtfsStreamRename`, `NtfsUpdateDuplicateInfo`, `NtfsWalkDownTreeOnDisk`, `NtfsWriteUsnForRenameAndCommit`, `NtfsPrepareToShrinkFileSize`, `EfsWaitForServiceReady`. None carry a semantic or security change.

---

## 9. Unmatched Functions

| Direction | Notes |
|---|---|
| Added (patched only) | `NtfsSetPositionInfo` (extracted case-14 handler) and the `Feature_2681941305` staging helpers. |
| Removed (unpatched only) | None. |

---

## 10. Confidence & Caveats

**Confidence: High** on the mechanism; **Low** on impact severity.

- The added checks (`>= 0` on the user-supplied 64-bit size/offset, returning `STATUS_INVALID_PARAMETER`) are confirmed in both the decompiled C and the disassembly of all three handlers.
- The pre-patch code demonstrably validated only an upper bound with a signed comparison, so negative values were accepted and committed — this is CWE-839 (numeric range comparison without a minimum check).
- The entry point is `NtSetInformationFile` / `IRP_MJ_SET_INFORMATION` (information classes 14/19/20), **not** an FSCTL / `NtFsControlFile` path.
- The fix is feature-gated behind `Feature_2681941305`; the old (unchecked) path is retained when the flag is off, so this is a staged rollout whose default state is not observable in the static image.
- No out-of-bounds access, information leak, or privilege-escalation primitive is demonstrable from this diff. Downstream consequences of a committed negative size (corruption, DoS) are plausible but unproven here and are not claimed as fact.
