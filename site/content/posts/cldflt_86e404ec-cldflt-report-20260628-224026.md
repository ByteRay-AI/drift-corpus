Title: cldflt.sys — Missing sign/bounds/overflow validation of file-range values on cloud-files control paths (CWE-20) made unconditional; fixed
Date: 2026-06-09
Slug: cldflt_86e404ec-cldflt-report-20260628-224026
Category: Corpus
Author: Argus
Summary: KB5094127
Severity: Medium
KBDate: 2026-06-09

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `cldflt_unpatched.sys` |
| Patched binary | `cldflt_patched.sys` |
| Overall similarity | 0.9917 |
| Matched functions | 1010 |
| Changed functions | 3 |
| Identical functions | 1007 |
| Unmatched (unpatched → patched) | 0 / 0 |

**Verdict:** Three validation checks (sign / bounds / integer-overflow) on caller-influenced file-range values were gated behind the WIL feature-staging predicate `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage` (at `0x1C00097F8` in the unpatched build). While that feature is not enabled, C short-circuit evaluation skips each check. The patch deletes the predicate from the binary entirely and makes all three checks unconditional (no legacy branch is retained), so this is a delivered fix, not a staged rollout. The reachable impact is limited to passing an unvalidated negative/oversized/overflowing file offset or length into internal range bookkeeping, a file-zeroing FSCTL, and the cloud-files transfer handlers; no memory-corruption primitive is demonstrable from the binaries.

---

## 2. Vulnerability Summary

All three findings share one root cause: a security-relevant validation is placed under the control of `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage` (`0x1C00097F8`), a WIL feature-staging predicate. In the unpatched build the predicate returns the feature's current state; when the feature is not enabled the guarded validation does not run. The patch removes the predicate (its slot at `0x1C00097F8` is occupied by an unrelated helper in the patched build) and runs each validation unconditionally.

Note: `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage` reads the cached WIL feature-enabled state (`WPP_MAIN_CB.Dpc.DeferredContext`, bit `0x10` selects the cached value in bit `0`) and otherwise falls back to `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledFallback` → `wil_details_IsEnabledFallback`. This is feature staging, not ETW/WPP tracing.

### Finding A - `HsmiOpDehydrateNotificationCallback (0x1C007A2A0)` (MEDIUM, primary)

- **Severity:** Medium
- **Class:** Missing sign/bounds validation of a file-range offset (CWE-20: Improper Input Validation; CWE-670: Always-Incorrect Control Flow Implementation)
- **Affected function:** Pre-operation callback registered for the cloud-files dehydrate operation (via `HsmpCldNotifyPreOperation`).

**Root cause.** The checked value is loaded at `0x1C007A2FB` (`mov rcx, [r15+10h]`) from the dehydrate parameters block (`Parameters + 0x10`, decompiled as `v79 = *((_QWORD *)Parameters + 2)`). This is the start offset of the file range being dehydrated, taken from the HSM control message, not the create `AllocationSize`. The strict check `if (v79 < 0 || v79 > v32)` (where `v32` is the stream size) is placed inside `if (Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage() != 0)`. When the feature is not enabled, execution falls through to only `else if (v79 > v32)` - a signed comparison that a negative offset passes (`negative < positive`). A negative or oversized offset then flows into:
- `v80 = v79 + *((_QWORD *)Parameters + 3)` (range end = offset + length), used later only in size comparisons and masking (it is not dereferenced as a pointer),
- alignment math `v39 = v79 - 1` and a size argument to `HsmiMarkFileRangeNoLock (0x1C0052BD8)` (internal file-range bookkeeping, pool tags `0x4244`/`0x4256`),
- the `FILE_ZERO_DATA_INFORMATION` offset passed to `FltFsControlFile(..., 0x980C8 /* FSCTL_SET_ZERO_DATA */, &InputBuffer, 0x10, ...)`.

The patch makes the check unconditional: `if (v82 < 0 || v82 > v32)` rejects out-of-range offsets with `0xC000CF0B` before any of the above.

**Entry point & call chain:**
1. A caller issues `IRP_MJ_FILE_SYSTEM_CONTROL` with an HSM control code (e.g. `0x9043C`) carrying a dehydrate request for a cloud-backed file.
2. `HsmFltPreFILE_SYSTEM_CONTROL (0x1C0076D40)` dispatches it (`Iopb->MajorFunction == 13`).
3. → `HsmFltProcessHSMControl (0x1C002FE70)`
4. → `HsmFltProcessDehydrate (0x1C0078674)`, which registers the callback via `HsmpCldNotifyPreOperation (0x1C0038910)`.
5. → `HsmiOpDehydrateNotificationCallback (0x1C007A2A0)`, where the range offset is validated.

### Finding B - `CldiPortProcessTransfer (0x1C0062258)` (MEDIUM)

- **Severity:** Medium
- **Class:** Missing sign + integer-overflow validation (CWE-190: Integer Overflow; CWE-20)
- **Affected function:** Dispatcher for transfer messages (`0x101`–`0x106`) on the Cloud Files communication port.

**Root cause.** The reject condition is `if (Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage() != 0 && (v16 < 0 || (v26 != -1 && (v26 < 0 || v26 > 0x7FFFFFFFFFFFFFFF - v16))))`. This is a short-circuit AND on the *reject* branch: when the feature is not enabled the left operand is `0`, the reject branch is skipped, and the dispatcher proceeds to the transfer handlers without validating the sizes/offsets `v16` (r14) and `v26` (rdi). `v16` and `v26` are parsed from the transfer message; `v26` is read from the message body (`*(_QWORD *)(v24 + v8)`) after header validation. `WPP_SF_qiiDiid (0x1C0009D20)` / `WPP_SF_qiiDqDd (0x1C0009DCC)` are WPP software-trace helpers on the error branch, not memory-copy routines. The patch removes the feature operand so the sign+overflow check always runs.

**Entry point & call chain:**
1. A client of the cloud-files communication port sends a transfer message with code `0x101`–`0x106`.
2. → `CldiPortProcessTransfer (0x1C0062258)`.
3. → the matching handler (`CldiPortProcessTransferData` / `CldiPortProcessAckData` / `CldiPortProcessRetrieveData` / `CldiPortProcessRestartHydration` / `CldiPortProcessTransferPlaceholders` / `CldiPortProcessReportProgress`) with `v16` / `v26` as offset/length arguments.

### Finding C - `HsmiOpUpdatePlaceholderFile (0x1C007BD14)` (LOW)

- **Severity:** Low
- **Class:** Missing sign check on a computed file offset (CWE-20)
- **Affected function:** Placeholder-update handler.

**Root cause.** In a loop over the update range list, the code computes an aligned file offset `v64` and then applies `if (Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage() != 0 && v64 < 0)`. Short-circuit AND means the `v64 < 0` check is skipped when the feature is not enabled, and `v64` flows into `HsmiMarkFileRangeNoLock (0x1C0052BD8)` (pool tag `0x4244`) as the range offset. The patch collapses the condition to `if (v64 < 0)`. Because `v64` is a page-aligned value derived from the update entries, a negative result is an edge case, which is why this is rated Low.

---

## 3. Pseudocode Diff

### Finding A - `HsmiOpDehydrateNotificationCallback`

```c
// ===== UNPATCHED (0x1C007A2A0) =====
v79 = *((_QWORD *)Parameters + 2);               // dehydrate range start offset (Parameters+0x10)
v80 = v79 + *((_QWORD *)Parameters + 3);         // range end = offset + length
...
if ( Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage() != 0 ) {  // *** FEATURE GATE ***
    if ( v79 < 0 || v79 > v32 ) {                // strict check: negative OR > stream size
        InformationFile = 0xC000CF0B;            //   (skipped when feature not enabled)
        goto reject;
    }
}
else if ( v79 > v32 ) {                          // fallthrough: signed cmp only
    InformationFile = 0xC000CF0B;                //   negative v79 is NOT caught
    goto reject;
}
// proceeds with unchecked negative/oversized offset:
v39 = v79 - 1;                                    // alignment math -> size for HsmiMarkFileRangeNoLock
HsmiMarkFileRangeNoLock(v8, 0x4256u, v78, v77, ...);
FltFsControlFile(Instance, FileObject, 0x980C8 /*FSCTL_SET_ZERO_DATA*/, &InputBuffer, 0x10, ...);

// ===== PATCHED (0x1C007A290) =====
if ( v82 < 0 || v82 > v32 ) {                     // *** UNCONDITIONAL ***
    InformationFile = 0xC000CF0B;                 // reject any out-of-range offset
    goto reject;
}
// proceeds only with a valid in-range offset
```

### Finding B - `CldiPortProcessTransfer`

```c
// ===== UNPATCHED (0x1C0062258) =====
if ( Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage() != 0   // feature not enabled -> AND is false
    && (v16 < 0
        || v26 != -1 && (v26 < 0 || v26 > 0x7FFFFFFFFFFFFFFF - v16)) )                // reject branch skipped
{
    v17 = 0xC000CF0B;                             // reject
    return v17;
}
// proceeds to the 0x101-0x106 transfer handlers with v16 / v26

// ===== PATCHED =====
if ( v16 < 0
    || v26 != -1 && (v26 < 0 || v26 > 0x7FFFFFFFFFFFFFFF - v16) )                      // always checked
{
    v17 = 0xC000CF0B;
    return v17;
}
```

### Finding C - `HsmiOpUpdatePlaceholderFile`

```c
// ===== UNPATCHED (0x1C007BD14) =====
if ( Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage() != 0 && v64 < 0 ) {  // AND -> check skipped
    // negative-offset error handling
}
HsmiMarkFileRangeNoLock(a2, 0x4244u, v64, v65, ...);

// ===== PATCHED (0x1C007BCA4) =====
if ( v64 < 0 ) {                                   // unconditional
    // negative-offset error handling
}
```

---

## 4. Assembly Analysis

### Finding A - `HsmiOpDehydrateNotificationCallback`

Unpatched (`0x1C007A2A0`), the gated check:

```asm
00000001C007A831  call    Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage
00000001C007A836  test    eax, eax
00000001C007A838  jz      loc_1C007A897      ; feature not enabled -> skip strict check
; --- strict check reached only when feature enabled ---
00000001C007A83A  mov     rax, [rbp+57h+var_B8]  ; reload range offset (Parameters+0x10)
00000001C007A83E  test    rax, rax
00000001C007A841  js      loc_1C007A84C      ; offset < 0 -> reject
00000001C007A843  cmp     rax, rbx           ; offset vs stream size
00000001C007A846  jle     loc_1C007A8E8      ; offset <= size -> proceed
; --- fallthrough when feature not enabled ---
00000001C007A897  cmp     [rbp+57h+var_B8], rbx  ; offset vs stream size only
00000001C007A89B  jle     loc_1C007A8E8      ; signed: negative offset proceeds
00000001C007A89D  mov     eax, 0C000CF0Bh    ; reject only when offset > size
; --- downstream use of an unchecked offset ---
00000001C007AB2A  call    HsmiMarkFileRangeNoLock
00000001C007ADF0  call    cs:__imp_FltFsControlFile  ; FSCTL 0x980C8 (SET_ZERO_DATA)
```

Patched (`0x1C007A290`) replaces the gate with an unconditional check:

```asm
00000001C007A824  test    rcx, rcx
00000001C007A827  js      loc_1C007AEB2      ; offset < 0 -> error (unconditional)
00000001C007A82D  cmp     rcx, rax           ; offset vs stream size
00000001C007A830  jg      loc_1C007AEB2      ; offset > size -> error (unconditional)
; error path at 0x1C007AEB2: mov ebx, 0C000CF0Bh
```

### Finding B - `CldiPortProcessTransfer`

Unpatched (`0x1C0062258`):

```asm
00000001C0062477  call    Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage
00000001C006247C  test    eax, eax
00000001C006247E  jz      loc_1C0062520      ; feature not enabled -> skip check, go to dispatch
00000001C0062484  test    r14, r14
00000001C0062487  js      short loc_1C00624AA
00000001C0062489  cmp     rdi, 0FFFFFFFFFFFFFFFFh
00000001C006248D  jz      loc_1C0062520
00000001C0062493  test    rdi, rdi
00000001C0062496  js      short loc_1C00624AA
00000001C0062498  mov     rax, 7FFFFFFFFFFFFFFFh
00000001C00624A2  sub     rax, r14
00000001C00624A5  cmp     rdi, rax
00000001C00624A8  jle     short loc_1C0062520
00000001C00624AA  mov     ebx, 0C000CF0Bh    ; reject
```

Patched (`0x1C0062258`) - the feature call is gone and the check runs first:

```asm
00000001C0062477  test    r14, r14
00000001C006247A  js      short loc_1C006249D
00000001C006247C  cmp     rdi, 0FFFFFFFFFFFFFFFFh
00000001C0062480  jz      loc_1C0062513
00000001C0062486  test    rdi, rdi
00000001C0062489  js      short loc_1C006249D
00000001C006248B  mov     rax, 7FFFFFFFFFFFFFFFh
00000001C0062495  sub     rax, r14
00000001C0062498  cmp     rdi, rax
00000001C006249B  jle     short loc_1C0062513
00000001C006249D  mov     ebx, 0C000CF0Bh    ; reject
```

The WPP error-branch callees relocated (`WPP_SF_qiiDiid`/`WPP_SF_qiiDqDd` moved from `0x1C0009D20`/`0x1C0009DCC` to `0x1C0009CCC`/`0x1C0009D78`) purely because the two feature-predicate functions were removed from the binary; this is address churn, not a behavioral change.

### Finding C - `HsmiOpUpdatePlaceholderFile`

Unpatched (`0x1C007BD14`):

```asm
00000001C007C8E7  call    Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage
00000001C007C8EC  test    eax, eax
00000001C007C8EE  jz      short loc_1C007C8F9    ; feature not enabled -> skip r12 check
00000001C007C8F0  test    r12, r12
00000001C007C8F3  js      loc_1C007C98F          ; offset < 0 -> reject
00000001C007C8F9  ; ... r8 = r12 (offset); edx = 4244h; call HsmiMarkFileRangeNoLock
```

Patched (`0x1C007BCA4`):

```asm
00000001C007C877  test    r12, r12               ; sign check always runs
00000001C007C87A  js      loc_1C007CAE8
00000001C007C880  ; ... r8 = r12; edx = 4244h; call HsmiMarkFileRangeNoLock
```

---

## 5. Trigger Conditions

### Finding A
1. `cldflt.sys` loaded and active on a volume backing cloud-synced files. Confirm with `fltmc filters`.
2. A caller able to send the HSM dehydrate control (`IRP_MJ_FILE_SYSTEM_CONTROL`, control code `0x9043C`) for a cloud-backed placeholder file.
3. The dehydrate request specifies a range whose start offset (`Parameters + 0x10`), interpreted as signed `int64`, is negative or exceeds the stream size.
4. The feature `Feature_Servicing_PostRelOutlookHangIssue` is not enabled, so `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage` returns 0 and the strict `v79 < 0 || v79 > v32` check is skipped; the fallthrough `v79 > v32` does not catch a negative offset.
5. Observable effect on the unpatched build: the unvalidated offset reaches `HsmiMarkFileRangeNoLock` (internal range bookkeeping) and the `FSCTL_SET_ZERO_DATA` request. This is a missing-validation defect; a memory-corruption outcome is not demonstrable from the binaries and the underlying file system independently validates the `SET_ZERO_DATA` range.

### Finding B
1. A client connected to the cloud-files communication port.
2. A transfer message with code `0x101`–`0x106` whose parsed values `v16` (offset) and `v26` (length) sum past `0x7FFFFFFFFFFFFFFF`, or where `v16`/`v26` is negative.
3. Feature not enabled, so the sign+overflow reject branch is skipped and the values reach the transfer handler unchecked.

### Finding C
1. A placeholder-update operation whose range list yields a computed aligned offset `v64` that is negative.
2. Feature not enabled, so the `v64 < 0` check is skipped and `v64` reaches `HsmiMarkFileRangeNoLock`.

No race conditions are involved; these are straight-line validation gaps.

---

## 6. Impact Assessment

The delivered change is input-validation hardening on kernel file-range values reached from the cloud-files control and communication-port paths. Concretely:

- **Finding A:** an unvalidated negative/oversized dehydration offset reaches internal file-range bookkeeping (`HsmiMarkFileRangeNoLock`) and a `FSCTL_SET_ZERO_DATA` request. The value is a file offset/length, not a kernel address, and is not dereferenced as a pointer.
- **Finding B:** an unvalidated size/offset pair with no overflow check reaches the `0x101`–`0x106` transfer handlers.
- **Finding C:** an unvalidated negative computed offset reaches `HsmiMarkFileRangeNoLock`.

No exploit primitive (out-of-bounds read/write of kernel memory, controlled pointer, info-leak, or pool-corruption chain) is demonstrable from these two builds. The realistic worst case is inconsistent internal range state or a failed/oddly-scoped file operation rather than a proven memory-safety violation. Severity is therefore Medium for A and B (attacker-influenced values on kernel control paths, missing sign/bounds/overflow checks) and Low for C (negative result is an edge case of a page-aligned computation).

---

## 7. Verification Notes

For anyone reproducing this against the two binaries:

1. Confirm `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage` exists at `0x1C00097F8` in `cldflt_unpatched.sys` and is absent from `cldflt_patched.sys` (its slot at `0x1C00097F8` holds `RtlStringCchPrintfW` in the patched build).
2. Finding A: at `0x1C007A831` (feature call) → `0x1C007A838` (`jz 0x1C007A897`), the strict check at `0x1C007A83A`–`0x1C007A846` is bypassed when the feature is not enabled; the fallthrough at `0x1C007A897`–`0x1C007A89B` compares against the stream size only. The checked offset is loaded at `0x1C007A2FB` from `Parameters + 0x10`. In the patched build the unconditional check is at `0x1C007A824`–`0x1C007A830`.
3. Finding B: at `0x1C0062477` (feature call) → `0x1C006247E` (`jz 0x1C0062520`), the sign+overflow check at `0x1C0062484`–`0x1C00624A8` is bypassed when the feature is not enabled. In the patched build the check runs first at `0x1C0062477`.
4. Finding C: at `0x1C007C8E7` (feature call) → `0x1C007C8EE` (`jz 0x1C007C8F9`), the `test r12,r12; js` check at `0x1C007C8F0` is bypassed when the feature is not enabled. In the patched build the check runs unconditionally at `0x1C007C877`.
5. The dehydrate range offset for Finding A originates in the HSM control message parsed by `HsmFltProcessHSMControl (0x1C002FE70)` and carried into `HsmFltProcessDehydrate (0x1C0078674)`; the offset/length for Finding B come from the transfer message parsed in `CldiPortProcessTransfer`.

---

## 8. Changed Functions - Full Triage

Only three functions changed; all three are the same feature-gated-validation fix.

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `HsmiOpDehydrateNotificationCallback (0x1C007A2A0)` | 0.9642 | security_relevant | Removed the `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage()` gate around the sign/bounds check on the dehydration range offset (`Parameters + 0x10`); `if (offset < 0 || offset > stream_size)` is now unconditional. |
| `CldiPortProcessTransfer (0x1C0062258)` | 0.9850 | security_relevant | Removed the feature operand from the short-circuit AND on the reject branch; the sign+integer-overflow check on `v16`/`v26` from the transfer message now always runs. WPP error-branch callees relocated because the feature-predicate functions were removed (address churn only). |
| `HsmiOpUpdatePlaceholderFile (0x1C007BD14)` | 0.9889 | security_relevant | Removed the feature operand from the short-circuit AND guarding `v64 < 0`; the negative-offset check now always runs. |

The feature predicate `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage (0x1C00097F8)` and its fallback `Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledFallback (0x1C0009830)` are both removed from the patched build.

---

## 9. Unmatched Functions

None added or removed by the diff. The patch is surgical within three existing functions (plus deletion of the two feature-predicate helpers).

---

## 10. Confidence & Caveats

**Confidence: High** on the mechanism and direction. In all three functions the unpatched build gates a sign/bounds/overflow check behind the feature predicate and the patched build removes the predicate and runs the check unconditionally, with no legacy branch retained - a delivered fix. The pseudocode and assembly addresses cited above are taken directly from the two builds.

**Caveats:**
- The default enabled/disabled state of `Feature_Servicing_PostRelOutlookHangIssue` cannot be read from these binaries alone; the assessment assumes the guarded (strict) behavior was not universally active, which is consistent with the vendor converting it to unconditional.
- No memory-corruption or information-disclosure primitive is demonstrable from the two builds; the impact is rated on the missing validation of attacker-influenced kernel file-range values, not on any reconstructed exploit.
- The exact access required to reach the HSM dehydrate control (Finding A) and the cloud-files communication port (Finding B) is not established here and bounds real-world reachability.

DONE
