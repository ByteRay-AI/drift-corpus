Title: ehstorclass.sys — Missing device-type check before installing IEEE 1667 silo completion routine (CWE-697/CWE-843) — fixed
Date: 2026-06-28
Slug: ehstorclass_b1beb976-ehstorclass-report-20260628-222013
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `ehstorclass_unpatched.sys` |
| Patched binary | `ehstorclass_patched.sys` |
| Overall similarity | 0.9913 |
| Matched functions | 164 |
| Changed functions | 1 |
| Identical functions | 163 |
| Unmatched (unpatched → patched) | 0 / 0 |

**Verdict:** The patch inserts a single device-type gate inside the WDM IRP preprocess callback (`FilterDeviceEvtWdmIoctlIrpPreprocess`, `0x1c0005790`) that runs for `IRP_MJ_DEVICE_CONTROL` / `IRP_MJ_INTERNAL_DEVICE_CONTROL` on IEEE 1667 disk PDOs. Without this gate the driver installs the silo-specific completion routine (`FilterDeviceWdmIoctlCompletionRoutine`) for SCSI and IOCTL `0x4d004` silo traffic on any silo PDO, including device types whose extension capability field marks them as ones the silo post-processing should not touch. The completion routine's job is to rewrite the SCSI sense/status response (inject CHECK CONDITION), so running it on the wrong device type corrupts that device's SCSI responses. The completion routine itself is byte-identical between the two builds; the entire security delta is the inline gate in the dispatch function.

---

## 2. Vulnerability Summary

### Finding #1 — Silo completion routine installed without a device-type check

| Attribute | Value |
|---|---|
| Severity | **Low** |
| Vulnerability class | Missing device-type validation (CWE-697) before applying IEEE 1667 silo-specific processing to an incompatible device type (CWE-843) |
| Affected function | `FilterDeviceEvtWdmIoctlIrpPreprocess` (`0x1c0005790`, WDM IOCTL/SCSI IRP preprocess callback) |
| Entry point | `IRP_MJ_DEVICE_CONTROL` (IOCTL `0x4d004`/`0x4d005` IEEE 1667 silo commands) and `IRP_MJ_INTERNAL_DEVICE_CONTROL` (SCSI pass-through) against IEEE 1667 disk PDOs |

**Root cause.** `FilterDeviceEvtWdmIoctlIrpPreprocess` is registered via `WdfDeviceInitAssignWdmIrpPreprocessCallback` (in `DriverEvtDeviceAdd`, `0x1c0013010`) for major functions `0x0E` and `0x0F`. After computing its copy/forward dispatch flags, the unpatched code calls `IoCopyCurrentIrpStackLocationToNext` and installs the completion routine `FilterDeviceWdmIoctlCompletionRoutine` with `Control = 0xC0` (`SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR`) whenever:

- the request is `IRP_MJ_INTERNAL_DEVICE_CONTROL` (SCSI, major function `0x0F`) on a silo device (`ext+0x08 != 0`), **or**
- the request is `IRP_MJ_DEVICE_CONTROL` with IOCTL `0x4d004`/`0x4d005` and the system buffer bytes at offsets `0x24`/`0x25` do *not* match the rejection magic `0xa2/0xee` or `0xb5/0xee`.

The completion routine then performs silo-specific post-processing on the completed request:

1. Acquires a WDF lock at `ext+0x1E8` and releases it after the table walk.
2. Parses SCSI VPD/CDB response descriptors (type codes `0x40`/`0x41`/`0x42`) out of a response buffer, computing an LBA range. This parsing is bounds-checked against the descriptor length before each field read (for example `cmp rax, rcx; ja <exit>` at `0x1c0005c5d`/`0x1c0005c60`, `0x1c0005c85`/`0x1c0005c88`, and the length checks at `0x1c0005dfc` and `0x1c0005e2f`).
3. Binary-searches a silo LBA-range table at `ext+0x1D0` (entry count at `ext+0x1D8`, each entry `0x18` bytes). The table walk is guarded by the entry count: the search loop runs only when the count is `> 1` (`cmp r10d, 1; jbe` at `0x1c000610d`), and a count of `0` skips every table dereference (`cmp edx, r10d; jnb` at `0x1c0006145`).
4. If a matching range is found, mutates the SCSI response: sets the status byte to CHECK CONDITION (`| 0x70`), writes sense code `0x0220`, and ORs `0x80` into the SRB status flags (`0x1c00061ee`–`0x1c0006233`).

This response rewriting is only appropriate for IEEE 1667 silo devices whose type warrants silo interception. For device PDOs whose capability field at `ext+0x130` has bits 12–15 `>= 6` (`[ext+0x130] & 0xf000 >= 0x6000`), the unpatched driver still installs the completion routine and can therefore rewrite the SCSI sense/status of an otherwise-healthy response for a device that should have been passed through untouched.

**Demonstrable impact.** What the binaries actually support is an **integrity/availability** problem localized to the affected device: the completion routine can inject a spurious CHECK CONDITION and sense code `0x0220` into the SCSI response for a device type that should not be intercepted, corrupting that device's I/O response semantics. The table walk (`ext+0x1D0`/`ext+0x1D8`) is count-guarded and the VPD/descriptor parsing is length-checked, so the natural zero-initialized extension state (count `0`, pointer NULL) does not dereference the table. No out-of-bounds access, pool corruption, or control-flow primitive is demonstrable from these binaries.

**Patch.** The patched binary inserts a gate at `0x1c0005930`: it reads `[ext+0x130]`, masks with `0xf000`, compares against `0x6000`, and folds the result (`sbb`) into both the copy flag (`bpl`) and the forward flag (`dil`). When the masked field is `>= 0x6000` both flags are forced to `0`, so the function takes `IoSkipCurrentIrpStackLocation + IofCallDriver` (transparent pass-through) and never installs the completion routine.

**Call chain (attacker → flaw):**

1. `DeviceIoControl(hDevice, 0x4d004, ...)` or `IOCTL_SCSI_PASS_THROUGH[_DIRECT]` produces `IRP_MJ_DEVICE_CONTROL` (`0x0E`) or `IRP_MJ_INTERNAL_DEVICE_CONTROL` (`0x0F`) on the IEEE 1667 PDO.
2. WDF routes the IRP to the WDM preprocess callback `FilterDeviceEvtWdmIoctlIrpPreprocess` (registered in `DriverEvtDeviceAdd`, `0x1c0013010`, for major functions `0x0E`/`0x0F`).
3. `FilterDeviceEvtWdmIoctlIrpPreprocess` dispatches by major function, computes the copy/forward flags, calls `IoCopyCurrentIrpStackLocationToNext`, and installs `FilterDeviceWdmIoctlCompletionRoutine` as the completion routine.
4. `IofCallDriver` forwards the IRP to the lower storage port driver.
5. On completion, `FilterDeviceWdmIoctlCompletionRoutine` runs: takes the `ext+0x1E8` lock, parses the SCSI response descriptors, searches the `ext+0x1D0` range table, and (on a range match) rewrites the SCSI sense/status — even for a device type where this interception is not intended.

---

## 3. Pseudocode Diff

```c
// === UNPATCHED FilterDeviceEvtWdmIoctlIrpPreprocess (0x1c0005790) — forwarding section (NO device-type check) ===
// r8b = "copy stack + install completion" flag
// sil = "use WDF forward vs IofCallDriver" flag

if (r8b != 1) {
    // IoSkipCurrentIrpStackLocation
    irp->CurrentLocation++;
    irp->Tail.Overlay.CurrentStackLocation = &stack_loc_next;
} else {
    // IoCopyCurrentIrpStackLocationToNext + install completion routine
    *(stack_loc - 0x48) = *stack_loc;            // copy parameters etc.
    *(stack_loc - 0x38) =  stack_loc[1];
    *(stack_loc - 0x28) =  stack_loc[2];
    *(stack_loc - 0x18) =  stack_loc[3];
    *(stack_loc - 0x45) =  0;                    // clear Control
    cur = irp->Tail.Overlay.CurrentStackLocation;
    *(cur - 0x10)       =  FilterDeviceWdmIoctlCompletionRoutine;  // *** COMPLETION ROUTINE — UNCONDITIONAL ***
    *(cur - 0x08)       =  device_object;         // context
    *(cur - 0x45)       =  0xC0;                  // SUCCESS | ERROR
}

// Forward — no inspection of device extension type
if (sil != 1)
    status = IofCallDriver(target_dev, irp);
else
    status = (*drv_obj->wdf_forward)(ctx, dev, irp);

// === PATCHED FilterDeviceEvtWdmIoctlIrpPreprocess (0x1c0005790) — NEW device-type gate ===
if (status >= 0) {
    int devtype = device_ext[0x130] & 0xF000;    // *** NEW: read+mask capability field ***
    bool ok    = (devtype < 0x6000);             // *** NEW: only silo-appropriate types ***

    // sbb folds `ok` into the existing dispatch flags:
    //   al = ok ? copy_flag    : 0
    //   dl = ok ? forward_flag : 0

    if (al != 1) {                               // devtype >= 0x6000  → SKIP completion
        irp->CurrentLocation++;
        irp->Tail.Overlay.CurrentStackLocation = &stack_loc_next;
    } else {                                     // devtype < 0x6000 → install as before
        *(stack_loc - 0x48) = *stack_loc;
        // ...
        *(cur - 0x10)       =  FilterDeviceWdmIoctlCompletionRoutine;  // same routine (relocated)
        *(cur - 0x08)       =  device_object;
        *(cur - 0x45)       =  0xC0;
    }

    if (dl != 1)
        status = IofCallDriver(target_dev, irp);
    else
        status = (*drv_obj->wdf_forward)(ctx, dev, irp);
}
```

**Inline notes**

- The unpatched code never reads `device_extension[0x130]`. The patched gate is the only behavioral addition; everything else is code/data shift.
- The completion-routine target address changes from `0x1c0005b50` (unpatched) to `0x1c0005ba0` (patched). This is pure relocation: the patched preprocess function grew by `0x50` bytes, shifting every following function down by the same amount. The completion routine's instructions are byte-identical between builds.
- The WPP trace-string reference also shifts as a data-section relocation artifact — not a behavioral change.
- The unpatched reject path (`STATUS_INVALID_PARAMETER`, `0xC000000D`) jumps directly to the epilogue after `IofCompleteRequest`. The patched build restructures the epilogue: the reject path stores the status into `r14d` and reaches a single early-return check (`test r14d, r14d; js <epilogue>` at `0x1c0005927`). This is behaviorally equivalent to the unpatched direct jump — a refactoring artifact of the restructured function, not a new security check.

---

## 4. Assembly Analysis

### UNPATCHED `FilterDeviceEvtWdmIoctlIrpPreprocess` (`0x1c0005790`)

```asm
; ---- Prologue / device-extension fetch ----
0x1c0005790: mov  rax, rsp
0x1c00057a3: push r14
0x1c00057a5: sub  rsp, 0x20
0x1c00057b0: mov  rbp, rdx                 ; rbp = IRP (arg2)
0x1c00057ba: mov  r14, rcx                 ; r14 = device object (arg1)
0x1c00057ce: call [__guard_dispatch_icall_fptr]   ; get device extension
0x1c00057db: mov  rdi, rax                 ; rdi = device extension
; (acquire/release ext lock around reading ext->flag_08 / ext->flag_10)
0x1c00057f5: mov  ebx, [rdi+0x08]          ; ebx = ext->isSilo flag
0x1c00057f8: mov  esi, [rdi+0x10]          ; esi = ext->flag_10
0x1c0005813: call [__guard_dispatch_icall_fptr]   ; release lock

0x1c0005819: mov  rdx, [rbp+0xb8]          ; rdx = CurrentStackLocation
0x1c0005820: test ebx, ebx                 ; silo device?
0x1c0005822: jnz  0x1c000583e              ; yes → MF dispatch

; ---- non-silo: short-circuit on STORAGE_QUERY_PROPERTY ----
0x1c0005824: cmp  byte [rdx], 0x0e
0x1c0005827: jnz  0x1c0005836
0x1c0005829: cmp  dword [rdx+0x18], 0x2d1400
0x1c0005830: jz   0x1c0005913
0x1c0005836: xor  sil, sil
0x1c0005839: jmp  0x1c0005916

; ---- SCSI path (MF == 0x0f) ----
0x1c000583e: mov  al, [rdx]
0x1c0005840: cmp  al, 0x0f
0x1c0005842: jnz  0x1c0005874
0x1c0005844: mov  rax, [rdx+0x08]          ; SRB pointer
0x1c0005848: cmp  byte [rax+0x02], 0x28
0x1c000584c: jnz  0x1c0005854
0x1c000584e: mov  r9d, [rax+0x18]
0x1c0005852: jmp  0x1c0005858
0x1c0005854: mov  r9d, [rax+0x0c]
0x1c0005858: mov  r8b, 0x1                 ; r8b = 1 → COPY + completion routine
0x1c000585b: test r8b, sil
0x1c000585e: setz cl
0x1c0005861: bt   r9d, 0x13
0x1c0005866: setnb al
0x1c0005869: test al, cl
0x1c000586b: setnz sil                     ; forward-method flag
0x1c000586f: jmp  0x1c0005919

; ---- IOCTL path (MF == 0x0e) ----
0x1c0005874: cmp  al, 0x0e
0x1c0005876: jnz  0x1c0005913
0x1c000587c: mov  ecx, [rdx+0x18]          ; IoControlCode
0x1c000587f: lea  eax, [rcx-0x4d004]
0x1c0005885: test eax, 0xffffffef          ; 0x4d004 / 0x4d005 ?
0x1c000588a: jnz  0x1c00058fa              ; no → try 0x4d02c

;   --- silo command rejection (magic 0xa2/0xee or 0xb5/0xee) ---
0x1c000588c: mov  rax, [rbp+0x18]          ; SystemBuffer
0x1c0005890: mov  cl,  [rax+0x24]
0x1c0005893: cmp  cl,  0xa2
0x1c0005896: jz   0x1c000589d
0x1c0005898: cmp  cl,  0xb5
0x1c000589b: jnz  0x1c00058ef              ; forward WITH completion
0x1c000589d: cmp  byte [rax+0x25], 0xee
0x1c00058a1: jnz  0x1c00058ef              ; forward WITH completion
;   --- magic MATCH → reject with STATUS_INVALID_PARAMETER ---
0x1c00058d1: mov  ebx, 0xc000000d
0x1c00058db: mov  [rbp+0x30], ebx          ; IRP->IoStatus.Status
0x1c00058de: call [__imp_IofCompleteRequest]
0x1c00058ea: jmp  0x1c00059b8              ; return

;   --- magic MISMATCH → set r8b = 1 ---
0x1c00058ef: mov  r8b, 0x1
0x1c00058f2: not  sil
0x1c00058f5: and  sil, r8b
0x1c00058f8: jmp  0x1c0005919

; ---- IOCTL 0x4d02c: SKIP completion (r8b = 0) ----
0x1c00058fa: lea  eax, [rcx-0x4d02c]
0x1c0005900: test eax, 0xfffffffb
0x1c0005905: jnz  0x1c0005913
0x1c0005907: xor  r8b, r8b
0x1c000590a: not  sil
0x1c000590d: and  sil, 0x1
0x1c0005911: jmp  0x1c0005919

0x1c0005913: mov  sil, 0x1
0x1c0005916: xor  r8b, r8b                 ; default r8b = 0

; ==================== THE FORK (no device-type check) ====================
0x1c0005919: cmp  r8b, 0x1
0x1c000591d: jnz  0x1c0005960              ; r8b != 1 → skip completion

; --- IoCopyCurrentIrpStackLocationToNext + install completion ---
0x1c000591f: movups xmm0, [rdx]
0x1c0005922: lea   rcx, [FilterDeviceWdmIoctlCompletionRoutine]  ; = 0x1c0005b50
0x1c0005929: movups [rdx-0x48], xmm0
0x1c000592d: movups xmm1, [rdx+0x10]
0x1c0005931: movups [rdx-0x38], xmm1
0x1c0005935: movups xmm0, [rdx+0x20]
0x1c0005939: movups [rdx-0x28], xmm0
0x1c000593d: movsd  xmm1, [rdx+0x30]
0x1c0005942: movsd  [rdx-0x18], xmm1
0x1c0005947: mov  byte [rdx-0x45], 0x0     ; clear Control
0x1c000594b: mov  rax, [rbp+0xb8]          ; reload stack loc ptr
0x1c0005952: mov  [rax-0x10], rcx          ; CompletionRoutine = FilterDeviceWdmIoctlCompletionRoutine
0x1c0005956: mov  [rax-0x08], r14          ; Context = device object
0x1c000595a: mov  byte [rax-0x45], 0xc0    ; Control = SUCCESS|ERROR
0x1c000595e: jmp  0x1c000596e

; --- IoSkipCurrentIrpStackLocation ---
0x1c0005960: inc  byte [rbp+0x43]          ; CurrentLocation++
0x1c0005963: lea  rax, [rdx+0x48]
0x1c0005967: mov  [rbp+0xb8], rax          ; advance CurrentStackLocation

; ---- Forward (no device-type check anywhere) ----
0x1c000596e: mov  rax, [WdfFunctions]
0x1c0005975: mov  rdx, r14                 ; device object
0x1c000597f: cmp  sil, 0x1
0x1c0005983: jnz  0x1c0005997              ; sil != 1 → IofCallDriver
0x1c0005985: mov  rax, [rax+0x110]         ; WDF forward
0x1c000598f: call [__guard_dispatch_icall_fptr]
0x1c0005995: jmp  0x1c00059b6
0x1c0005997: mov  rax, [rax+0x100]         ; target device
0x1c000599e: call [__guard_dispatch_icall_fptr]
0x1c00059aa: call [__imp_IofCallDriver]
0x1c00059b6: mov  ebx, eax
0x1c00059d4: retn
```

### PATCHED `FilterDeviceEvtWdmIoctlIrpPreprocess` (`0x1c0005790`) — the inserted gate

```asm
; After the dispatch-flag computation (dil = forward flag, bpl = copy flag, r9b = 1), BEFORE the fork:
0x1c0005927: test r14d, r14d                ; early-return check (reject path stored 0xC000000D here)
0x1c000592a: js   0x1c00059f8               ; negative status → epilogue, never forward

0x1c0005930: mov  eax, [r13+0x130]          ; ★★★ NEW: read device_ext[0x130]
0x1c0005937: mov  r8d, 0x6000               ; ★★★ NEW: threshold
0x1c000593d: mov  rcx, [rsi+0xb8]           ; CurrentStackLocation
0x1c0005944: and  eax, 0xf000               ; ★★★ NEW: mask capability nibble
0x1c0005949: cmp  eax, r8d                  ; ★★★ NEW: (field & 0xf000) vs 0x6000
0x1c000594c: sbb  dl, dl                    ; dl = (field < 0x6000) ? 0xFF : 0x00
0x1c000594e: and  dl,  dil                  ; dl &= forward_flag
0x1c0005951: cmp  eax, r8d
0x1c0005954: sbb  al, al                    ; al = (field < 0x6000) ? 0xFF : 0x00
0x1c0005956: and  al,  bpl                  ; al &= copy_flag
0x1c0005959: cmp  al,  r9b                  ; r9b = 1
0x1c000595c: jnz  0x1c000599f               ; ★★★ if NOT 1 → SKIP completion (pass-through)
;   When field >= 0x6000: al = 0 → jnz taken → IoSkipCurrentIrpStackLocation + IofCallDriver
;   When field <  0x6000: al = copy_flag → completion installed only if the dispatch wanted it
0x1c0005983: lea  rcx, [FilterDeviceWdmIoctlCompletionRoutine]  ; = 0x1c0005ba0 (relocated, same routine)
0x1c0005991: mov  [rax-0x10], rcx
0x1c0005995: mov  [rax-0x08], r12          ; Context = device object
0x1c0005999: mov  byte [rax-0x45], 0xc0
0x1c00059b5: cmp  dl,  r9b                  ; forward-method selection (dl gated by device type)
0x1c00059b8: jnz  0x1c00059d6              ; dl != 1 → IofCallDriver
```

**What the patch adds.** In the unpatched binary `device_extension[0x130]` is never loaded anywhere in this function. The patched insertion (`mov eax, [r13+0x130]` / `and eax, 0xf000` / `cmp eax, 0x6000`) plus the two `sbb`-folds into the copy and forward flags is the entire behavioral delta. When `(field & 0xf000) >= 0x6000` both folded flags become `0`, forcing pass-through with no completion routine.

---

## 5. Trigger Conditions

1. **A silo PDO whose extension field at `+0x130` satisfies `(field & 0xf000) >= 0x6000`.** This is a device-type/capability value set during enumeration/initialization, not per-request attacker input. Reaching the vulnerable path requires such a device to be present and to be a silo device (`ext+0x08 != 0`).
2. **Obtain a handle** to the PDO or its silo device interface (e.g., `SetupDiGetClassDevs` with the IEEE 1667 interface GUID, then `CreateFileW` on the returned device path).
3. **Injection vector:**
   - **IOCTL path:** `DeviceIoControl` with IOCTL `0x4d004` (`CTL_CODE(FILE_DEVICE_CONTROLLER=0x4, 0x401, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)`).
     - Input buffer must be **≥ 0x26 bytes**.
     - Set `inBuf[0x24]` to anything **other than** `0xa2` or `0xb5` *OR* set `inBuf[0x25]` to anything **other than** `0xee`. This defeats the magic-byte rejection at `0x1c0005890`–`0x1c00058a1` and causes the IRP to be forwarded *with* the completion routine installed.
   - **SCSI path:** `IOCTL_SCSI_PASS_THROUGH` or `IOCTL_SCSI_PASS_THROUGH_DIRECT` with a CDB (e.g., INQUIRY, READ CAPACITY, MODE SENSE, or a VPD request returning page descriptors of type `0x40`/`0x41`/`0x42`). This produces `IRP_MJ_INTERNAL_DEVICE_CONTROL` and lands in the `cmp al, 0x0f` branch at `0x1c0005840`.
4. **No ordering or race is required.** The completion routine fires deterministically when the lower driver completes the IRP.
5. **Observable difference between builds:**
   - **Unpatched:** for a device with `(ext+0x130 & 0xf000) >= 0x6000`, the completion routine runs. If its descriptor parse and range-table lookup produce a range match, the SCSI response is rewritten — CHECK CONDITION injected, sense code `0x0220` written, SRB status `|= 0x80` — corrupting the response for a device that should have passed through untouched.
   - **Patched:** the same input skips the completion routine entirely; the IRP passes through and the original lower-driver response is returned unmodified.

---

## 6. Impact Assessment

**Reachable, demonstrable impact.** The change removes the installation of the silo completion routine for device types with `(ext+0x130 & 0xf000) >= 0x6000`. On the unpatched build those devices could have their SCSI sense/status response rewritten by the completion routine (CHECK CONDITION `| 0x70`, sense `0x0220`, SRB status `| 0x80`). The concrete consequence is an **integrity/availability** issue localized to the affected device: a valid SCSI response can be turned into a spurious error, disrupting that device's I/O or its IEEE 1667 command handling.

**What is not supported by the binaries.** The completion routine's table walk is guarded by its entry count (`cmp r10d, 1; jbe` at `0x1c000610d`; `cmp edx, r10d; jnb` at `0x1c0006145`), so the zero-initialized extension state (count `0`, table pointer NULL) performs no table dereference. The VPD/descriptor parsing is length-checked before each field access (`cmp rax, rcx; ja` at `0x1c0005c60`, `0x1c0005c88`; length checks at `0x1c0005dfc`, `0x1c0005e2f`). These binaries therefore do **not** demonstrate a NULL-dereference reachable from the natural uninitialized state, an out-of-bounds read/write, pool corruption, an information leak, or a control-flow-hijack primitive. Any such escalation would require an extension state (e.g., a non-zero entry count paired with a stale/NULL table pointer, or an incompatible-type device whose silo table is populated with mismatched data) that is not shown to be reachable in these two builds. Severity is rated **Low** on the demonstrable I/O-integrity impact alone.

---

## 7. Analysis Anchors

Image base in this analysis is `0x1c0000000`; all values are RVA-from-base. Substitute the actual loaded base (`lm ehstorclass`) when working against a live image.

### Key instruction anchors (unpatched)

| Address | Meaning |
|---|---|
| `0x1c0005819` | `mov rdx, [rbp+0xb8]` — loads `CurrentStackLocation` for dispatch |
| `0x1c0005820` | `test ebx, ebx` — silo-device gate (`ext+0x08`) |
| `0x1c0005840` | `cmp al, 0x0f` — SCSI (`IRP_MJ_INTERNAL_DEVICE_CONTROL`) branch |
| `0x1c0005874` | `cmp al, 0x0e` — IOCTL (`IRP_MJ_DEVICE_CONTROL`) branch |
| `0x1c000588c` | `mov rax, [rbp+0x18]` — SystemBuffer for magic-byte check |
| `0x1c0005890` | `mov cl, [rax+0x24]` — silo command byte |
| `0x1c000591f` | `movups [rdx-0x48], xmm0` — `IoCopyCurrentIrpStackLocationToNext` start |
| `0x1c0005952` | `mov [rax-0x10], rcx` — completion-routine store (installed with no device-type check) |
| `0x1c000595a` | `mov byte [rax-0x45], 0xc0` — sets `SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR` |

### Key instruction anchors (patched)

| Address | Meaning |
|---|---|
| `0x1c0005927` | `test r14d, r14d; js` — early-return on the reject/error path (restructured epilogue) |
| `0x1c0005930` | `mov eax, [r13+0x130]` — NEW device-type read |
| `0x1c0005944` | `and eax, 0xf000` — NEW mask |
| `0x1c0005949` | `cmp eax, r8d` (`0x6000`) — NEW device-type comparison |
| `0x1c000595c` | `jnz 0x1c000599f` — NEW redirect to pass-through when `field >= 0x6000` |

### Completion routine `FilterDeviceWdmIoctlCompletionRoutine` (unpatched `0x1c0005b50`, patched `0x1c0005ba0`)

| Address (unpatched) | Meaning |
|---|---|
| `0x1c00060c3` / `0x1c00061cf` | acquire / release WDF lock at `ext+0x1E8` |
| `0x1c0006101` | `mov r10d, [r15+0x1d8]` — silo range-table entry count |
| `0x1c000610d` | `cmp r10d, 1; jbe` — table binary-search runs only when count `> 1` |
| `0x1c0006113` / `0x1c0006125` | `mov r11, [r15+0x1d0]` then `mov rax, [r11+rcx*8]` — `0x18`-byte-stride table access |
| `0x1c0006145` | `cmp edx, r10d; jnb` — count `0` skips all table dereferences |
| `0x1c00061f7`–`0x1c00061fc` | `and dl, 0xf0; or dl, 0x70; mov [rcx], dl` — inject CHECK CONDITION into the response |
| `0x1c0006211` / `0x1c0006223` | `mov word [rcx+...], 0x220` — write sense code `0x0220` |
| `0x1c0006233` | `or byte [rax+3], 0x80` — set SRB status flag |

### Struct / offset notes

- **IRP** (`rbp` unpatched / `rsi` patched): `+0x18` = `AssociatedIrp.SystemBuffer`; `+0x30` = `IoStatus.Status`; `+0x43` = `CurrentLocation` (byte); `+0xb8` = `Tail.Overlay.CurrentStackLocation`.
- **IO_STACK_LOCATION** (at dispatch): `+0x00` = MajorFunction; `+0x08` = SRB / Type3InputBuffer pointer; `+0x18` = `IoControlCode`.
- **Device extension** (`rdi` unpatched / `r13` patched; `r15` in completion routine): `+0x08` = silo/state flag; `+0x10` = flag_10; `+0x130` = capability/device-type field (the newly gated field); `+0x1D0` = silo LBA-range table pointer; `+0x1D8` = range-table entry count (`0x18` bytes each); `+0x1E8` = WDF lock.
- **SRB** (SCSI path): `+0x02` = Function; `+0x0c` and `+0x18` = fields consulted by the dispatch logic.

The driver's PDB path string is referenced at `0x1c000dbf4`; loading `EhStorClass.pdb` recovers the real symbol names (the function names used above are the recovered names).

---

## 8. Changed Functions — Full Triage

Only one function changed between the two builds:

- **`FilterDeviceEvtWdmIoctlIrpPreprocess`** (`0x1c0005790`) — similarity 0.8696 — **security-relevant**.
  - Added the device-type gate (`mov eax, [r13+0x130]; and eax, 0xf000; cmp eax, 0x6000`) at patched `0x1c0005930`, folded into the existing copy/forward dispatch flags via `sbb`.
  - Restructured the epilogue: the `STATUS_INVALID_PARAMETER` reject path now stores the status into `r14d` and reaches a single early-return check (`test r14d, r14d; js` at patched `0x1c0005927`). This is behaviorally equivalent to the unpatched direct jump to the epilogue — a refactoring artifact, not a new security check.
  - **Relocation-only differences:** the completion-routine target address changed from `0x1c0005b50` to `0x1c0005ba0`, and the WPP trace-string reference shifted. Both follow from the `0x50`-byte growth of this function shifting all later code/data; neither is a behavioral change.

The completion routine `FilterDeviceWdmIoctlCompletionRoutine` is byte-identical between builds (verified instruction-by-instruction; only relocated branch targets differ). No other function changed.

---

## 9. Unmatched Functions

None. Both binaries have the same function count (164 matched), with 0 added and 0 removed on either side. There is no removed sanitizer and no added mitigation helper — the entire security delta is the inline gate inside `FilterDeviceEvtWdmIoctlIrpPreprocess`.

---

## 10. Confidence & Caveats

**Confidence: High on the change itself; the severity is bounded by what the binaries demonstrate.** The patch is unambiguous: a single inserted device-type gate, identical control flow everywhere else, and the completion routine byte-identical between builds. The gate's direction is correct — the patched build is strictly more restrictive (it withholds the completion routine for `field >= 0x6000`).

**Assumptions made:**

- The field at `device_extension+0x130` is a device-type/capability value whose bits 12–15 select a family; this is consistent with the patch's mask (`0xf000`) and threshold (`0x6000`), but the symbolic name is not recovered.
- `FilterDeviceEvtWdmIoctlIrpPreprocess` is registered for major functions `0x0E` and `0x0F` — confirmed directly in `DriverEvtDeviceAdd` (`0x1c0013010`), which calls `WdfDeviceInitAssignWdmIrpPreprocessCallback` (WdfFunctions `+0x248`) with the callback and `MajorFunction = 0x0E` (`0x1c0013621`/`0x1c001362f`) and `0x0F` (`0x1c0013681`/`0x1c001368f`).

**Bounds on the impact claim:**

- The completion routine's silo range-table walk is count-guarded and its VPD/descriptor parsing is length-checked (see Sections 2, 6, 7). The zero-initialized extension state does not dereference the table. No out-of-bounds access, pool corruption, information leak, or control-flow primitive is demonstrable from these binaries; the assessed impact is confined to SCSI response corruption (integrity/availability) for the affected device type.
- Whether the `+0x130` capability value is influenceable by an attacker-supplied device (e.g., a crafted USB device enumerating as IEEE 1667) is not determinable from these binaries alone; the trigger assumes such a device is present.
