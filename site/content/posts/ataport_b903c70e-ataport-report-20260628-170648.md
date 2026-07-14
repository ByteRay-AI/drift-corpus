Title: ataport.sys — cross-version refactor and defense-in-depth stack initialization
Date: 2026-06-09
Slug: ataport_b903c70e-ataport-report-20260628-170648
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Unknown
KBDate: 2026-06-09

## 1. Overview

*   **Unpatched Binary:** `ataport_unpatched.sys`
*   **Patched Binary:** `ataport_patched.sys`
*   **Overall Similarity Score:** 0.6819
*   **Diff Statistics:** 550 matched functions (222 identical, 328 changed), 0 unmatched functions in either direction.
*   **Verdict:** The two builds span different Windows release branches (17763 -> 20348), so the great majority of the 328 changed functions are version churn. Three functions on the ATA PassThrough path were examined in detail because they carry the largest logic changes; none of them delivers a reachable security fix or introduces a demonstrable regression:
    *   The ATA PassThrough IRB control-flag computation (`PortPassThroughSrbInitialize`) was restructured but is functionally equivalent between builds.
    *   `PortPassThroughBuildIrpEx` adds a zero-initialization of the stack-local `KAPC_STATE` before `KeStackAttachProcess`. In both builds the structure is only ever read after `KeStackAttachProcess` populates it, so the added zero-init has no reachable effect; it is defense-in-depth stack initialization consistent with a newer toolchain, not a fix for a consumed uninitialized value.
    *   `PortPassThroughValidateNormalizedRequest` removes a WinPE-only registry gate on task-file command `0x48` and moves an overflow check into the `RtlULongAdd` helper. The overflow handling is equivalent; the gate removal makes the patched build *less* restrictive and reflects a cross-version policy change, not a security fix.

---

## 2. Vulnerability Summary

### Finding 1: IRB Control Flag Computation Refactor (Informational)
*   **Vulnerability Class:** Refactoring / No Behavioral Change
*   **Affected Function:** `PortPassThroughSrbInitialize` (`sub_1c002a7d0` unpatched -> `sub_1c002f9d4` patched)
*   **Analysis:** When processing an ATA PassThrough request, both builds compute the IRB control-flags field (context offset `0xC`) from the transfer type (`0x80` read / `0x40` write / `0xc0` other, or `0` for zero-length) plus a no-data-buffer indicator bit (`0x20`) and a completion bit (`0x100`). The unpatched build pre-computes the no-buffer value in a parallel register as `transfer_type + 0x20` via `lea ecx, [rax+0x20]` (yielding `0xa0`/`0x60`/`0xe0`, or `0x20` for zero-length) and conditionally stores it when the data buffer pointer is `NULL`; the patched build instead ORs `0x20` onto the transfer-type value via `or eax, 0x20`. Because bit `0x20` is clear in `0x80`/`0x40`/`0xc0`, `transfer_type + 0x20 == transfer_type | 0x20`, so the transfer-type bits are preserved in both builds and the final field value is identical for every input combination.
*   **Impact:** None. The IRB flags forwarded to the miniport are identical between builds; this is a structure/codegen difference, not a behavioral or security change.
*   **Reachability of the path:**
    1.  A caller sends `DeviceIoControl` / `NtDeviceIoControlFile` with an ATA pass-through IOCTL to a physical drive handle.
    2.  `PortPassThroughSendAsync (sub_1c002a3dc)` parses and validates the input.
    3.  `PortPassThroughBuildSrb (sub_1c002a8b8)` allocates the request context.
    4.  `PortPassThroughSrbInitialize (sub_1c002a7d0)` initializes the IRB and computes the control flags.

### Finding 2: WinPE Registry Gate Removal & Bounds-Check Refactor (Informational)
*   **Vulnerability Class:** Version Policy Change / Refactoring
*   **Affected Function:** `PortPassThroughValidateNormalizedRequest` (`sub_1c002a63c` unpatched -> `sub_1c002fba4` patched)
*   **Analysis:** The unpatched validator gates task-file command `0x48` to WinPE environments by probing the registry key `\Registry\Machine\System\CurrentControlSet\Control\MiniNT` via `ZwOpenKey`, returning `STATUS_NOT_SUPPORTED` (`0xC00000BB`) when the key is absent. The patched validator removes this registry probe entirely, so command `0x48` is no longer environment-gated. This is a real behavioral difference, but the direction is that the *patched* build is less restrictive, and command `0x48` still passes the same sector-range, block-count and device-limit validation in both builds. Between two OS release branches this is a policy change, not a delivered security fix, and no dangerous primitive is demonstrably unlocked by the removal. Separately, the unpatched validator computes the end-sector with inline arithmetic (`add ecx, edx; cmp ecx, edx; cmovnb; jb`), which correctly detects 32-bit wraparound; the patched build performs the same check via the `RtlULongAdd (sub_1c0013808)` helper. The two produce equivalent overflow handling, so that part is a refactor to a standard helper, not a fix for a present overflow.

### Finding 3: KAPC_STATE Zero-Initialization (Defense-in-depth, no reachable impact)
*   **Vulnerability Class:** Defensive stack initialization (no consumed uninitialized value)
*   **Affected Function:** `PortPassThroughBuildIrpEx` (`sub_1c0015678` unpatched -> `sub_1c0005b48` patched)
*   **Analysis:** On the cross-process MDL probe path (requesting process != current process), the driver passes a stack-local `KAPC_STATE` structure to `KeStackAttachProcess`. The unpatched build leaves this structure uninitialized before the call at `0x1c0015782`; the patched build zero-initializes it with `xorps`/`movups` at `0x1c0005b7b`-`0x1c0005b88` before its call at `0x1c0005c64`. The two functions are otherwise near-identical (similarity 0.9906), the only material difference being this zero-fill. In **both** builds, `KeUnstackDetachProcess` and every read of the structure are gated on an attach flag (`sil` / the `[rsp+...]` byte at `var_88`) that is set to `1` exclusively on the instruction immediately following a successful `KeStackAttachProcess` (unpatched `0x1c001578e`/`0x1c0015791`; patched `0x1c0005c70`/`0x1c0005c73`). `KeStackAttachProcess` fully populates the `KAPC_STATE` on entry. The structure is therefore never consumed before it is written, so the added zero-init has no reachable effect on behavior. It is defense-in-depth stack initialization consistent with a newer toolchain, not a fix for a use of an uninitialized value.

---

## 3. Pseudocode Diff

The following pseudocode shows the IRB control-flag computation in the initializer (`PortPassThroughSrbInitialize`, `sub_1c002a7d0` vs `sub_1c002f9d4`). Both builds compute the same final value.

```c
// UNPATCHED: PortPassThroughSrbInitialize (sub_1c002a7d0)
if (*(arg2 + 0xc) != 0) { // If transfer length is non-zero
    if (!dir) { v9 = 0x80; v8 = 0xa0; }        // Read  (0xa0 == 0x80|0x20)
    else if (dir == 1) { v9 = 0x40; v8 = 0x60; } // Write (0x60 == 0x40|0x20)
    else { v9 = 0xc0; v8 = 0xe0; }             // Other (0xe0 == 0xc0|0x20)
    a1[3] = v9;
} else {
    a1[3] = 0; v8 = 0x20; v9 = 0;
}

if (!arg5) {          // NO DATA BUFFER provided
    a1[3] = v8;       // stores transfer_type + 0x20 (== transfer_type | 0x20)
    v9 = v8;
}
a1[3] = v9 | 0x100; // Final IRB flags assigned


// PATCHED: PortPassThroughSrbInitialize (sub_1c002f9d4)
if (*(arg2 + 0xc) != 0) {
    if (!dir) v8 = 0x80;
    else if (dir == 1) v8 = 0x40;
    else v8 = 0xc0;
} else {
    v8 = 0;
}

if (!arg5) {
    v8 |= 0x20;    // ORs the no-data flag onto the transfer type
}
a1[3] = v8 | 0x100; // Final IRB flags assigned (same value as unpatched)
```

---

## 4. Assembly Analysis

### PassThrough Dispatch & Validation Path (Unpatched)

The unpatched dispatch function (`PortPassThroughSendAsync`, `sub_1c002a3dc`) and validator (`PortPassThroughValidateNormalizedRequest`, `sub_1c002a63c`) parse the caller input and feed it to the initializer.

```assembly
; --- PortPassThroughSendAsync (sub_1c002a3dc) - PassThrough Dispatch ---
0x1c002a41e : call PortPassThroughNormalize (0x1c00153c8) ; Parse ATA pass-through input
0x1c002a441 : call PortPassThroughValidateNormalizedRequest (0x1c002a63c) ; Validate input
0x1c002a454 : test ebp, ebp               ; Transfer length check
0x1c002a475 : test rcx, rax               ; Alignment mask check
0x1c002a49b : shr rcx, 0xc                ; Calculate page count
0x1c002a49f : cmp ecx, [rsp+0xc8+arg_20]  ; Check against max_pages
0x1c002a4a6 : ja 0x1c002a4b1              ; -> STATUS_INVALID_PARAMETER
0x1c002a4f9 : call PortPassThroughBuildIrpEx (0x1c0015678) ; Build IRP/MDL
0x1c002a5af : call qword [ExAllocatePoolWithTag] ; Allocate async context
0x1c002a621 : call qword [IofCallDriver]  ; Forward to miniport

; --- PortPassThroughValidateNormalizedRequest (sub_1c002a63c) ---
; WinPE gate for task-file command 0x48 (removed in patched build)
0x1c002a658 : cmp byte [rcx+0x24], 0x48   ; Command == 0x48?
0x1c002a66c : jnz 0x1c002a6e5             ; Not 0x48 -> skip registry probe
0x1c002a66e : lea rdx, aRegistryMachin_3  ; '\Registry\Machine\System\...\MiniNT'
0x1c002a679 : call RtlInitUnicodeString
0x1c002a6a5 : mov edx, 0x20019            ; KEY_READ
0x1c002a6bd : call ZwOpenKey              ; Probes registry key existence
0x1c002a6cb : jns 0x1c002a6d4             ; Success -> continue
0x1c002a6cd : mov eax, 0xc00000bb         ; STATUS_NOT_SUPPORTED

; Inline sector-range arithmetic (equivalent overflow check)
0x1c002a6f2 : mov edx, dword [rbx+0x20]   ; Start sector
0x1c002a6f9 : movzx ecx, al              ; Sector count (byte)
0x1c002a6fc : add ecx, edx               ; End = start + count
0x1c002a6fe : cmp ecx, edx               ; Overflow check
0x1c002a700 : cmovnb r8d, ecx            ; Conditional move
0x1c002a704 : jb 0x1c002a744             ; Overflow -> STATUS_INVALID_PARAMETER
```

### Validator (Patched) — Gate Removed, Overflow Check via Helper

```assembly
; --- PortPassThroughValidateNormalizedRequest (sub_1c002fba4) ---
; No command==0x48 check and no ZwOpenKey/MiniNT probe: the function begins
; directly at the bounds check.
0x1c002fbbc : cmp byte [rcx+6], 0x10      ; Block-count bound
0x1c002fbd1 : mov ecx, [rcx+0x20]         ; Start sector (ulAugend)
0x1c002fbd9 : mov edx, eax                ; Sector count (ulAddend)
0x1c002fbdb : call RtlULongAdd (0x1c0013808) ; End = start + count with overflow status
0x1c002fbe2 : js 0x1c002fc29             ; Overflow -> STATUS_INVALID_PARAMETER
```

### KAPC_STATE Zero-Init (Unpatched vs Patched)

The attach path in `PortPassThroughBuildIrpEx` is identical apart from the added zero-fill in the patched build. In both builds the detach and any read of the structure are gated on the attach flag that is set only after `KeStackAttachProcess` returns.

```assembly
; UNPATCHED PortPassThroughBuildIrpEx (sub_1c0015678) - no zero-init:
0x1c0015755 : call IoGetRequestorProcess
0x1c0015769 : call IoGetCurrentProcess
0x1c0015775 : cmp rdi, rax               ; requestor != current?
0x1c001577a : lea rdx, [rsp+ApcState]
0x1c0015782 : call KeStackAttachProcess  ; populates KAPC_STATE
0x1c001578e : mov sil, 1                  ; attach flag set only here
0x1c0015791 : mov [rsp+var_88], sil
0x1c00157b8 : test sil, sil               ; detach gated on the flag
0x1c00157bd : call KeUnstackDetachProcess

; PATCHED PortPassThroughBuildIrpEx (sub_1c0005b48) - adds zero-init:
0x1c0005b7b : xorps xmm0, xmm0
0x1c0005b7e : movups [rsp+ApcState.ApcListHead], xmm0
0x1c0005b83 : movups [rsp+ApcState.ApcListHead+0x10], xmm0
0x1c0005b88 : movups [rsp+ApcState.Process], xmm0
0x1c0005c64 : call KeStackAttachProcess  ; populates KAPC_STATE
0x1c0005c70 : mov sil, 1                  ; attach flag set only here
0x1c0005c9f : call KeUnstackDetachProcess ; detach gated on the flag
```

### IRB Context Initializer (Unpatched vs Patched)

The offsets show the equivalent flag computation between builds.

```assembly
; UNPATCHED PortPassThroughSrbInitialize (sub_1c002a7d0) - Key offsets:
0x1c002a85a : mov [rbx+0xC], eax  ; a1[3] = transfer-type flag (e.g., 0x80)
0x1c002a867 : mov [rbx+0xC], ecx  ; when arg5==NULL, store transfer_type+0x20 (e.g., 0xa0)
0x1c002a86a : mov eax, ecx        ; carry the same value into eax
0x1c002a86c : bts eax, 8          ; OR in 0x100

; PATCHED PortPassThroughSrbInitialize (sub_1c002f9d4) - Key offset:
0x1c002fa54 : or eax, 0x20        ; OR the no-data flag onto transfer type (same result)
0x1c002fa57 : bts eax, 8          ; OR in 0x100
```

---

## 5. Trigger Conditions

To exercise the ATA PassThrough path:

1.  Obtain a handle to an ATA storage device (e.g., `\\.\PhysicalDrive0` or `\\.\ScsiX:`) from user mode. (Note: This typically requires administrative privileges, depending on device ACLs).
2.  Construct an `ATA_PASS_THROUGH_DIRECT` structure (InputBufferLength = `0x38` for 64-bit, first DWORD = `0x38`).
3.  Set the following fields in the structure:
    *   `DataTransferLength`: Set to any non-zero value (parsed at struct offset `0xC`).
    *   `CurrentTaskFile`: Valid command/direction bits (parsed at struct offset `0x24`).
    *   `DataBuffer`: Set explicitly to `NULL` (0).
4.  Send the buffer to the device via `DeviceIoControl` using an ATA pass-through IOCTL that routes to `PortPassThroughSendAsync`.
5.  **Effect on the IRB flags:** In both builds the IRB control-flags field is set to `transfer_type | 0x20 | 0x100`; the value is identical, so the no-data-buffer case produces no differential behavior between the two drivers.

The cross-process MDL probe path in `PortPassThroughBuildIrpEx` is reached when the requesting process differs from the current process. On the unpatched build the `KAPC_STATE` passed to `KeStackAttachProcess` is not zero-initialized, but the structure is written by `KeStackAttachProcess` before it is ever read (Finding 3), so there is no observable behavioral difference between the builds on this path either.

---

## 6. Exploit Primitive & Development Notes

*   **Primitive:** None. The IRB control-flag computation yields identical values in both builds, so it provides no exploit primitive. The `KAPC_STATE` zero-initialization added in the patched build is defense-in-depth: `KeStackAttachProcess` populates the structure on entry, and in both builds `KeUnstackDetachProcess` and every read of the structure are gated on a flag set only after that call, so no uninitialized value is ever consumed. The WinPE registry-gate removal makes the patched build less restrictive for command `0x48` but unlocks no demonstrable dangerous primitive, and command `0x48` remains subject to the same range and device-limit checks.
*   **Development Notes:**
    1.  The attach flag (`sil` / `var_88`) is set to `1` only on the instruction immediately after `KeStackAttachProcess`; the detach and any read of the `KAPC_STATE` are gated on that flag in both builds, so there is no error path that inspects the structure before it is populated.
    2.  The pass-through flag path requires no further analysis because it is behaviorally equivalent to the patched driver.
*   **Mitigations:**
    *   Standard kernel mitigations (SMEP, SMAP, CFG) apply normally; no DMA-based bypass is implied because the flag computation is unchanged.
    *   HVCI/VBS and KASLR are unaffected by these changes.

---

## 7. Debugger PoC Playbook

This playbook is for a researcher with a kernel debugger (WinDbg/KD) attached to the two builds to confirm that the analyzed changes produce no differential security-relevant behavior.

### Breakpoints
*   `bp ataport+0x1c002a3dc` — **PassThrough Dispatch Entry.** Inspect the raw caller buffer. `rcx` = DeviceObject, `rdx` = pointer to the normalized input struct. View the `DataTransferLength` (offset `0xC`) and `DataBuffer` (offset `0x10`) fields.
*   `bp ataport+0x1c002a63c` — **Secondary Validator (unpatched).** Confirm your input isn't rejected by the bounds check or the WinPE registry gate (for command `0x48`). Step over `0x1c002a6fc` (`add ecx, edx`) to observe the inline sector-range overflow check. The patched validator (`sub_1c002fba4`) has no registry gate and uses `RtlULongAdd` for the same overflow check.
*   `bp ataport+0x1c002a7d0` — **IRB Initializer.** Step through to observe the flag calculation.
*   `bp ataport+0x1c0015782` — **Cross-Process MDL Probe.** Break just before `KeStackAttachProcess` on the unpatched build to inspect the stack-local `KAPC_STATE`.

### Key Instructions/Offsets to Trace
Inside `ataport!PortPassThroughSrbInitialize (sub_1c002a7d0)`:
1.  At `0x1c002a85a`: Observe `rbx[0xC]` initialized with the primary transfer type (e.g., `0x80`).
2.  At `0x1c002a867`: Because `arg5` (DataBuffer) is NULL, execution hits this instruction. Observe `rbx[0xC]` set to `transfer_type + 0x20` (e.g., `0xa0`); the transfer-type bits are preserved, so the final field value matches the patched build.
3.  Inside `ataport!PortPassThroughBuildIrpEx (sub_1c0015678)`: at `0x1c0015782`, dump the `KAPC_STATE` argument before `KeStackAttachProcess`. On the unpatched build it holds residual stack data; the patched build (`0x1c0005b7b`-`0x1c0005b88`) zero-fills it first. In both builds the structure is written by `KeStackAttachProcess` before any read, so the difference is not observable downstream.

### Trigger Setup
1.  Compile a C++ user-mode application.
2.  Use `CreateFileW` to open `\\.\PhysicalDrive0` with `GENERIC_READ | GENERIC_WRITE`.
3.  Zero out a buffer of `0x38` bytes. Set `buffer[0]` = `0x38` (length). Set the `DataTransferLength` field at offset `0xC` to `0x1000`. Set the `DataBuffer` field at offset `0x10` to `NULL`.
4.  Send via `DeviceIoControl` with an ATA pass-through IOCTL that routes to `PortPassThroughSendAsync`.

### Expected Observation
At `PortPassThroughSrbInitialize`, the IRB control-flags field (`rbx[0xC]`) is set to `transfer_type | 0x20 | 0x100` in the no-data-buffer case; this value is identical to the patched build. At the `KeStackAttachProcess` call, the unpatched `KAPC_STATE` contains residual stack contents and the patched one is zero, but neither build reads the structure before `KeStackAttachProcess` populates it, so no differential behavior is observable. All three analyzed changes are behavior-preserving with respect to security.

---

## 8. Changed Functions — Full Triage

*   **`PortPassThroughSrbInitialize (sub_1c002a7d0)` -> `PortPassThroughSrbInitialize (sub_1c002f9d4)`** (Sim: 0.0): **[INFORMATIONAL]** IRB control-flag computation restructured. The unpatched no-data-buffer path stores `transfer_type + 0x20` (0xa0/0x60/0xe0) via `lea ecx, [rax+0x20]`, while the patched path ORs `0x20` onto the transfer type via `or eax, 0x20`. Because bit `0x20` is clear in `0x80`/`0x40`/`0xc0`, both builds produce the identical final field value in every case. No behavioral change.
*   **`PortPassThroughValidateNormalizedRequest (sub_1c002a63c)` -> `PortPassThroughValidateNormalizedRequest (sub_1c002fba4)`** (Sim: 0.0): **[INFORMATIONAL]** Removed the WinPE registry probe (`ZwOpenKey` on the `MiniNT` key) that gated command `0x48`, and replaced the inline sector-range overflow check (`add ecx, edx; cmp ecx, edx; cmovnb; jb`) with the `RtlULongAdd (sub_1c0013808)` helper. The inline check and the helper produce equivalent 32-bit overflow handling. The gate removal makes the patched build less restrictive (a cross-version policy change), not a security fix, and command `0x48` remains subject to the same range and device-limit validation in both builds.
*   **`PortPassThroughSendAsync (sub_1c002a3dc)` -> `PortPassThroughSendAsync (sub_1c002f7d4)`** (Sim: 0.686): **[BEHAVIORAL]** Refactored inline validation into a dedicated function (`PortPassThroughValidate (sub_1c002faa0)`) and migrated the async-context allocation from `ExAllocatePoolWithTag` to `ExAllocatePool2`. The alignment/size/page-count validation is mathematically identical between versions. No direct exploitability change.
*   **`PortPassThroughBuildIrpEx (sub_1c0015678)` -> `PortPassThroughBuildIrpEx (sub_1c0005b48)`** (Sim: 0.9906): **[DEFENSE-IN-DEPTH]** Added explicit zero-initialization (`xorps`/`movups`) of the stack-local `KAPC_STATE` before `KeStackAttachProcess`. In both builds the structure is only read after `KeStackAttachProcess` populates it (the detach is gated on a flag set only after the attach call), so this has no reachable effect on behavior; it is consistent with newer-toolchain stack initialization rather than a fix for a consumed uninitialized value.
*   **`IdeProcessCompletedRequests (sub_1C000D8D0)` -> `IdeProcessCompletedRequests (sub_1C00036A0)`** (Sim: 0.5168): **[TELEMETRY]** Massive churn due to expanded ETW tracing (`EtwWrite`, `IoGetActivityIdIrp`) and added power management requests (`PoRequestPowerIrp`). Not security relevant.

*Note: The large number of functions marked as "changed" with high similarity scores (e.g., >0.90) are entirely cosmetic, representing compiler version differences, register allocation swaps, or basic block reordering.*

---

## 9. Unmatched Functions

*   **Added:** 0
*   **Removed:** 0
There are no unmatched functions. The diff relies entirely on modifying existing logic rather than introducing or removing standalone routines.

---

## 10. Confidence & Caveats

*   **Confidence:** **High.** No reachable security-relevant change was found in the analyzed functions. The IRB control-flag computation is functionally equivalent between builds (`transfer_type + 0x20 == transfer_type | 0x20` because bit `0x20` is clear in `0x80`/`0x40`/`0xc0`). The `KAPC_STATE` zero-initialization in `PortPassThroughBuildIrpEx` has no reachable impact because in both builds the structure is written by `KeStackAttachProcess` before it is ever read, and the detach is gated on a flag set only after that call. The WinPE registry-gate removal in `PortPassThroughValidateNormalizedRequest` is a cross-version policy change that makes the patched build less restrictive, not a security fix, and the accompanying sector-range change is an equivalent refactor to `RtlULongAdd`.
*   **Assumptions:**
    *   The analysis assumes the target device's ACL permits user-mode opening of the Physical Drive handle (which is standard for Administrator contexts).
    *   The exact IOCTL routing to `PortPassThroughSendAsync (sub_1c002a3dc)` was taken from the `ATA_PASS_THROUGH_DIRECT` layout observed in the parser; a researcher can confirm the exact IOCTL code via the IRP dispatch table.
*   **Verification Required:** None of the three analyzed changes yields a differential security-relevant behavior between the builds. A researcher wishing to reconfirm can trace the IRB flag field and the `KAPC_STATE` argument as described in Section 7 and observe identical downstream behavior.
