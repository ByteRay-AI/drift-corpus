Title: cdrom.sys — Request IRP AssociatedIrp.SystemBuffer left dangling after synchronous forward in RequestHandleVolumeOnline (CWE-459) fixed
Date: 2026-03-10
Slug: cdrom_ad9dd120-cdrom-report-20260626-132557
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Medium
KBDate: 2026-03-10

### 1. Overview
- **Unpatched Binary:** `cdrom_unpatched.sys`
- **Patched Binary:** `cdrom_patched.sys`
- **Overall Similarity:** 0.9928
- **Diff Statistics:** Matched: 317 | Changed: 1 | Identical: 316 | Unmatched: 0
- **Verdict:** The patch fixes an incomplete-cleanup bug in the CD-ROM class driver. `RequestHandleVolumeOnline` temporarily repurposes the request IRP's `AssociatedIrp.SystemBuffer` field to point into the device extension while it synchronously forwards the request to the volume I/O target, but the unpatched build never restores the field before returning. The patch adds a save-before-overwrite / restore-after-send pair.

### 2. Vulnerability Summary
- **Severity:** Medium
- **Vulnerability Class:** Incomplete cleanup — a temporarily overwritten IRP pointer field is not restored (CWE-459: Incomplete Cleanup)
- **Affected Function:** `RequestHandleVolumeOnline @ 0x1C0009328` (handler for `IOCTL_VOLUME_ONLINE` `0x56C008` and `IOCTL_VOLUME_POST_ONLINE` `0x56C064`)

**Root Cause:**
In `RequestHandleVolumeOnline`, the handler obtains the WDM IRP backing the current request by calling `WdfRequestWdmGetIrp` (WDF function-table slot `+0x8E8`) on the request handle (`a2`). It then reads the IRP's current stack location from `IRP+0xB8`, and overwrites `IRP+0x18` — the `AssociatedIrp.SystemBuffer` field — with `device_extension + 0x68`. This provides the data buffer for the request that is then synchronously forwarded to the volume I/O target via `RequestSend` (called with option flag `2` = `WDF_REQUEST_SEND_OPTION_SYNCHRONOUS`).

In the unpatched build the function returns immediately after the synchronous send without restoring `AssociatedIrp.SystemBuffer` to its original value. The IRP therefore continues to hold `device_extension + 0x68` in `SystemBuffer` when the original buffered IOCTL request completes back to its caller. For a `METHOD_BUFFERED` request the I/O manager's completion path consumes `AssociatedIrp.SystemBuffer` (buffer copy-back / deallocation), so it operates on device-extension memory instead of the framework-owned system buffer. The most direct consequence is a free of a pointer that is not the original allocation (pool corruption / bugcheck) and, where output is copied back, limited exposure of adjacent device-extension bytes.

This is a per-request defect on the specific request being handled. It is not a modification of a device-lifetime shared object, and it does not by itself corrupt unrelated subsequent I/O.

**Attacker-Reachable Entry Point & Data Flow:**
1. **User Mode:** `DeviceIoControl(\\.\CdRom0, 0x56C008 or 0x56C064, ...)`
2. **Serialized dispatch:** the request is serviced on the driver's serialized IOCTL work item `IoctlWorkItemRoutine @ 0x1C00189F0`.
3. **IOCTL Router:** `RequestProcessSerializedIoctl @ 0x1C0018BD4` switches on the IOCTL code and routes `0x56C008` / `0x56C064` to `RequestHandleVolumeOnline`.
4. **IRP Retrieval:** `RequestHandleVolumeOnline` calls `WdfRequestWdmGetIrp` to obtain the request's WDM IRP (`v6`).
5. **Temporary overwrite:** it sets `IRP->AssociatedIrp.SystemBuffer` (`v6+0x18`) to `device_extension + 0x68`.
6. **Synchronous send:** it calls `RequestSend` to forward the request to the volume I/O target and blocks until completion.
7. **Missing restore:** the unpatched function returns without restoring `AssociatedIrp.SystemBuffer`, leaving the IRP pointer dangling into the device extension when the original request completes.

### 3. Pseudocode Diff
The unpatched version overwrites the IRP's `AssociatedIrp.SystemBuffer` and never restores it; the patched version saves the original value and writes it back after the synchronous send.

```c
// --- UNPATCHED RequestHandleVolumeOnline @ 0x1C0009328 ---
v6 = WdfRequestWdmGetIrp(a2);            // per-request WDM IRP
v7 = *(_QWORD *)(v6 + 184);             // IRP current stack location (IRP+0xB8)
// BUG: no save of the original SystemBuffer
*(_QWORD *)(v6 + 24) = a1 + 104;        // IRP->AssociatedIrp.SystemBuffer = devext+0x68
*(_DWORD *)(v7 - 64) = 0;
*(_DWORD *)(v7 - 56) = 4;
*(_DWORD *)(v7 - 48) = 0x7C220;
RequestSend(a1, a2, *(a1 + 24), 2, 0);  // synchronous forward to volume I/O target
// MISSING: *(_QWORD *)(v6 + 24) = original_value;
return 0;

// --- PATCHED RequestHandleVolumeOnline @ 0x1C0009328 ---
v6 = WdfRequestWdmGetIrp(a2);
v7 = *(_QWORD *)(v6 + 184);
v8 = *(_QWORD *)(v6 + 24);              // FIX: save original AssociatedIrp.SystemBuffer
*(_QWORD *)(v6 + 24) = a1 + 104;        // temporary overwrite
*(_DWORD *)(v7 - 64) = 0;
*(_DWORD *)(v7 - 56) = 4;
*(_DWORD *)(v7 - 48) = 0x7C220;
RequestSend(a1, a2, *(a1 + 24), 2, 0);
*(_QWORD *)(v6 + 24) = v8;              // FIX: restore original AssociatedIrp.SystemBuffer
return 0;
```

### 4. Assembly Analysis
The fix appears as an added save before the overwrite and an added restore after the send call. The following listings are copied from the authoritative disassembly of each build.

**Unpatched (`RequestHandleVolumeOnline @ 0x1C0009328`, key sequence)**
```assembly
0x1C00093B7  mov     rax, [rax+8E8h]                ; WdfRequestWdmGetIrp slot
0x1C00093BE  call    cs:__guard_dispatch_icall_fptr ; rax = request IRP
0x1C00093C4  and     [rsp+38h+var_18], 0
0x1C00093CA  lea     rcx, [rbx+68h]                 ; rcx = device_extension + 0x68
0x1C00093CE  mov     r9d, 2                         ; WDF_REQUEST_SEND_OPTION_SYNCHRONOUS
0x1C00093D4  mov     rdx, [rax+0B8h]                ; rdx = IRP current stack location
0x1C00093DB  mov     [rax+18h], rcx                 ; overwrite IRP->AssociatedIrp.SystemBuffer, NO SAVE
0x1C00093DF  mov     rcx, rbx
0x1C00093E2  and     dword ptr [rdx-40h], 0
0x1C00093E6  mov     dword ptr [rdx-38h], 4
0x1C00093ED  mov     dword ptr [rdx-30h], 7C220h
0x1C00093F4  mov     rdx, rdi
0x1C00093F7  mov     r8, [rbx+18h]                  ; r8 = device I/O target (devext+0x18)
0x1C00093FB  call    RequestSend                    ; synchronous forward
0x1C0009400  mov     rbx, [rsp+38h+arg_0]           ; restores callee-saved rbx only
0x1C0009405  xor     eax, eax
0x1C0009407  add     rsp, 30h
0x1C000940B  pop     rdi
0x1C000940C  retn                                   ; returns; SystemBuffer NOT restored
```

**Patched (`RequestHandleVolumeOnline @ 0x1C0009328`, key sequence)**
```assembly
0x1C00093C0  mov     rax, [rax+8E8h]                ; WdfRequestWdmGetIrp slot
0x1C00093C7  call    cs:__guard_dispatch_icall_fptr ; rax = request IRP
0x1C00093CD  and     [rsp+38h+var_18], 0
0x1C00093D3  lea     rcx, [rsi+68h]                 ; rcx = device_extension + 0x68
0x1C00093D7  mov     r9d, 2
0x1C00093DD  mov     rdi, rax                       ; rdi = IRP
0x1C00093E0  mov     rdx, [rax+0B8h]
0x1C00093E7  mov     rbx, [rax+18h]                 ; SAVE original AssociatedIrp.SystemBuffer
0x1C00093EB  mov     [rax+18h], rcx                 ; overwrite (temporary)
0x1C00093EF  mov     rcx, rsi
0x1C00093F2  and     dword ptr [rdx-40h], 0
0x1C00093F6  mov     dword ptr [rdx-38h], 4
0x1C00093FD  mov     dword ptr [rdx-30h], 7C220h
0x1C0009404  mov     rdx, rbp
0x1C0009407  mov     r8, [rsi+18h]
0x1C000940B  call    RequestSend
0x1C0009410  mov     rbp, [rsp+38h+arg_8]
0x1C0009415  xor     eax, eax
0x1C0009417  mov     rsi, [rsp+38h+arg_18]
0x1C000941C  mov     [rdi+18h], rbx                 ; RESTORE original AssociatedIrp.SystemBuffer
0x1C0009420  mov     rbx, [rsp+38h+arg_0]
0x1C0009425  add     rsp, 30h
0x1C0009429  pop     rdi
0x1C000942A  retn
```

### 5. Trigger Conditions
1. Obtain a handle to a CD-ROM device via `CreateFileW("\\\\.\\CdRom0", ...)` with access sufficient to issue the volume IOCTLs (these codes carry `FILE_READ_ACCESS | FILE_WRITE_ACCESS`).
2. Send `DeviceIoControl` with `dwIoControlCode = 0x56C008` (`IOCTL_VOLUME_ONLINE`) or `0x56C064` (`IOCTL_VOLUME_POST_ONLINE`). The request is serialized onto `IoctlWorkItemRoutine`, routed by `RequestProcessSerializedIoctl`, and handled by `RequestHandleVolumeOnline`, which overwrites the request IRP's `AssociatedIrp.SystemBuffer` and forwards the request synchronously without restoring the field.
3. **Observable effect (unpatched):** when the request completes, the `METHOD_BUFFERED` completion path uses `AssociatedIrp.SystemBuffer = device_extension + 0x68` instead of the framework-owned system buffer. The plausible outcomes are a deallocation of a pointer that is not the original allocation (pool corruption, typically a bugcheck) and, where output is copied back to the caller, exposure of adjacent device-extension bytes. The exact outcome depends on the request's buffered-I/O completion flags and reported `Information` length.

### 6. Impact Assessment
- **Nature:** Incomplete cleanup of a temporarily borrowed IRP pointer field (`AssociatedIrp.SystemBuffer`).
- **Mechanism:** The handler borrows `IRP->AssociatedIrp.SystemBuffer` to supply the data buffer (`device_extension + 0x68`) for the request it synchronously forwards to the volume I/O target. Because the send is synchronous, the borrow is only needed for the duration of the call; the patched build restores the original pointer immediately afterward. The unpatched build leaves the borrowed pointer in place, so the buffered-IOCTL completion machinery later acts on device-extension memory.
- **Reachable impact:** kernel pool corruption / bugcheck from freeing a non-allocation pointer, and limited kernel-memory exposure on copy-back. This is a per-request effect; it does not persist as a modification of a shared device-lifetime object.
- **Not demonstrated:** an arbitrary kernel read/write primitive, a controlled pool-spray/overwrite chain, or any control-flow hijack. The field value written (`device_extension + 0x68`) is fixed by driver layout, not attacker-supplied, so this is not a controllable write-what-where.

### 7. Debugger Notes
To observe the behaviour on the **unpatched** binary with a kernel debugger:

**Breakpoints (offsets relative to `cdrom!RequestHandleVolumeOnline` base `0x1C0009328`):**
- Entry `+0x0` (`0x1C0009328`): `rcx` = device-extension pointer (`a1`), `rdx` = request handle (`a2`).
- Overwrite `+0xB3` (`0x1C00093DB`): `rax` = the request's WDM IRP; `rcx` = `device_extension + 0x68`. Read `dq @rax+18 L1` before this instruction to capture the original `AssociatedIrp.SystemBuffer`; step over and read again to see it replaced by `device_extension + 0x68`.

**What to inspect:**
At function exit (`0x1C000940C` `retn` in the unpatched build) inspect the IRP captured at the overwrite: `IRP+0x18` still holds `device_extension + 0x68` rather than the original system-buffer pointer. On the patched build the same field is restored by the instruction at `0x1C000941C` (`mov [rdi+18h], rbx`) before the function returns.

**Trigger from user mode:**
```cpp
HANDLE hDevice = CreateFileW(L"\\\\.\\CdRom0", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DWORD bytesReturned = 0;
UCHAR inputBuffer[INPUT_SIZE];
DeviceIoControl(hDevice, 0x56C008, inputBuffer, sizeof(inputBuffer), NULL, 0, &bytesReturned, NULL);
```

### 8. Changed Functions — Full Triage
- **`RequestHandleVolumeOnline @ 0x1C0009328`** (Similarity: 0.9515)
  - **Change Type:** Security Relevant
  - **Notes:** Register allocation changed (`rdi` now holds the IRP, `rsi` holds `a1`, `rbp` holds `a2`, `rbx` holds the saved field value). A save (`mov rbx, [rax+18h]` at `0x1C00093E7`) and a restore (`mov [rdi+18h], rbx` at `0x1C000941C`) were added around the `RequestSend` call so that `IRP->AssociatedIrp.SystemBuffer` is preserved across the synchronous forward. This fixes the incomplete-cleanup defect.
- *Note: The remaining 316 matched functions are identical or feature only cosmetic/spatial compilation differences with no functional impact.*

### 9. Unmatched Functions
- None. Both binaries feature identical function counts and boundaries.

### 10. Confidence & Caveats
- **Confidence:** High that the change is a real save/restore of `IRP->AssociatedIrp.SystemBuffer` around a synchronous forward, and that the unpatched build omits the restore. The function, addresses, instructions, and direction all match both builds.
- **Assumptions:** `0x56C008` and `0x56C064` are assumed reachable by a process holding a handle to the CD-ROM device with the access these codes require (`FILE_READ_ACCESS | FILE_WRITE_ACCESS`). These volume IOCTLs are normally issued by the volume/mount manager; the handler contains no explicit privilege check.
- **Verification required:** the precise downstream effect (wrong-pointer free versus copy-back of device-extension bytes versus benign) depends on the buffered-I/O completion flags and the `Information` length reported for the completing request, which are not fully determinable from the static images alone. The device-extension layout at `+0x68` should be inspected to characterise what memory is exposed on copy-back.
