Title: dxgkrnl.sys — Use-After-Free (CWE-416) — missing reference count on DXGSHAREDVMOBJECT in DXG_HOST_REMOTEOBJECTCHANNEL::ProcessChannelMessage fixed
Date: 2026-06-26
Slug: dxgkrnl_6ac125d5-dxgkrnl-report-20260626-092344
Category: Corpus
Author: Argus
Summary: KB5073724
Severity: Critical

## 1. Overview

- **Unpatched Binary**: `dxgkrnl_unpatched.sys`
- **Patched Binary**: `dxgkrnl_patched.sys`
- **Overall Similarity**: 0.99 (99%)
- **Diff Statistics**:
  - Matched Functions: 6897
  - Changed Functions: 38
  - Identical Functions: 6859
  - Unmatched Functions: 0 (Unpatched), 0 (Patched)

**Verdict**: The patch remediates multiple critical vulnerabilities in the GPU paravirtualization (VMBus) interfaces of `dxgkrnl.sys`, most notably a Use-After-Free (UAF) in the Remote Object Channel and a cross-device memory access bypass, both enabled by security checks being improperly gated behind disabled feature flags.

---

## 2. Vulnerability Summary

The patch addresses several critical flaws stemming from missing locks, missing reference counting, and bypassed authorization checks—most of which were erroneously gated behind internal feature-staging flags in the unpatched build.

### Finding 1: Use-After-Free in `ProcessChannelMessage`
- **Severity**: Critical
- **Vulnerability Class**: Use-After-Free (CWE-416)
- **Affected Function**: `DXG_HOST_REMOTEOBJECTCHANNEL::ProcessChannelMessage`
- **Root Cause**: When processing VMBus message type 1 (CreateBundle, size 0x58), the handler iterates over guest-supplied shared VM object handles. The unpatched code only calls `DXGSHAREDVMOBJECT::AddReference()` if `Feature_1259646266__private_IsEnabledDeviceUsage()` returns true. Because this flag is disabled by default, the object pointer is used to read data (`+0x8` and `+0x0`) without holding a reference. A concurrent thread or VMBus message (e.g., type 3 DestroyBundle) can free the object, causing the kernel to read from reclaimed pool memory.
- **Entry Point & Data Flow**:
  1. Malicious guest VM sends VMBus packet to `DXG_HOST_REMOTEOBJECTCHANNEL`.
  2. `VmBusProcessPacket` dispatches the packet to `ProcessChannelMessage`.
  3. Handler matches message type 1, size 0x58.
  4. Iterates array of handles at `arg2+0x18` (count at `arg2+0x10`).
  5. Looks up `DXGSHAREDVMOBJECT` from handle table.
  6. Skips `AddReference` due to disabled feature flag, leaving a dangling pointer.

### Finding 2: Cross-Device Memory Access in `VmBusBlt`
- **Severity**: High
- **Vulnerability Class**: Missing Authorization / Confused Deputy (CWE-863)
- **Affected Function**: `DXG_HOST_VIRTUALGPU_VMBUS::VmBusBlt`
- **Root Cause**: While handling `DXGKVMB_COMMAND_BLT` from a guest VM, the unpatched code validates that the provided DXGCONTEXT belongs to the provided DXGDEVICE by comparing `context->device` pointers. However, this critical isolation check is bypassed if `Feature_611095865` returns false. A malicious guest can intentionally mismatch device and context handles to execute a BLT (memory copy) operation across device boundaries, breaking VM-to-VM or process-to-process isolation on the GPU.
- **Entry Point & Data Flow**:
  1. Guest VM sends `DXGKVMB_COMMAND_BLT` over the virtual GPU VMBus.
  2. `VmBusBlt` extracts the target context and device handles.
  3. The function skips the ownership validation check due to the feature flag.
  4. The BLT command proceeds with unauthorized memory access.

### Finding 3: Missing Resource Reference in `VmBusCreateNtSharedObject`
- **Severity**: High
- **Vulnerability Class**: Missing Reference Count (CWE-911)
- **Affected Function**: `DXG_HOST_GLOBAL_VMBUS::VmBusCreateNtSharedObject`
- **Root Cause**: If the handle table entry type is `0x4` (`DXGRESOURCE`), the code is supposed to create a `DXGRESOURCEREFERENCE` for safe tracking. The unpatched code skips this reference creation if `Feature_309893433` is disabled, while still sharing the object. This leads to a potential UAF when the underlying resource is destroyed.

### Finding 4: Race Conditions in Pin/Unpin Operations
- **Severity**: Medium to High
- **Vulnerability Class**: Race Condition (CWE-362)
- **Affected Functions**: `DXGDEVICE::PinResources`, `DXGDEVICE::UnpinResource`, `DXGCONTEXT::RenderKmLda`, `DXG_HOST_VIRTUALGPU_VMBUS::VmBusSignalSyncObjectCblt`, `SignalSynchronizationObjectFromCpu`
- **Root Cause**: The unpatched code performs these operations without the protecting locks. The patch adds/restores the locking in two distinct directions. `DXGSYNCOBJECTLOCK::AcquireShared` already exists in the unpatched build but is gated behind `Feature_2505606457`; the patch removes that gate and makes the acquire unconditional. Per-resource `DXGAUTOMUTEX::Acquire` locking is entirely NEW in the patch (0 occurrences in the unpatched build) and is itself gated behind the newly-introduced `Feature_253710648` staging flag, i.e. a staged rollout where the lock is only taken once the flag is enabled. With the locks absent, the code modifies allocation flags, triggers GPU paging callbacks, or signals sync objects without holding the required locks, allowing concurrent modification. This locking-based hardening matches the KB's assigned CWE-362 race-condition CVEs (CVE-2026-20814, CVE-2026-20836).

---

## 3. Pseudocode Diff

### `DXG_HOST_REMOTEOBJECTCHANNEL::ProcessChannelMessage` (UAF)

```c
// UNPATCHED  (decompilation of 0x1C028C3A0, per-handle loop body)
// v35 is the DXGSHAREDVMOBJECT looked up from the guest's handle table.
v35 = *((DXGSHAREDVMOBJECT **)v30 + 2 * (unsigned int)v34);
if ( v35 == nullptr )
    break;
if ( (unsigned int)Feature_1259646266__private_IsEnabledDeviceUsage() != 0 )
{
    DXGSHAREDVMOBJECT::AddReference(v35, v36);   // reference taken only when flag is enabled
    v66[v32] = v35;                              // and only then recorded for later release
}
v67[v32]     = *((void **)v35 + 1);   // read object+0x8  (runs even when no reference was taken)
a2[v32 + 6]  = *(_DWORD *)v35;        // read object+0x0  (runs even when no reference was taken)

// PATCHED  (decompilation of 0x1C028C490, same loop body)
v35 = *((DXGSHAREDVMOBJECT **)v30 + 2 * (unsigned int)v34);
if ( v35 == nullptr )
    break;
DXGSHAREDVMOBJECT::AddReference(v35, v33);   // reference taken unconditionally
v64[v32]     = *((void **)v35 + 1);   // read object+0x8, reference now held
a2[v32 + 6]  = *(_DWORD *)v35;        // read object+0x0, reference now held
v63[v32]     = v35;                   // recorded for later release, unconditionally
```

---

## 4. Assembly Analysis

### `DXG_HOST_REMOTEOBJECTCHANNEL::ProcessChannelMessage`

**Unpatched Assembly (Vulnerable Sequence, 0x1C028C3A0)**
```assembly
00000001C028C73C  mov     r12, [r8+r12*8]      ; look up DXGSHAREDVMOBJECT from handle table
00000001C028C740  test    r12, r12
00000001C028C743  jz      loc_1C028C7CC
00000001C028C749  call    Feature_1259646266__private_IsEnabledDeviceUsage  ; 0x1C00281DC
00000001C028C74E  test    eax, eax
00000001C028C750  jz      short loc_1C028C75F  ; flag disabled: skip AddReference and the ref-array store
00000001C028C752  mov     rcx, r12
00000001C028C755  call    ?AddReference@DXGSHAREDVMOBJECT@@QEAAJXZ  ; 0x1C0238ED8
00000001C028C75A  mov     [rbp+r13*8+110h+var_150], r12  ; record object for later release
00000001C028C75F  mov     rax, [r12+8]         ; read object+0x8 without a reference held
00000001C028C764  mov     [rbp+r13*8+110h+var_D0], rax
00000001C028C769  mov     eax, [r12]           ; read object+0x0 without a reference held
00000001C028C76D  mov     [rsi+r13*4+18h], eax
00000001C028C772  mov     eax, [rsp+210h+var_1E0]
00000001C028C776  inc     eax
00000001C028C778  mov     [rsp+210h+var_1E0], eax
00000001C028C77C  cmp     eax, [rsi+10h]
00000001C028C77F  jnb     loc_1C028C805
00000001C028C785  mov     r12, [rsp+210h+var_1D8]
00000001C028C78A  jmp     loc_1C028C6D4        ; next handle
```

**Patched Assembly (Fixed Sequence, 0x1C028C490)**
```assembly
00000001C028C82C  mov     r12, [r8+r12*8]      ; look up DXGSHAREDVMOBJECT from handle table
00000001C028C830  test    r12, r12
00000001C028C833  jz      short loc_1C028C8AF
00000001C028C835  mov     rcx, r12
00000001C028C838  call    ?AddReference@DXGSHAREDVMOBJECT@@QEAAJXZ  ; 0x1C0238A98, no feature-flag gate
00000001C028C83D  mov     rax, [r12+8]         ; read object+0x8, reference now held
00000001C028C842  mov     [rbp+r13*8+110h+var_D0], rax
00000001C028C847  mov     eax, [r12]           ; read object+0x0, reference now held
00000001C028C84B  mov     [rsi+r13*4+18h], eax
00000001C028C850  mov     eax, [rsp+210h+var_1E0]
00000001C028C854  inc     eax
00000001C028C856  mov     [rbp+r13*8+110h+var_150], r12  ; record object for later release, unconditionally
00000001C028C85B  mov     [rsp+210h+var_1E0], eax
00000001C028C85F  cmp     eax, [rsi+10h]
00000001C028C862  jnb     loc_1C028C8E8
00000001C028C868  mov     r12, [rsp+210h+var_1D8]
00000001C028C86D  jmp     loc_1C028C7C4        ; next handle
```

### `DXG_HOST_VIRTUALGPU_VMBUS::VmBusBlt`

**Unpatched Assembly (Vulnerable Sequence, 0x1C023D020)**
```assembly
00000001C023D1E0  call    Feature_611095865__private_IsEnabledDeviceUsage  ; 0x1C0026B38
00000001C023D1E5  mov     rcx, [rsp+1A0h+var_148]  ; context object
00000001C023D1EA  test    eax, eax
00000001C023D1EC  jz      short loc_1C023D20E      ; flag disabled: skip the ownership check entirely
00000001C023D1EE  cmp     [rcx+10h], r14           ; context->device vs supplied device
00000001C023D1F2  jz      short loc_1C023D20E      ; match: proceed
00000001C023D1F4  call    cs:__imp_WdLogNewEntry5_WdError  ; mismatch: reject
00000001C023D1FB  nop     dword ptr [rax+rax+00h]
00000001C023D200  mov     rcx, rax
00000001C023D203  mov     rax, [rsp+1A0h+var_148]
00000001C023D208  mov     [rcx+20h], r14
00000001C023D20C  jmp     short loc_1C023D1B0
00000001C023D20E  add     rcx, 1D0h               ; proceed: acquire context push lock and run the BLT
```

**Patched Assembly (Fixed Sequence, 0x1C023CBE0)**
```assembly
00000001C023CD57  mov     rcx, [rsp+1A0h+var_148]  ; context object
00000001C023CD5C  test    rcx, rcx
00000001C023CD5F  jnz     short loc_1C023CDA3
; ... null-context path logs an error ...
00000001C023CDA3  cmp     [rcx+10h], r14           ; context->device vs supplied device, no feature-flag gate
00000001C023CDA7  jz      short loc_1C023CDC3      ; match: proceed
00000001C023CDA9  call    cs:__imp_WdLogNewEntry5_WdError  ; mismatch: reject
00000001C023CDB0  nop     dword ptr [rax+rax+00h]
00000001C023CDB5  mov     rcx, rax
00000001C023CDB8  mov     rax, [rsp+1A0h+var_148]
00000001C023CDBD  mov     [rcx+20h], r14
00000001C023CDC1  jmp     short loc_1C023CD73
00000001C023CDC3  add     rcx, 1D0h               ; proceed: acquire context push lock and run the BLT
```

---

## 5. Trigger Conditions

To trigger the critical UAF (`ProcessChannelMessage`):

1. Obtain access to the Hyper-V GPU Paravirtualization VMBus interface from a malicious guest VM.
2. Ensure the target host has internal feature flag `Feature_1259646266` disabled (default state).
3. Send a message of type 1 (CreateBundle) to the Remote Object Channel with a size of exactly 0x58.
4. The message structure must be formatted as follows:
   - `+0x10`: Handle count (`> 0` and `<= 0x10`)
   - `+0x14`: Flags (Bit 0 must be set to indicate shared VM objects are present)
   - `+0x18`: Array of handles resolving to valid `DXGSHAREDVMOBJECT` (type `0xd`) in the host handle table.
5. From a secondary thread or virtual CPU in the guest, immediately send a type 3 message (DestroyBundle) targeting one of the shared VM object handles provided in step 4.
6. **Race Constraint**: Because no `AddReference` is taken (feature flag disabled), the looked-up object is not kept alive by this code path. The concurrent teardown must drop the object's last reference and free it between the handle-table lookup (`mov r12, [r8+r12*8]` at `0x1c028c73c`) and the two reads (`mov rax, [r12+8]` at `0x1c028c75f` and `mov eax, [r12]` at `0x1c028c769`), so those reads land on freed pool memory.
7. **Observable Effect**: Kernel crash (BSOD) due to paged out or corrupted pool memory being accessed, or silent kernel memory corruption if the pool has been sprayed with attacker-controlled data.

---

## 6. Exploit Primitive & Development Notes

- **Provided Primitive**: The bug offers a **Kernel Use-After-Free (UAF)**. The attacker frees a `DXGSHAREDVMOBJECT` kernel pool allocation while the host kernel holds a stale pointer to it. The kernel subsequently reads from offsets `+0x0` and `+0x8` of the freed allocation.
- **Turning it into a Full Exploit**:
  1. **Heap Spray**: Reclaim the freed pool allocation (typically Nonpaged Pool) using a kernel object of identical allocation size that allows user-mode data injection. Good candidates involve `NtCreateWorkerFactory` or specific GDI objects depending on the exact size of `DXGSHAREDVMOBJECT`.
  2. **Info Leak**: Combine with a separate information leak vulnerability (or use the stale read itself if the reclaimed data contains pointers) to defeat KASLR.
  3. **Control Flow Hijack**: Although the visible unpatched sequence only shows *reads*, modifying the object's internal state via reclaimed memory could corrupt subsequent kernel operations relying on that object's lifetime or vtable.
- **Mitigations Impact**: 
  - **KASLR**: Must be bypassed to utilize kernel function pointers.
  - **Pool Integrity/SEGMENTHEAP**: Modern Windows pool segregation may require careful spray sizing to ensure the reclaimed object lands in the exact freed slot.
  - **VBS/HVCI**: If active, arbitrary write primitive development must rely on data-only attacks (corrupting privilege bits or linked lists) rather than write-what-where shellcode execution.

---

## 7. Debugger PoC Playbook

To validate and trace this vulnerability on an unpatched host with a kernel debugger (KD/WinDbg) attached:

- **Breakpoints**:
  - `bp dxgkrnl!DXG_HOST_REMOTEOBJECTCHANNEL::ProcessChannelMessage` (or `bp 0x1c028c3a0` if symbols are unavailable). This is the entry point to catch message type 1.
  - `bp 0x1c00281dc` (Target `Feature_1259646266__private_IsEnabledDeviceUsage`). Inspect the return value to confirm the vulnerable path is taken.
  - `bp 0x1c028c73c` (`mov r12, [r8+r12*8]`, the handle-table lookup that loads the `DXGSHAREDVMOBJECT` pointer; the feature-flag check follows at `0x1c028c749`).

- **What to inspect at each breakpoint**:
  - At `ProcessChannelMessage`: `rcx` holds `arg2` (the message packet). Read `poi(rcx+0x10)` for handle count, and `poi(rcx+0x14)` to verify bit 0 is set.
  - At the handle iteration loop: `r12` holds the raw pointer to the looked-up `DXGSHAREDVMOBJECT`. Monitor `r12` closely.
  - At `0x1c028c74e` (`test eax, eax`, right after the feature call): verify `eax` (return value of the feature check). If `eax == 0`, the `jz` at `0x1c028c750` jumps over `AddReference` and the ref-array store, straight to the reads at `0x1c028c75f`.

- **Key instructions/offsets**:
  - `0x1c0238ed8`: The `DXGSHAREDVMOBJECT::AddReference` call that is skipped when the flag is disabled.
  - `0x1c028c805`: `Release@DXGAUTOPUSHLOCK`, where the handle-table shared push lock is released after the loop completes.
  - `mov rax, [r12+0x8]` at `0x1c028c75f` and `mov eax, [r12]` at `0x1c028c769`: the exact instructions performing the reference-less dereference.

- **Trigger Setup**:
  - This requires a Hyper-V environment. The host runs the unpatched `dxgkrnl.sys`.
  - Spin up a guest VM with GPU-PV (GPU Paravirtualization) enabled.
  - From the guest, use custom code to interact with the virtual GPU device interface, sending raw VMBus packets. Specifically, issue a CreateBundle (type 1) with a shared VM object handle, while concurrently issuing a DestroyBundle (type 3) for the same handle.

- **Expected observation**:
  - If the race is won, the kernel debugger will halt with a Bugcheck (e.g., `PAGE_FAULT_IN_NONPAGED_AREA`).
  - The faulting instruction will be the memory read from `r12`. 
  - Inspecting `!pool r12` will show that the memory is `Free`, confirming the UAF.

---

## 8. Changed Functions — Full Triage

**Security-Critical Changes**:
- `DXG_HOST_REMOTEOBJECTCHANNEL::ProcessChannelMessage`: Removed feature flag gate for `AddReference` (Critical UAF fix).
- `DXG_HOST_VIRTUALGPU_VMBUS::VmBusBlt`: Removed feature flag gate for context/device authorization check (Confused Deputy fix).
- `DXG_HOST_GLOBAL_VMBUS::VmBusCreateNtSharedObject`: Enforced `DXGRESOURCEREFERENCE` for type 0x4 objects.
- `SignalSynchronizationObjectFromCpu`, `DXG_HOST_VIRTUALGPU_VMBUS::VmBusSignalSyncObjectCblt`, `DXG_HOST_VIRTUALGPU_VMBUS::VmBusSignalSyncObject`: Hardened sync-object locking by REMOVING the `Feature_2505606457` gate around `DXGSYNCOBJECTLOCK::AcquireShared` (unpatched gated behind the flag, patched unconditional).
- `DXGDEVICE::PinResources`, `DXGDEVICE::UnpinResource`, `DXGCONTEXT::RenderKmLda`: ADDED per-resource `DXGAUTOMUTEX::Acquire` / `DXGPUSHLOCK::AcquireShared` locking that is absent from the unpatched build; the new locking is itself gated behind the newly-introduced `Feature_253710648` staging flag (present only in the patched build).

**Behavioral / Cosmetic Changes (Bulk Triage)**:
The remaining functions (`DXGDEVICE::EvictAllResources`, `DxgEnumHandleChildrenCB`, `DxgkGetDeviceStateInternal`, `DXGCHANNELENDPOINTPROXY::FreeHandle`, `DXGDEVICE::DestroyDeferredAllocations`, `ADAPTER_RENDER::FreeResourceHandleAndWaitForZeroReferences`, `DXGDEVICE::PinDirectFlipResources`, `DXGDEVICE::DisablePinnedHardware`, `DXGDEVICE::AppendAllocationListToResourceOrDevice`, `DXGDEVICE::DestroyClientResource`, `DXGDEVICE::GetDeviceExecutionState`, `DxgkCddEvict`, `DxgkCddMakeResident`, `DXGDEVICE::OpenCddPrimaryHandle`, `MapGpuVirtualAddressToAllocation`, `DXGDEVICE::CheckMultiPlaneOverlaySupport3`, `DXGDEVICE::ReportDeviceResources`, `DxgEscapeEvictWorker`, `DxgkOpenSyncObjectFromNtHandle2Impl`, `DXGDXGIKEYEDMUTEX::OpenSharedSurfForDevice`, `REMOTEVSYNCMAPPING::AddMapping`, `DxgkCreateSynchronizationObjectImpl`, `DXGDEVICE::TerminateAllocations`, `DxgkDestroyAllocationInternal`, `DXGDEVICE::CreateAllocation`) primarily underwent structural restructuring, register reallocation by the compiler, and the addition of the same feature flag gates for various mutex operations that were subsequently cleaned up in the security-critical fixes.

---

## 9. Unmatched Functions

There were no added or removed functions between the unpatched and patched binaries. The patch relies entirely on modifying control flow and removing conditional feature flag branches inside existing functions.

---

## 10. Confidence & Caveats

- **Confidence Level**: High. The patch differences clearly identify the removal of `Feature_*_IsEnabled()` wrappers around critical security boundaries (locking, reference counting, and authorization).
- **Assumptions Made**: The analysis assumes the default state of the mentioned internal feature flags (`Feature_1259646266`, `Feature_611095865`, etc.) is `FALSE` in the unpatched production binary, given that their purpose in patching is to enable security mechanisms unconditionally.
- **Verification Required**: A researcher developing a PoC must confirm the size of the `DXGSHAREDVMOBJECT` to prepare the kernel heap spray. Additionally, developing a reliable VMBus packet injector from a guest VM is required to actually trigger the race condition, which requires interacting with the Hyper-V integration components.
