Title: dxgkrnl.sys — Race condition (insufficient lock strength) leading to double-free / use-after-free in DXGSWAPCHAIN swapchain sync-object teardown (CWE-362) fixed
Date: 2026-06-28
Slug: dxgkrnl_63e9ddff-dxgkrnl-report-20260628-223412
Category: Corpus
Author: Argus
Summary: KB5078885
Severity: High
KBDate: 2026-03-10

## 1. Overview

- **Unpatched Binary:** `dxgkrnl_unpatched.sys`
- **Patched Binary:** `dxgkrnl_patched.sys`
- **Overall Similarity:** 0.9913
- **Diff Statistics:** 6879 matched, 9 changed, 6870 identical, 0 unmatched in either direction.

**Verdict:** This patch removes WIL feature-staging (flighting) branches that gated legacy vs. new implementations in two subsystems of the DirectX graphics kernel: (1) OPM (Output Protection Manager) handle management in `ADAPTER_DISPLAY`, and (2) swapchain sync-object teardown in `DXGSWAPCHAIN`. The OPM change is a hardening that stops handing a raw kernel pointer back to the caller as the OPM handle (a kernel-address disclosure) and switches to opaque 64-bit IDs. The swapchain change is the memory-safety-relevant one: it removes a shared-lock teardown path that can double-free a sync object under concurrency.

`Feature_<id>__private_IsEnabledDeviceUsage` is the Windows Implementation Library (WIL) feature-staging pattern: a runtime flag used to roll out a new implementation gradually. Both flags here gate a newer, safer implementation that the patch makes unconditional.

## 2. Vulnerability Summary

### Finding 1: OPM Handle Is a Raw Kernel Pointer (Kernel-Address Disclosure), Hardened to Opaque IDs
- **Severity:** Medium
- **Vulnerability Class:** Information Exposure (kernel address disclosure) via pointer-as-handle. NOT type confusion / arbitrary write.
- **Affected Functions:** `ADAPTER_DISPLAY::OpmCreateHandle` (`sub_1C0175174`), `ADAPTER_DISPLAY::OpmTranslateHandle` (`sub_1C0174F34`), `ADAPTER_DISPLAY::OpmTranslateAndDestroyHandle` (`sub_1C0174AA8`), `ADAPTER_DISPLAY::OpmValidateAdapterHandle` (`sub_1C0175044`)

**Root Cause:**
The unpatched `dxgkrnl.sys` uses WIL feature-staging flag `Feature_2161340729__private_IsEnabledDeviceUsage` (`sub_1c00259e8`) to select between two OPM handle schemes:

- **Legacy (flag OFF):** `OpmCreateHandle` allocates an `_OPM_HANDLE_MAPPING` node, inserts it into the adapter's list at `this+0x130`, and returns the **raw kernel address of that node** to the caller as the OPM handle (`*a3 = node`). On translate/destroy, the supplied handle is re-validated by `OpmValidateAdapterHandle`, which walks the list and returns 1 **only if the pointer is an exact live member** (`i == a2`).
- **New (flag ON, and the only scheme in the patched build):** the handle is an opaque, uniquely generated 64-bit ID stored at `node+0x18`. Lookups use `ADAPTER_DISPLAY::FindOpmAdapterMapping` (`sub_1c00d7190` unpatched / `sub_1c00d6190` patched — the **same** function, relocated), comparing `result[3] == a2`.

**Why this is not a type confusion or arbitrary write:** In the legacy path the destroy operation only unlinks a node that `OpmValidateAdapterHandle` confirmed is a live list member, and the unlink is guarded by a `__fastfail(3)` consistency check (`flink->blink == node && blink->flink == node`) before the two neighbor writes. A value that is not a live member returns 0 and takes the error path; it never matches an unrelated object and never produces a wrong-object write. The real weakness of the legacy scheme is that a kernel heap address is disclosed to the OPM client as the handle value, weakening KASLR, and the fragile pointer-as-handle pattern. The patch removes the legacy path, so OPM handles are always opaque IDs.

**Attacker-Reachable Entry Point & Data Flow:**
1. A client drives the OPM protected-output APIs, reaching the OPM IOCTL dispatch.
2. `DpiPdoDispatchInternalIoctl` (`sub_1c016a270`) -> `DpiPdoHandleOpmIoctls` (`sub_1c0174bd4`).
3. -> `DxgkOpmCreateHandle` / `DxgkOpmTranslateHandle` (`sub_1c0174e8c`) / `DxgkOpmTranslateAndDestroyHandle` (`sub_1c0174a00`).
4. -> `ADAPTER_DISPLAY::OpmCreateHandle` (`sub_1c0175174`) / `OpmTranslateHandle` (`sub_1c0174f34`) / `OpmTranslateAndDestroyHandle` (`sub_1c0174aa8`).
5. With the flag OFF, the handle returned by create is a kernel pointer; translate/destroy re-validate it by list-membership walk.

### Finding 2: Swapchain Sync-Object Teardown Uses Only a Shared Lock (Double-Free / UAF)
- **Severity:** High
- **Vulnerability Class:** Race Condition (insufficient lock strength) leading to double-free / Use-After-Free
- **Affected Functions:** `DXGSWAPCHAIN::DestroySurfacesResourcesLocal` (`sub_1C02ABA68`), `DXGSWAPCHAIN::DestroySurfacesResourcesGlobal` (`sub_1C02AB988`)

**Root Cause:**
The unpatched `DestroySurfacesResourcesLocal` synchronizes access to the swapchain's handle-table `DXGSYNCOBJECT` entry using two mechanisms gated by WIL flag `Feature_342658361__private_IsEnabledDeviceUsage` (`sub_1c0027f20`):

- **New (flag ON, kept by the patch):** takes an **EXCLUSIVE** handle-table lock (`DXGHANDLETABLELOCKEXCLUSIVE`, `sub_1c0002630` / `DXGAUTOPUSHLOCK` release `sub_1c0004488`) and, while holding it, sets the `0x2000` "in-destruction" bit on the table entry.
- **Legacy (flag OFF, removed by the patch):** takes only a **SHARED** push lock (`DXGPUSHLOCK::AcquireShared`, `sub_1c0007018`, released via `ExReleasePushLockSharedEx` + `KeLeaveCriticalRegion`) and does **not** set the `0x2000` marker.

Because `DXGGLOBAL::DestroySyncObject` (`sub_1c00ddb58`) is called **after** the lock is released, two threads running the shared-lock path concurrently can both fetch the same `DXGSYNCOBJECT` and both destroy it — a double-free / use-after-free. The exclusive-lock path plus the `0x2000` marker prevents this: a second thread sees `(entry & 0x2000) != 0` and fetches `nullptr`. The sibling `DestroySurfacesResourcesGlobal` mirrors the pattern: the legacy path skips the exclusive `DXGSYNCOBJECTLOCK` (`sub_1c00186fc`) and passes `arg4=0` to `DestroySyncObject`, while the patch always acquires the exclusive lock and passes `arg4=1`.

> Correction over the initial triage: the flag-ON path is the **exclusive** lock (safe); the flag-OFF path is the **shared** push lock (racy). The earlier reading had these reversed and described the exclusive-lock helpers as "lock-free."

## 3. Pseudocode Diff

### Finding 1: Validated Unlink (`ADAPTER_DISPLAY::OpmTranslateAndDestroyHandle`, `sub_1C0174AA8`)

```c
// --- UNPATCHED sub_1C0174AA8 ---
if (Feature_2161340729__private_IsEnabledDeviceUsage() != 0) {   // flag ON: opaque ID
    node = FindOpmAdapterMapping(this, a2);                       // sub_1c00d7190
    if (node == nullptr) return 0xC01E050C;                      // error
} else if (OpmValidateAdapterHandle(this, a2) == 0) {            // flag OFF: pointer-membership
    return 0xC01E050C;                                           // not a live member -> error
} else {
    node = a2;                                                   // validated live pointer
}
flink = *node; *a3 = node[2];                                    // return +0x10 field
if (*(flink+8) != node || *(blink = node[1]) != node)
    __fastfail(3);                                               // link integrity check
*blink = flink; *(flink+8) = blink;                             // safe unlink of a validated node
operator delete(node);

// --- PATCHED sub_1C0174054 ---
node = FindOpmAdapterMapping(this, a2);                          // sub_1c00d6190, a2 is a 64-bit ID
if (node) { /* same integrity-checked unlink */ }
else       { /* assertion + error */ }
```

### Finding 1: Handle Creation (`ADAPTER_DISPLAY::OpmCreateHandle`, `sub_1C0175174`)

```c
// --- UNPATCHED sub_1C0175174 ---
if (Feature_2161340729__private_IsEnabledDeviceUsage() == 0) {  // legacy
    ...insert node at this+0x130...
    *a3 = node;                    // OPM handle = RAW KERNEL POINTER (info leak)
} else {                          // new
    do { id = (*(this+0x140))++; } while (id == 0 || FindOpmAdapterMapping(this, id));
    node[3] = id; ...insert...;    // stamp +0x18 ID
    *a3 = id;                      // OPM handle = opaque ID
}
```

## 4. Assembly Analysis

### Finding 1: Membership Validation vs. ID Lookup

```assembly
; UNPATCHED ADAPTER_DISPLAY::OpmValidateAdapterHandle (sub_1c0175044) - returns bool
; rdi = candidate handle (raw pointer in the legacy scheme)
0x1c017509a: lea rcx, [rbx+0x130]     ; rcx = &list head (this+0x130)
0x1c01750a1: mov rax, [rcx]           ; rax = first list node
0x1c01750a4: cmp rax, rcx             ; wrapped back to the head?
0x1c01750a7: jz  0x1c01750c1          ; end of list -> return 0
0x1c01750a9: cmp rax, rdi             ; exact NODE-POINTER match against a live member
0x1c01750ac: jnz 0x1c01750bc          ; not this node -> advance
0x1c01750ae: mov al, 1               ; rdi IS a genuine list node -> return 1
0x1c01750bc: mov rax, [rax]           ; next node
0x1c01750bf: jmp 0x1c01750a4
0x1c01750c1: xor al, al               ; non-member -> return 0

; FindOpmAdapterMapping (sub_1c00d7190 unpatched == sub_1c00d6190 patched) - ID lookup
; addresses shown for the patched copy at 0x1c00d6190; rdi = candidate ID
0x1c00d6201: lea rcx, [rbx+0x130]     ; rcx = &list head (this+0x130)
0x1c00d6208: mov rax, [rcx]           ; rax = first list node
0x1c00d620b: jmp 0x1c00d6216
0x1c00d620d: cmp [rax+0x18], rdi      ; *** ID field at +0x18 ***
0x1c00d6211: jz  0x1c00d621d          ; match -> return node
0x1c00d6213: mov rax, [rax]           ; next node
0x1c00d6216: cmp rax, rcx             ; wrapped back to the head?
0x1c00d6219: jnz 0x1c00d620d          ; more nodes -> keep scanning
0x1c00d621b: xor eax, eax             ; not found -> nullptr
```

`OpmValidateAdapterHandle` is a boolean validator, not a lookup that returns a caller-influenced node. `FindOpmAdapterMapping` is byte-for-byte the same routine in both builds (only its address and internal assertion line numbers shift); it is a relocation, not a fix.

### Finding 2: Lock Strength (`DXGSWAPCHAIN::DestroySurfacesResourcesLocal`, `sub_1c02aba68`)

```assembly
; UNPATCHED sub_1c02aba68
call    0x1c0027f20        ; Feature_342658361__private_IsEnabledDeviceUsage
test    eax, eax
je      legacy_shared_path

; NEW PATH (flag ON) - EXCLUSIVE lock + 0x2000 marking
call    0x1c0002630        ; DXGHANDLETABLELOCKEXCLUSIVE::ctor
; ... lookup; on match: or dword [entry], 0x2000 ...
call    0x1c0004488        ; DXGAUTOPUSHLOCK::dtor
jmp     destroy

legacy_shared_path:        ; (flag OFF) - SHARED push lock, NO marking
call    0x1c0007018        ; DXGPUSHLOCK::AcquireShared
; ... same lookup, no 0x2000 ...
call    qword [rel ExReleasePushLockSharedEx]
call    qword [rel KeLeaveCriticalRegion]

destroy:
call    0x1c00ddb58        ; DXGGLOBAL::DestroySyncObject (AFTER lock release)

; PATCHED sub_1c02aa8bc - single exclusive path
call    0x1c0002630        ; DXGHANDLETABLELOCKEXCLUSIVE::ctor
; ... lookup; or dword [entry], 0x2000 ...
call    0x1c0004488        ; DXGAUTOPUSHLOCK::dtor
```

## 5. Trigger Conditions

Finding 1 (kernel-address disclosure):
1. Drive the OPM protected-output APIs to reach `OpmCreateHandle`.
2. Ensure `Feature_2161340729__private_IsEnabledDeviceUsage` (`sub_1c00259e8`) is OFF (legacy scheme).
3. Observe the returned OPM handle is a kernel pointer (`0xFFFF...`) rather than a small opaque counter.

Finding 2 (double-free / UAF):
1. Ensure `Feature_342658361__private_IsEnabledDeviceUsage` (`sub_1c0027f20`) is OFF (shared-lock path).
2. Create a swapchain with sync objects via D3DKMT swapchain APIs.
3. Issue concurrent swapchain / surface destruction from multiple threads targeting the same surface; the shared-lock path lets two threads both resolve and destroy the same `DXGSYNCOBJECT`.

## 6. Exploit Primitive & Development Notes

**Primitives Provided:**
- **Finding 1:** Kernel-address information disclosure only. The OPM handle in the legacy path is the kernel address of the mapping node, usable to defeat KASLR for that pool. There is no write-what-where and no arbitrary read: `OpmValidateAdapterHandle` requires an exact list-member pointer, and the unlink is `__fastfail`-guarded, so only genuine, validated nodes are ever translated or unlinked.
- **Finding 2:** Double-free / use-after-free of a `DXGSYNCOBJECT`. Two concurrent shared-lock-path threads both free the same object. The freed pool block can be reclaimed with attacker-controlled data (named-pipe or object spray), enabling further corruption.

**Exploit Development Steps (Finding 2):**
1. Win the race: two threads calling the swapchain surface teardown on the same handle under the shared-lock (flag OFF) path.
2. Reclaim the freed `DXGSYNCOBJECT` pool block between/after the two frees with controlled data.
3. Pivot from the corrupted object (e.g., function pointer or type field) toward a data-only privilege escalation.

**Mitigations:**
- **KASLR:** Finding 1's disclosure directly weakens KASLR for the OPM handle pool.
- **SMEP / SMAP / CFG:** relevant only to Finding 2's UAF if execution is hijacked via a reclaimed object; data-only reclamation avoids CFG.

## 7. Debugger PoC Playbook

Attach a local kernel debugger (WinDbg/KD) to the unpatched target.

**Breakpoints:**
```text
bp dxgkrnl_unpatched!Feature_2161340729__private_IsEnabledDeviceUsage   ; sub_1c00259e8
bp dxgkrnl_unpatched!OpmCreateHandle                                    ; sub_1c0175174
bp dxgkrnl_unpatched!OpmValidateAdapterHandle                           ; sub_1c0175044
bp dxgkrnl_unpatched!DestroySurfacesResourcesLocal                      ; sub_1c02aba68
bp dxgkrnl_unpatched!Feature_342658361__private_IsEnabledDeviceUsage    ; sub_1c0027f20
```

> Address note: in the **patched** image, `0x1c00259e8` is a different function (`DXGOVERLAYMUTEX` constructor) due to address reuse. The feature-flag breakpoints above are meaningful only against the unpatched image.

**Execution & Inspection:**
1. **Verify OPM scheme:** Break `sub_1c00259e8`, `gu`, inspect `eax`. `eax == 0` => legacy raw-pointer-handle path is active.
2. **Observe the disclosed pointer:** Break `OpmCreateHandle`; on the legacy path step to the `*a3 = node` store and confirm the handle handed back is a kernel pointer.
3. **Confirm safe validation:** Break `OpmValidateAdapterHandle`. `rcx` = adapter, `rdx` = candidate handle. Confirm the loop only returns 1 on an exact member match; a non-member value falls through to `return 0` (error path, no wrong-object match).
4. **Observe the race path:** Break `sub_1c02aba68`, `gu` past `sub_1c0027f20`. `eax == 0` => shared-lock path with no `0x2000` marking; watch the handle-table entry dword to confirm the marker is absent, then watch two threads both reach `DXGGLOBAL::DestroySyncObject` on the same object.

**Expected Observation on Crash (Finding 2):**
- `BAD_POOL_HEADER (0x19)` or `BAD_POOL_CALLER (0xC2)` from the double-free of the `DXGSYNCOBJECT` pool block, or a delayed use-after-free if the block is reclaimed between frees. Finding 1 produces no crash under normal validation; its only consequence is kernel-address disclosure.

## 8. Changed Functions — Full Triage

- **`VmBusOpmRequest (sub_1C0245C70)`** (0.49 similarity, behavioral): Removed a WIL feature-staging check (`Feature_15692090__private_IsEnabledDeviceUsage`, `sub_1c0026850`) that gated two VmBus command handling paths. No memory-safety consequence observed.
- **`DXGSWAPCHAIN::DestroySurfacesResourcesLocal (sub_1C02ABA68)`** (0.75 similarity, security-relevant): Removed the shared-lock legacy teardown path; the patch always takes the exclusive handle-table lock and sets the `0x2000` in-destruction marker. (Finding 2.)
- **`DXGSWAPCHAIN::DestroySurfacesResourcesGlobal (sub_1C02AB988)`** (0.76 similarity, security-relevant): Removed the flag that skipped the exclusive `DXGSYNCOBJECTLOCK` (`sub_1c00186fc`); the patch always acquires it and passes `arg4=1` to `DXGGLOBAL::DestroySyncObject` (`sub_1c00ddb58`).
- **`ADAPTER_DISPLAY::OpmTranslateHandle (sub_1C0174F34)`** (0.77 similarity, security-relevant): Removed the dual lookup path; the patch always uses ID-based `FindOpmAdapterMapping`. Legacy path validated a raw pointer handle via membership walk. (Finding 1.)
- **`ADAPTER_DISPLAY::OpmTranslateAndDestroyHandle (sub_1C0174AA8)`** (0.79 similarity, security-relevant): Same dual-path removal; additionally unlinks and frees the (validated) node. No wrong-object write. (Finding 1.)
- **`ADAPTER_DISPLAY::OpmCreateHandle (sub_1C0175174)`** (0.86 similarity, security-relevant): Removed the legacy path that returned the raw node pointer as the handle; the patch always generates a unique opaque ID. (Finding 1.)
- **`DXGGLOBAL::DestroySyncObject (sub_1C00DDB58)`** (0.90 similarity, behavioral): Removed feature-staging that gated internal assertion codes (`0xac7/0xacb/0xad0` vs `0xac6/0xaca`). Core destruction logic unchanged.
- **`DXG_HOST_VIRTUALGPU_VMBUS::VmBusGetRegistryKeys (sub_1C02430A0)`** (0.97 similarity, cosmetic): Call-target address shifts plus one removed WIL feature-staging check.
- **`VIDPN_MGR::BuildSetTimingsPathInfoFromClientVidPn (sub_1C0142590)`** (0.98 similarity, cosmetic): Address-reference shifts due to binary layout differences.

## 9. Unmatched Functions

No added or removed functions (`unmatched_unpatched: 0`, `unmatched_patched: 0`). The patch consolidates existing functions by removing feature-staging branches.

## 10. Confidence & Caveats

**Confidence Level:** High for the mechanics. The diff clearly shows WIL feature-staging removal: OPM handles migrate from raw kernel pointers to opaque IDs, and swapchain sync-object teardown migrates from a shared lock (no in-destruction marker) to an exclusive lock with a marker.

**Corrections from the initial triage:**
- The affected functions are **OPM (Output Protection Manager)** and **swapchain** routines, not "sync object (fence/monitor)" enumeration. The `sub_<ADDR>` labels resolve to `ADAPTER_DISPLAY::Opm*` and `DXGSWAPCHAIN::DestroySurfacesResources*`.
- Finding 1 is **not** a type confusion or write-what-where. `OpmValidateAdapterHandle` is a boolean list-membership validator; the unlink is `__fastfail`-guarded. The real issue is kernel-address disclosure via pointer-as-handle.
- In Finding 2 the lock-strength/flag mapping was reversed: flag ON = exclusive (safe), flag OFF = shared (racy).
- `FindOpmAdapterMapping` at `sub_1c00d7190` (unpatched) and `sub_1c00d6190` (patched) is the same function relocated, not a new fixed lookup.

**Assumptions:**
- Exploitability depends on the runtime state of the WIL feature-staging flags in the shipped unpatched build; the flag defaulting to the legacy path is what exposes each issue.

**Manual Verification Required:**
- Map the exact OPM IOCTL codes and buffer layouts from `DpiPdoHandleOpmIoctlsInternal` (`sub_1c001cc94`) to the user-mode OPM APIs to confirm the client-reachable path for Finding 1's disclosure, and identify the swapchain-destroy IOCTL that concurrently reaches `DestroySurfacesResourcesLocal` for Finding 2.
