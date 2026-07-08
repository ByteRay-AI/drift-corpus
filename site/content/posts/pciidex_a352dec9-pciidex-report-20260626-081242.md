Title: pciidex.sys — MMIO BAR mapped executable via deprecated MmMapIoSpace, non-executable protection enforced with MmMapIoSpaceEx (CWE-732) — fixed
Date: 2026-06-26
Slug: pciidex_a352dec9-pciidex-report-20260626-081242
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Low
KBDate: 2026-01-13

## 1. Overview

- **Unpatched Binary:** `pciidex_unpatched.sys`
- **Patched Binary:** `pciidex_patched.sys`
- **Overall Similarity Score:** `0.9154` (91.54%)
- **Diff Statistics:**
  - Matched Functions: 195
  - Changed Functions: 115
  - Identical Functions: 80
  - Unmatched Functions (Unpatched/Patched): 0 / 2
- **Verdict:** The patch replaces the deprecated `MmMapIoSpace` API with `MmMapIoSpaceEx` in the `GenPopulateAccessRange` function, adding an explicit page-protection argument (`0x204` = `PAGE_NOCACHE | PAGE_READWRITE`) so that mapped PCI IDE MMIO regions are non-executable (NX) rather than mapped read-write-execute. This is a genuine, correctly-directed defense-in-depth hardening; it is not a self-contained exploitable vulnerability. Severity: Low.

---

## 2. Vulnerability Summary

### Finding: Executable MMIO Mapping via Deprecated API (CWE-732)
- **Severity:** Low (defense-in-depth hardening)
- **Vulnerability Class:** Incorrect Permission Assignment for Critical Resource / Weak Memory Protection on MMIO mapping
- **Affected Function:** `GenPopulateAccessRange` (unpatched `@ 0x1C0008FB0`, patched `@ 0x1C000A120`)

**Root Cause Analysis:**
The unpatched `pciidex.sys` driver uses the deprecated `MmMapIoSpace()` API to map PCI IDE controller memory resources (from `CmResourceTypeMemory` descriptors) into kernel virtual address space during device start. `MmMapIoSpace` takes only a cache type (here `MmNonCached`) and does not allow the caller to specify page protection; the resulting mapping is read-write-execute, i.e. the pages carry no explicit Non-Executable (NX) attribute.

The patch replaces this call with `MmMapIoSpaceEx()`, passing `0x204` (`PAGE_NOCACHE | PAGE_READWRITE`) as the `Protect` argument. This makes the mapped I/O region explicitly non-executable, which is Microsoft's documented reason for introducing `MmMapIoSpaceEx` and deprecating `MmMapIoSpace`. The direction of the change is correct: only the patched build enforces NX on these mappings.

This is a hardening change, not a directly reachable exploit. The physical addresses and lengths come from PCI BAR resource descriptors assigned by the PnP/PCI bus driver, not from an IOCTL or other attacker-controlled request. Turning the executable MMIO mapping into a code-execution primitive would additionally require an attacker to control the physical memory contents behind the BAR (for example a malicious or DMA-capable device, or an emulated/pass-through device in a virtualized guest) and a separate control-flow hijack to redirect execution into the mapped virtual address. None of that is demonstrable from this driver alone.

**Attacker-Reachable Entry Point & Data Flow:**
1. The vulnerability is triggered during the standard Plug and Play (PnP) enumeration of a PCI IDE controller.
2. The OS sends an `IRP_MJ_PNP` request with the minor code `IRP_MN_START_DEVICE` (`ControllerStartDevice`).
3. The driver processes the translated resource requirements, eventually calling `GenPopulateAccessRange` to map hardware resources.
4. `GenPopulateAccessRange` evaluates the resource descriptors. For memory descriptors (`CmResourceTypeMemory` / type `3`), it extracts the physical address and length.
5. The function passes this physical address and length to the vulnerable `MmMapIoSpace` API, mapping the memory without explicit NX enforcement.

---

## 3. Pseudocode Diff

The following decompilation shows the resource mapping logic in `GenPopulateAccessRange` for memory-type resources. `v10` walks the resource descriptors; `*((_BYTE *)v10 - 12)` is the descriptor `Type` (`3` = `CmResourceTypeMemory`), `v8[5 * v9 + 1]` is the physical start address, and `*v10` is the length.

```c
/* Unpatched GenPopulateAccessRange @ 0x1C0008FB0 */
if ( *((_BYTE *)v10 - 12) == 3 )   // CmResourceTypeMemory
{
    // Deprecated API: only a cache type is supplied (MmNonCached);
    // the resulting mapping carries no explicit non-executable protection.
    v11 = MmMapIoSpace(*(PHYSICAL_ADDRESS *)&v8[5 * v9 + 1], (unsigned int)*v10, MmNonCached);
    *(_QWORD *)(a2 + 24 * v2) = v11;
    *(PHYSICAL_ADDRESS *)(a2 + 24 * v2 + 8) = MmGetPhysicalAddress(v11);
    *(_DWORD *)(a2 + 24 * v2 + 16) = *v10;
    *(_BYTE *)(a2 + 24 * v2 + 20) = 1;
}

/* Patched GenPopulateAccessRange @ 0x1C000A120 */
if ( *((_BYTE *)v10 - 12) == 3 )   // CmResourceTypeMemory
{
    // Modern API: 516 == 0x204 == PAGE_NOCACHE | PAGE_READWRITE.
    // The mapping is explicitly read-write and non-executable.
    v11 = (void *)MmMapIoSpaceEx(*(_QWORD *)&v8[5 * v9 + 1], (unsigned int)*v10, 516);
    *(_QWORD *)(a2 + 24 * v2) = v11;
    *(PHYSICAL_ADDRESS *)(a2 + 24 * v2 + 8) = MmGetPhysicalAddress(v11);
    *(_DWORD *)(a2 + 24 * v2 + 16) = *v10;
    *(_BYTE *)(a2 + 24 * v2 + 20) = 1;
}
```

---

## 4. Assembly Analysis

The change is localized to the resource mapping loop inside `GenPopulateAccessRange`.

### Unpatched Assembly
```assembly
; Unpatched GenPopulateAccessRange @ 0x1C0008FB0, Type==3 (CmResourceTypeMemory) path:
00000001C0009017  mov     edx, [rdi]              ; NumberOfBytes (length)
00000001C0009019  lea     rcx, [r14+r14*4]
00000001C000901D  mov     rcx, [r12+rcx*4+4]      ; PhysicalAddress from descriptor
00000001C0009022  xor     r8d, r8d                ; CacheType = MmNonCached (0); no page protection arg
00000001C0009025  call    cs:__imp_MmMapIoSpace
```

### Patched Assembly
```assembly
; Patched GenPopulateAccessRange @ 0x1C000A120, Type==3 (CmResourceTypeMemory) path:
00000001C000A18B  mov     edx, [rdi]              ; NumberOfBytes (length)
00000001C000A18D  lea     rcx, [r14+r14*4]
00000001C000A191  mov     rcx, [r12+rcx*4+4]      ; PhysicalAddress from descriptor
00000001C000A196  mov     r8d, 204h               ; Protect = PAGE_NOCACHE|PAGE_READWRITE (explicit NX)
00000001C000A19C  call    cs:__imp_MmMapIoSpaceEx
```

---

## 5. Trigger Conditions

To reach the vulnerable code path:

1. Obtain a handle or mechanism to interact with the PnP subsystem (requires administrative privileges by default).
2. Force the target PCI IDE controller (handled by `pciidex.sys`) to process an `IRP_MN_START_DEVICE` request. This can be done by restarting the device.
3. The device must supply resource requirements of type `CmResourceTypeMemory` (Type `3`). 
4. No specific race conditions or timing constraints are required.
5. **Observable Effect:** In the unpatched binary, inspecting the Page Table Entry (`PTE`) of the returned kernel Virtual Address (`VA`) via a debugger shows the mapping without the NX (Execute-Disable) bit; in the patched binary the same mapping is non-executable. This is the only directly observable difference between the two builds.

---

## 6. Impact & Notes

- **Nature of the change:** A defense-in-depth hardening. The unpatched build maps PCI IDE memory BARs read-write-execute; the patched build maps them read-write, non-executable. There is no self-contained exploit primitive in this driver.
- **Preconditions any exploitation would require (not demonstrable here):** an attacker able to control the physical memory contents behind the mapped BAR (for example a malicious or DMA-capable device, or an emulated/pass-through device in a virtualized guest), plus a separate control-flow hijack to redirect kernel execution into the mapped VA. The physical address and length passed to the mapping call originate from PCI resource descriptors assigned during PnP enumeration, not from attacker-supplied requests.
- **Environmental mitigations:**
  - **HVCI / VBS:** Hypervisor-Protected Code Integrity enforces NX on kernel pages regardless of the OS kernel's request, so the two builds are equivalent when VBS/HVCI is enabled.
  - **SMEP / SMAP:** Prevent user-mode pages from being executed/accessed in kernel mode, but do not affect kernel-mapped MMIO regions.

---

## 7. Debugger PoC Playbook

Follow these steps using a kernel debugger (WinDbg/KD) attached to the **unpatched** target to confirm the behavior.

### Breakpoints
Set breakpoints on the vulnerable function and the deprecated API itself:
```text
bp pciidex!GenPopulateAccessRange
bp nt!MmMapIoSpace
```
*Why:* `GenPopulateAccessRange` confirms we have entered the correct resource mapping logic. Breaking on `nt!MmMapIoSpace` allows us to intercept the exact moment the vulnerable mapping occurs.

### What to Inspect at Each Breakpoint
- **At `pciidex!GenPopulateAccessRange`:**
  - `rcx` holds `arg1` (the resource list pointer).
  - `rdx` holds `arg2` (the output access range array pointer).
  - Trace execution to the `Type == 3` branch to confirm a memory resource is being processed.
- **At `nt!MmMapIoSpace`:**
  - `rcx` = Physical Address from the PCI BAR descriptor.
  - `rdx` = Length of the mapping.
  - `r8d` = `0` (`MmNonCached`), demonstrating the lack of explicit page protection.
  - Step over (`p`) the call and inspect the return value in `rax` (this is the mapped kernel VA).

### Key Instructions/Offsets
- `0x1C0008FB0`: Entry point of `GenPopulateAccessRange` (unpatched).
- `0x1C0009025`: The `MmMapIoSpace` call site in the unpatched binary (the `Type == 3` / `CmResourceTypeMemory` branch).
- `0x1C000A19C`: The corresponding `MmMapIoSpaceEx` call site in the patched binary, preceded by `mov r8d, 204h` at `0x1C000A196`.

### Trigger Setup
No custom script or IOCTL packet is required to trigger this flaw. It occurs during normal device initialization. 
1. Open an elevated command prompt or Device Manager.
2. Identify the PCI IDE Controller (e.g., Standard SATA AHCI Controller in IDE mode).
3. Disable and re-enable the device, or run `pnputil /restart-device *DeviceID*`.
4. The breakpoints will hit automatically.

### Expected Observation
After `MmMapIoSpace` returns, take the pointer in `rax` and run the WinDbg extension command:
```text
!pte <rax>
```
Observe the PTE output. On the unpatched system the Execute-Disable (`NX`) bit is not set, so the mapped MMIO region is executable. On the patched system (using `MmMapIoSpaceEx` with `0x204`), the mapping is non-executable. This confirms the direction of the fix; it is not, by itself, a code-execution demonstration.

---

## 8. Changed Functions — Full Triage

Out of 115 changed functions, the overwhelming majority are compiler-level optimizations, register re-allocations, and basic block reordering. Below are the notable behavioral and security-adjacent changes:

- **GenPopulateAccessRange** (`0.9901` similarity): **Security Relevant**. Replaced `MmMapIoSpace` with `MmMapIoSpaceEx` to enforce explicit NX protection (`0x204`) on mapped memory.
- **ControllerInitControllerInfo** (`0.9217`): *Behavioral*. Changed how PCI IDE channel mode flags are initialized at offset `0x1ac`; patched version uses individual byte writes rather than a single 32-bit write. No functional difference.
- **PciIdeRegReadDwordDeviceKey** (`0.9714`): *Behavioral*. Function signature gained a 5th parameter. Registry DWORD values are now written directly to a caller-provided buffer instead of relying on a local stack variable, eliminating potential stack-residue leaks.
- **PciIdeChannelEnabled** (`0.9219`): *Behavioral*. Updated to account for the new signature of `PciIdeRegReadDwordDeviceKey`. Control flow simplified.
- **GenPnpFdoRemoveDevice** (`0.7963`): *Behavioral*. Device teardown refactored. `IoDetachDevice`/`IoDeleteDevice` inline code was extracted to `GenPnpFreeFdo()`. PDO removal paths unified.
- **GenPnpPdoStartDevice** (`0.9786`): *Behavioral*. State flag masking updated to re-read a value after `ChannelStartDevice` completes, fixing a minor state machine correctness issue using stale data.
- **ControllerStartMiniport, FdoSystemPowerDownCompletion, PciIdeUnload, RemovePdoExtension, PciIdeXSetBusData, ControllerQueryBusRelations, ChannelBuildDeviceId, ChannelQueryResourceRequirements, ControllerInterruptControl**: *Cosmetic*. These functions exhibit compiler-driven changes such as variable renaming (`rsi` to `rdi`), branch swapping, jump target offset shifts, and tail-call restructuring. The underlying logic is identical.

---

## 9. Unmatched Functions

No functions were removed. Two functions exist only in the patched build, both refactoring extractions of code that was previously inlined in existing functions:

- **GenPnpFreeFdo** (`@ 0x1C000919C`): FDO teardown helper extracted from the device-removal path (set state, unlink from the global list, `IoDetachDevice`/`IoDeleteDevice`). Same operations as the inlined unpatched code.
- **PdoCompleteSystemPowerIrp** (`@ 0x1C0002B40`): system power-IRP completion helper (records the requested power state, calls `PoSetPowerState` when it changes, then `PoStartNextPowerIrp` and `IofCompleteRequest`), extracted from the PDO power dispatch path.

Neither introduces new security behavior.

---

## 10. Confidence & Caveats

- **Confidence Level:** High. The API replacement (`MmMapIoSpace` -> `MmMapIoSpaceEx` with `0x204`) is present in both the decompilation and the disassembly of `GenPopulateAccessRange`, matches at the exact call sites (`0x1C0009025` vs `0x1C000A19C`), and aligns with Microsoft's deprecation of `MmMapIoSpace` in favour of `MmMapIoSpaceEx`.
- **Severity rationale (Low):** The change enforces NX on MMIO mappings but does not, on its own, constitute a reachable exploit. The mapped physical addresses come from PnP-assigned PCI BAR resource descriptors rather than attacker-controlled input, and turning an executable MMIO page into code execution would require both control of the mapped physical memory contents and a separate control-flow hijack. Under HVCI/VBS the two builds behave identically.
- **Verification Note:** The executable-vs-NX difference is observable via `!pte` on the returned VA in the two builds; this confirms the fix direction but is not a code-execution demonstration.
