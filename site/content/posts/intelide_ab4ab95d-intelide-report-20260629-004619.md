Title: intelide.sys — Uninitialized PCI-config stack buffers zero-initialized in init-only enumeration callbacks (CWE-908, not attacker-reachable) fixed
Date: 2026-05-12
Slug: intelide_ab4ab95d-intelide-report-20260629-004619
Category: Corpus
Author: Argus
Summary: KB5087545
Severity: Informational
KBDate: 2026-05-12

## 1. Overview

- **Unpatched Binary:** `intelide_unpatched.sys`
- **Patched Binary:** `intelide_patched.sys`
- **Overall Similarity:** `0.7894` (78.94%)
- **Diff Statistics:** the patched build is a full recompile; every function is relocated. Matching by content, the intentional source-level change is the addition of zero-initialization (a `memset` and inlined stack-variable zeroing) in three `PciIdeXInitialize` enumeration callbacks. The remaining differences are compiler codegen and toolchain additions.
- **Verdict:** The patch adds zero-initialization of stack buffers before they are handed to `PciIdeXGetBusData`/`PciIdeXSetBusData` in the Intel PCI IDE controller's enumeration callbacks. This is a genuine CWE-908 (use of potentially uninitialized memory) hardening change and the direction is correct (the patched build is stricter). However, all affected routines run only during controller initialization/enumeration, driven by the PCIIDEX port driver, and they read the controller's *own* PCI configuration space. They are not reachable from any untrusted IOCTL or user-controlled input surface, so this is defense-in-depth, not a remediation of an attacker-reachable vulnerability. The severities and exploit chains in the original draft were inflated and have been corrected below.

---

## 2. Vulnerability Summary

The patch makes three zero-initialization (CWE-908) hardening changes plus one compiler-codegen change. None is demonstrably attacker-reachable.

### Finding 1: PiixIdeGetControllerProperties — PCI-config buffers not zeroed before read
- **Severity:** Informational (init-only, not attacker-reachable)
- **Vulnerability Class:** Use of potentially uninitialized memory (CWE-908)
- **Affected Function:** `PiixIdeGetControllerProperties` (unpatched @ `0x1C0001040`, patched @ `0x1C0001050`)
- **Root Cause:** The unpatched function allocates a `0x40`-byte stack buffer (`var_E8`) and a `0x56`-byte stack buffer (`var_A8`) and passes them to `PciIdeXGetBusData` without zeroing them first. The read results are only consumed on success (`js` bails on a negative NTSTATUS), so this only matters in the theoretical case of `PciIdeXGetBusData` returning success while writing fewer bytes than requested. The patched build adds a `memset` (at `0x1C0002200`) before each read. The buffer content that is read is the IDE controller's own PCI configuration space, obtained during enumeration; it is not an untrusted input.
- **Reachability:** This is the `GetControllerProperties` callback registered with `PciIdeXInitialize`. It is invoked by the PCIIDEX port driver during controller enumeration, not from any IOCTL/user path. It is therefore not attacker-reachable in the normal software threat model.

### Finding 2: PiixIdeTransferModeSelect — timing output locals not zeroed before use
- **Severity:** Informational (redundant defense-in-depth; init-only)
- **Vulnerability Class:** Use of potentially uninitialized memory (CWE-908)
- **Affected Function:** `PiixIdeTransferModeSelect` (unpatched @ `0x1C0001660`, patched @ `0x1C00016B0`)
- **Root Cause:** The function declares five stack locals that it passes by reference to the timing calculator `PiixIdepTransferModeSelect` and then uses as data buffers for `PciIdeXSetBusData` writes to PCI config offsets `0x44`, `0x48`, `0x4a`, and `0x54`. The patched build zero-initializes these five locals at function entry. In practice the timing calculator writes all six of its output parameters unconditionally at its tail before its single `return 0` path, so the locals are never actually consumed uninitialized. The added zeroing is redundant belt-and-suspenders hardening rather than the fix of a live uninitialized-use bug. The earlier claim that the timing calculator has paths leaving outputs unwritten is not supported by the disassembly.
- **Reachability:** `PiixIdeTransferModeSelect` is the `TransferModeSelect` callback registered at `[arg2+0x28]` by `PiixIdeGetControllerProperties`. It runs during controller configuration under the PCIIDEX framework, not from an untrusted IOCTL surface.

### Finding 3: PiixIdeChannelEnabled — channel-status buffer not zeroed before read
- **Severity:** Informational (init-only, not attacker-reachable)
- **Vulnerability Class:** Use of potentially uninitialized memory (CWE-908)
- **Affected Function:** `PiixIdeChannelEnabled` (unpatched @ `0x1C0001580`, patched @ `0x1C00015B0`)
- **Root Cause:** The function reads 4 bytes of PCI config data at offset `0x40` into `[rsp+0x60]` and then reads `byte [rsp+rbx*2+0x61]` (shifted right by 7) to determine whether an IDE channel is enabled. The read only occurs and is only consumed on success. The patched build adds a `memset` zeroing a `0x4c`-byte stack region before the read. As with Finding 1 the input is the controller's own PCI config space read during enumeration.

### Finding 4: __GSHandlerCheckCommon — compiler codegen change (no security relevance)
- **Severity:** None (no security-relevant change)
- **Vulnerability Class:** Not applicable
- **Affected Function:** `__GSHandlerCheckCommon` (unpatched @ `0x1C0002004`, patched @ `0x1C0002054`)
- **Root Cause:** This is a compiler-generated `/GS` stack-cookie handler helper from the C runtime. The unpatched build loads a byte with `mov dl, byte [rcx+rax+3]` and later does `movzx eax, dl`; the patched build loads it with `movzx edx, byte [rcx+rax+3]` and later does `mov eax, edx`. Both sequences compute the identical masked value, and the byte is fully consumed via the zero-extending `movzx eax, dl` in the unpatched path, so there is no stale-bit information leak and no behavioral difference. This is MSVC codegen churn from the recompile, not a security fix. The original CWE-197 "partial register write" characterization was unfounded.

---

## 3. Pseudocode Diff

### Finding 1: `PiixIdeGetControllerProperties`

```c
// --- UNPATCHED (0x1C0001040) ---
if (*arg2 == 0x50) {
    int16_t var_e8;                          // NOT zeroed
    result = PciIdeXGetBusData(dev, &var_e8, 0, 0x40);
    if (result >= 0) {                       // only used on success
        *arg3 = var_e6;                      // device ID word
        if (var_e8 == 0x8086) { ... }        // vendor check
    }
}

// --- PATCHED (0x1C0001050) ---
if (*arg2 == 0x50) {
    int16_t var_e0;
    memset(&var_e0, 0, 0x40);                // ADDED
    result = PciIdeXGetBusData(dev, &var_e0, 0, 0x40);
    if (result >= 0) { ... }                 // same logic, now on a zeroed buffer
}
```

### Finding 2: `PiixIdeTransferModeSelect`

```c
// --- UNPATCHED (0x1C0001660) ---
uint64_t PiixIdeTransferModeSelect(int16_t* dev, int32_t* ctx) {
    int16_t var_50; char arg_18, arg_20, var_58; int16_t var_4c;   // not zeroed
    PiixIdepTransferModeSelect(dev, ctx, &var_50, &arg_18, &arg_20, &var_58, &var_4c);
    // callee writes all outputs before returning 0, so these are defined on return
    // ... PciIdeXSetBusData(dev, &..., ..., 0x44/0x48/0x4a/0x54, 1) ...
}

// --- PATCHED (0x1C00016B0) ---
uint64_t PiixIdeTransferModeSelect(int16_t* dev, int32_t* ctx) {
    int16_t var_50 = 0; char arg_18 = 0, arg_20 = 0, var_58 = 0; int16_t var_4c = 0;  // ADDED zeroing
    PiixIdepTransferModeSelect(dev, ctx, &var_50, &arg_18, &arg_20, &var_58, &var_4c);
    // ... same writes ...
}
```

---

## 4. Assembly Analysis

### Finding 1: `PiixIdeGetControllerProperties` — added `memset`

First buffer (`0x40` bytes):

```assembly
; --- UNPATCHED PiixIdeGetControllerProperties @ 0x1C0001040 ---
00000001C0001069  cmp     dword ptr [rdx], 50h
00000001C0001072  jz      short loc_1C000107E
00000001C000107E  mov     r9d, 40h                 ; length = 0x40
00000001C0001084  lea     rdx, [rsp+118h+var_E8]   ; buffer, NOT zeroed
00000001C0001089  xor     r8d, r8d                 ; offset 0
00000001C000108C  call    cs:__imp_PciIdeXGetBusData

; --- PATCHED PiixIdeGetControllerProperties @ 0x1C0001050 ---
00000001C0001080  mov     esi, 40h
00000001C0001085  lea     rcx, [rsp+110h+var_E0]
00000001C000108A  mov     r8d, esi
00000001C000108D  xor     edx, edx
00000001C000108F  call    memset                   ; ADDED: memset(&var_e0, 0, 0x40)
00000001C0001094  cmp     dword ptr [rdi], 50h
00000001C00010A3  mov     r9d, esi
00000001C00010A6  lea     rdx, [rsp+110h+var_E0]    ; buffer, now zeroed
00000001C00010AB  xor     r8d, r8d
00000001C00010B1  call    cs:__imp_PciIdeXGetBusData
```

Second buffer (`0x56` bytes):

```assembly
; --- UNPATCHED ---
00000001C00012D3  mov     r9d, 56h
00000001C00012D9  lea     rdx, [rsp+118h+var_A8]    ; NOT zeroed
00000001C00012E1  mov     rcx, rbx
00000001C00012E4  call    cs:__imp_PciIdeXGetBusData

; --- PATCHED ---
00000001C00012E2  mov     r14d, 56h
00000001C00012E8  lea     rcx, [rbp+57h+var_A0]
00000001C00012EC  mov     r8d, r14d
00000001C00012EF  xor     edx, edx
00000001C00012F1  call    memset                    ; ADDED: memset(&var_a0, 0, 0x56)
00000001C00012F6  mov     r9d, r14d
00000001C00012F9  lea     rdx, [rbp+57h+var_A0]      ; now zeroed
00000001C0001303  call    cs:__imp_PciIdeXGetBusData
```

### Finding 2: `PiixIdeTransferModeSelect` — added local zeroing

```assembly
; --- UNPATCHED PiixIdeTransferModeSelect @ 0x1C0001660 ---
00000001C0001673  sub     rsp, 60h
00000001C0001677  mov     r14d, 2
; no zeroing of the timing-output locals
00000001C000172E  call    PiixIdepTransferModeSelect   ; writes all outputs before returning 0

; --- PATCHED PiixIdeTransferModeSelect @ 0x1C00016B0 ---
00000001C00016C3  sub     rsp, 60h
00000001C00016C7  xor     esi, esi
00000001C00016D0  mov     [rbp+var_18], si     ; ADDED
00000001C00016D7  mov     [rbp+arg_10], sil    ; ADDED
00000001C00016DE  mov     [rbp+arg_18], sil    ; ADDED
00000001C00016E6  mov     [rbp+var_20], sil    ; ADDED
00000001C00016ED  mov     [rbp+var_14], si     ; ADDED
00000001C0001793  call    PiixIdepTransferModeSelect
```

### Finding 3: `PiixIdeChannelEnabled` — added `memset`

```assembly
; --- UNPATCHED PiixIdeChannelEnabled @ 0x1C0001580 ---
00000001C00015A6  mov     r9d, 4
00000001C00015AC  lea     rdx, [rsp+88h+var_28]    ; buffer, NOT zeroed
00000001C00015B1  lea     r8d, [r9+3Ch]            ; PCI offset 0x40
00000001C00015B5  call    cs:__imp_PciIdeXGetBusData
00000001C00015CC  movzx   eax, [rsp+rbx*2+88h+var_27]
00000001C00015D1  shr     eax, 7

; --- PATCHED PiixIdeChannelEnabled @ 0x1C00015B0 ---
00000001C00015D1  xor     edx, edx
00000001C00015D3  lea     rcx, [rsp+88h+var_68]
00000001C00015D8  lea     r8d, [rdx+4Ch]
00000001C00015DC  call    memset                   ; ADDED: memset(&var_68, 0, 0x4c)
00000001C00015F3  lea     rdx, [rsp+88h+var_28]     ; now zeroed
00000001C00015FF  call    cs:__imp_PciIdeXGetBusData
00000001C0001616  movzx   eax, [rsp+rbx*2+88h+var_27]
```

### Finding 4: `__GSHandlerCheckCommon` — codegen only

```assembly
; --- UNPATCHED __GSHandlerCheckCommon @ 0x1C0002004 ---
00000001C0002041  mov     dl, [rcx+rax+3]
00000001C0002045  test    dl, 0Fh
00000001C000204A  movzx   eax, dl          ; byte fully consumed
00000001C000204D  and     eax, 0FFFFFFF0h

; --- PATCHED __GSHandlerCheckCommon @ 0x1C0002054 ---
00000001C0002091  movzx   edx, byte ptr [rcx+rax+3]
00000001C0002096  test    dl, 0Fh
00000001C000209B  mov     eax, edx
00000001C000209D  and     eax, 0FFFFFFF0h
```

Both compute the same value; no behavioral or security difference.

---

## 5. Trigger Conditions / Reachability

These routines are the `PciIdeXInitialize` callback set for the Intel PIIX-family IDE controller. `DriverEntry` (`0x1C0001008`) calls `PciIdeXInitialize(DriverObject, RegistryPath, PiixIdeGetControllerProperties, 0x41c)`, and `PiixIdeGetControllerProperties` registers the remaining callbacks (`PiixIdeChannelEnabled` at `[arg2+0x18]`, `PiixIdeTransferModeSelect` at `[arg2+0x28]`, etc.). The PCIIDEX port driver invokes these during controller enumeration and configuration.

Consequently:

1. The only conceivable way to influence the buffer contents is to control the physical/emulated IDE controller hardware whose PCI configuration space is read via `PciIdeXGetBusData`. This is a hardware-level threat model, not a software (IOCTL/user-mode) one.
2. Even under that model the buffers hold the controller's own PCI config space, and the values are consumed only on a successful `PciIdeXGetBusData` return. The zeroing guards the theoretical "success with short read" case.
3. There is no untrusted length or offset under caller control; the read sizes (`0x40`, `0x56`, `4`) and offsets are compile-time constants.

No attacker-reachable primitive (arbitrary read/write, info leak to user mode, KASLR bypass, etc.) is demonstrable from these changes.

---

## 6. Impact Assessment

- The changes are memory-safety hardening (zero-init) of the driver's own initialization paths. Worst-case realistic impact of the *unpatched* state, and only if a `PciIdeXGetBusData`/`PciIdeXSetBusData` short-read/short-write actually occurred, would be mis-programmed IDE timing on the local controller (a robustness/DoS concern on attacker-controlled hardware), not memory corruption of unrelated kernel state.
- For Finding 2 specifically, the callee writes all outputs before returning, so no uninitialized value is actually consumed even in the unpatched build; the zeroing is redundant.
- The driver runs in ring 0, but these routines are not on any untrusted input path, so ring-0 execution does not translate into an attacker-reachable primitive here.

---

## 7. Changed Functions — Full Triage

| Function | Unpatched @ | Patched @ | Change | Note |
| :--- | :--- | :--- | :--- | :--- |
| `PiixIdeGetControllerProperties` | `0x1C0001040` | `0x1C0001050` | Hardening (CWE-908) | Added `memset` to zero the `0x40`- and `0x56`-byte PCI-config buffers before `PciIdeXGetBusData`. Init-only; not attacker-reachable. |
| `PiixIdeChannelEnabled` | `0x1C0001580` | `0x1C00015B0` | Hardening (CWE-908) | Added `memset` to zero a `0x4c`-byte region before the channel-status `PciIdeXGetBusData`. Init-only. |
| `PiixIdeTransferModeSelect` | `0x1C0001660` | `0x1C00016B0` | Hardening (CWE-908, redundant) | Zero-initializes five timing-output locals; the callee already writes them before returning. Init-only. |
| `PiixIdepTransferModeSelect` | `0x1C00019B8` | `0x1C0001A24` | Behavioral (codegen) | Control-flow restructuring and register reallocation; logic preserved. Writes all outputs before its single `return 0`. Not security-relevant. |
| `PiixIdeUdmaModesSupported` | `0x1C0001600` | `0x1C0001660` | Behavioral (codegen) | Minor loop-shape codegen difference; behavior identical. Not security-relevant. |
| `__GSHandlerCheckCommon` | `0x1C0002004` | `0x1C0002054` | Codegen only | `mov dl`/`movzx eax,dl` → `movzx edx`/`mov eax,edx`; identical result. Not a security fix. |

---

## 8. Added/Removed Functions

The patched build additionally contains `memset` (`0x1C0002200`), its helpers `__memset_repmovs` (`0x1C0002340`) and `__memset_query` (`0x1C00023C0`), `__cpu_features_init` (`0x1C00020D0`), and `_guard_xfg_dispatch_icall_nop` (`0x1C00021C0`). These are C-runtime and toolchain support routines pulled in by the recompile: the `memset` family is required by the new zero-init calls, and the XFG/CPU-feature helpers come from the updated compiler/CFG settings. None represents a driver-logic security change. No functions were removed.

---

## 9. Confidence & Caveats

- **Confidence:** High that the zero-init additions are real and correctly directed (the patched build is the stricter one), and high that they are not attacker-reachable (init-only enumeration callbacks reading the controller's own PCI config space).
- The PCI config offsets (`0x40`–`0x54`) referenced are Intel IDE controller timing/mode registers per the controller architecture; the read/write sizes and offsets in this driver are compile-time constants, not caller-controlled.
- No exploit primitive, information leak to user mode, or KASLR/mitigation-bypass is supported by these changes; any such claim would be speculative and has been removed.
