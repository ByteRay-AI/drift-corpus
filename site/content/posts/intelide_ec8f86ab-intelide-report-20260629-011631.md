Title: intelide.sys — init-only PCI-config stack buffers zero-initialized; CWE-908 hardening, not attacker-reachable
Date: 2026-04-14
Slug: intelide_ec8f86ab-intelide-report-20260629-011631
Category: Corpus
Author: Argus
Summary: KB5082142
Severity: Informational
KBDate: 2026-04-14

## 1. Overview

*   **Unpatched Binary:** `intelide_unpatched.sys`
*   **Patched Binary:** `intelide_patched.sys`
*   **Overall Similarity:** 78.94%
*   **Diff Statistics:** The three initialization-path functions that carry logic changes are `PiixIdeGetControllerProperties`, `PiixIdeChannelEnabled`, and `PiixIdeTransferModeSelect`. `PiixIdepTransferModeSelect` is compiler-restructured but semantically equivalent. The patched build additionally links five support functions the unpatched build does not contain (`memset` and its two helpers, `__cpu_features_init`, and an XFG dispatch thunk); these are pulled in as a byproduct of introducing the `memset` calls, not standalone fixes.
*   **Verdict:** The patch adds zero-initialization of local stack buffers/variables before PCI configuration-space reads in the Intel IDE controller *initialization* path. This is Use-of-Uninitialized-Resource (CWE-908) style defensive hardening. Every touched routine runs only during driver initialization, operates on the controller's own assigned PCI configuration space, and is not reachable from any untrusted or attacker-controlled surface. No exploitable impact (information disclosure, corruption, or DoS) is demonstrable, and one of the three changes (`PiixIdeTransferModeSelect`) guards locals that the called routine already fills unconditionally on its only return path. Net assessment: defense-in-depth hardening with no reachable security impact.

## 2. Change Summary

### Finding 1: Controller Properties Callback (`PiixIdeGetControllerProperties`)
*   **Severity:** Informational (defensive hardening; not attacker-reachable)
*   **Class:** Use of Uninitialized Resource (CWE-908) — hardening
*   **Affected Function:** `PiixIdeGetControllerProperties` (unpatched `0x1C0001040`, patched `0x1C0001050`)
*   **Change:** The unpatched function requests PCI configuration data into stack buffers via `PciIdeXGetBusData` (0x40 bytes into `var_E8`, then 0x56 bytes into `var_A8`) without clearing them first, and calls `PciIdexGetBusLocation` into an uncleared local (`var_F8`). If `PciIdeXGetBusData` were to return success while only partially filling a buffer, the untouched bytes would hold stale stack contents; those bytes then feed device-ID/vendor and capability decisions (`var_E6`, `var_DF`) and the bus-location comparison. The patched build adds `memset(buf, 0, 0x40)`, `memset(buf, 0, 0x56)`, and a zeroing of the bus-location local before each corresponding read.
*   **Reachability:** The routine is the controller-properties callback registered through `PciIdeXInitialize`. It runs once during controller enumeration/initialization, reads only the controller's own PCI config space through the PCIIDEX library, and is not driven by any user-mode or network input. There is no attacker-controlled data flow and no observable leak channel.

### Finding 2: Channel-Enabled Callback (`PiixIdeChannelEnabled`)
*   **Severity:** Informational (defensive hardening; not attacker-reachable)
*   **Class:** Use of Uninitialized Resource (CWE-908) — hardening
*   **Affected Function:** `PiixIdeChannelEnabled` (unpatched `0x1C0001580`, patched `0x1C00015B0`)
*   **Change:** The function reads 4 bytes of PCI config space at offset `0x40` into a stack buffer and extracts bit 7 of a per-channel byte (`[rsp+rbx*2+var_27]`, `rbx` = channel index 0/1) to report whether an IDE channel is enabled. The unpatched build does not clear the buffer before the read; the patched build adds `memset(buf, 0, 0x4C)` covering the buffer region prior to `PciIdeXGetBusData`.
*   **Reachability:** Registered by `PiixIdeGetControllerProperties` at offset `+0x18` of the properties structure. Called by the PCIIDEX library during channel setup, reading the controller's own config space. Not attacker-reachable.

### Finding 3: Transfer-Mode-Select Callback (`PiixIdeTransferModeSelect`) — no actual uninitialized use
*   **Severity:** None (no security-relevant change)
*   **Class:** Defensive zero-init of locals that are already fully written by the callee
*   **Affected Function:** `PiixIdeTransferModeSelect` (unpatched `0x1C0001660`, patched `0x1C00016B0`)
*   **Change:** The patched prologue explicitly zeroes five locals (`var_50`, `arg_18`, `arg_20`, `var_58`, `var_4c`) before passing their addresses to `PiixIdepTransferModeSelect`, which computes IDE timing values and returns them through those output pointers. Those values are later written to PCI config registers via `PciIdeXSetBusData`.
*   **Why this is not a vulnerability:** In BOTH builds `PiixIdepTransferModeSelect` has a single return path and writes all six output parameters (`*a3`…`*a8`) unconditionally immediately before `return 0`; there is no early return that could leave an output unwritten. `PiixIdeTransferModeSelect` only proceeds to the `PciIdeXSetBusData` writes when that call returns `>= 0` (always, since it returns 0). Therefore the locals are always fully initialized by the callee before use in every path of the unpatched build. The added zeroing is dead defensive code (robustness against future callee changes), not a fix for a reachable uninitialized read.

## 3. Decompiled Diff

### `PiixIdeGetControllerProperties`
```c
// --- UNPATCHED (0x1C0001040) ---
__int16 v33;                 // var_E8, buffer for first read — NOT cleared
_DWORD v32[4];               // var_F8, bus-location out — NOT cleared
_BYTE  v36[84];              // var_A8, buffer for second read — NOT cleared

result = PciIdeXGetBusData(a1, &v33, 0, 64);      // first read, no prior memset
...
v5 = PciIdeXGetBusData(a1, v36, 0, 86);           // second read, no prior memset
...
PciIdexGetBusLocation(a1, v32, 2147483665, ...);  // v32 not initialized
if ( v32[0] == 2031618 ) ...                       // 0x1F0002

// --- PATCHED (0x1C0001050) ---
_WORD v42[32];               // 64-byte buffer
_WORD v43[48];               // 86-byte buffer
_DWORD v41[4];               // bus-location out

memset(v42, 0, sizeof(v42));           // <<< ADDED, 0x40
result = PciIdeXGetBusData(a1, v42, 0, 64);
...
memset(v43, 0, 0x56u);                 // <<< ADDED, 0x56
v5 = PciIdeXGetBusData(a1, v43, 0, 86);
...
v41[0] = 0;                            // <<< ADDED
PciIdexGetBusLocation(a1, v41, 10176, 2147483665);
if ( v41[0] == 2031618 ) ...
```

### `PiixIdeChannelEnabled`
```c
// --- UNPATCHED (0x1C0001580) ---
_BYTE v4[16];                          // buffer — NOT cleared
if ( (int)PciIdeXGetBusData(a1, v4, 64, 4) >= 0 )
    return (unsigned __int8)v4[2 * v2 + 1] >> 7;
return 2;

// --- PATCHED (0x1C00015B0) ---
_BYTE v5[80];
memset(v5, 0, 0x4Cu);                  // <<< ADDED
if ( (int)PciIdeXGetBusData(a1, &v5[64], 64, 4) >= 0 )
    return (unsigned __int8)v5[2 * v2 + 65] >> 7;
return 2;
```

### `PiixIdeTransferModeSelect`
```c
// --- UNPATCHED (0x1C0001660) --- locals not pre-zeroed
PiixIdepTransferModeSelect(a1, a2, &v29, v27, &v30, &v31, v25, v28);
// callee writes ALL of *a3..*a8 unconditionally before returning 0

// --- PATCHED (0x1C00016B0) --- defensive zero-init added
v25[0] = 0; v28 = 0; v29 = 0; v23[0] = 0; v26[0] = 0;   // <<< ADDED (dead: callee overwrites)
PiixIdepTransferModeSelect(a1, a2, &v27, v25, &v28, &v29, v23, v26);
```

## 4. Assembly Evidence

### `PiixIdeGetControllerProperties` — first PCI read
```assembly
; --- UNPATCHED (no clear before read) ---
00000001C000107E  mov     r9d, 40h
00000001C0001084  lea     rdx, [rsp+118h+var_E8]      ; buffer, NOT cleared
00000001C0001089  xor     r8d, r8d
00000001C000108C  call    cs:__imp_PciIdeXGetBusData
00000001C00010A2  movzx   ecx, [rsp+118h+var_E6]      ; device ID from buffer
00000001C00010AF  cmp     [rsp+118h+var_E8], ax        ; vendor 0x8086 check
00000001C00010CA  test    [rsp+118h+var_DF], 80h       ; capability bit from buffer

; --- PATCHED (memset added) ---
00000001C0001080  mov     esi, 40h
00000001C0001085  lea     rcx, [rsp+110h+var_E0]       ; buffer
00000001C000108A  mov     r8d, esi                     ; Size = 0x40
00000001C000108D  xor     edx, edx                     ; Val = 0
00000001C000108F  call    memset                       ; <<< ADDED
00000001C00010A3  mov     r9d, esi
00000001C00010A6  lea     rdx, [rsp+110h+var_E0]
00000001C00010B1  call    cs:__imp_PciIdeXGetBusData
```

### `PiixIdeGetControllerProperties` — second read and bus-location
```assembly
; --- PATCHED second read (0x56) ---
00000001C00012E2  mov     r14d, 56h
00000001C00012E8  lea     rcx, [rbp+57h+var_A0]
00000001C00012EC  mov     r8d, r14d
00000001C00012EF  xor     edx, edx
00000001C00012F1  call    memset                       ; <<< ADDED
00000001C0001303  call    cs:__imp_PciIdeXGetBusData

; --- UNPATCHED bus-location (var_F8 not cleared) ---
00000001C0001468  lea     rdx, [rsp+118h+var_F8]
00000001C0001470  call    cs:__imp_PciIdexGetBusLocation
00000001C00014B3  cmp     [rsp+118h+var_F8], 1F0002h

; --- PATCHED bus-location (var_F0 zeroed first) ---
00000001C0001487  and     [rsp+110h+var_F0], 0         ; <<< ADDED zero-init
00000001C0001494  call    cs:__imp_PciIdexGetBusLocation
00000001C00014D9  cmp     [rsp+110h+var_F0], 1F0002h
```

### `PiixIdeChannelEnabled`
```assembly
; --- UNPATCHED ---
00000001C00015A6  mov     r9d, 4
00000001C00015AC  lea     rdx, [rsp+88h+var_28]        ; buffer, NOT cleared
00000001C00015B1  lea     r8d, [r9+3Ch]                ; offset 0x40
00000001C00015B5  call    cs:__imp_PciIdeXGetBusData
00000001C00015CC  movzx   eax, [rsp+rbx*2+88h+var_27]  ; per-channel byte
00000001C00015D1  shr     eax, 7                       ; bit 7 = channel enabled

; --- PATCHED (memset added) ---
00000001C00015D1  xor     edx, edx
00000001C00015D3  lea     rcx, [rsp+88h+var_68]
00000001C00015D8  lea     r8d, [rdx+4Ch]               ; Size = 0x4C
00000001C00015DC  call    memset                       ; <<< ADDED
00000001C00015ED  mov     r9d, 4
00000001C00015F3  lea     rdx, [rsp+88h+var_28]
00000001C00015FF  call    cs:__imp_PciIdeXGetBusData
```

### `PiixIdeTransferModeSelect` — prologue zero-init (defensive, dead)
```assembly
; --- UNPATCHED (no local zero-init before callee) ---
00000001C0001670  mov     rbp, rsp
00000001C0001673  sub     rsp, 60h
00000001C0001677  mov     r14d, 2
...
00000001C000172E  call    PiixIdepTransferModeSelect   ; callee fills all outputs

; --- PATCHED (5 locals zeroed) ---
00000001C00016C7  xor     esi, esi
00000001C00016D0  mov     [rbp+var_18], si             ; <<< var_50 = 0
00000001C00016D7  mov     [rbp+arg_10], sil            ; <<< arg_18 = 0
00000001C00016DE  mov     [rbp+arg_18], sil            ; <<< arg_20 = 0
00000001C00016E6  mov     [rbp+var_20], sil            ; <<< var_58 = 0
00000001C00016ED  mov     [rbp+var_14], si             ; <<< var_4c = 0
...
00000001C0001793  call    PiixIdepTransferModeSelect   ; callee still fills all outputs
```

## 5. Trigger / Reachability

These changes live entirely in the driver-initialization path and are not asynchronously reachable:

1.  The PE entry `GsDriverEntry` (`0x1C0007010`) calls `DriverEntry` (`0x1C0001008`), which calls `PciIdeXInitialize(DriverObject, RegistryPath, PiixIdeGetControllerProperties, 1052)`.
2.  During PCI IDE controller enumeration, the PCIIDEX library invokes `PiixIdeGetControllerProperties`, which reads the controller's own PCI configuration space and registers the per-controller callbacks (`PiixIdeChannelEnabled` at `+0x18`, `PiixIdeTransferModeSelect` at `+0x28`, `PiixIdeUseDma` at `+0x38`, `PiixIdeUdmaModesSupported` at `+0x48`, `PiixIdeSyncAccessRequired` at `+0x20`).
3.  All data consumed by the modified code originates from the controller's assigned PCI configuration registers via the PCIIDEX library, not from any user-mode, file, or network input.

Because the only way to observe the pre-patch behavior would be for `PciIdeXGetBusData` to report success while leaving part of a requested buffer unwritten, and because that data path is the device's own config space during boot, there is no attacker-controlled input and no exposed read-back channel. The hardening removes a latent stale-data dependency; it does not close a reachable attack.

## 6. Exploitability

No exploit primitive is present. The affected routines are init-only, operate on the controller's own PCI configuration space, and are not reachable from an untrusted surface. There is no demonstrable information-disclosure, memory-corruption, or denial-of-service primitive derivable from these changes. Claims of a KASLR bypass or a leak of kernel pointers through PCI configuration registers are not supported by the binaries: the driver writes computed IDE timing values (in `PiixIdeTransferModeSelect`) that the callee has already fully populated, and there is no path that copies kernel stack addresses into an attacker-readable register.

## 7. Verification Notes

The pre- and post-patch behavior can be compared under a kernel debugger by observing the added initialization rather than any exploitable effect:

*   `PiixIdeGetControllerProperties` (unpatched `0x1C0001040`): the buffer at `var_E8` is uncleared before the `PciIdeXGetBusData` call at `0x1C000108C`; in the patched build (`0x1C0001050`) `memset` runs at `0x1C000108F` before the read at `0x1C00010B1`.
*   `PiixIdeChannelEnabled` (unpatched `0x1C0001580`): the byte read at `0x1C00015CC` comes from an uncleared buffer; the patched build (`0x1C00015B0`) clears it via `memset` at `0x1C00015DC`.
*   `PiixIdeTransferModeSelect` (unpatched `0x1C0001660`): break after `PiixIdepTransferModeSelect` returns (`0x1C0001733`) and confirm the six output locals are populated by the callee on every path; the patched build's prologue zero-init (`0x1C00016C7`–`0x1C00016ED`) does not change the observed outputs.

## 8. Changed Functions — Full Triage

*   **`PiixIdeGetControllerProperties`** (unpatched `0x1C0001040` → patched `0x1C0001050`): [Hardening] Adds `memset` before both `PciIdeXGetBusData` reads (0x40 and 0x56 bytes) and zeroes the bus-location local before `PciIdexGetBusLocation`. Init-only, not attacker-reachable.
*   **`PiixIdeChannelEnabled`** (unpatched `0x1C0001580` → patched `0x1C00015B0`): [Hardening] Adds `memset(buf, 0, 0x4C)` before the `PciIdeXGetBusData` read. Init-only, not attacker-reachable.
*   **`PiixIdeTransferModeSelect`** (unpatched `0x1C0001660` → patched `0x1C00016B0`): [No security change] Adds defensive zero-init of five locals that `PiixIdepTransferModeSelect` already writes unconditionally; no reachable uninitialized use.
*   **`PiixIdepTransferModeSelect`** (unpatched `0x1C00019B8` → patched `0x1C0001A24`): [Cosmetic/Behavioral] Register reallocation and basic-block restructuring; still writes all six output parameters unconditionally before returning. No security checks changed.
*   **`PiixIdeUdmaModesSupported`** (unpatched `0x1C0001600` → patched `0x1C0001660`): [Cosmetic] Trivial bit-count loop codegen difference; semantically equivalent.
*   **`__GSHandlerCheckCommon`** (unpatched `0x1C0002004` → patched `0x1C0002054`): [Cosmetic] Zero-extension instruction-selection difference from binary layout shift.

## 9. Added / Removed Functions

*   **Added in patched (byproduct of introducing `memset`, not fixes):** `memset` (`0x1C0002200`), `__memset_repmovs` (`0x1C0002340`), `__memset_query` (`0x1C00023C0`), `__cpu_features_init` (`0x1C00020D0`) — the compiler-runtime `memset` implementation and its CPU-feature probe — plus `_guard_xfg_dispatch_icall_nop` (`0x1C00021C0`), an XFG control-flow-guard dispatch thunk. None is a standalone security fix.
*   **Removed:** None.

## 10. Confidence & Caveats

*   **Confidence:** High. The added `memset`/zero-init instructions are present in the patched build at the addresses above and absent in the unpatched build; the direction is unambiguous (patched initializes; unpatched does not).
*   **Assessment:** The change is CWE-908-style defensive initialization confined to the controller-initialization path. It is not reachable from an untrusted surface, and one of the three touched sites (`PiixIdeTransferModeSelect`) guards locals the callee already fully writes. No exploitable information-disclosure, corruption, or DoS primitive is demonstrable from the binaries.
*   **Caveat:** Observing any pre-patch difference at all requires `PciIdeXGetBusData` to report success while under-filling a requested buffer for the controller's own configuration space during boot — a hardware/library-dependent condition with no attacker-controlled input.
