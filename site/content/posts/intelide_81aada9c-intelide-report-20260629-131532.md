Title: intelide.sys — No security-relevant change (init-only zero-init hardening of PCI IDE enumeration callbacks)
Date: 2026-06-29
Slug: intelide_81aada9c-intelide-report-20260629-131532
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Informational
KBDate: 2026-06-09

## 1. Overview

- **Unpatched Binary:** `intelide_unpatched.sys`
- **Patched Binary:** `intelide_patched.sys`
- **Overall Similarity Score:** 0.7894
- **Diff Statistics:**
  - Matched functions: 16 in the unpatched build; the three callbacks that changed added zero-initialization only.
  - Added in the patched build: 5 functions — `memset` (0x1C0002200), `__memset_repmovs` (0x1C0002340), `__memset_query` (0x1C00023C0), `__cpu_features_init` (0x1C00020D0), and `_guard_xfg_dispatch_icall_nop` (0x1C00021C0). These are the memset runtime family pulled in by the new memset calls, the CPUID feature probe that memset uses to pick a code path, and a Control Flow Guard (XFG) dispatch thunk. None is a security fix in itself.
  - Removed: none.

**Verdict:** The patch adds zero-initialization (a `memset` before each `PciIdeXGetBusData` read, and explicit zeroing of five stack slots before a timing-calculator call) to three PCI IDE controller callbacks. These callbacks run only during device initialization / enumeration, they operate on the IDE controller's own PCI configuration space, the fields they consume are all within the requested read length and are used only after the read is confirmed to have succeeded, and in the timing-calculator case the callee already writes every output on every path in both builds. The changes are defense-in-depth CWE-908 zero-init hardening, not a fix for a reachable vulnerability. There is no demonstrable attacker-reachable information disclosure or memory-corruption primitive.

---

## 2. Vulnerability Summary

### Finding 1: Zero-init hardening of the PCI config reads in `PiixIdeGetControllerProperties`
- **Severity:** Informational (defense-in-depth hardening; no reachable impact)
- **Class:** Use of Uninitialized Memory (CWE-908) — hardening only
- **Affected Function:** `PiixIdeGetControllerProperties` (unpatched @ 0x1C0001040, patched @ 0x1C0001050)

**What changed:**
`PiixIdeGetControllerProperties` is the `ControllerInitialize`/properties callback registered with the PciIdeX framework (see `DriverEntry` → `PciIdeXInitialize(..., PiixIdeGetControllerProperties, 1052)`). It reads the controller's own PCI configuration space into two stack buffers: a 0x40-byte read into `v33`/`var_E8` (call at 0x1C000108C) and a 0x56-byte read into `v36`/`var_A8` (call at 0x1C00012E4). The patched build adds `memset(v42, 0, 0x40)` at 0x1C000108F before the first read and `memset(v43, 0, 0x56)` at 0x1C00012F1 before the second read; it also zeroes `v41[0]` before the `PciIdexGetBusLocation` call.

**Why this is not a reachable vulnerability:**
- The buffers are populated by `PciIdeXGetBusData`, and every field the function later consumes lies inside the requested read length: vendor ID at buffer offset 0 (`cmp [rsp+var_E8], 0x8086` at 0x1C00010AF), device ID `var_E6` at offset 2 (0x1C00010A2), the `var_DF` bit-7 test at offset 9 (0x1C00010CA), and the timing byte at offset 84 in the 0x56-byte read. All uses are also gated on the read returning success (`js` at 0x1C000109C; `if ( v5 >= 0 )` for the second read).
- Standard PCI configuration space is at least 256 bytes, so the 0x40- and 0x56-byte reads are fully satisfied on conformant hardware; the "partial read leaves stack residue" scenario is speculative, not demonstrated.
- The callback runs only during PnP device start / enumeration on the controller's own config space, which is not an untrusted, attacker-controlled input surface.

### Finding 2: Zero-init hardening of the sync-mode read in `PiixIdeChannelEnabled`
- **Severity:** Informational (defense-in-depth hardening; no reachable impact)
- **Class:** Use of Uninitialized Memory (CWE-908) — hardening only
- **Affected Function:** `PiixIdeChannelEnabled` (unpatched @ 0x1C0001580, patched @ 0x1C00015B0)

**What changed:**
`PiixIdeChannelEnabled` reads 4 bytes of PCI config at offset 0x40 into `v4`/`var_28` (call at 0x1C00015B5) and returns `v4[2*channel + 1] >> 7`. The patched build adds `memset(v5, 0, 0x4C)` at 0x1C00015DC before the read.

**Why this is not a reachable vulnerability:**
- `a2` (the channel index) is constrained to 0 or 1 by the `test edx, 0xFFFFFFFE` guard at 0x1C0001580; the extracted byte is `var_27[1]` or `var_27[3]`, both inside the 4-byte read.
- The return value is produced only when the read succeeds (`jns` at 0x1C00015C3); on failure the function returns 2.
- This is an init/enumeration-time callback reading the controller's own config space. No attacker-controlled input reaches it, and a 4-byte config read at offset 0x40 is always satisfied on conformant hardware.

### Finding 3: Redundant zero-init of timing-calculator outputs in `PiixIdeTransferModeSelect`
- **Severity:** Informational (redundant hardening; not a bug in either build)
- **Class:** Use of Uninitialized Memory (CWE-908) — hardening only
- **Affected Function:** `PiixIdeTransferModeSelect` (unpatched @ 0x1C0001660, patched @ 0x1C00016B0)

**What changed:**
`PiixIdeTransferModeSelect` passes five stack slots as output pointers to `PiixIdepTransferModeSelect` (the timing calculator, unpatched @ 0x1C00019B8, patched @ 0x1C0001A24), then writes the results to PCI config via `PciIdeXSetBusData`. The patched build zero-initializes those five slots up front (0x1C00016C7 `xor esi, esi` followed by the stores at 0x1C00016D0, 0x1C00016D7, 0x1C00016DE, 0x1C00016E6, 0x1C00016ED).

**Why this is not a reachable vulnerability:**
- The timing calculator has a single return and writes **all six** of its output parameters unconditionally immediately before it (`*a3 = ...; *a4 = ...; *a5 = ...; *a6 = ...; *a7 = ...; *a8 = ...; return 0;`). This is true in **both** builds. There is no path that leaves an output unwritten, so the caller's slots are always initialized by the callee before use.
- Because the callee never returns a negative value, the caller always reaches the `PciIdeXSetBusData` calls with fully-written data. The added zero-init in the patched caller is dead/redundant defense-in-depth, not a fix.

---

## 3. Pseudocode Diff

### `PiixIdeGetControllerProperties`
```c
// UNPATCHED (buffers filled by the reads; fields used are within the read length and gated on success)
__int16 v33;              // [rbp-E8h] BYREF  (0x40-byte PCI config buffer)
_BYTE  v36[84];           // [rbp-A8h] BYREF  (0x56-byte PCI config buffer)
result = PciIdeXGetBusData(a1, &v33, 0, 64);
if ( (int)result >= 0 ) {
    v6 = v34;                       // device ID at offset 2 (within 0x40 read)
    if ( v33 != -32634 ) ...        // vendor ID 0x8086 at offset 0
    if ( v35 >= 0 ) ...             // byte at offset 9 (within 0x40 read)
    ...
    v5 = PciIdeXGetBusData(a1, v36, 0, 86);
    if ( v5 >= 0 ) { ... v37 ... }  // byte at offset 84 (within 0x56 read)
}

// PATCHED (adds a memset before each read; same field uses)
memset(v42, 0, sizeof(v42));        // 0x40 bytes, before first read
result = PciIdeXGetBusData(a1, v42, 0, 64);
...
memset(v43, 0, 0x56u);              // before second read
v5 = PciIdeXGetBusData(a1, v43, 0, 86);
```

### `PiixIdeChannelEnabled`
```c
// UNPATCHED
_BYTE v4[16];             // [rbp-28h] BYREF
if ( (a2 & 0xFFFFFFFE) != 0 ) return 0;                 // channel constrained to 0/1
if ( (int)PciIdeXGetBusData(a1, v4, 64, 4) >= 0 )       // read gated on success
    return (unsigned __int8)v4[2 * v2 + 1] >> 7;        // index 1 or 3, within the 4-byte read
return 2;

// PATCHED (adds memset over the enclosing 0x4C-byte region before the read)
_BYTE v5[80];             // [rbp-68h] BYREF
memset(v5, 0, 0x4Cu);
if ( (v2 & 0xFFFFFFFE) != 0 ) return 0;
if ( (int)PciIdeXGetBusData(a1, &v5[64], 64, 4) >= 0 )
    return (unsigned __int8)v5[2 * v2 + 65] >> 7;
```

### `PiixIdeTransferModeSelect` / `PiixIdepTransferModeSelect`
```c
// Caller: UNPATCHED passes five stack slots uninitialized; PATCHED zeroes them first.
// Callee PiixIdepTransferModeSelect (BOTH builds) writes every output on its single return path:
    *a3 = v61[0];
    *a4 = v63;
    *a5 = v62;
    *a6 = v48;
    *a7 = v49;
    *a8 = v40;
    return 0;
// => the caller's slots are always initialized by the callee before use in either build;
//    the patched caller's zero-init is redundant.
```

---

## 4. Assembly Analysis

### `PiixIdeGetControllerProperties`
```
; UNPATCHED @ 0x1C0001040 (first read, no preceding memset)
00000001C000107E  mov     r9d, 40h                 ; length 0x40
00000001C0001084  lea     rdx, [rsp+118h+var_E8]   ; buffer
00000001C0001089  xor     r8d, r8d                 ; offset 0
00000001C000108C  call    cs:__imp_PciIdeXGetBusData
00000001C000109C  js      loc_1C000154E            ; use gated on success
00000001C00010AF  cmp     [rsp+118h+var_E8], ax    ; vendor ID (offset 0) vs 0x8086
00000001C00010CA  test    [rsp+118h+var_DF], 80h   ; byte at offset 9 (within the 0x40 read)
...
00000001C00012E4  call    cs:__imp_PciIdeXGetBusData ; second read (0x56 into var_A8)

; PATCHED @ 0x1C0001050 (memset before each read)
00000001C000108F  call    memset                   ; zero var_E8 (0x40) before the read
00000001C00010B1  call    cs:__imp_PciIdeXGetBusData
...
00000001C00012F1  call    memset                   ; zero var_A8 (0x56) before the read
00000001C0001303  call    cs:__imp_PciIdeXGetBusData
```

### `PiixIdeChannelEnabled`
```
; UNPATCHED @ 0x1C0001580
00000001C000159A  test    edx, 0FFFFFFFEh          ; channel constrained to 0/1
00000001C00015A6  mov     r9d, 4                   ; length 4
00000001C00015AC  lea     rdx, [rsp+88h+var_28]    ; buffer
00000001C00015B1  lea     r8d, [r9+3Ch]            ; offset 0x40
00000001C00015B5  call    cs:__imp_PciIdeXGetBusData
00000001C00015C3  jns     short loc_1C00015CC      ; use gated on success
00000001C00015CC  movzx   eax, [rsp+rbx*2+88h+var_27] ; index 1 or 3, within the 4-byte read
00000001C00015D1  shr     eax, 7

; PATCHED @ 0x1C00015B0
00000001C00015DC  call    memset                   ; zero 0x4C region before the read
00000001C00015FF  call    cs:__imp_PciIdeXGetBusData
```

### `PiixIdeTransferModeSelect`
```
; PATCHED @ 0x1C00016B0 (redundant zero-init of the five output slots)
00000001C00016C7  xor     esi, esi
00000001C00016D0  mov     [rbp+var_18], si
00000001C00016D7  mov     [rbp+arg_10], sil
00000001C00016DE  mov     [rbp+arg_18], sil
00000001C00016E6  mov     [rbp+var_20], sil
00000001C00016ED  mov     [rbp+var_14], si
; The unpatched function (@ 0x1C0001660) omits these stores, but PiixIdepTransferModeSelect
; writes all six outputs on its only return path in both builds, so the slots are always
; initialized by the callee before use.
```

---

## 5. Trigger Conditions

The three callbacks are invoked by the PciIdeX framework during IDE controller initialization / enumeration:

1. `DriverEntry` calls `PciIdeXInitialize` and registers `PiixIdeGetControllerProperties`; that callback in turn stores `PiixIdeChannelEnabled`, `PiixIdeSyncAccessRequired`, `PiixIdeUseDma`, `PiixIdeUdmaModesSupported`, and `PiixIdeTransferModeSelect` into the controller property structure.
2. These run at device start (boot, or on re-enumeration via "Scan for hardware changes" / `pnputil /scan-devices`), reading and writing the IDE controller's own PCI configuration space.

There is no untrusted, attacker-controlled input to these paths: the data comes from the controller's PCI config space, the consumed fields are within the requested read lengths, the uses are gated on read success, and the timing-calculator outputs are always written by the callee. No information-disclosure or corruption effect is demonstrable from these changes.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive is demonstrable. The changes are zero-initialization hardening on init-only enumeration callbacks:

- The buffers in `PiixIdeGetControllerProperties` and `PiixIdeChannelEnabled` are filled by `PciIdeXGetBusData`, the consumed fields are within the requested read lengths, and the uses are gated on the read succeeding. On conformant PCI hardware the reads (0x40, 0x56, and 4 bytes, all within the 256-byte minimum config space) are fully satisfied.
- In `PiixIdeTransferModeSelect`, the callee writes every output parameter on its single return path in both builds, so no uninitialized value can reach the `PciIdeXSetBusData` writes.
- These callbacks are not reachable from an untrusted IOCTL or user-mode surface; they run during PnP device initialization on the controller's own configuration space.

Consequently there is no KASLR/info-leak, pool, or corruption primitive to build from this diff.

---

## 7. Observation Playbook

The following addresses correspond to the actual instructions in the unpatched build, for anyone who wants to confirm the (benign) behavior in a kernel debugger:

### `PiixIdeGetControllerProperties`
- `bp intelide_unpatched!PiixIdeGetControllerProperties` (0x1C0001040).
- First `PciIdeXGetBusData` call: 0x1C000108C (0x40 bytes into `var_E8`). The vendor-ID check is at 0x1C00010AF; the offset-9 bit test is at 0x1C00010CA. Second read: 0x1C00012E4 (0x56 bytes into `var_A8`).
- Expected: the read fills the requested length on conformant hardware; all consumed fields are within the read and are only used after the success check at 0x1C000109C.

### `PiixIdeChannelEnabled`
- `bp intelide_unpatched!PiixIdeChannelEnabled` (0x1C0001580).
- Read at 0x1C00015B5 (4 bytes at offset 0x40); extraction at 0x1C00015CC / 0x1C00015D1. The channel index is masked to 0/1 at 0x1C000159A, and the result is produced only on the success path (`jns` at 0x1C00015C3).

### `PiixIdeTransferModeSelect`
- `bp intelide_unpatched!PiixIdeTransferModeSelect` (0x1C0001660) and `bp intelide_unpatched!PiixIdepTransferModeSelect` (0x1C00019B8).
- Expected: on return from the timing calculator, all six output slots are written (the callee assigns `*a3`..`*a8` unconditionally before `return 0`), so the subsequent `PciIdeXSetBusData` calls never write uninitialized data.

---

## 8. Changed Functions — Full Triage

- **`PiixIdeGetControllerProperties`** (unpatched 0x1C0001040 / patched 0x1C0001050, similarity ~0.91): **Hardening, not security-relevant.** Added `memset` before each `PciIdeXGetBusData` read and zeroed `v41[0]` before `PciIdexGetBusLocation`. Consumed fields are within the read lengths and gated on success; init-only.
- **`PiixIdeChannelEnabled`** (unpatched 0x1C0001580 / patched 0x1C00015B0, similarity ~0.87): **Hardening, not security-relevant.** Added `memset(0x4C)` before the 4-byte config read; the extracted byte is within the read and gated on success.
- **`PiixIdeTransferModeSelect`** (unpatched 0x1C0001660 / patched 0x1C00016B0, similarity ~0.99): **Redundant hardening, not security-relevant.** Zero-initializes five output slots that the callee already writes on every path in both builds.
- **`PiixIdepTransferModeSelect`** (unpatched 0x1C00019B8 / patched 0x1C0001A24, similarity ~0.86): **Register allocation / control-flow representation only.** Same timing logic; writes all outputs on its single return in both builds. No security change.
- **`PiixIdeUdmaModesSupported`** (unpatched 0x1C0001600 / patched 0x1C0001660): Minor loop/register representation difference (e.g. `*a3 = v8 - 1` vs `v9 = v8++; *a3 = v9`), semantically equivalent. No security change.
- **`__GSHandlerCheckCommon`** (unpatched 0x1C0002004 / patched 0x1C0002054): `mov dl` → `movzx edx` zero-extension of a byte read; functionally equivalent. No security change.

Added in the patched build (compiler/CFG runtime support, not security fixes):
- **`memset`** (0x1C0002200), **`__memset_repmovs`** (0x1C0002340), **`__memset_query`** (0x1C00023C0): the memset runtime family pulled in by the new `memset` calls.
- **`__cpu_features_init`** (0x1C00020D0): CPUID feature probe that `memset` uses to select a `rep movs` vs SSE path.
- **`_guard_xfg_dispatch_icall_nop`** (0x1C00021C0): a Control Flow Guard (XFG) dispatch thunk (guard modernization).

---

## 9. Unmatched Functions

- **Added (patched):** `memset` (0x1C0002200), `__memset_repmovs` (0x1C0002340), `__memset_query` (0x1C00023C0), `__cpu_features_init` (0x1C00020D0), `_guard_xfg_dispatch_icall_nop` (0x1C00021C0). All are memset-runtime / CPU-feature / CFG-guard support introduced by the zero-init change; none is an independent security fix.
- **Removed:** None.

---

## 10. Confidence & Caveats

- **Confidence Level:** High. The decompilation and disassembly of both builds show the changes are zero-initialization added ahead of PCI config reads and one timing-calculator call.
- **Basis for the downgrade:** In all three callbacks the consumed data is within the requested read length and gated on read success, and the timing calculator writes every output on its only return path in both builds, so no uninitialized value is actually used or leaked. The callbacks are init/enumeration-only and operate on the controller's own PCI config space, not an untrusted input surface.
- **Nature of the change:** Defense-in-depth CWE-908 zero-init hardening, consistent with a compiler-driven or code-hygiene initialization pass. No attacker-reachable information-disclosure or corruption primitive follows from this diff.
