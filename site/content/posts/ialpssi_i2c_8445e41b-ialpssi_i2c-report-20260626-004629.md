Title: ialpssi_i2c.sys — No security-relevant change (I2C spike-suppression register programming added; speed-mode writes refactored per mode)
Date: 2026-06-26
Slug: ialpssi_i2c_8445e41b-ialpssi_i2c-report-20260626-004629
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: None

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `ialpssi_i2c_unpatched.sys` |
| **Patched binary** | `ialpssi_i2c_patched.sys` |
| **Overall similarity** | 0.9912 (99.12%) |
| **Matched functions** | 165 |
| **Changed functions (below similarity threshold)** | 6 |
| **Identical functions** | 159 |
| **Unmatched (unpatched)** | 0 |
| **Unmatched (patched)** | 0 |

**Verdict:** The patch adds programming of the Intel LPSS (DesignWare-compatible) I2C controller's spike-suppression length registers (`SPKLEN` at MMIO `0xA0`, `HS_SPKLEN` at MMIO `0xA4`) and restructures the SCL-count register writes in `ControllerConfigureForTransfer` from an unconditional linear sequence into per-speed-mode branches. This is a **functional / hardware-correctness change, not a security fix.** The values written come from build-time defaults, ACPI/registry configuration, and hardware-ID overrides - none of them is attacker-controlled. The change crosses no trust boundary, introduces no memory-safety effect, and provides no exploit primitive. The remaining changed functions differ only by a struct-offset cascade (four new `SPK_Cnt` config fields grow `PBC_DEVICE` by `0x10` bytes), a WPP trace-GUID rebuild-identity rename, and a DMA cache-type tweak.

---

## 2. Change Summary

### Finding 1: Added `SPKLEN` / `HS_SPKLEN` programming and per-mode restructuring of speed-register writes

| Attribute | Detail |
|---|---|
| **Severity** | None (functional / hardware-correctness change) |
| **Class** | Hardware register programming / configuration completeness |
| **Affected function** | `ControllerConfigureForTransfer` (unpatched `0x1400083c0`, patched `0x140008360`) |
| **Attacker-controlled input** | None - all values are compile-time defaults, ACPI/registry values, or hardware-ID overrides |
| **Impact** | No kernel memory corruption, no code execution, no privilege escalation, no trust-boundary crossing. At most a device-level reliability/correctness improvement whose real effect depends on silicon reset defaults that cannot be determined from these binaries. |

**What actually changed:** In the unpatched build, `ControllerConfigureForTransfer` writes the Standard (`0x14`/`0x18`), Fast/FastPlus (`0x1c`/`0x20`) and HighSpeed (`0x24`/`0x28`) SCL high/low count registers as one linear sequence, and it does not write the `SPKLEN` (`0xA0`) or `HS_SPKLEN` (`0xA4`) registers at all. The active speed mode is still selected - it is programmed into the `IC_CON` control register at MMIO offset `0` (`(2 * (mode & 3)) | 0x61`), and it drives a `switch` that selects the SDA-hold value written to `0x7c`.

In the patched build the SCL-count writes are moved inside that same speed-mode `switch`, so each branch writes only the register group relevant to the selected mode, and each branch additionally writes `SPKLEN` (`0xA0`) from a new per-mode `SPK_Cnt` config field. The HighSpeed branch also writes `HS_SPKLEN` (`0xA4`).

**Why this is not a security issue:**

- On DesignWare-compatible I2C controllers the SCL-count registers for a given speed are consumed only when `IC_CON` selects that speed. Writing the count registers for inactive modes stages values that the hardware ignores; it does not corrupt controller state. The unpatched linear sequence is therefore functionally harmless, and the patched restructuring is a code-cleanup side effect of introducing the `SPK_Cnt` fields, not the repair of a corruption bug.
- The `SPK_Cnt` values are populated by `GetDefaultSettings` (constants), `GetRegistrySettings` (registry, i.e. administrator-controlled), and `OverrideDefaultsForHardware` (hardware-ID constants). None is reachable from an untrusted input surface.
- The hardware reset value of `SPKLEN`/`HS_SPKLEN` on the target silicon cannot be read from these binaries, so the claim that the unpatched driver leaves "no spike filtering" cannot be substantiated. Any effect of the added programming is at most a bus-reliability improvement under real electrical conditions, not a security boundary.

**Code path that reaches the changed function:**

1. An SPB (Simple Peripheral Bus) I2C read/write/sequence request handled by `OnRead` (`0x140004ec8`), `OnWrite` (`0x140005b90`), `OnSequence` (`0x1400055b4`), or `PbcRequestConfigureForNonSequence` (`0x140006298`).
2. `ControllerConfigureForTransfer_PassiveLevel` (`0x140002434`) - WDF passive-level work-item callback.
3. `ControllerConfigureForTransfer` (`0x1400083c0`) - programs the I2C controller registers.

This path is standard for an SPB controller driver; it is the reason the function runs, not evidence of an attack surface for the register-programming change.

---

## 3. Decompiled Diff

### `ControllerConfigureForTransfer` - Before vs. After

The following reflects the decompiled register-programming region of each build (`a1` = `PBC_DEVICE*`, `*((_QWORD*)a1 + 1)` = MMIO base at `a1+0x8`).

```c
// ============================================================
// UNPATCHED - ControllerConfigureForTransfer (0x1400083c0)
// ============================================================
// IC_CON at MMIO+0 encodes the speed mode: (2*(mode&3)) | 0x61
HWREG<unsigned long>::Write(mmio,        (2 * (req_params->speed_mode & 3)) | 0x61);

// SCL high/low counts for ALL modes, written linearly (no per-mode gating):
HWREG<unsigned long>::Write(mmio + 0x14, a1->SS_SCL_High);   // a1+0x70
HWREG<unsigned long>::Write(mmio + 0x18, a1->SS_SCL_Low);    // a1+0x74
HWREG<unsigned long>::Write(mmio + 0x1c, /* FS or FSPlus SCL High */); // a1+0x7c / a1+0x88
HWREG<unsigned long>::Write(mmio + 0x20, /* FS or FSPlus SCL Low  */); // a1+0x80 / a1+0x8c
HWREG<unsigned long>::Write(mmio + 0x24, a1->HS_SCL_High);   // a1+0x94
HWREG<unsigned long>::Write(mmio + 0x28, a1->HS_SCL_Low);    // a1+0x98

// No write to SPKLEN (0xA0) or HS_SPKLEN (0xA4) anywhere in the function.

// switch on speed mode selects only the SDA-hold value written to 0x7c:
switch (req_params->speed_mode) {
  case 1: HWREG::Write(mmio + 0x7c, a1->SS_SDA_Hold);    break; // a1+0x78
  case 2: HWREG::Write(mmio + 0x7c, /* FS/FSPlus hold */); break;
  case 3: HWREG::Write(mmio + 0x7c, a1->HS_SDA_Hold);    break;
}
HWREG<unsigned long>::Write(mmio + 0x6c, 1);  // enable controller

// ============================================================
// PATCHED - ControllerConfigureForTransfer (0x140008360)
// ============================================================
HWREG<unsigned long>::Write(mmio, (2 * (req_params->speed_mode & 3)) | 0x61);

switch (req_params->speed_mode) {
  case 1: // Standard
    HWREG::Write(mmio + 0x14, a1->SS_SCL_High);   // a1+0x70
    HWREG::Write(mmio + 0x18, a1->SS_SCL_Low);    // a1+0x74
    HWREG::Write(mmio + 0xa0, a1->SS_SPK_Cnt);    // a1+0x7c  <<< NEW SPKLEN
    HWREG::Write(mmio + 0x7c, a1->SS_SDA_Hold);   // a1+0x78
    break;
  case 2: // Fast / FastPlus (two sub-paths on the FastPlus flag)
    HWREG::Write(mmio + 0x1c, /* FS/FSPlus SCL High */); // a1+0x80 / a1+0x90
    HWREG::Write(mmio + 0x20, /* FS/FSPlus SCL Low  */); // a1+0x84 / a1+0x94
    HWREG::Write(mmio + 0xa0, /* FS/FSPlus SPK_Cnt  */); // a1+0x8c / a1+0x9c  <<< NEW SPKLEN
    HWREG::Write(mmio + 0x7c, /* FS/FSPlus SDA hold */); // a1+0x88 / a1+0x98
    break;
  case 3: // HighSpeed (writes the FS-phase group plus the HS group)
    HWREG::Write(mmio + 0x1c, a1->FS_SCL_High);   // a1+0x80
    HWREG::Write(mmio + 0x20, a1->FS_SCL_Low);    // a1+0x84
    HWREG::Write(mmio + 0xa0, a1->FS_SPK_Cnt);    // a1+0x8c  <<< NEW SPKLEN
    HWREG::Write(mmio + 0x24, a1->HS_SCL_High);   // a1+0xa0
    HWREG::Write(mmio + 0x28, a1->HS_SCL_Low);    // a1+0xa4
    HWREG::Write(mmio + 0xa4, a1->HS_SPK_Cnt);    // a1+0xac  <<< NEW HS_SPKLEN
    HWREG::Write(mmio + 0x7c, a1->HS_SDA_Hold);   // a1+0xa8
    break;
}
HWREG<unsigned long>::Write(mmio + 0x6c, 1);  // enable controller
```

**Key takeaways:**

- The unpatched code writes all three SCL-count groups linearly; the patched code moves them inside the existing per-mode `switch`.
- The patched code adds a `SPKLEN` (`0xA0`) write in every branch and an `HS_SPKLEN` (`0xA4`) write in the HighSpeed branch.
- The mode is programmed into `IC_CON` (MMIO `0`) in both builds, so the hardware always operates in the intended speed regardless of the linear-vs-branched write ordering.

---

## 4. Assembly Analysis

### Unpatched `ControllerConfigureForTransfer` - speed-register block

The following instructions are copied from the unpatched disassembly (`rsi` = `PBC_DEVICE*`, `[rsi+8]` = MMIO base). The register-programming block runs from `0x1400087e0` through the speed-mode check at `0x140008878`:

```asm
00000001400087E4  mov     edx, [rsi+70h]      ; Standard SCL High count
00000001400087E7  add     rcx, 14h            ; MMIO + 0x14 (SS_SCL_HCNT)
00000001400087EB  call    ?Write@?$HWREG@K@@QEAAKK@Z
00000001400087F0  mov     rcx, [rsi+8]
00000001400087F4  mov     edx, [rsi+74h]      ; Standard SCL Low count
00000001400087F7  add     rcx, 18h            ; MMIO + 0x18 (SS_SCL_LCNT)
00000001400087FB  call    ?Write@?$HWREG@K@@QEAAKK@Z
0000000140008800  mov     rax, [rsi+30h]      ; request params
0000000140008804  mov     rcx, [rsi+8]
0000000140008808  add     rcx, 1Ch            ; MMIO + 0x1c (FS_SCL_HCNT)
000000014000880C  cmp     [rax+14h], r13b     ; FastPlus flag
0000000140008810  jnz     short loc_140008822
0000000140008812  mov     edx, [rsi+7Ch]      ; Fast SCL High
0000000140008815  call    ?Write@?$HWREG@K@@QEAAKK@Z
000000014000881A  mov     edx, [rsi+80h]      ; Fast SCL Low (staged)
0000000140008820  jmp     short loc_140008833
0000000140008822  mov     edx, [rsi+88h]      ; FastPlus SCL High
0000000140008828  call    ?Write@?$HWREG@K@@QEAAKK@Z
000000014000882D  mov     edx, [rsi+8Ch]      ; FastPlus SCL Low
0000000140008833  mov     rcx, [rsi+8]
0000000140008837  add     rcx, 20h            ; MMIO + 0x20 (FS_SCL_LCNT)
000000014000883B  call    ?Write@?$HWREG@K@@QEAAKK@Z
0000000140008840  mov     rcx, [rsi+8]
0000000140008844  mov     edx, [rsi+94h]      ; HighSpeed SCL High count
000000014000884A  add     rcx, 24h            ; MMIO + 0x24 (HS_SCL_HCNT)
000000014000884E  call    ?Write@?$HWREG@K@@QEAAKK@Z   ; written regardless of mode
0000000140008853  mov     rcx, [rsi+8]
0000000140008857  mov     edx, [rsi+98h]      ; HighSpeed SCL Low count
000000014000885D  add     rcx, 28h            ; MMIO + 0x28 (HS_SCL_LCNT)
0000000140008861  call    ?Write@?$HWREG@K@@QEAAKK@Z   ; written regardless of mode
0000000140008866  mov     ecx, [rsi+rbp*4+60B8h]       ; per-mode timeout value
000000014000886D  mov     [r15+24h], ecx
0000000140008871  mov     rcx, [rsi+30h]      ; request params
0000000140008875  mov     eax, [rcx+10h]      ; speed mode (1=Std, 2=Fast, 3=HS)
0000000140008878  cmp     eax, r12d           ; mode == 1 (Standard)?
```

No instruction anywhere in the unpatched function targets `MMIO+0xA0` (`SPKLEN`) or `MMIO+0xA4` (`HS_SPKLEN`) - confirmed by scanning the full function body (`0x1400083c0`–`0x140009bf8`) for `add rcx, 0A0h` / `0A4h`, which yields no match.

### Patched `ControllerConfigureForTransfer` - added writes

In the patched function (`0x140008360`–`0x140009c50`) the same scan finds the new writes: `add rcx, 0A0h` at `0x1400087be`, `0x140008830`, `0x140008892`, `0x140008901` (the `SPKLEN` writes across the Standard, both Fast sub-paths, and HighSpeed branches) and `add rcx, 0A4h` at `0x14000893d` (the `HS_SPKLEN` write in the HighSpeed branch). Each is reached only inside its speed-mode branch.

---

## 5. Reachability

1. **Obtain a handle to the I2C controller device.** From user mode, open the SPB device interface (e.g. WinRT `Windows.Devices.I2c.I2cDevice.FromIdAsync()`, or `CreateFileW` on the SPB device symbolic link). Opening the device typically requires device-access capability or an appropriately privileged caller.

2. **Submit any I2C read or write transfer.** Any valid transfer causes `ControllerConfigureForTransfer` to run. The register-programming change is unconditional with respect to request content; no special buffer size, offset, or sequence influences it.

3. **No attacker-controlled data flows into the changed code.** The `SPK_Cnt` and SCL-count values come from driver configuration (defaults, ACPI/registry, hardware-ID overrides), not from the request. There is no input-dependent branch, bounds decision, or buffer sizing here.

---

## 6. Impact Assessment

### Primitive

None. There is no kernel memory corruption, no arbitrary read/write, no use-after-free, and no code-execution primitive. The change only alters which fixed hardware-configuration values are written to controller registers and in what order.

### Scope and limitations

- This is a functional/correctness change to hardware register programming. It does not cross a trust boundary and provides no escalation.
- No memory-safety mitigation (SMEP/SMAP/CFG/kASLR/HVCI) is relevant, because no memory-safety condition is involved.
- The practical effect of adding `SPKLEN`/`HS_SPKLEN` programming depends on the silicon's reset defaults for those registers, which are not observable in these binaries. The most that can be stated is that the patched driver now sets spike-suppression length from configuration rather than relying on the hardware default.

---

## 7. Observing the Change in a Debugger

This section describes how to observe the changed behavior; it is not an exploit. The change has no exploit primitive.

### Breakpoints

```windbg
bp ialpssi_i2c!ControllerConfigureForTransfer   ;; entry of the changed function
bp ialpssi_i2c!HWREG<unsigned long>::Write       ;; every controller register write (0x14000be00)
```

If symbols are unavailable, use load-adjusted absolute addresses:

```windbg
bp 0x1400083c0    ;; ControllerConfigureForTransfer entry (unpatched)
bp 0x14000be00    ;; HWREG<unsigned long>::Write
```

> Adjust by the actual load base: `actual = module_base + (preferred - 0x140000000)`. Use `lm ialpssi_i2c` for the base.

### What to inspect

**At `ControllerConfigureForTransfer` entry:** `rcx` = `PBC_DEVICE*`; `[rcx+0x8]` = MMIO base; `rdx` = `PBC_REQUEST*`.

**At each `HWREG::Write` (`0x14000be00`):** `rcx` = MMIO base + register offset (low byte identifies the register: `0x14`/`0x18` SS SCL, `0x1c`/`0x20` FS SCL, `0x24`/`0x28` HS SCL, `0xA0` `SPKLEN`, `0xA4` `HS_SPKLEN`, `0x7c` SDA hold, `0x6c` enable); `edx` = value written. The speed mode is at `poi(rsi+0x30)+0x10` (`1`=Standard, `2`=Fast/FastPlus, `3`=HighSpeed).

### Expected observation

- **Unpatched:** MMIO `0xA0` and `0xA4` are never written; the SCL-count registers for all three speed groups are written on every configuration.
- **Patched:** MMIO `0xA0` is written in each speed-mode branch and `0xA4` in the HighSpeed branch; only the selected mode's SCL-count registers are written.

### `PBC_DEVICE` field layout

The patch inserts one `SPK_Cnt` DWORD after each speed-mode group, growing `PBC_DEVICE` by `0x10` bytes and cascading all later field offsets by `+0x10`.

| Patched field offset | Field | Written to MMIO |
|---|---|---|
| `+0x70` | StandardSpeed SCL High | `0x14` |
| `+0x74` | StandardSpeed SCL Low | `0x18` |
| `+0x78` | StandardSpeed SDA Hold | `0x7c` |
| `+0x7c` | StandardSpeed SPK_Cnt (**new**) | `0xA0` |
| `+0x80` | FastSpeed SCL High | `0x1c` |
| `+0x84` | FastSpeed SCL Low | `0x20` |
| `+0x88` | FastSpeed SDA Hold | `0x7c` |
| `+0x8c` | FastSpeed SPK_Cnt (**new**) | `0xA0` |
| `+0x90` | FastSpeedPlus SCL High | `0x1c` |
| `+0x94` | FastSpeedPlus SCL Low | `0x20` |
| `+0x98` | FastSpeedPlus SDA Hold | `0x7c` |
| `+0x9c` | FastSpeedPlus SPK_Cnt (**new**) | `0xA0` |
| `+0xa0` | HighSpeed SCL High | `0x24` |
| `+0xa4` | HighSpeed SCL Low | `0x28` |
| `+0xa8` | HighSpeed SDA Hold | `0x7c` |
| `+0xac` | HighSpeed SPK_Cnt (**new**) | `0xA4` |

In the unpatched layout the same fields sit `0x10` bytes lower from `+0x7c` onward (no `SPK_Cnt` fields present).

---

## 8. Changed Functions - Full Triage

The binary-diff similarity threshold flagged six functions. An independent function-by-function diff of both decompilations (matching by mangled name, ignoring address relocation) confirms that every other apparent difference is limited to the `+0x10` struct-offset cascade, a WPP trace-GUID symbol rename (`c7fd46ab…` → `64ec75d3…`, build identity), and decompiler cast/formatting churn. No omitted security-relevant change was found.

### 1. `GetDefaultSettings` (similarity 0.9756) - non-security

- Adds four `SPK_Cnt` default values, one per speed group, at the new struct offsets (`0x7c`, `0x8c`, `0x9c`, `0xac`).
- Subsequent field offsets shift `+0x10`; WPP `TraceGUIDs` changed (build identity).

### 2. `GetRegistrySettings` (similarity 0.9889) - non-security

- Adds four `ReadRegistryKeyForController` calls to read `SPK_Cnt` values from the registry into the new offsets.
- Subsequent field offsets shift `+0x10`.

### 3. `OverrideDefaultsForHardware` (similarity 0.9891) - non-security

- Adds `SPK_Cnt` override values for a specific hardware ID at the new offsets.
- Subsequent field offsets shift `+0x10`.

### 4. `ControllerConfigureForTransfer` (similarity 0.985) - functional, non-security

- Adds `SPKLEN` (`0xA0`) programming in every speed-mode branch and `HS_SPKLEN` (`0xA4`) in the HighSpeed branch; moves the SCL-count writes inside the existing per-mode `switch`. See Sections 3–4. Not a security fix (see Section 2).

### 5. `ControllerConfigureForTransfer_PassiveLevel` (similarity 0.985) - cosmetic

- Field offset `+0x10` cascade and updated jump target into the relocated `ControllerConfigureForTransfer`. No behavioral change.

### 6. `I2CInitDma` (similarity 0.9927) - non-security

- `MmAllocateContiguousMemorySpecifyCache` `CacheType` changed from `MmNonCached` (`0`) to `MmCached` (`1`) for the DMA contiguous buffer. A performance/correctness change, not security-relevant.
- DMA-related struct offsets shift `+0x10`; register-allocation differences are cosmetic.

---

## 9. Unmatched Functions

No functions were added or removed (`unmatched_unpatched: 0`, `unmatched_patched: 0`). No new validation, sanitizer, or mitigation helper was introduced or removed.

---

## 10. Confidence & Caveats

### Confidence: High (that the change is not security-relevant)

- The diff is small and the changed region is fully accounted for by verified disassembly and decompilation.
- The independent per-function diff confirms no security-relevant change was omitted.

### Notes

1. **Register map is DesignWare-compatible.** The offsets (`0x14`/`0x18` SS, `0x1c`/`0x20` FS, `0x24`/`0x28` HS, `0xA0` `SPKLEN`, `0xA4` `HS_SPKLEN`, `0x7c` SDA hold, `0x6c` enable, `0` `IC_CON`) match the Synopsys DesignWare I2C map that Intel LPSS uses, consistent with the driver name and the observed usage.

2. **`SPK_Cnt` values are configuration constants.** They originate from `GetDefaultSettings`, `GetRegistrySettings`, and `OverrideDefaultsForHardware` - none is attacker-controlled.

3. **Reset-default behavior of `SPKLEN`/`HS_SPKLEN` is not observable here.** Whether the unpatched driver left spike suppression at a usable value or not depends on silicon reset defaults that these binaries do not reveal; the security-neutral conclusion does not depend on that value.
