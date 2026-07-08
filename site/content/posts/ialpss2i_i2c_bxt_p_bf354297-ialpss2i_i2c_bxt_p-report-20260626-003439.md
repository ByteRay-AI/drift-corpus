Title: ialpss2i_i2c_bxt_p.sys — No security-relevant change (compiler codegen refactor of identical I2C command / RX-FIFO-threshold logic)
Date: 2026-06-26
Slug: ialpss2i_i2c_bxt_p_bf354297-ialpss2i_i2c_bxt_p-report-20260626-003439
Category: Corpus
Author: Argus
Summary: KB5073723

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `ialpss2i_i2c_bxt_p_unpatched.sys` |
| Patched binary | `ialpss2i_i2c_bxt_p_patched.sys` |
| Overall similarity | **0.9472** |
| Matched functions | 170 |
| Changed functions | **99** |
| Identical functions | 71 |
| Unmatched (either direction) | 0 / 0 |

**Verdict:** The patch is a routine recompile of the Intel LPSS2 DesignWare I2C controller driver. Every WPP trace GUID in the module was regenerated (all 10 trace-provider GUID symbols differ between the two builds), which is why nearly every function shows a diff. The two concrete instruction-level deltas that were examined in detail — one in `ControllerDoReadPrepare` and one in `ControllerInitialize` — are both cases where the compiler emitted a *branchless* selection (`neg`/`sbb`/`and`/`add`) in place of a *branchy* selection (`cmovz`, or `cmp`/`jz`/`mov`). In both cases the computed value written to the hardware register is bit-for-bit identical between the two builds for every input. There is no behavioral change, no missing-STOP condition, and no FIFO-threshold change. No security-relevant fix is present.

---

## 2. Change Summary

### Change A — `ControllerDoReadPrepare` (branchless codegen of the same read command)

- **Severity:** None (no security-relevant change)
- **Nature:** Compiler replaced a `cmovz` with an equivalent branchless computation. Same value written.
- **Affected function:** `ControllerDoReadPrepare`
  - Unpatched: `0x14000C940`
  - Patched: `0x14000CAB4`
- **Register touched:** `IC_DATA_CMD` at `controller_base + 0x10`.

**What the function actually does (both builds):**

`ControllerDoReadPrepare` runs a per-byte loop that issues one I2C read command word into `IC_DATA_CMD` (`+0x10`) for each byte still to be read. The loop index `rdi` runs from `[req+0x40]` up to `[req+0x38]`. For each iteration it composes the command word:

- If `rdi == 0` (the first byte of the transfer), the command is `0x500` = `READ (0x100) | RESTART (0x400)`.
- Otherwise the command is `0x100` = `READ` only.
- Additionally, if a device flag (`[req+0x78]`) is set and this is the last byte (`total - rdi == 1`), bit 9 is set (`bts esi, 9`) to add `STOP (0x200)`.

The DesignWare register bit meanings are confirmed by the driver's own trace strings in this function (`and eax, 0x600`; `cmp 0x200 → "| STOP"`, `cmp 0x400 → "| RESTART"`, `cmp 0x600 → "| RESTART | STOP"`). So `0x200` is STOP and `0x400` is RESTART. This is standard DesignWare behavior: RESTART on the first read byte, STOP on the last. Nothing here omits a STOP.

**What changed:** only the way the `0x100`-vs-`0x500` selection is computed. The unpatched build uses `cmovz`; the patched build uses `neg`/`sbb`/`and`/`add`. The `bts esi, 9` STOP-on-last-byte logic is present and identical in both builds. See Section 4 for the real disassembly of both.

### Change B — `ControllerInitialize` (branchless codegen of the same RX-FIFO threshold select)

- **Severity:** None (no security-relevant change)
- **Nature:** Compiler replaced a `cmp`/`jz`/`xor`/`mov` select with an equivalent branchless computation. Same value written.
- **Affected function:** `ControllerInitialize`
  - Unpatched: `0x14000D5EC`
  - Patched: `0x14000D738`
- **Register touched:** `IC_RX_TL` (RX FIFO threshold) at `controller_base + 0x38`.

**What the function actually does (both builds):**

`ControllerInitialize` writes the RX FIFO threshold based on a device-configuration field read from `[dev+0xF0]`:

- If `[dev+0xF0] == 1`, it writes `0` to `IC_RX_TL`.
- Otherwise it writes `0xF` (threshold 15).

This selection is present and produces the same result in both builds. The unpatched build expresses it as `cmp dword [dev+0xF0], 1` / `jnz` / `xor edx,edx` / `jmp` / `mov edx,0Fh`. The patched build expresses it as `mov eax,[dev+0xF0]` / `dec eax` / `neg eax` / `sbb edx,edx` / `and edx,0Fh`. Both yield `0` when `[dev+0xF0] == 1` and `0xF` otherwise. The threshold is **not** hard-coded to `0` in the patched build; the earlier claim to that effect was incorrect.

---

## 3. Logic Diff (real, both builds equivalent)

### Change A — `ControllerDoReadPrepare`

```
// Both builds compute the same command word:
//   cmd = (rdi == 0) ? 0x500 /*READ|RESTART*/ : 0x100 /*READ*/;
//   if ([req+0x78] != 0 && (total - rdi) == 1) cmd |= 0x200 /*STOP*/;
//   Write(IC_DATA_CMD /* controller_base + 0x10 */, cmd);
//
// Only the codegen of the first line differs:
//   unpatched: cmovz  (branchy select)
//   patched:   neg/sbb/and/add (branchless, same result)
```

### Change B — `ControllerInitialize`

```
// Both builds compute the same threshold:
//   rx_tl = ([dev+0xF0] == 1) ? 0 : 0xF;
//   Write(IC_RX_TL /* controller_base + 0x38 */, rx_tl);
//
// Only the codegen differs:
//   unpatched: cmp/jz/xor/jmp/mov (branchy)
//   patched:   dec/neg/sbb/and (branchless, same result)
```

---

## 4. Assembly Analysis (real disassembly from both builds)

### Change A — `ControllerDoReadPrepare` command selection

**Unpatched (`0x14000C940`), command compose + STOP + write:**

```asm
000000014000CAF1  test    rdi, rdi
000000014000CAF4  mov     esi, 100h            ; READ
000000014000CAF9  mov     eax, 500h            ; READ | RESTART
000000014000CAFE  cmovz   esi, eax             ; rdi==0 -> 0x500, else 0x100
000000014000CB01  cmp     byte ptr [r13+78h], 0
000000014000CB06  jz      short loc_14000CB18
000000014000CB08  mov     rax, r12
000000014000CB0B  sub     rax, rdi
000000014000CB0E  cmp     rax, 1
000000014000CB12  jnz     short loc_14000CB18  ; last byte?
000000014000CB14  bts     esi, 9               ; add STOP (0x200)
; ...
000000014000CBEA  mov     rcx, [r14+30h]       ; MMIO base object
000000014000CBEE  mov     edx, esi             ; command word
000000014000CBF0  add     rcx, 10h             ; IC_DATA_CMD
000000014000CBF4  call    HWREG<ulong>::Write
```

**Patched (`0x14000CAB4`), same logic, branchless compose:**

```asm
000000014000CC57  mov     rax, rdi
000000014000CC5A  neg     rax
000000014000CC5D  sbb     ecx, ecx             ; rdi!=0 -> 0xFFFFFFFF, else 0
000000014000CC5F  and     ecx, 0FFFFFC00h
000000014000CC65  add     ecx, 500h            ; rdi!=0 -> 0x100, else 0x500
000000014000CC6B  cmp     byte ptr [r13+78h], 0
000000014000CC70  mov     esi, ecx
000000014000CC72  jz      short loc_14000CC84
000000014000CC74  mov     rax, r12
000000014000CC77  sub     rax, rdi
000000014000CC7A  cmp     rax, 1
000000014000CC7E  jnz     short loc_14000CC84  ; last byte?
000000014000CC80  bts     esi, 9               ; add STOP (0x200)
```

The two compose sequences produce identical values (`rdi==0 → 0x500`, else `0x100`), and the STOP-on-last-byte step is unchanged.

### Change B — `ControllerInitialize` RX-FIFO threshold selection

**Unpatched (`0x14000D5EC`):**

```asm
000000014000D6C5  mov     rcx, [rsi+38h]       ; MMIO base object
000000014000D6C9  add     rcx, 38h             ; IC_RX_TL
000000014000D6CD  cmp     dword ptr [rsi+0F0h], 1
000000014000D6D4  jnz     short loc_14000D6DA
000000014000D6D6  xor     edx, edx             ; == 1 -> 0
000000014000D6D8  jmp     short loc_14000D6DF
000000014000D6DA  mov     edx, 0Fh             ; != 1 -> 0xF
000000014000D6DF  call    HWREG<ulong>::Write
```

**Patched (`0x14000D738`), same logic, branchless:**

```asm
000000014000D811  mov     eax, [rsi+0F0h]
000000014000D817  mov     rcx, [rsi+38h]
000000014000D81B  dec     eax
000000014000D81D  neg     eax                  ; sets CF unless [dev+0xF0]==1
000000014000D81F  sbb     edx, edx             ; !=1 -> 0xFFFFFFFF, ==1 -> 0
000000014000D821  add     rcx, 38h             ; IC_RX_TL
000000014000D825  and     edx, 0Fh             ; !=1 -> 0xF, ==1 -> 0
000000014000D828  call    HWREG<ulong>::Write
```

Both write `0` when `[dev+0xF0] == 1` and `0xF` otherwise.

---

## 5. Trigger Conditions

None. Neither change alters any value written to hardware for any input, so there is no state an attacker (or the device) can drive into a different outcome than the unpatched build already produced. The read path always issues RESTART on the first byte and STOP on the last (when the device flag is set), in both builds. There is no missing-STOP path and therefore no reachable overrun condition to trigger.

---

## 6. Exploit Primitive

None. There is no behavioral difference to weaponize. The previously hypothesized DMA RX pool overflow does not exist: `ControllerDoReadPrepare` issues per-byte read commands through a bounded loop (`rdi` from `[req+0x40]` to `[req+0x38]`) and asserts STOP on the final byte identically in both builds; the RX threshold selection in `ControllerInitialize` is unchanged.

---

## 7. Debugger Notes

For anyone wishing to confirm the equivalence on a live system:

- `ControllerDoReadPrepare`: break at the command compose (`0x14000CAF1` unpatched / `0x14000CC57` patched) and observe that the value moved into `esi`/`edx` before the `IC_DATA_CMD` write at `controller_base + 0x10` is `0x500` for the first byte and `0x100` for subsequent bytes in both builds, with `0x200` (STOP) added on the last byte when `[req+0x78] != 0`.
- `ControllerInitialize`: break at the `IC_RX_TL` write (`0x14000D6DF` unpatched / `0x14000D828` patched) and observe the written value is `0` iff `[dev+0xF0] == 1`, else `0xF`, in both builds.
- DesignWare register offsets used above: `IC_DATA_CMD = +0x10`, `IC_RX_TL = +0x38`. Command word bits (from the driver's own trace strings): `READ = 0x100`, `STOP = 0x200`, `RESTART = 0x400`.

---

## 8. Changed Functions — Triage

All 99 changed functions carry regenerated WPP trace-provider GUIDs (every one of the module's 10 trace GUID symbols differs between builds), so a diff appears in essentially every function that traces. The two functions with a concrete non-trace instruction delta were examined above and both reduce to branchless-vs-branchy codegen of identical logic:

- **`ControllerDoReadPrepare`** — sim 0.9789. `cmovz` command select replaced by branchless `neg`/`sbb`/`and`/`add`. Same command word written to `IC_DATA_CMD`. No behavioral change.
- **`ControllerInitialize`** — sim 0.8664. `cmp`/`jz` threshold select replaced by branchless `dec`/`neg`/`sbb`/`and`. Same value written to `IC_RX_TL`. No behavioral change.

The remaining changed functions differ by WPP trace GUID rotation and ordinary compiler codegen (register allocation, branch layout). The following were flagged in earlier triage as large functions worth a look; on inspection of the concrete deltas above and the module-wide GUID rotation, they are consistent with recompilation churn rather than a delivered behavioral fix:

`ControllerConfigureForTransfer` (0.909), `ControllerProcessInterrupts` (0.9191), `DmaInitSw` (0.9237), `FillDmaTxLliBuffer` (0.9337), `DmaTxComplete` (0.9401), `DmaRxComplete` (0.9485), `OnSequence` (0.9558), `OnCancel` (0.9559).

Cosmetic (WPP GUID rotation, register renaming, branch-tree restructuring): `CheckSupportedHardware` (0.7502), `FillDmaRxLliBuffer` (0.9707), `GetCurrentDmaTransferLeft` (0.8411), `OnInterruptIsr` (0.9632), `ControllerDoWrite` (0.9789), `ControllerDoRead` (0.9906), `PbcRequestDoTransfer` (0.9547), `OverrideDefaultsForHardware` (0.9737), `GetHardwareVersion` (0.934), `EvtProgramDmaRx` (0.9257).

> Note: because WPP GUIDs were rotated module-wide, similarity score alone is a poor signal — a low score (e.g. `CheckSupportedHardware` at 0.75) can be entirely GUID/codegen churn.

---

## 9. Unmatched Functions

- **Removed:** none.
- **Added:** none.

No sanitizer, guard, bounds-check, or mitigation function was added or removed. This is consistent with a plain recompile: no structural change to the driver's logic.

---

## 10. Confidence & Caveats

**Overall confidence: High that this patch contains no security-relevant change.**

- Both concrete instruction-level deltas were disassembled in full in both builds (Section 4) and shown to compute identical hardware-register values for every input. The difference is purely branchless-vs-branchy codegen.
- The DesignWare command-bit meanings are taken from the driver's own embedded trace strings (`"| STOP"` at `0x200`, `"| RESTART"` at `0x400`), not from an external assumption.
- All 10 WPP trace-provider GUID symbols differ between the two builds, which fully accounts for the large number of "changed" functions without any behavioral edit.
- No function was added or removed; no new validation or mitigation code exists in the patched build.
