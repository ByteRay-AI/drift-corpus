Title: fvevol.sys — Datum type-field high bit not masked before presence/type checks (CWE-20) fixed
Date: 2026-06-09
Slug: fvevol_eb05ca6b-fvevol-report-20260628-232612
Category: Corpus
Author: Argus
Summary: KB5094127
Severity: Low
KBDate: 2026-06-09

## 1. Overview

- **Unpatched Binary:** `fvevol_unpatched.sys`
- **Patched Binary:** `fvevol_patched.sys`
- **Overall Similarity Score:** 0.9778
- **Diff Statistics:**
  - Matched Functions: 1382
  - Changed Functions: 30
  - Identical Functions: 1352
  - Unmatched (Unpatched / Patched): 0 / 0
- **Verdict:** The patch hardens how BitLocker FVE metadata "datum" type fields are consumed. Wherever the 32-bit type field is used to decide whether a datum is present or to match/dispatch a datum by type, the patch now strips bit 31 (`& 0x7fffffff` / `btr reg, 0x1f`) before the value is used, so the high flag bit can no longer alter type identity. The patch also introduces support for new key-protector datum types (0x1c-0x22), refactors datum/dataset access into new helper functions, and adds a per-object initialized flag that gates deferred hash cleanup.

---

## 2. Vulnerability Summary

### Finding: Datum Type-Field High Bit Not Masked Before Presence/Type Checks
- **Severity:** Low
- **Vulnerability Class:** Improper input validation (CWE-20).
- **Affected Functions:** `FveKeyringGetCachedVmkTargetType (sub_1C0008D28)`, `FveKeyringGetNext (sub_1C000EE6C)`, `FveKeyringEraseAll (sub_1C000EC74)`.

**Root Cause:**
Each BitLocker FVE keyring dataset carries a 32-bit type field at offset +4. In the unpatched build, several keyring routines read this field and use it directly: `FveKeyringGetCachedVmkTargetType` treats the dataset as present when the raw field is non-zero (`cmp [rdi+4], r15d`, with `r15d = 0`), and `FveKeyringGetNext` compares the raw field against a requested type (`cmp [r15+4], ebp`). The patched build treats bit 31 as not part of the type identity and strips it before the field is consumed. Consequently, in the unpatched build a dataset whose type field is `0x80000000` is treated as a non-empty entry, and a dataset whose type is `type | 0x80000000` does not compare equal to `type` during enumeration.

The patched build masks bit 31 at every one of these use sites before the field is consumed. The effect is a logic-level normalization of the type field: an empty/flagged entry is no longer treated as present, and the high bit no longer alters a type match. The datasets involved are still subject to the same structural validation (`FveDatasetIsValid` / `FveDatumIsValidBounded` / `FveDatumVmkIsValid`) in both builds, so the demonstrable consequence is a presence/match discrepancy, not a memory-safety condition.

**Attacker-Reachable Entry Point and Call Chain:**
This code path is reached by mounting or attaching a storage volume (VHD, VMDK, or physical media) that carries a `-FVE-FS-` BitLocker metadata block whose datum entries have crafted type fields.
1. **Disk I/O:** The system reads the BitLocker metadata block from the attached volume.
2. `FveInformationIsValid (sub_1C00034BC)`: Validates the `-FVE-FS-` signature and parses version/size fields.
3. `FveDatasetIsValid (sub_1C0003DD4)`: Performs structural validation on the metadata block (cross-field size checks).
4. `FveKeyringGetCachedVmkTargetType (sub_1C0008D28)`: Enumerates keyring datasets and inspects datum type fields.

---

## 3. Pseudocode Diff

The change is a mask on the datum type field before it is used to decide presence or match a type.

**Unpatched (`FveKeyringGetCachedVmkTargetType`, sub_1C0008D28):**
```c
// datum type field read raw
if (datum[1] != 0)                       // 0x80000000 counts as "present"
{
    status = FveDatasetIsValid(datum, datum[0]);   // sub_1C0003DD4
    // ... walk datums, validate each via the bounded validator
    status = FveDatumIsValidBounded(datum + off, remaining, 1);  // sub_1C0003F6C
}
```

**Patched (`FveKeyringGetCachedVmkTargetType`, sub_1C0009094):**
```c
// bit 31 stripped before the presence test
if ((datum[1] & 0x7fffffff) != 0)        // 0x80000000 -> 0, treated as empty
{
    status = FveDatasetIsValidEx(datum, datum[0], flag);  // sub_1C0009840
    // ... walk datums via the extracted helper, which still calls the bounded validator
    status = FveDatasetGetDatumPointer(datum, off, &out); // sub_1C00097F4 -> FveDatumIsValidBounded
}
```

**Patched (`FveKeyringGetNext`, sub_1C0010EA4):**
```c
// type match now strips bit 31 first
uint32_t t = datum[1];
t &= ~0x80000000;                        // btr eax, 0x1f
if (t == requested_type) { /* match */ }
```

---

## 4. Assembly Analysis

The mask is inserted at each site where the datum type field feeds a presence test or a type comparison.

**`FveKeyringGetCachedVmkTargetType` presence test:**
```assembly
; Unpatched sub_1C0008D28
0x1c0008dad: cmp dword [rdi+0x4], r15d   ; type != 0 ? (raw, 0x80000000 passes)
0x1c0008db1: jz  0x1c0008e73

; Patched sub_1C0009094
0x1c0009111: test dword [rdi+0x4], 0x7fffffff  ; bit 31 masked, 0x80000000 -> skip
0x1c0009118: jz   0x1c00091c9
```

**`FveKeyringGetNext` type comparison:**
```assembly
; Unpatched sub_1C000EE6C
0x1c000eefe: cmp dword [r15+0x4], ebp    ; raw type compared

; Patched sub_1C0010EA4
0x1c0010f36: mov eax, dword [r15+0x4]
0x1c0010f3a: btr eax, 0x1f               ; clear bit 31
0x1c0010f3e: cmp eax, ebp                ; masked type compared
```

**`FveKeyringEraseAll` type value:**
```assembly
; Patched sub_1C0010CA4 (no corresponding mask in unpatched sub_1C000EC74)
0x1c0010cd3: btr edx, 0x1f               ; clear bit 31 before use
```

**Call-site refactor inside `FveKeyringGetCachedVmkTargetType`:**
```assembly
; Unpatched sub_1C0008D28 walked datums with an inline validator call
0x1c0008dbc: call FveDatasetIsValid            ; sub_1C0003DD4
0x1c0008e05: call FveDatumIsValidBounded       ; sub_1C0003F6C (recursive datum-tree validator)

; Patched sub_1C0009094 routes the same work through new helpers
0x1c0009123: call FveDatasetIsValidEx          ; sub_1C0009840 (extended, 3rd param)
0x1c000915d: call FveDatasetGetDatumPointer    ; sub_1C00097F4 (wraps FveDatumIsValidBounded)
```

---

## 5. Behavior of the Datum Validator Across Both Builds

`FveDatumIsValidBounded` is a depth-bounded (max depth 10, `arg3 <= 0xa`) validator that walks a datum and its nested sub-datums. It is present in both builds — unpatched at `0x1C0003F6C`, patched at `0x1C0003F14` — and its body is essentially unchanged between them. In both builds it:
- validates the datum header via `FveDatumHeaderSafe (sub_1C00046A0)`,
- looks the type up in a dispatch table (`off_1C0023AD0` unpatched, `off_1C0025AD0` patched),
- recursively calls itself on each sub-datum (`call FveDatumIsValidBounded` at `0x1C0004045` / `0x1C0003FED`),
- advances the consumed offset by the sub-datum size (`add di, word [rsp+var_38]` at `0x1C000404E` / `0x1C0003FF6`) and loops while `consumed < total` (`cmp di, [rsp+arg_18]; jb`).

The one substantive difference is the type-table bound: `cmp ecx, 1Ah` (26 types) in the unpatched build becomes `cmp ecx, 23h` (35 types) in the patched build, matching the expanded dispatch table for the new key-protector datum types. The recursion and offset-advance loop are identical in both builds; this function is not the subject of a loop or bounds fix in this patch.

The patched build additionally introduces a thin wrapper, `FveDatasetGetDatumPointer (sub_1C00097F4)`, which computes `ptr = base + offset` and `remaining = *(base+0xC) - offset` and then calls `FveDatumIsValidBounded` to validate the datum at that offset, returning the validated pointer. Several call sites that previously invoked `FveDatumIsValidBounded` inline now go through this wrapper.

---

## 6. Trigger Conditions

To exercise the datum type-field path:

1. **Volume Creation:** Create a raw disk image, VHD, or VMDK formatted with a BitLocker signature.
2. **Signature:** Ensure the metadata offset contains the `-FVE-FS-` signature and passes size validation (`size >= 0x30`).
3. **Structural Consistency:** The metadata block fields must pass `FveDatasetIsValid (sub_1C0003DD4)` (header size, total size, and data size arithmetically consistent).
4. **Crafting the Datum:** Include a keyring datum whose 32-bit type field at offset +4 has bit 31 set (for example `0x80000000`, or `realtype | 0x80000000`).
5. **Execution:** Mount the volume. In the unpatched build the flagged datum is treated as present / mismatches type matching; in the patched build the high bit is stripped before either decision.

---

## 7. Exploit Primitive & Development Notes

- **Primitive:** The primary consequence is a logic-level type-handling discrepancy: an empty datum with only bit 31 set is treated as present, and a datum whose type is `realtype | 0x80000000` will not match a lookup for `realtype`. Depending on the caller, this can cause a valid protector to be skipped or an unexpected datum to be handed to a type handler.
- **Mitigations:** This is an input-validation hardening rather than a memory-corruption primitive; standard kernel mitigations (SMEP, SMAP, CFG, HVCI, KASLR) are not directly relevant to reaching or fixing it.
- **Development Notes:** A researcher can extract a standard BitLocker metadata block, set bit 31 in a keyring datum's type field, and observe divergent presence/match behavior between the two builds at the sites listed in Section 4.

---

## 8. Debugger PoC Playbook

Attach a kernel debugger (WinDbg/KD) to the target.

### Breakpoints
```text
bp fvevol!sub_1C00034BC     ; -FVE-FS- header parsing
bp fvevol+0x8DA5            ; FveKeyringGetCachedVmkTargetType datum presence test
bp fvevol+0xEEFE            ; FveKeyringGetNext raw type comparison (unpatched)
bp fvevol!sub_1C00046A0     ; FveDatumHeaderSafe (datum header validation)
```

### What to Inspect
- **At `FveKeyringGetCachedVmkTargetType` presence test (unpatched `+0x8DA5`, `cmp [rdi+4], r15d`):**
  - `dword [rdi+0x4]` = datum type field. A value of `0x80000000` passes the raw non-zero test in the unpatched build.
- **At `FveKeyringGetNext` type comparison (unpatched `+0xEEFE`, `cmp [r15+4], ebp`):**
  - `dword [r15+0x4]` = candidate datum type; `ebp` = requested type. A candidate of `ebp | 0x80000000` fails to match in the unpatched build.
- **In the patched build**, the same fields are read into a register, `btr reg, 0x1f` clears bit 31, and the masked value is compared instead.

### Trigger Setup
1. Transfer the crafted VHD containing the `-FVE-FS-` metadata to the target.
2. Trigger volume mount via `diskpart`, `mountvol`, or `AttachVirtualDisk` / `OpenVirtualDisk`.
3. Observe the datum type field values at the breakpoints above.

### Expected Observation
In the unpatched build, a datum with bit 31 set in its type field passes the presence test or fails type matching. In the patched build, bit 31 is cleared before either check, so the datum is treated by its low 31 type bits only.

---

## 9. Changed Functions — Full Triage

- **`FveKeyringGetCachedVmkTargetType (sub_1C0008D28)` -> patched `sub_1C0009094`**: *Security.* Datum presence test masked (`cmp [rdi+4],r15d` -> `test [rdi+4],0x7fffffff`). Datum walk refactored to call the extended validator `FveDatasetIsValidEx (sub_1C0009840)` and the new wrapper `FveDatasetGetDatumPointer (sub_1C00097F4)` instead of the inline `FveDatasetIsValid` / `FveDatumIsValidBounded` calls.
- **`FveKeyringGetNext (sub_1C000EE6C)` -> patched `sub_1C0010EA4`**: *Security.* Added `btr eax, 0x1f` so the datum type field is masked before the type comparison.
- **`FveKeyringEraseAll (sub_1C000EC74)` -> patched `sub_1C0010CA4`**: *Security.* Added `btr edx, 0x1f` to mask bit 31 of the datum type field before use.
- **`FveDatumIsValidBounded (sub_1C0003F6C)` -> patched `sub_1C0003F14`**: *Feature.* Depth-bounded recursive datum-tree validator; body unchanged except the type-table bound raised from `0x1a` (26) to `0x23` (35) and the table relocated (`off_1C0023AD0` -> `off_1C0025AD0`) to cover the new key-protector datum types. No loop or bounds change.
- **`FveDatasetGetDatumPointer (sub_1C00097F4)`**: *Refactor (new).* Patched-only helper: computes `ptr = base + offset`, `remaining = *(base+0xC) - offset`, calls `FveDatumIsValidBounded`, returns the validated pointer. Wraps existing validation; introduces no new bounds logic.
- **`FveDatasetIsValidEx (sub_1C0009840)`**: *Refactor (new).* Patched-only helper carrying the dataset structural-validation loop with an added third parameter (`char`). `FveDatasetIsValid` (relocated to `sub_1C000399C`) is now a thin forwarder to it.
- **`FveDatasetIsValid (sub_1C0003DD4)` -> patched `sub_1C000399C`**: *Refactor.* Structural block validator (min size `0x30`, cross-field consistency). Body extracted into `FveDatasetIsValidEx`; this symbol forwards to it.
- **`FveInformationIsValid (sub_1C00034BC)` -> patched `sub_1C0003B2C`**: *Behavioral.* Parses `-FVE-FS-`; updated to call `FveDatasetIsValidEx` with the added parameter.
- **`FveDatumIsValidTypeSpecificChecks (sub_1C000475C)` -> patched `sub_1C000474C`**: *Feature.* Type dispatch expanded for new key-protector datum types (`0x1c`-`0x22`); existing handlers (2, 7, 8, 0xf, 0x15) preserved.
- **`FveSha256Init (sub_1C0004BD4)` -> patched `sub_1C0004C18`**: *Resource-lifecycle hardening.* The `BCryptCreateHash` status is returned to the caller in both builds (it is the function's return value). The patch adds a per-object initialized flag: on success it sets `mov byte [rbx+8], 1`, and on failure it skips that store (`js loc_1C0004C63`), so deferred cleanup only runs on a successfully created hash object. Not attacker-reachable from disk metadata; requires `BCryptCreateHash` to fail.
- **`FveDatumUpdateCreateFromDataset (sub_1C0007038)` -> patched `sub_1C0007074`**: *Refactor.* Hash lifecycle updated to use create/finish/destroy wrappers with error checking.
- **`FveDatumTpmEncBlobUnbox (sub_1C0011538)` -> patched `sub_1C00136C0`**: *Refactor.* TPM-unseal logic extracted into the new `FveUnsealTpmData (sub_1C000A424)`, which itself calls `FveDatumIsValidBounded`. The recursive validator is still used, not eliminated.
- **`FveUnsealTpmData (sub_1C000A424)`**: *Refactor (new).* Patched-only helper holding the extracted TPM-unseal flow; validates the datum via `FveDatumIsValidBounded`.
- **`LogErrorDataset (sub_1C005E578)` -> patched `sub_1C0062B4C`**: *Behavioral.* Simplified metadata iteration; added a 4th parameter (`char`) controlling processing of `0x1f`/`0x20` datum types; ETW telemetry renumbered.
- **`LogKeyRingErrors (sub_1C005E988)` -> patched `sub_1C0062CB4`**: *Cosmetic.* ETW telemetry renumbering and helper renames; passes the new 4th parameter (`=1`).
- **`FveDatumPerformConcatHash (sub_1C0011780)` -> patched `sub_1C0013744`**: *Refactor.* Hash lifecycle cleanup with explicit cleanup call before exit.
- **HSTI/DE platform reporting (`sub_1C00A7414`, `sub_1C00A619C`, `sub_1C001090C`)**: *Cosmetic.* ETW telemetry renumbering and global data address shifts.

---

## 10. Unmatched Functions

The diff tool reports 0 added / 0 removed because it pairs each new helper against the relocated original whose body it was extracted from. Concretely, the patched build introduces three helper functions that have no unpatched counterpart of the same name: `FveDatasetGetDatumPointer (sub_1C00097F4)`, `FveDatasetIsValidEx (sub_1C0009840)`, and `FveUnsealTpmData (sub_1C000A424)`. The originals they were factored out of (`FveDatasetIsValid`, `FveDatumTpmEncBlobUnbox`) remain in the patched build, relocated.

---

## 11. Confidence & Caveats

- **Confidence:** High. The type-field masking is directly observable as new `& 0x7fffffff` / `btr reg, 0x1f` instructions at the datum type-field use sites in the patched build, absent in the unpatched build.
- **Scope:** The recursive datum validator `FveDatumIsValidBounded` is present in both builds with an unchanged recursion/offset-advance loop; the only change to it is the enlarged type-table bound for the new key-protector datum types. This patch does not alter that loop.
- **Manual Verification:** A researcher can confirm the masking by setting bit 31 in a keyring datum's type field within a `-FVE-FS-` metadata block and observing divergent presence/match behavior between the two builds at the sites in Section 4.
