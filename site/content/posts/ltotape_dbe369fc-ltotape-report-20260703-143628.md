Title: ltotape.sys — No security-relevant change (LTO-9 density code 0x60 support added to GetMediaTypes)
Date: 2026-07-03
Slug: ltotape_dbe369fc-ltotape-report-20260703-143628
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: None

### 1. Overview
- **Unpatched Binary:** `ltotape_unpatched.sys`
- **Patched Binary:** `ltotape_patched.sys`
- **Overall Similarity Score:** 0.9823 (98.23%)
- **Diff Statistics:** 29 matched functions, 1 changed function, 28 identical functions, 0 unmatched functions in either direction.
- **Verdict:** The patch modifies the tape minidriver's `GetMediaTypes` callback (`0x1C0001CA0`) to add SCSI density code `0x60` (LTO-9) to the set of codes for which the callback fills in the per-media density and capacity fields. The previously accepted set of density codes is unchanged; `0x60` is the only value added. This is a functional enhancement to support a new tape generation, not a security fix. No validation was removed or tightened, and no memory-safety behavior changed.

### 2. Change Summary
- **Severity:** None (no security-relevant change)
- **Change Class:** Functional feature addition (new media density code accepted)
- **Affected Function:** `GetMediaTypes` (`0x1C0001CA0`)

**Nature of the change:**
`GetMediaTypes` processes the mode/log sense data returned in the SRB data buffer (`a4->DataBuffer`) and, for the media-type query path, fills in density and capacity fields for recognized density codes. The density code is byte offset 4 of that buffer.

The unpatched build accepts density codes `{0x00, 0x40, 0x42, 0x44, 0x46, 0x58, 0x5A, 0x5C, 0x5E}` via a single range check (`density - 0x40 <= 0x1E`) combined with bitmask `0x55000055`. The patched build accepts exactly that same set **plus** `0x60`, by restructuring the check into two branches: a first branch (`density <= 0x58`, bitmask `0x1000055`) reproducing acceptance of `{0x40, 0x42, 0x44, 0x46, 0x58}` and the `density == 0` special case, and a second branch (`density > 0x58`) that accepts `{0x5A, 0x5C, 0x5E, 0x60}`.

Because the accepted set only grows (by the single value `0x60`), the patched build is marginally *less* restrictive, not more. There is no attacker-relevant primitive: when a density code is accepted, the density byte and the 24-bit capacity value are written to fixed fields of the output descriptor (`[r15+0x11]` and `[r15+0x8]`). That write path is byte-for-byte identical between the two builds and is bounded by the fixed-size `LTOMedia` table iterated by the descriptor loop; accepting one additional value does not change any bound or introduce any out-of-range access. When a code is not accepted, the corresponding descriptor is simply returned without those two fields populated.

**Claims that do not hold against the binaries:**
- There is no "wrong SRB pointer" bug. `rdi` is set to `r9` in the prologue (`mov rdi, r9` @ `0x1C0001CC5`), so `[rdi+0x18]` (unpatched) and `[r9+0x18]` (patched) read the identical location. Both decompilations render the read as `a4->DataBuffer`.
- There is no "hardcoded `*arg2 = 0x1E`" bug. Both builds write `0x1E` (decimal 30) on the same branch (`a6 == 30 && a5 == 1` → `*a2 = 30`). The unpatched build sources `0x1E` from a scratch register (`r9d`, loaded at `0x1C0001CF2`); the patched build uses the immediate/`ecx`, which equals `0x1E` on that already-verified path. The stored value is identical.
- The `r12`/`rbp` swaps for the density code and capacity value are compiler register-allocation churn, not a fix for "upper-byte garbage": in both builds the density byte is materialized with a byte-width move and the range comparison is done on the low byte (`al`).

### 3. Pseudocode Diff

```c
// === UNPATCHED GetMediaTypes (density accept test) ===
DataBuffer = a4->DataBuffer;                 // == [rdi+0x18], rdi == r9
LOBYTE(v7)  = DataBuffer[4];                 // density code
v12 = DataBuffer[11] | ((DataBuffer[10] | (DataBuffer[9] << 8)) << 8);  // 24-bit capacity
if ( (BYTE)v7 == 0
     || ((unsigned __int8)(v7 - 0x40) <= 0x1E && _bittest(&(v20=0x55000055), v7 - 0x40)) )
    v8 = 0x56;                               // accepted -> descriptor fields populated
// accepted set: {0x00, 0x40, 0x42, 0x44, 0x46, 0x58, 0x5A, 0x5C, 0x5E}

// === PATCHED GetMediaTypes (density accept test) ===
DataBuffer = a4->DataBuffer;                 // == [r9+0x18], identical read
LOBYTE(v7)  = DataBuffer[4];                 // density code
v12 = DataBuffer[11] | ((DataBuffer[10] | (DataBuffer[9] << 8)) << 8);
if ( (unsigned __int8)v7 > 0x58 ) {
    if ( (((BYTE)v7 - 0x5A) & 0xF9) != 0 || (BYTE)v7 == 0x60 )
        v21 = ((BYTE)v7 == 0x60);            // accepts 0x5A,0x5C,0x5E and 0x60
    ...
} else if ( (unsigned __int8)(v7 - 0x40) > 0x18 || !_bittest(&(v20=0x1000055), v7 - 0x40) ) {
    v21 = ((BYTE)v7 == 0);                   // density 0 special case
    ...
}
v8 = 0x56;                                   // accepted
// accepted set: same as unpatched PLUS 0x60
```

### 4. Assembly Analysis

**Unpatched density accept test (`ltotape_unpatched.sys`, `GetMediaTypes`):**
```assembly
00000001C0001DC1  mov     rcx, [rdi+18h]      ; rdi == r9 -> a4->DataBuffer
00000001C0001DCD  mov     r12b, [rcx+4]       ; density code
00000001C0001DE7  test    r12b, r12b
00000001C0001DEA  jz      loc_1C0001E00       ; density 0 accepted
00000001C0001DEC  lea     eax, [r12-40h]
00000001C0001DF1  cmp     al, r9b             ; r9b = 0x1E
00000001C0001DF4  ja      loc_1C0001E1C       ; reject if (density-0x40) > 0x1E
00000001C0001DF6  mov     ecx, 55000055h
00000001C0001DFB  bt      ecx, eax
00000001C0001DFE  jnb     loc_1C0001E1C       ; reject if bit clear
00000001C0001E00  mov     ebx, 56h            ; accept
00000001C0001E05  jmp     loc_1C0001E1C
```

**Patched density accept test (`ltotape_patched.sys`, `GetMediaTypes`):**
```assembly
00000001C0001DBC  mov     rcx, [r9+18h]       ; a4->DataBuffer (same location)
00000001C0001DC9  mov     bpl, [rcx+4]        ; density code
00000001C0001DE7  cmp     bpl, 58h
00000001C0001DEB  ja      loc_1C0001E03       ; density > 0x58 -> new branch
00000001C0001DED  lea     eax, [rbp-40h]
00000001C0001DF0  cmp     al, 18h
00000001C0001DF2  ja      loc_1C0001DFE
00000001C0001DF4  mov     ecx, 1000055h
00000001C0001DF9  bt      ecx, eax
00000001C0001DFC  jb      loc_1C0001E16       ; accept 0x40,0x42,0x44,0x46,0x58
00000001C0001DFE  test    bpl, bpl
00000001C0001E01  jmp     loc_1C0001E14       ; density 0 special case
00000001C0001E03  lea     eax, [rbp-5Ah]
00000001C0001E06  test    al, 0F9h
00000001C0001E08  jnz     loc_1C0001E10
00000001C0001E0A  cmp     bpl, 60h
00000001C0001E0E  jnz     loc_1C0001E16       ; 0x5A/0x5C/0x5E accept
00000001C0001E10  cmp     bpl, 60h
00000001C0001E14  jnz     loc_1C0001E33       ; reject
00000001C0001E16  mov     ebx, 56h            ; accept (now reached by 0x60 too)
00000001C0001E1B  jmp     loc_1C0001E33
```

The output-write block that consumes the accept decision is unchanged between builds:
```assembly
; both builds, per accepted media entry
mov     [r15+11h], r12b/bpl   ; density code byte
mov     [r15+8],   ebp/r12d   ; 24-bit capacity value
```
The register names differ (`r12b`/`ebp` unpatched vs `bpl`/`r12d` patched) purely due to register allocation; the effect is identical.

### 5. Behavioral Difference (Trigger)
1. A tape device (a real LTO-9 drive, or an emulated SCSI sequential-access device) reports density code `0x60` at byte offset 4 of the sense data buffer.
2. An application queries tape media types, which reaches `GetMediaTypes` on the media-type path (`a5 == 2`, `a6 == 3`, `*a2 == 0`).
3. **Observable effect:** On the unpatched build the `0x60` entry is returned without its density/capacity fields populated (the code falls through the reject path); on the patched build those fields are populated. No crash, no memory corruption, and no change in the amount of data written in either case.

### 6. Exploit Primitive
None. This is a functional change that adds recognition of one additional density code. It removes no check and adds no attacker-reachable memory-safety condition. The density byte and capacity value written on the accept path are bounded output-descriptor fields written identically in both builds; the size and destination of every write are independent of the density value.

### 7. Observation Notes
The behavioral difference can be observed at the density accept test. On the unpatched build the decision is made at `0x1C0001DEC`–`0x1C0001DFE`; on the patched build at `0x1C0001DE7`–`0x1C0001E14`. With a device reporting density `0x60`:
- Unpatched: `(0x60 - 0x40) = 0x20 > 0x1E`, so `ja` at `0x1C0001DF4` is taken and `ebx` stays `0`; the matching `LTOMedia` entry is emitted without density/capacity.
- Patched: the `> 0x58` branch reaches `cmp bpl, 60h` at `0x1C0001E10`, `ebx` is set to `0x56` at `0x1C0001E16`, and the entry is emitted with density/capacity populated.

There is no fault to reproduce; the only difference is which fields of a returned descriptor are filled in.

### 8. Changed Functions — Full Triage
**`GetMediaTypes`** (`0x1C0001CA0`; Similarity: 0.919 | Type: functional, not security-relevant)
- Adds acceptance of density code `0x60` (LTO-9); all other accepted codes (`0x00, 0x40, 0x42, 0x44, 0x46, 0x58, 0x5A, 0x5C, 0x5E`) are unchanged.
- Restructures the single range/bitmask test into a two-branch test (`<= 0x58` with bitmask `0x1000055`, and `> 0x58` with explicit checks) that reproduces the old accepts and adds `0x60`.
- Register-allocation churn: density code held in `bpl` (was `r12b`); capacity value held in `r12d` (was `ebp`).
- `mov [r14], r9d` (with `r9d = 0x1E`) becomes `mov [r14], ecx` and `cmp ecx, r9d` becomes `cmp ecx, 1Eh`; both write/compare the same constant `0x1E` on the `a6 == 30` path.

### 9. Unmatched Functions
- **Added:** None.
- **Removed:** None.

### 10. Confidence & Caveats
- **Confidence Level:** High. The full accepted-density-code set was enumerated for both builds; they are identical except for the added `0x60`. All other diffs in the function are register allocation and constant-materialization changes with identical effect.
- **Independent diff:** A content-level diff of both builds shows `GetMediaTypes` as the only function with a changed body; every other function is identical apart from relocation. No omitted security-relevant change was found.
