Title: ltotape.sys — No security-relevant change (LTO-9 density code 0x60 support added to GetMediaTypes)
Date: 2026-07-03
Slug: ltotape_dbe369fc-ltotape-report-20260703-151135
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: None

## 1. Overview

- **Unpatched Binary:** `ltotape_unpatched.sys`
- **Patched Binary:** `ltotape_patched.sys`
- **Overall Similarity Score:** 0.9823
- **Diff Statistics:** Matched: 29, Changed: 1, Identical: 28, Unmatched: 0
- **Verdict:** The patch modifies one function, the tape minidriver's `GetMediaTypes` callback (`0x1C0001CA0`), to add SCSI density code `0x60` (LTO-9) to the set of density codes for which the callback populates the per-media density and capacity fields. The accepted-code set only grows (by the single value `0x60`); nothing is removed or tightened. This is a functional enhancement for a new tape generation, not a security fix.

## 2. Change Summary

- **Severity:** None (no security-relevant change)
- **Change Class:** Functional feature addition (new media density code accepted)
- **Affected Function:** `GetMediaTypes` (`0x1C0001CA0`)

### Nature of the change
`GetMediaTypes` parses the sense data returned in the SRB data buffer (`a4->DataBuffer`) and, on the media-type query path, fills in density and capacity fields for recognized density codes read from byte offset 4.

Enumerating the accepted codes for both builds:
- **Unpatched accepts:** `0x00, 0x40, 0x42, 0x44, 0x46, 0x58, 0x5A, 0x5C, 0x5E` (single check `density - 0x40 <= 0x1E` with bitmask `0x55000055`).
- **Patched accepts:** the same set **plus** `0x60`.

The change is a relaxation (one additional accepted value), so the patched build is not stricter. This corrects any impression that the patch removes acceptance of codes such as `0x54`, `0x56`, `0x58`, `0x5A`, `0x5C`, or `0x5E`:
- `0x54` and `0x56` were **never** accepted in either build. Their bitmask offsets (`0x14`, `0x16`) fall in the zero middle bytes of `0x55000055`, so the unpatched test already rejected them.
- `0x58`, `0x5A`, `0x5C`, `0x5E` remain accepted in **both** builds.

### Not a memory-safety issue
When a density code is accepted, the density byte and the 24-bit capacity value are written to fixed output-descriptor fields (`[r15+0x11]` and `[r15+0x8]`). That write is byte-for-byte identical between the two builds and is bounded by the fixed-size `LTOMedia` table iterated by the descriptor loop. Accepting one more density value does not change any bound, does not add or remove any write, and does not create any out-of-range access. There is no injection into `tape.sys` structures beyond these already-present descriptor fields.

### Claims that do not hold against the binaries
- **No "wrong SRB pointer" difference.** `rdi` is set to `r9` in the prologue (`mov rdi, r9` @ `0x1C0001CC5`); `[rdi+0x18]` and `[r9+0x18]` read the same location. Both decompilations show `a4->DataBuffer`.
- **No "hardcoded 0x1E" bug.** Both builds write `0x1E` (30) on the `a6 == 30 && a5 == 1` branch (`*a2 = 30`). The unpatched build sources `0x1E` from scratch register `r9d`; the patched build uses the immediate/`ecx`, equal to `0x1E` on that verified path. Same stored value.

## 3. Pseudocode Diff

```c
// --- UNPATCHED density accept test ---
DataBuffer = a4->DataBuffer;                 // == [rdi+0x18], rdi == r9
uint8_t density = DataBuffer[4];
if ( density == 0
     || ((uint8_t)(density - 0x40) <= 0x1E && _bittest(&(v=0x55000055), density - 0x40)) )
    v8 = 0x56;                               // accept
// accepted: {0x00,0x40,0x42,0x44,0x46,0x58,0x5A,0x5C,0x5E}

// --- PATCHED density accept test ---
DataBuffer = a4->DataBuffer;                 // == [r9+0x18], identical read
uint8_t density = DataBuffer[4];
if ( density > 0x58 ) {
    if ( ((density - 0x5A) & 0xF9) != 0 || density == 0x60 ) { /* 0x5A,0x5C,0x5E,0x60 */ }
} else if ( (uint8_t)(density - 0x40) > 0x18 || !_bittest(&(v=0x1000055), density - 0x40) ) {
    /* density==0 special case */
}
v8 = 0x56;
// accepted: same as unpatched PLUS 0x60
```

## 4. Assembly Analysis

### Unpatched density accept test
```assembly
0x1C0001DC1: mov   rcx, [rdi+18h]     ; rdi == r9 -> a4->DataBuffer
0x1C0001DCD: mov   r12b, [rcx+4]      ; density code
0x1C0001DE7: test  r12b, r12b
0x1C0001DEA: jz    0x1C0001E00        ; density 0 accepted
0x1C0001DEC: lea   eax, [r12-40h]
0x1C0001DF1: cmp   al, r9b            ; r9b = 0x1E
0x1C0001DF4: ja    0x1C0001E1C        ; reject if (density-0x40) > 0x1E
0x1C0001DF6: mov   ecx, 55000055h
0x1C0001DFB: bt    ecx, eax
0x1C0001DFE: jnb   0x1C0001E1C        ; reject if bit clear
0x1C0001E00: mov   ebx, 56h           ; accept
```

### Patched density accept test
```assembly
0x1C0001DBC: mov   rcx, [r9+18h]      ; a4->DataBuffer (same location)
0x1C0001DC9: mov   bpl, [rcx+4]       ; density code
0x1C0001DE7: cmp   bpl, 58h
0x1C0001DEB: ja    0x1C0001E03        ; density > 0x58 -> new branch
0x1C0001DED: lea   eax, [rbp-40h]
0x1C0001DF0: cmp   al, 18h
0x1C0001DF2: ja    0x1C0001DFE
0x1C0001DF4: mov   ecx, 1000055h
0x1C0001DF9: bt    ecx, eax
0x1C0001DFC: jb    0x1C0001E16        ; accept 0x40,0x42,0x44,0x46,0x58
0x1C0001E03: lea   eax, [rbp-5Ah]
0x1C0001E06: test  al, 0F9h
0x1C0001E08: jnz   0x1C0001E10
0x1C0001E0A: cmp   bpl, 60h
0x1C0001E0E: jnz   0x1C0001E16        ; 0x5A/0x5C/0x5E accept
0x1C0001E10: cmp   bpl, 60h
0x1C0001E14: jnz   0x1C0001E33        ; reject
0x1C0001E16: mov   ebx, 56h           ; accept (now reached by 0x60 too)
```

The output write block is unchanged between builds:
```assembly
mov   [r15+11h], r12b/bpl   ; density code byte (r12b unpatched, bpl patched)
mov   [r15+8],   ebp/r12d   ; 24-bit capacity value
```

## 5. Behavioral Difference (Trigger)

1. A tape device reports density code `0x60` at byte offset 4 of the sense data buffer.
2. `GetMediaTypes` is reached on the media-type path (`a5 == 2`, `a6 == 3`, `*a2 == 0`).
3. **Observable effect:** the unpatched build returns the `0x60` media entry without density/capacity populated; the patched build populates those fields. No crash and no change in the amount or destination of any write in either case.

## 6. Exploit Primitive

None. The change removes no validation and adds no attacker-reachable memory-safety condition. The density byte and capacity value written on the accept path are bounded output-descriptor fields written identically in both builds; the size and destination of every write are independent of the density value. Accepting an additional density code does not cause an out-of-spec write or an over-read.

## 7. Observation Notes

The behavioral difference is at the density accept test (unpatched `0x1C0001DEC`–`0x1C0001DFE`; patched `0x1C0001DE7`–`0x1C0001E14`). For a device reporting `0x60`:
- Unpatched: `0x60 - 0x40 = 0x20 > 0x1E`, so `ja` at `0x1C0001DF4` is taken; `ebx` stays `0` and the entry is emitted without density/capacity.
- Patched: the `> 0x58` branch reaches `cmp bpl, 60h` at `0x1C0001E10`; `ebx` becomes `0x56` at `0x1C0001E16` and the entry is emitted with density/capacity populated.

There is no fault to reproduce.

## 8. Changed Functions — Full Triage

- **`GetMediaTypes`** (`0x1C0001CA0`; Similarity: 0.919; Type: functional, not security-relevant)
  - Adds acceptance of density code `0x60` (LTO-9); the rest of the accepted set is unchanged.
  - Bitmask `0x55000055` (range `<= 0x1E`) replaced by a two-branch test: `0x1000055` for `density <= 0x58` plus explicit handling of `0x5A/0x5C/0x5E/0x60` for `density > 0x58`. The two forms accept the same codes except that the patched form additionally accepts `0x60`.
  - `mov [r14], r9d` (with `r9d = 0x1E`) becomes `mov [r14], ecx`; both store `0x1E` on the `a6 == 30` path.
  - Register allocation reorganized (density code `r12b`→`bpl`; capacity value `ebp`→`r12d`).

## 9. Unmatched Functions

- **Added/Removed:** None.
- **Implications:** The change is contained within `GetMediaTypes`; no new function, sanitizer, or bounds check was added at any level.

## 10. Confidence & Caveats

- **Confidence:** High. The accepted-density-code set was enumerated for both builds and differs only by the added `0x60`.
- **Independent diff:** A content-level diff of both builds identifies `GetMediaTypes` as the only function with a changed body; all others are identical apart from relocation. No omitted security-relevant change was found.
