Title: hidparse.sys — No security-relevant change (input-validation relaxation / recompilation)
Date: 2026-06-28
Slug: hidparse_bd89d5a2-hidparse-report-20260628-235655
Category: Corpus
Author: Argus
Summary: KB5078752

### 1. Overview
- **Unpatched Binary:** `hidparse_unpatched.sys`
- **Patched Binary:** `hidparse_patched.sys`
- **Overall Similarity:** 0.9905
- **Diff Statistics:** 65 matched functions, 1 changed function, 64 identical functions, 0 unmatched functions in either direction.
- **Verdict:** The single changed function is `HidP_AllocateCollections (sub_1C000D280)`. Both builds fully zero-initialize the collection node and the collection-description (`HidP KDR`) structures they allocate, so no uninitialized kernel memory reaches the caller in either build. The only behavioral difference is the removal of one redundant byte-range validation in the End-Collection finalization path; the surrounding code byte-truncates the same counts and sizes the output allocation from them either way, so there is no memory-safety impact. The remaining differences are register allocation and instruction scheduling introduced by recompilation.

### 2. Change Summary
- **Severity:** Informational (no security-relevant change).
- **Class:** Input-validation relaxation / recompilation.
- **Affected Function:** `HidP_AllocateCollections (sub_1C000D280)` (HID descriptor parser, invoked by `HidP_GetCollectionDescription`).
- **What the function does:** When `hidparse.sys` parses a HID report descriptor and encounters a Collection item (`0xA1`) at the outermost nesting level, it allocates a 0x30-byte collection node via `ExAllocatePoolWithTag` (tag `'HidP'`). When it later encounters the matching End-Collection item (`0xC0`) that closes the outermost collection, it computes a total size, allocates the variable-length `HidP KDR` descriptor structure, `memset`s it to zero, and fills in count fields.
- **Node initialization (both builds):** Immediately after the node allocation succeeds, the code writes zero to all six qwords of the 0x30-byte node (offsets `0x00, 0x08, 0x10, 0x18, 0x20, 0x28`) before linking it into the parent list. There is no window in which uninitialized node memory is observable.
- **`HidP KDR` initialization (both builds):** The descriptor buffer is fully zeroed with `memset(buf, 0, size)` before any field is written, and its size is derived from the parsed counts.
- **Entry Point:** `HidP_GetCollectionDescription` (exported function at `0x1C000B010`), which calls `HidP_AllocateCollections` to build the collection description.

### 3. Pseudocode Diff

The one semantic difference is in the End-Collection (`0xC0`) finalization path, after the `HidP KDR` structure is allocated and zeroed:

```c
// === UNPATCHED HidP_AllocateCollections (End-Collection finalization) ===
buf = ExAllocatePoolWithTag(PoolType, size, 'HidP');   // size = 104*(...) + 16*(...) + 148
if (!buf) { /* error */ }
memset(buf, 0, size);                                  // whole struct zeroed
*(DWORD*)buf       = 'HidP';
*(DWORD*)(buf + 4) = ' KDR';
*(WORD*)(buf + 16) = 0;
*(WORD*)(buf + 20) = 0;
if ((count_a + count_b) > 0xFF)                        // early-error range check
    goto error;                                        // reject descriptor
*(WORD*)(buf + 24) = (BYTE)count_c;                    // fields written byte-truncated
// ... remaining count fields ...

// === PATCHED HidP_AllocateCollections (End-Collection finalization) ===
buf = ExAllocatePoolWithTag(PoolType, size, 'HidP');   // same size formula
if (!buf) { /* error */ }
memset(buf, 0, size);                                  // whole struct zeroed
*(DWORD*)buf       = 'HidP';
*(DWORD*)(buf + 4) = ' KDR';
*(WORD*)(buf + 16) = 0;
*(WORD*)(buf + 24) = (BYTE)count_c;                    // same byte-truncated writes
// ... remaining count fields ...
// (the (count_a + count_b) > 0xFF early-error check is not present)
```

### 4. Assembly Analysis

**Node allocation and zeroing (both builds, success path):**
```assembly
; Unpatched 0x1C000D3ED / Patched 0x1C000D3E0 — allocation size
  mov     edx, 30h                 ; unpatched: fixed 0x30 bytes
  lea     edx, [r13+2Fh]           ; patched: r13 == 1 at this point, so also 0x30 bytes
  call    cs:__imp_ExAllocatePoolWithTag
  ...
  test    rax, rax
  je      <alloc-fail>
  xor     eax, eax
  mov     [r10], rax               ; node[0x00] = 0
  mov     [r10+8], rax             ; node[0x08] = 0
  mov     [r10+10h], rax           ; node[0x10] = 0
  mov     [r10+18h], rax           ; node[0x18] = 0
  mov     [r10+20h], rax           ; node[0x20] = 0
  mov     [r10+28h], rax           ; node[0x28] = 0
  ...
  mov     [rdi+28h], r10           ; link fully-zeroed node into parent list
```
All six qwords of the node are written to zero in both binaries before the node is linked, so the node contents are fully initialized in both.

**End-Collection finalization — the one differing check:**
```assembly
; UNPATCHED (0x1C000D52C..0x1C000D552)
  lea     eax, [r14+rbp]           ; eax = count_a + count_b
  mov     r9, [r10+20h]
  mov     dword [r9], 50646948h    ; 'HidP'
  mov     dword [r9+4], 52444B20h  ; ' KDR'
  mov     [r9+10h], r13w
  mov     [r9+14h], r13w
  cmp     eax, 0FFh                ; range check
  ja      loc_1C000D974            ; reject if sum > 255
  ...
  movzx   eax, r11b                ; count fields written byte-truncated
  mov     [r9+18h], ax

; PATCHED (0x1C000D525..) — no sum/compare; same byte-truncated writes
  mov     r11d, [rsp+88h+var_50]
  movzx   eax, r11b
  mov     r9, [r10+20h]
  mov     [r9+18h], ax
  mov     dword [r9], 50646948h    ; 'HidP'
  mov     dword [r9+4], 52444B20h  ; ' KDR'
  ...
```
The `lea eax, [r14+rbp] / cmp eax, 0FFh / ja` triple is present only in the unpatched build. The `HidP KDR` structure is `memset` to zero in both builds before these writes, and the destination offsets (`+0x18` through `+0x2A`) fall well inside the allocated size (at least 148 bytes), so these writes are in-bounds regardless of the check.

### 5. Effect of the Removed Check
- In the unpatched build, a report descriptor whose accumulated `count_a + count_b` exceeds 255 causes `HidP_AllocateCollections` to return an error (status `0xC00000B9`) from the End-Collection path.
- In the patched build, that descriptor is accepted; the count fields are byte-truncated (`movzx ... , r11b`) and stored, and parsing continues.
- The output buffer size (`104 * (...) + 16 * (...) + 148`) is computed from the full (non-truncated) counts in both builds, so the truncated values stored in the fixed count fields are always less than or equal to the buffer capacity. No out-of-bounds read or write follows from the change.

### 6. Initialization Detail
- **Collection node (0x30 bytes):** allocated at `0x1C000D3ED` (unpatched) / `0x1C000D3E0` (patched); zeroed across all six qwords at `0x1C000D418`–`0x1C000D430` (unpatched) / `0x1C000D410`–`0x1C000D428` (patched); linked at `0x1C000D439` (unpatched) / `0x1C000D431` (patched). No uninitialized bytes are exposed.
- **`HidP KDR` descriptor:** allocated at `0x1C000D4FC` (unpatched) / `0x1C000D4F0` (patched) and immediately `memset` to zero before any field write in both builds.

### 7. Reachability
`HidP_GetCollectionDescription` (`0x1C000B010`) calls `HidP_AllocateCollections` (`0x1C000D280`) to parse a HID report descriptor supplied by a connected HID device. The parse path exercised by the change is:
1. A HID device (physical or emulated) presents a report descriptor.
2. The HID stack calls `HidP_GetCollectionDescription`, which calls `HidP_AllocateCollections`.
3. Collection items (`0xA1`) allocate and fully zero collection nodes; the closing End-Collection (`0xC0`) allocates, zeroes, and populates the `HidP KDR` structure.
The behavioral difference is only observable as whether a descriptor with an oversized combined count is accepted (patched) or rejected (unpatched).

### 8. Changed Functions — Full Triage

- **`HidP_AllocateCollections (sub_1C000D280)`** (Similarity: 0.8926)
  - **Change Type:** Non-security (input-validation relaxation + recompilation).
  - **Notes:**
    - The collection node (0x30 bytes) is zero-initialized across all six qwords in both builds before it is linked, so its contents are fully defined in both.
    - The `HidP KDR` descriptor structure is `memset` to zero before field population in both builds.
    - The node allocation size is `0x30` bytes in both builds (`mov edx, 30h` in one, `lea edx, [r13+2Fh]` with `r13 == 1` in the other; the decompiled size is `0x30u` in both).
    - The End-Collection (`0xC0`) path drops the `(count_a + count_b) > 0xFF` early-error check; counts are byte-truncated and the output buffer is sized from the same counts in both builds, so no memory-safety property changes.
    - All other differences are register allocation and instruction scheduling from recompilation (for example `r13`/`r15`, `rsi`/`r12`, `r14`/`r9` swaps, and a stack frame reduced from `0x98` to `0x88`).

### 9. Unmatched Functions
- None. The delta consists entirely of in-place modifications to `HidP_AllocateCollections (sub_1C000D280)`.

### 10. Confidence & Caveats
- **Confidence:** High. Both binaries were compared at the instruction and decompiled-source level. The node and `HidP KDR` structures are provably zero-initialized in both builds, and the sole logic difference is the removed range check.
- **Assessment:** This function makes no security-relevant memory-safety change between the two builds. There is no uninitialized-memory disclosure and no out-of-bounds access tied to the change; the difference is a relaxation of an input-acceptance policy in the collection finalization path.
