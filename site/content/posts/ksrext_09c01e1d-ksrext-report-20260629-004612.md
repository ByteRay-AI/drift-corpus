Title: ksrext.sys — Integer overflow in soft-reboot partition-restore allocation (CWE-190) removed and restore error path hardened to fail-fast; fixed
Date: 2026-06-29
Slug: ksrext_09c01e1d-ksrext-report-20260629-004612
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Low

## 1. Overview

- **Unpatched Binary:** `ksrext_unpatched.sys`
- **Patched Binary:** `ksrext_patched.sys`
- **Overall Similarity Score:** `0.6282` (62.82%)
- **Diff Statistics:**
  - Matched Functions: 166
  - Changed Functions: 82
  - Identical Functions: 84
  - Unmatched (Unpatched/Patched): 0 / 0
- **Verdict:** The patch rearchitects the persisted-memory partition-restore path. Two changes are security-relevant: (1) the unpatched combined allocation in `KsrpRestoreMemoryPartition` sizes a kernel pool buffer from a 32-bit-truncated sum of two entry counts while subsequent writes use the full 64-bit counts (integer overflow, CWE-190/CWE-122), and the patch removes that combined allocation entirely; (2) the unpatched `KsrpRestoreMemoryPartitionsWorker` continues execution after a partition restore fails and mutates the internal page database, whereas the patch replaces that recovery path with a `KeBugCheckEx` fail-fast. The remaining diffs previously described here as a use-after-free and a TOCTOU/overflow are not substantiated by the binaries and are downgraded below. Both security-relevant changes require control of kernel soft-reboot persisted-memory metadata, an in-memory state carried across a warm reboot rather than an attacker-writable disk file, so practical reachability is limited.

---

## 2. Vulnerability Summary

### Finding 1: Integer Overflow in Combined Allocation (removed by patch)
- **Severity:** Low
- **Vulnerability Class:** Integer Overflow / Heap Overflow (CWE-190 / CWE-122)
- **Affected Function:** `KsrpRestoreMemoryPartition` (unpatched `0x1C000B160`, patched `0x14000DFF0`)
- **Root Cause:** The unpatched function loads two 32-bit entry counts and adds them with a 32-bit `lea edi, [r15+r12]`, truncating the sum to 32 bits. The zero-extended sum is scaled by 8 and added to the metadata size to form the `ExAllocatePool2` size. The subsequent element copies compute their destination offsets from the full 64-bit counts (`[rax+r12*8]`, `[rcx+r15*8]`). If the two counts sum to more than `0xFFFFFFFF`, the allocation wraps to a small value while the copies write at the true, unwrapped offsets, overflowing the pool buffer. The patched build removes this combined count-based allocation: it allocates only the metadata block and processes the persisted pages through an MDL list (`MmMapLockedPagesSpecifyCache` + `KsrDbAddBadPageRanges`).
- **Reachability:** The counts are produced by `KsrPdRetrieveMemoryRegion` over kernel soft-reboot persisted memory. To make the truncated sum wrap, `count1 + count2` must exceed `0xFFFFFFFF` (about four billion 8-byte entries, roughly 32 GB of entry data describing on the order of terabytes of physical memory). This is not a demonstrably reachable primitive on realistic systems, and the persisted-memory metadata is not an ordinary attacker-writable surface. The change is a genuine removal of overflow-prone arithmetic; the demonstrable impact is low.

### Finding 2: Continued Execution on Restore Failure (replaced by fail-fast bugcheck)
- **Severity:** Low
- **Vulnerability Class:** Use of Inconsistent State on Error Path (CWE-758)
- **Affected Function:** `KsrpRestoreMemoryPartitionsWorker` (unpatched `0x1C000BCB0`, patched `0x14000E830`)
- **Root Cause:** When `KsrpRestoreMemoryPartition` returns a negative status, the unpatched worker does not stop. It increments a global counter and walks the internal page database `KsrpPdDatabase` linked list, and for every entry whose partition id matches the failed partition it decrements a global counter (`dec dword ptr [rax+24h]` or `dec qword ptr [rax+28h]`) and zeroes the entry. After a partition that was partially restored before failing, these internal structures can be in a partly-initialized state, so this rollback runs over possibly-inconsistent bookkeeping. The patch removes this recovery entirely and calls `KeBugCheckEx(0x70, 0x211, status, descriptor, ...)` immediately on failure.
- **Impact:** This is a fail-fast hardening: the driver stops rather than continuing to mutate internal state after a failed restore. The rollback operated on driver-owned structures, not directly on attacker-supplied buffers, and no concrete memory-corruption primitive is demonstrable from the code. Severity is Low (robustness / defense-in-depth), and the direction is correct (the patched build is the stricter one).

### Finding 3: Work-area free in page database teardown — No security-relevant change
- **Severity:** None (refactor)
- **Affected Function:** `KsrpPdDestroyDatabase` (unpatched `0x1C000C8B0`, patched `0x1400114F0`)
- **Assessment:** The unpatched build frees the work area via the helper `KsrPdFreeWorkArea(P[6])`, which does `MmFreeMappingAddress(*P, tag)` then `ExFreePoolWithTag(P, tag)`. The patched build inlines the same two calls and adds `*v9 = 0` between them. That store zeroes the mapping-handle field of the work area on the line immediately before the work area itself is freed, so it is dead and cannot prevent any use. The work-area pointer `P[6]` is not read again after this point in either build, and the patch does not NULL the parent pointer. There is no reachable use-after-free. The additional `ZwSetSystemInformation(SystemPoolTagInformation|0x80, 0, 0)` call on the teardown-with-free path is behavioral, not a memory-safety fix.

### Finding 4: Partition range query allocation — No security-relevant change
- **Severity:** None (refactor)
- **Affected Function:** `KsrpHotAddPartitionMemory` (unpatched `0x1C000AFC0`, patched `0x14000DE34`)
- **Assessment:** The allocation `ExAllocatePool2(258, 16 * (count + 3LL), tag)` is computed in 64-bit arithmetic in both builds; at a count near `0xFFFFFFFF` the size is about 68 GB and does not wrap. The two-call pattern (`KsrDbQueryPartitionRanges` first for the count, then again to fill the buffer at `pool+48`) is present unchanged in both builds, and `ZwManagePartition` is used in both builds. The real differences are: two output parameters added to hand the count and range sum back to the caller, the `KsrPd`→`KsrDb` prefix rename, and removal of a `count <= 0xFFFFFFFF` check that was a no-op after the count variable's type narrowed. None of these are a security fix.

---

## 3. Pseudocode Diff

### `KsrpRestoreMemoryPartition` (Finding 1)
```c
// --- UNPATCHED: KsrpRestoreMemoryPartition @ 0x1C000B160 ---
v15 = v42;                 // count2 (32-bit from KsrPdRetrieveMemoryRegion, flag 0x80000000)
v16 = v41;                 // count1 (32-bit from KsrPdRetrieveMemoryRegion, flag 0)
v17 = v42 + v41;           // 32-bit add: sum TRUNCATED to 32 bits, then widened
...
Pool2 = ExAllocatePool2(258, (unsigned int)v44 + 8 * v17, 1165128523);   // size from truncated sum
v22 = (__int64)Pool2 + 8 * v16;        // destination offset uses full 64-bit count1
v23 = v22 + 8 * v15;                    // destination offset uses full 64-bit count2
KsrPdRetrieveMemoryRegion(a1, ..., Pool2, v16, 0, &v41);          // writes count1 entries
KsrPdRetrieveMemoryRegion(a1, ..., v22,   v15, 0x80000000, &v42); // writes count2 entries at Pool2+count1*8

// --- PATCHED: KsrpRestoreMemoryPartition @ 0x14000DFF0 ---
RegionMetadata = KsrDbQueryRegionMetadata(v10, v9, v7, 0, 0, &v33);  // single metadata size
Pool2 = ExAllocatePool2(258, v33, 1165128523);                       // allocates metadata only
// persisted pages are processed via an MDL list:
//   MmMapLockedPagesSpecifyCache(MemoryDescriptorList, ...) + KsrDbAddBadPageRanges(...)
// the combined count-based buffer no longer exists
```

### `KsrpRestoreMemoryPartitionsWorker` (Finding 2)
```c
// --- UNPATCHED: KsrpRestoreMemoryPartitionsWorker @ 0x1C000BCB0 ---
v13 = KsrpRestoreMemoryPartition(...);
if ( v13 < 0 ) {
    if ( v7 >= 0 ) v7 = v13;
    ++dword_1C0012178;
    for ( j = *((_QWORD *)KsrpPdDatabase + 1); j; j = *(_QWORD *)j ) {   // walk internal database
        for ( k = 0; (unsigned)k < *(_DWORD *)(j + 20); ++k ) {
            v14 = j + 32 * ((unsigned)k + 1);
            if ( (matched failed partition id) ) {
                if ( ... ) --*((_DWORD *)KsrpPdDatabase + 9);   // dec [KsrpPdDatabase+0x24]
                else       --*((_QWORD *)KsrpPdDatabase + 5);   // dec [KsrpPdDatabase+0x28]
                *(_QWORD *)v14 = 0;                             // zero entry
            }
        }
    }
}

// --- PATCHED: KsrpRestoreMemoryPartitionsWorker @ 0x14000E830 ---
v12 = KsrpRestoreMemoryPartition(...);
if ( v12 < 0 ) {
    // (optional ETW trace)
    KeBugCheckEx(0x70, 0x211, v7, (ULONG_PTR)v10, descriptor);   // fail-fast, no cleanup
}
```

### `KsrpPdDestroyDatabase` (Finding 3 — no security-relevant change)
```c
// --- UNPATCHED: KsrpPdDestroyDatabase @ 0x1C000C8B0 ---
KsrPdFreeWorkArea(*((PVOID *)P + 6));   // helper: MmFreeMappingAddress(*P, tag); ExFreePoolWithTag(P, tag);
// P[6] is not read again

// --- PATCHED: KsrpPdDestroyDatabase @ 0x1400114F0 ---
v9 = (PVOID *)P[6];
MmFreeMappingAddress(*v9, tag);
*v9 = nullptr;                 // zeroes a field of v9, which is freed on the next line (dead store)
ExFreePoolWithTag(v9, tag);
// the parent pointer P[6] is not NULLed; no subsequent use of P[6]
```

---

## 4. Assembly Evidence

### `KsrpRestoreMemoryPartition` truncated allocation (unpatched)
```assembly
; KsrpRestoreMemoryPartition @ 0x1C000B160 (unpatched)
00000001C000B277  mov     r15d, [rbp+70h+var_E4]     ; count2 (32-bit)
00000001C000B27B  mov     r12d, [rbp+70h+var_E8]     ; count1 (32-bit)
00000001C000B27F  lea     edi, [r15+r12]             ; edi = count1+count2, 32-bit add -> TRUNCATED
...
00000001C000B397  mov     esi, dword ptr [rbp+70h+var_D8]  ; metadata size
00000001C000B3A5  lea     rdx, [rsi+rdi*8]           ; alloc size = metadata + sum*8 (sum truncated)
00000001C000B3A9  call    cs:__imp_ExAllocatePool2
00000001C000B3D2  lea     rcx, [rax+r12*8]           ; dest = pool + count1*8 (full 64-bit count1)
00000001C000B3DA  lea     rdi, [rcx+r15*8]           ; dest = pool + (count1+count2)*8 (full 64-bit)
```

### `KsrpRestoreMemoryPartitionsWorker` error path (unpatched vs patched)
```assembly
; unpatched @ 0x1C000BCB0 error-path cleanup
00000001C000BE04  mov     rax, cs:KsrpPdDatabase     ; load internal database
00000001C000BE52  dec     dword ptr [rax+24h]        ; decrement global counter
00000001C000BE57  dec     qword ptr [rax+28h]        ; decrement global counter
; (no KeBugCheckEx on this failure path)

; patched @ 0x14000E830 same logical point
000000014000EAE7  mov     edx, 211h                  ; bugcheck subcode
000000014000EAF1  call    cs:__imp_KeBugCheckEx      ; fail-fast on restore failure
```

### `KsrpRestoreMemoryPartition` metadata-only allocation (patched)
```assembly
; KsrpRestoreMemoryPartition @ 0x14000DFF0 (patched)
000000014000E0BE  call    KsrDbQueryRegionMetadata   ; single metadata query
000000014000E0EE  call    cs:__imp_ExAllocatePool2   ; allocation sized from metadata only
```

---

## 5. Trigger Conditions

For the integer overflow in `KsrpRestoreMemoryPartition` (Finding 1):

1. The restore path runs during soft-restart initialization: `KsrInitSystem` → `KsrpRestoreMemoryPartitions` (`0x1C000BFF4`) queues a work item that runs `KsrpRestoreMemoryPartitionsWorker`, which calls `KsrpRestoreMemoryPartition` for each persisted partition descriptor.
2. `KsrpRestoreMemoryPartition` reads two entry counts from the persisted memory region via `KsrPdRetrieveMemoryRegion`.
3. For the 32-bit sum to wrap, `count1 + count2` must exceed `0xFFFFFFFF`. Each count is the number of 8-byte persisted-page entries; reaching that total requires on the order of four billion entries, which is not attainable on realistic hardware and is not a normal attacker-controlled input.
4. If the sum did wrap, `ExAllocatePool2` would return an undersized buffer and the element copies would write past it. On realistic inputs the counts are far below the wrap threshold and the allocation is correctly sized.

Because the persisted-memory metadata is kernel soft-reboot state carried across a warm reboot (see `KsrEnumeratePersistedMemory`), not a file an unprivileged user can write, and because the wrap threshold is impractical, this is best characterized as removal of overflow-prone arithmetic rather than a reachable exploitation primitive.

---

## 6. Exploit Primitive Assessment

No exploitation primitive is demonstrable from the binaries.

- Finding 1 would, in principle, produce a pool overflow, but only at count totals that are not reachable on realistic systems and only if the persisted-memory metadata is attacker-controlled. No controlled write of a specific size or content is demonstrable, so no info-leak, grooming, or code-execution chain is supported by the evidence.
- Finding 2 changes an error-recovery path into a bugcheck. The unpatched rollback operates on driver-owned bookkeeping (`KsrpPdDatabase`); no attacker-controlled write primitive is demonstrable.

Statements about KASLR bypass, pool grooming, token-privilege overwrites, or shellcode redirection are not supported by these two builds and are omitted.

---

## 7. Debugging Notes

For the unpatched integer overflow (Finding 1):

- Break at `KsrpRestoreMemoryPartition` (`0x1C000B160`). The two counts are read at `0x1C000B277` (into `r15d`) and `0x1C000B27B` (into `r12d`); the truncating add is `lea edi, [r15+r12]` at `0x1C000B27F`.
- Inspect the size argument to `ExAllocatePool2` at `0x1C000B3A9`: it is `metadata + (truncated sum) * 8` (`lea rdx, [rsi+rdi*8]` at `0x1C000B3A5`). Compare it against the full-precision copy offsets computed at `0x1C000B3D2` (`pool + count1*8`) and `0x1C000B3DA` (`pool + (count1+count2)*8`).

For the unpatched error path (Finding 2):

- After a negative return from `KsrpRestoreMemoryPartition`, the unpatched worker loads `KsrpPdDatabase` at `0x1C000BE04` and decrements global counters at `0x1C000BE52` / `0x1C000BE57`. In the patched build the same failure reaches `KeBugCheckEx` (`mov edx, 211h` at `0x14000EAE7`, call at `0x14000EAF1`).

---

## 8. Changed Functions — Full Triage

- **`KsrpRestoreMemoryPartition` (`0x1C000B160` / `0x14000DFF0`):** Security-relevant. The combined count-based allocation with the 32-bit-truncated sum is removed; the patched build allocates only the metadata block and processes persisted pages through an MDL list (`MmMapLockedPagesSpecifyCache` + `KsrDbAddBadPageRanges`). Removes overflow-prone arithmetic (Finding 1).
- **`KsrpRestoreMemoryPartitionsWorker` (`0x1C000BCB0` / `0x14000E830`):** Security-relevant. On restore failure the unpatched database rollback is replaced with `KeBugCheckEx(0x70, 0x211, ...)`; the worker also moves to MDL-based enumeration of persisted memory (`KsrEnumeratePersistedMemory` + `KsrpBadPageListBlockCallback`). Fail-fast hardening (Finding 2).
- **`KsrpPdWalkRegionPage` (`0x1C000C690` / `0x140012B58`):** Security-relevant, part of the Finding 1 rearchitecture. The unpatched function only maps each persisted region page and calls `KsrpPdVerifyRamRanges`; it performs no aggregation copy. The patched function aggregates the chained pages' PFN entries into a pool buffer sized from the first page's advertised count and adds two capacity guards, `KeBugCheckEx(0x70, 5, 1, capacity, count)` and `KeBugCheckEx(0x70, 5, 0, capacity, count)`, before each `memmove`, so a later chained page that claims more entries than were allocated fails-stops instead of overflowing. This is the defensively-written replacement path for the combined allocation that Finding 1 removed, not a separate unpatched overflow (the unpatched build had no copy here).
- **`KsrPdPersistMemoryRegion` (patched `0x140010040`):** Behavioral, persist/serialize side. Adds `KeBugCheckEx(0x70, 1, ...)` (region within the located partition range) and `KeBugCheckEx(0x70, 3, ...)` (page-alignment) consistency checks in restructured code. Defense-in-depth on data the kernel itself serializes; not a demonstrable attacker-facing fix.
- **`KsrpPdDestroyDatabase` (`0x1C000C8B0` / `0x1400114F0`):** Not a security fix. `KsrPdFreeWorkArea` is inlined; the added `*handle = 0` store targets memory freed on the next line (dead). Behavioral `ZwSetSystemInformation` cleanup added on the free path (Finding 3).
- **`KsrpHotAddPartitionMemory` (`0x1C000AFC0` / `0x14000DE34`):** Not a security fix. 64-bit allocation math in both builds; double query-then-fill and `ZwManagePartition` present in both; adds two output parameters, prefix rename, and removes a no-op count check (Finding 4).
- **`KsrpPdAddAllocatedRangesCallback` (`0x1C000E1FC` / `0x140010B74`):** Not a security fix. The two adjacent 64-bit counter updates are combined into one `_mm_add_epi64` store (compiler auto-vectorization). The counters live in a stack-local accumulator passed by `KsrPdAddAllocatedRanges`, not shared state, and `_mm_add_epi64` is not an atomic operation, so there is no race being fixed.
- **`KsrMmAllocatePagesForMdlEx`:** Behavioral. Masks the flags argument with `0x7fffffff` before use; register-allocation differences.
- **`KsrRegisterLoaderCallbacks`:** Behavioral, not a vulnerability fix. Structure-size validation grows to accommodate a new field, and a feature-gated secure-loader path is added while the existing path is retained. Staged feature rollout, not a memory-safety fix.
- **`KsrPersistMemoryPartition`:** Behavioral. Adds `ObReferenceObjectByHandle` before querying partition data and restructures the locked traversal.
- **`KsrPdFreeMemoryRegions` (`0x1C000CC00` / `0x14000F75C`):** Behavioral. Matching logic and conditional processing restructured; equivalent offsets.
- **`KsrpPdInitializeDatabase` (`0x1C0009E68` / `0x14000D058`):** Cosmetic. Min/max physical-address calculation and register renaming; logically equivalent.
- **`KsrPdRetrieveMemoryRegion` (`0x1C000CF38` / `0x1400107B4`):** Cosmetic. Register renaming; the cleanup path changes from an inline `memset` to a helper call.

---

## 9. Unmatched Functions

- **Added/Removed:** None reported by the diff. The changes are in-place modifications, plus a driver-wide rename of the page-database helpers from the `KsrPd*` prefix to the `KsrDb*` prefix and the addition of secure-kernel feature branches.

---

## 10. Confidence & Caveats

- **Confidence Level:** High for the direction of each change (the patched build is the stricter one for Findings 1 and 2; Findings 3 and 4 are refactors).
- **Findings 1 and 2** are genuine security-relevant changes but with low demonstrable impact: Finding 1's overflow threshold is not reachable on realistic hardware, and Finding 2 converts an error-recovery path over driver-owned state into a bugcheck. Both depend on kernel soft-reboot persisted-memory metadata, which is not an ordinary user-writable surface.
- **Findings 3, 4, and the SIMD counter change** are downgraded to non-security refactors on the evidence above.
- The severities here reflect demonstrable, reachable impact in these two builds rather than speculative exploitation.
