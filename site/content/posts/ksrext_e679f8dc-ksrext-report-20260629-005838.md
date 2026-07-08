Title: ksrext.sys — No security-relevant change (rebuild/refactor: secure-call page-chain format addition, unlock-path consolidation, boot-restore database-lock hardening)
Date: 2026-06-29
Slug: ksrext_e679f8dc-ksrext-report-20260629-005838
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview
- **Unpatched Binary:** `ksrext_unpatched.sys`
- **Patched Binary:** `ksrext_patched.sys`
- **Overall Similarity Score:** `0.3722`
- **Diff Statistics:** heavy rebuild — the two builds do not share a common function layout; functions are renamed, relocated, and split, and pool allocations were migrated from `ExAllocatePoolWithTag` to `ExAllocatePool2` broadly. Both builds carry real symbol names.
- **Verdict:** This is predominantly a rebuild/refactor of the Kernel Soft Restart Extension. No attacker-reachable vulnerability is fixed. The three items originally flagged below were re-examined against both builds and reduced to their verifiable content: a secure-call MDL persistence routine gained a page-linkage field and an extra output parameter (a format/feature change, not a fix), a secure-loader connect routine had its MDL-unlock path consolidated into a single helper (a refactor, no leak), and the free-unused-partition-memory path was redesigned into a per-NUMA-node parallel worker model that now brackets its shared-tree traversal with the partition-database push-lock (boot-restore-only synchronization coupled to the new parallel design). The metadata bounds validation in the restore path is byte-equivalent in both builds.

---

## 2. Vulnerability Summary

### Finding 1: Page-chain field added to secure-call MDL persistence loop — format/feature change, not a fix
- **Severity:** Informational (No security-relevant change)
- **Vulnerability Class:** None demonstrable (defensive initialization of a newly-introduced page-linkage field)
- **Affected Function:** `KsrpNkAllocatePagesForMdl` (unpatched `0x1C000BB20`, patched `0x140013888`)
- **Reachability:** Reached only from the Secure Kernel → Normal Kernel secure-call dispatcher `KsrpNkHandleSecureCall` (unpatched `0x1C000C720`). Command index 0 (`0x1C000C7DE`) calls `KsrpNkAllocatePagesForMdl` at `0x1C000C7FD`. This is the normal-kernel side of a secure call; the caller boundary is the Secure Kernel, not an unprivileged user.
- **What actually changed:** The unpatched routine allocates pages for an MDL, copies up to `0x58` bytes of the MDL header into the caller's output buffer, and if the MDL page array is larger, copies the remaining page-array bytes into the allocated pages through a reserved mapping (loop at `0x1C000BBFD`–`0x1C000BC67`). The unpatched loop never writes the first quadword of each mapped page. The patched routine adds a back-linked chain: it writes the previous page's entry into each mapped page's first quadword (`mov [rdi], r13` at `0x1400139A5`), starts the chain with a `-1` sentinel (`or rax, 0xFFFFFFFFFFFFFFFF` at `0x140013950`, `or r13, rax` at `0x140013970`), and stores the chain head into a NEW output parameter (`mov [r13], rax` at `0x140013A02`). The patched signature also grew from 6 to 8 parameters (added a partition handle and the chain-head output) and calls `KsrMmAllocatePartitionNumaPagesForMdlEx` instead of `KsrMmAllocatePagesForMdlEx`.
- **Why this is not a security fix:** The unpatched format has no page chain at all — the missing write is not an omitted safety store but a field that did not exist in the old layout. No code in either build dereferences a persisted page's first quadword as a next-pointer. The consumer, `KsrpNkFreePersistedPages` (unpatched `0x1C000BE1C`, patched `0x140013FBC`), is logically identical in both builds and reads a fixed inline array of up to 11 entries from the request structure; it does not walk the chain the patched allocator writes. The added `mov [rdi], r13` therefore initializes memory that no in-binary path reads. Direction is not reversed (the patched build initializes more, not less), but there is no demonstrable reachable impact.

### Finding 2: Secure-loader MDL unlock path consolidated into one helper — refactor, no leak
- **Severity:** Informational (No security-relevant change)
- **Vulnerability Class:** None (resource-cleanup refactor)
- **Affected Function:** `KsrConnectSecureLoader` (unpatched `0x1C000CC90`, patched `0x140013180`)
- **What actually changed:** The unpatched function locks the transfer pages via `KsrpNkLockPagesForTransfer` (`0x1C000CD44`), performs the connect indirect call, then unlocks based on the page count computed from the returned descriptor: `MmUnlockPages` when the count is 1 (`0x1C000CDB7`) or `KsrpNkUnlockPagesForLargeTransfer` when it is greater than 1 (`0x1C000CDCA`). The patched function replaces this with a single unconditional call to `KsrpNkUnlockPagesForTransfer` (`0x140013286`), migrates the context allocation to `ExAllocatePool2` (`0x1400131E6`), and zero-initializes the descriptor up front (`memset` at `0x1400131BC`).
- **Why the reported leak is not real:** In the unpatched build both unlock branches converge at `0x1C000CDCF` and execute BEFORE the connection-result test (`test edi, edi` at `0x1C000CDCF`, failure branch to `0x1C000CDED`). The result test only decides whether the context structure is stored on success or freed on failure (`ExFreePoolWithTag` at `0x1C000CDFA`); it does not gate the unlock. The single count-`0` skip path (`0x1C000CDA8`) corresponds to the case where `KsrpNkLockPagesForTransfer` also locked nothing (it returns early for a zero page count). There is therefore no unlock-on-failure leak in the unpatched build. The patched change is a consolidation of the two matched unlock branches into one helper plus API modernization.

### Finding 3: Free-unused-partition-memory redesigned with per-NUMA-node workers and database-lock bracketing — boot-restore hardening, mechanism as originally described was incorrect
- **Severity:** Low (defense-in-depth synchronization, boot-restore reachable only; not attacker-controlled)
- **Vulnerability Class:** Missing synchronization on a shared tree traversal (CWE-362), boot-restore path
- **Affected Function:** unpatched `KsrPdFreeUnusedPartitionPages` (`0x1C000B500`); patched equivalent split into `KsrpFreeUnusedPartitionMemory` (`0x14000D8C4`), `KsrpFreeUnusedPartitionMemoryRoutine` (`0x14000DBFC`), and `KsrpFreeUnusedPartitionMemoryWorker` (`0x14000DE10`).
- **What actually changed:** The unpatched `KsrPdFreeUnusedPartitionPages` loads `KsrpPdDatabase` (`0x1C000B573`, `0x1C000B5E0`), walks the red-black tree rooted at `KsrpPdDatabase+0x40` (`0x1C000B5E7` onward, traversal `0x1C000B5EB`–`0x1C000B76B`), and frees pages within each range via `KsrPdFreePagesInRange` (`0x1C000B6A7`). It acquires no lock anywhere in the function, and its only caller, `KsrpRestoreMemoryPartition` (call at `0x1C0009631`), also holds no `KsrpPdDatabaseLock` on that path. The same database tree is protected by `KsrpPdDatabaseLock` (`ExAcquirePushLock*`) in other functions of the module, so this traversal is unsynchronized relative to those mutators. The patched build redesigns this into a NUMA-node-aware model that spawns worker threads (`PsCreateSystemThreadEx` at `0x14000DB4B`) and now brackets the equivalent work with `KsrpPdDatabaseLock`: shared while looking up the database object (acquire `0x14000DC7D`, release `0x14000DC9E`) and exclusive around the per-range cursor walk (`KsrpPdMovePartitionMemoryRangeCursor` at `0x14000DCC2`, acquire `0x14000DCB2`, release `0x14000DCFF`), snapshotting each range under the lock before freeing it via `KsrpPdFreePartitionRange` (`0x14000DD2C`).
- **Mechanism detail:** The unpatched traversal is a read-only red-black in-order walk: the `and rbx, 0xFFFFFFFFFFFFFFFC` operations mask the parent-pointer colour bits to find in-order successors, no tree node is removed, and the function's `ExFreePoolWithTag` calls free temporary scratch buffers and a local range list rather than tree nodes. It frees pages within each range via `KsrPdFreePagesInRange`. The synchronization added in the patched build is `KsrpPdDatabaseLock` acquired via `ExAcquirePushLockSharedEx`/`ExAcquirePushLockExclusiveEx`.
- **Scope of the change:** The traversal runs during soft-restart partition restoration (boot phase), on data owned by the OS, with no attacker-controlled input. The concurrency the lock guards against is largely introduced by the patched build's own parallel worker design; a concurrent mutation window in the unpatched single-threaded restore path is not demonstrable from these binaries. This is best characterized as defensive synchronization coupled to a redesign, not a fix to a demonstrated, attacker-reachable race.

---

## 3. Pseudocode Diff

### `KsrpNkAllocatePagesForMdl` (secure-call MDL persistence loop)
```c
// UNPATCHED KsrpNkAllocatePagesForMdl @ 0x1C000BB20
// v8 = allocated MDL; v9 = total header+page-array size; a6 = output buffer
memmove(a6, v8, min(v9, 0x58));            // copy MDL header + first entries
if (v10 != v9) {                            // more page-array bytes remain
  v12 = InterlockedExchange64(ctx+8, 0);    // borrow reserved mapping
  do {
    Next = v11->Next; v11 += 8;
    MmMapLockedPagesWithReservedMapping(v12, 'KsrS', &mdl, MmCached);
    // no write to *v12 here
    memmove(v12 + 0x30, (char*)v8 + v10, chunk);
    MmUnmapReservedMapping(v12, 'KsrS', &mdl);
    v10 += chunk;
  } while (v10 < v9);
  InterlockedExchange64(ctx+8, v12);
}

// PATCHED KsrpNkAllocatePagesForMdl @ 0x140013888  (signature grew: adds Handle, a8)
memmove(a8, v10, min(v12, 0x58));
if (v13 != v12) {
  v14 = InterlockedExchange64(ctx+8, 0);
  v16 = -1;                                 // chain sentinel
  do {
    v21 = *v17++;                           // current page entry
    MmMapLockedPagesWithReservedMapping(v14, 'KsrS', &mdl, MmCached);
    *v14 = v16;                             // NEW: write previous entry as chain link
    v16 = v21;
    memmove(v14 + 6, (char*)v10 + v13, chunk);
    MmUnmapReservedMapping(v14, 'KsrS', &mdl);
    v13 += chunk;
  } while (v13 < v12);
  InterlockedExchange64(ctx+8, v14);
  *v11 = v16;                               // NEW: store chain head into output param
}
```
The added writes populate a first-quadword back-link in each persisted page and a chain-head output. No path in either build reads these as pointers (`KsrpNkFreePersistedPages` reads an inline array from the request in both builds).

### `KsrConnectSecureLoader`
```c
// UNPATCHED @ 0x1C000CC90 — unlock is unconditional w.r.t. connect result
status = KsrpNkLockPagesForTransfer(&desc, addr, len, op);   // 0x1C000CD44
if (status < 0) goto out;
result = connect_icall(&req);                                 // 0x1C000CD83
pages = (desc_len + (desc_off & 0xFFF) + 0xFFF) >> 12;
if (pages == 1)      MmUnlockPages(&mdl);                      // 0x1C000CDB7
else if (pages > 1)  KsrpNkUnlockPagesForLargeTransfer(&desc); // 0x1C000CDCA
if (result < 0) { /* fall through */ }                        // 0x1C000CDCF
if (ctx) ExFreePoolWithTag(ctx, 'KsrS');                      // free only, unlock already done

// PATCHED @ 0x140013180 — consolidated unlock + ExAllocatePool2 + up-front memset
memset(&desc, 0, 0x48);
ctx = ExAllocatePool2(0x102, 0x30, 'KsrS');
...
result = connect_icall(&req);
KsrpNkUnlockPagesForTransfer(&desc);                          // 0x140013286, single helper
if (result < 0) { ExFreePoolWithTag(ctx, 'KsrS'); return result; }
```

### `KsrPdFreeUnusedPartitionPages` → `KsrpFreeUnusedPartitionMemoryRoutine`
```c
// UNPATCHED KsrPdFreeUnusedPartitionPages @ 0x1C000B500 — shared tree walk, no lock
tree = KsrpPdDatabase + 0x40;              // 0x1C000B5E7
for (node = first(tree); node; node = successor(node)) {   // 0x1C000B5EB..0x1C000B76B
  // read range fields; free pages within the range
  KsrPdFreePagesInRange(&mdl, ...);        // 0x1C000B6A7
}
// no ExAcquirePushLock* anywhere in this function; caller holds no KsrpPdDatabaseLock

// PATCHED KsrpFreeUnusedPartitionMemoryRoutine @ 0x14000DBFC — bracketed by database lock
ExAcquirePushLockSharedEx(&KsrpPdDatabaseLock, 0);          // 0x14000DC7D
obj = lookup_partition_object();
ExReleasePushLockSharedEx(&KsrpPdDatabaseLock, 0);          // 0x14000DC9E
...
ExAcquirePushLockExclusiveEx(&KsrpPdDatabaseLock, 0);       // 0x14000DCB2
range = KsrpPdMovePartitionMemoryRangeCursor(...);         // 0x14000DCC2 (snapshot under lock)
ExReleasePushLockExclusiveEx(&KsrpPdDatabaseLock, 0);      // 0x14000DCFF
KsrpPdFreePartitionRange(range);                           // 0x14000DD2C
```

---

## 4. Assembly Analysis

### `KsrpNkAllocatePagesForMdl` persistence loop
```assembly
; UNPATCHED @ 0x1C000BB20 — loop body 0x1C000BBFD..0x1C000BC67
00000001C000BBFD  mov     rax, [r12]                              ; current page-array entry
00000001C000BC01  lea     r8, [rsp+98h+MemoryDescriptorList]
00000001C000BC0C  mov     [rsp+98h+var_38], rax                   ; into stack MDL page slot
00000001C000BC16  lea     r12, [r12+8]
00000001C000BC1B  mov     rcx, rsi                                ; reserved mapping addr
00000001C000BC1E  call    cs:__imp_MmMapLockedPagesWithReservedMapping
; no store to [rsi] (mapping base) in this build
00000001C000BC2D  lea     rdx, [r14+rbp]
00000001C000BC34  lea     rcx, [rsi+30h]
00000001C000BC42  call    memmove                                 ; copy page-array bytes to mapping+0x30
00000001C000BC54  call    cs:__imp_MmUnmapReservedMapping
00000001C000BC66  jb      short loc_1C000BBFD

; PATCHED @ 0x140013888 — loop body 0x140013977..0x1400139E7
0000000140013977  mov     rax, [rsi]                              ; next page-array entry
0000000140013984  mov     [rbp+var_10], rax
000000014001398D  lea     rsi, [rsi+8]
0000000140013991  mov     rcx, rdi                                ; reserved mapping addr
0000000140013994  call    cs:__imp_MmMapLockedPagesWithReservedMapping
00000001400139A5  mov     [rdi], r13                              ; NEW: write chain link (prev entry)
00000001400139A8  mov     r13, [rbp+var_10]
00000001400139B3  lea     rcx, [rdi+30h]
00000001400139C4  call    memmove
00000001400139D5  call    cs:__imp_MmUnmapReservedMapping
00000001400139E7  jb      short loc_140013977
00000001400139E9  mov     [rbp+arg_40], r13
...
0000000140013A02  mov     [r13+0], rax                            ; NEW: store chain head to output param
```

### `KsrConnectSecureLoader` unlock path (unpatched)
```assembly
; UNPATCHED @ 0x1C000CC90 — unlock executes before the connect-result test
00000001C000CDA8  test    rax, rax                                ; page count
00000001C000CDAB  jz      short loc_1C000CDCF                     ; count 0 -> nothing was locked
00000001C000CDAD  cmp     rax, 1
00000001C000CDB1  jnz     short loc_1C000CDC5
00000001C000CDB7  call    cs:__imp_MmUnlockPages                  ; count == 1
00000001C000CDC3  jmp     short loc_1C000CDCF
00000001C000CDCA  call    KsrpNkUnlockPagesForLargeTransfer       ; count > 1
00000001C000CDCF  test    edi, edi                                ; connect result checked AFTER unlock
00000001C000CDD1  js      short loc_1C000CDED
...
00000001C000CDFA  call    cs:__imp_ExFreePoolWithTag              ; free context on failure only
```

### `KsrPdFreeUnusedPartitionPages` shared-tree walk (unpatched, no lock)
```assembly
; UNPATCHED @ 0x1C000B500
00000001C000B5E0  mov     rbx, cs:KsrpPdDatabase
00000001C000B5E7  add     rbx, 40h                                ; red-black tree root
00000001C000B6A7  call    KsrPdFreePagesInRange                   ; free pages within range
00000001C000B765  and     rbx, 0FFFFFFFFFFFFFFFCh                 ; parent colour-bit mask (successor walk)
00000001C000B76E  jnz     loc_1C000B611                           ; continue traversal
; no ExAcquirePushLock* anywhere in the function
```

---

## 5. Trigger Conditions

### `KsrpNkAllocatePagesForMdl` (Finding 1)
Reached only when the Secure Kernel issues secure-call command 0 into `KsrpNkHandleSecureCall` (`0x1C000C720` → `0x1C000C7FD`) with an allocation whose MDL page array exceeds the `0x58`-byte inline header copy. The added chain-link write initializes the persisted pages' first quadword; no in-binary path reads that field, so there is no observable fault or corruption to trigger. This is not an attacker-reachable vulnerability.

### `KsrConnectSecureLoader` (Finding 2)
Invoked during boot/soft-restart when the loader connects the secure loader. In the unpatched build the transfer pages are unlocked regardless of connection success, so no leak is triggerable. The patched change is behaviorally equivalent cleanup consolidation.

### `KsrPdFreeUnusedPartitionPages` (Finding 3)
Runs during soft-restart partition restoration via `KsrpRestoreMemoryPartition`. The unsynchronized traversal would only be a live race if another thread mutates the `KsrpPdDatabase` tree during that boot-restore window; such a concurrent path is not demonstrable in the unpatched build. The patched lock bracketing accompanies a redesign that introduces its own parallel workers.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive is supported by the two binaries.

- Finding 1 adds a page-linkage field and an output parameter that no in-binary consumer reads as a pointer; there is no memory-corruption or read/write primitive.
- Finding 2 does not leak (unlock is unconditional in the unpatched build), so there is no resource-exhaustion primitive.
- Finding 3 concerns a boot-restore traversal on OS-owned data with no attacker-controlled input and no demonstrable concurrent mutator in the unpatched build; no use-after-free or read/write primitive is demonstrable.

None of the reachable inputs here are attacker-controlled from an unprivileged context; the relevant boundaries are the Secure Kernel secure-call interface and the boot-time restoration path.

---

## 7. Debugger PoC Playbook

No reproducing PoC is supported, because none of the three items is a demonstrable, reachable vulnerability. The verifiable behavioral differences can be observed statically at the following anchors:

- `KsrpNkAllocatePagesForMdl` chain-link write: patched `0x1400139A5` (`mov [rdi], r13`) and head store `0x140013A02`; absent in the unpatched loop `0x1C000BBFD`–`0x1C000BC67`.
- `KsrConnectSecureLoader` unlock ordering: unpatched unlock at `0x1C000CDB7`/`0x1C000CDCA` precedes the result test at `0x1C000CDCF`; patched single unlock at `0x140013286`.
- `KsrPdFreeUnusedPartitionPages` lock delta: no acquire in the unpatched function (`0x1C000B500`); patched acquires `KsrpPdDatabaseLock` at `0x14000DC7D` (shared) and `0x14000DCB2` (exclusive).

---

## 8. Changed Functions — Full Triage

- **`KsrpNkAllocatePagesForMdl`** (unpatched `0x1C000BB20` → patched `0x140013888`): adds a back-linked page-chain field and a chain-head output parameter; signature grew 6→8 args; switched to `KsrMmAllocatePartitionNumaPagesForMdlEx`. Format/feature change; no consumer dereferences the field. Not a security fix.
- **`KsrConnectSecureLoader`** (`0x1C000CC90` → `0x140013180`): unlock path consolidated into `KsrpNkUnlockPagesForTransfer`; migrated to `ExAllocatePool2`; added up-front `memset`. Refactor/modernization; no leak in the unpatched build.
- **`KsrPdFreeUnusedPartitionPages`** (`0x1C000B500`) → **`KsrpFreeUnusedPartitionMemory`/`...Routine`/`...Worker`** (`0x14000D8C4`/`0x14000DBFC`/`0x14000DE10`): redesigned into a per-NUMA-node parallel worker model; the shared-tree traversal, previously unlocked, is now bracketed by `KsrpPdDatabaseLock`. Boot-restore-only synchronization hardening coupled to the redesign; not an attacker-reachable race. The unpatched traversal is a read-only in-order walk that frees pages within ranges (`KsrPdFreePagesInRange`); it neither removes tree nodes nor calls `RtlRbRemoveNode`.
- **`KsrpRestoreMemoryPartition`** (`0x1C000926C` → `0x14000DFF0`): the metadata offset/length bounds validation is byte-equivalent in both builds (fields at `+4/+8/+0xC/+0x10` checked against the metadata size, plus the two cross-field sums; reject target common to both). The only differences are a renamed query helper (`KsrPdQueryRegionMetadata` → `KsrDbQueryRegionMetadata`), `ExAllocatePool2` migration, and a dropped redundant retrieve call. No security-relevant change.
- **`KsrQueryMetadata`** (`0x1C0007290` region): metadata-query dispatch reorganized as part of the data-access-layer rename/split. Behavioral refactor, not security-relevant.
- **`KsrpRestoreMemoryPartitionsWorker`** (`0x1C0009770` → `0x14000E830`): restoration worker; changes are locking/consistency hardening (`KeBugCheckEx` on inconsistency) consistent with the redesign. Not a standalone vulnerability.
- **`KsrpNkLockPagesForLargeTransfer`** (`0x1C000BF30`): page-lock helper; error-path hardening and object-open modernization. Not security-relevant.
- **`KsrpNkLockPagesForTransfer`** (`0x1C000C45C` → `0x140014A20`): identical page-count math, `MmProbeAndLockPages`, and `>1`-page delegation. No change of security relevance.
- **`KsrPdQueryRegionMetadata`** (`0x1C000B7CC` → `0x14001060C`): identical table-index bound (`cmp edx,[rcx+0x14]; jnb reject`) and pre-`memmove` copy-size guard; only a block-id constant shifted. No change of security relevance.
- **Rebuild/optimization changes:** `memmove`/`memset` variant rewrites; the broad `ExAllocatePoolWithTag` → `ExAllocatePool2` migration; added WPP/ETW tracing (`McTemplate*_EtwWriteTransfer`); `KeBugCheckEx` error-path hardening; feature-flag staging (`KsrSecureKernelConnected`, `byte_140007143 & 8`, `dword_1400072A4 & 0x10`). None are security fixes.

---

## 9. Unmatched Functions
- **Added:** the patched build contains many functions with no unpatched counterpart (e.g. the secure-extension split `KsrNkConnectSecureExtension`, `KsrpNkMapTransferPage`), consistent with a rebuild/feature-staging redesign rather than a targeted patch.
- **Removed:** none of security relevance.

*Note: `KsrpNkMapTransferPage` (`0x140014B3C`) is new code carrying a one-page size cap (`cmp r8, 0x1000; jbe` at `0x140014B59`). Because it is newly-introduced code in a refactored path rather than a hardening of a pre-existing function, it is not scored as a fixed vulnerability.*

---

## 10. Confidence & Caveats
- **Confidence Level:** High for the direction and mechanism of each item, based on address-anchored comparison of both builds' disassembly and decompilation.
- **Basis:**
  1. Finding 1 is a format/feature addition (new chain field + new output parameter, signature change); no consumer reads the field, so no reachable impact.
  2. Finding 2's unlock executes before the connection-result test in the unpatched build, so the reported leak-on-failure does not exist.
  3. Finding 3 is a genuine lock delta but boot-restore-only, on OS-owned data, with concurrency coupled to the patched build's own new parallel design; no attacker-reachable race is demonstrable.
  4. The restore-path metadata bounds validation is identical in both builds.
- **Limits:** The persisted pages produced by Finding 1 and the partition database in Finding 3 may be consumed by components outside these two binaries (the Secure Kernel, the boot loader). Any impact through those external consumers cannot be confirmed from the provided files and is not claimed here.
