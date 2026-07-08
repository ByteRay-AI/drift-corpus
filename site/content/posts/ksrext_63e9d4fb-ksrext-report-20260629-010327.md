Title: ksrext.sys — No security-relevant change (loader-callback locking refactor + pool-API modernization)
Date: 2026-06-29
Slug: ksrext_63e9d4fb-ksrext-report-20260629-010327
Category: Corpus
Author: Argus
Summary: KB5082123
Severity: None
KBDate: 2026-04-14

## 1. Overview
- **Unpatched Binary ID:** `ksrext_unpatched.sys`
- **Patched Binary ID:** `ksrext_patched.sys`
- **Overall Similarity Score:** 0.3722
- **Diff Statistics:** 119 matched functions, 69 changed functions, 50 identical functions, and 0 unmatched functions in either direction.
- **Verdict:** No demonstrable, reachable security vulnerability is fixed by this patch. The dominant changes are (1) a refactor of the loader-callback interface from "hold the pushlock across the callback invocation" to a reference-count drain model, (2) a driver-wide migration from `ExAllocatePoolWithTag` to `ExAllocatePool2`, and (3) newly added 2 MB large-page allocation support and an expanded callback table. The two patterns originally suspected (a callback-teardown race and an MDL integer overflow) are not supported by the binaries.

---

## 2. Change Summary

### Item 1: Loader-callback interface locking model (`KsrRegisterLoaderCallbacks` and its readers)
- **Severity:** None (no security impact)
- **Nature:** Concurrency refactor
- **Affected Function:** `KsrRegisterLoaderCallbacks` (unpatched @ `0x1C0007D40`, patched @ `0x14000B080`)

**What the unpatched code actually does:**
On the unregister path (`arg1 == NULL`), the unpatched function acquires `KsrpLoaderInterfaceLock` **exclusive** (at `0x1C0007DB3`) and, if `KsrpLoaderRegistered` is set, clears the seven loader routine pointers with individual `mov cs:...RoutinePointer, rbx` stores (`rbx == 0`) at `0x1C0007ECD`–`0x1C0007F04`, then releases the lock at `0x1C0007F88`. There is no `memset`; there are seven pointers, not eight.

Every consumer reads its routine pointer under `KsrpLoaderInterfaceLock` **shared**, NULL-checks it, and invokes it through `__guard_dispatch_icall_fptr` **while still holding the shared lock**, releasing only after the call returns. Because shared and exclusive acquisitions of the same pushlock are mutually exclusive, the exclusive unregister path cannot clear a pointer between a consumer's read and its call. There is no read-then-release-then-call window, so no TOCTOU race exists in the unpatched build. A cleared pointer is also handled: each consumer NULL-checks and takes an error/fallback path rather than dereferencing NULL.

**What the patch changes (and why it is not a security fix):**
The patched consumers no longer hold the pushlock across the callback. They call `KsrpAcquireLoaderInterfaceReference` (which takes the shared lock, `lock inc KsrpLoaderInterfaceRefCount`, releases the lock), invoke the callback with **no lock held**, then call `KsrpReleaseLoaderInterfaceReference`. The register/unregister path now drains this counter first: it spins acquiring the exclusive lock, and while `KsrpLoaderInterfaceRefCount != 0` it releases the lock and blocks in `ExBlockOnAddressPushLock` (`0x14000B134`) on `KsrpLoaderInterfaceEvent`/`KsrpLoaderInterfaceRefCount` before modifying the table. The unregister path also installs concrete default handlers (`KsrDbPersistPagesWithMetadata`, `KsrDbPersistMemoryPartition`, ... at `0x14000B2D4`–`0x14000B34C`) instead of clearing the pointers.

This is a different concurrency strategy for the same safety property, not a fix for an exploitable defect. The unpatched lock-across-callback model was already safe; the patched model exists to avoid holding a pushlock across the callback (the table was also expanded — the accepted structure size check rises from `0x58` to `0x88` and additional function pointers are stored at `[rdi+58]`..`[rdi+78]` and `[rdi+80]`).

### Item 2: MDL allocation in `KsrMmAllocatePagesForMdlEx`
- **Severity:** None (no security impact)
- **Nature:** Allocator API modernization + new large-page feature
- **Affected Function:** `KsrMmAllocatePagesForMdlEx` (unpatched @ `0x1C0008AB0`, patched @ `0x14000BF10`)

**What actually changed:**
The MDL size arithmetic is byte-for-byte the same in both builds: `r15 = TotalBytes >> 0xC` then `lea edx, ds:30h[r15*8]`, i.e. `(page_count << 3) + 0x30` computed in the 32-bit register `edx`. Unpatched at `0x1C0008B7A`/`0x1C0008B84`; patched at `0x14000BFF9`/`0x14000C008`. The only allocator change is `ExAllocatePoolWithTag(PoolType=0x200, 'Boot')` at `0x1C0008B8C` becoming `ExAllocatePool2(0x42, 'Boot')` at `0x14000C010`. Because the size expression is identical, the switch to `ExAllocatePool2` does not change any overflow or truncation behaviour of the size computation. `ExAllocatePool2` is used at 46 call sites across the patched build and none in the unpatched build, which identifies this as a systematic API modernization rather than a targeted overflow fix.

The remaining patched changes are new functionality, not bounds hardening: `btr r13d, 0x1F` (`0x14000BF46`) with `test ebp, ebp` / `jns` (`0x14000BFA2`) routes a bit-31 flag straight to the tracing fallback allocator, and a 2 MB large-page path is added (`cmp rbx, 0x200000` at `0x14000BF7E`) served by the new helper `KsrpAllocateLargePagesFromMemoryRange` (`0x14000C0A8`).

---

## 3. Pseudocode Diff

### `KsrRegisterLoaderCallbacks` (unregister path)

```c
// UNPATCHED (0x1C0007EA2 onward): clears 7 pointers under the EXCLUSIVE lock.
// Consumers read+invoke under the SHARED lock, so no read/call race exists.
ExAcquirePushLockExclusiveEx(&KsrpLoaderInterfaceLock, 0);   // 0x1C0007DB3
if (arg1 == NULL) {
    if (!KsrpLoaderRegistered) KeBugCheckEx(0x70, 0x201, ...); // 0x1C0007EBE
    KsrpLoaderRegistered = 0;
    KsrpPersistMemoryWithMetadataRoutinePointer = 0;          // 0x1C0007EDA
    KsrpPersistMemoryPartitionRoutinePointer   = 0;
    KsrpClaimPersistentMemoryRoutinePointer     = 0;
    KsrpFreePersistentMemoryRoutinePointer      = 0;
    KsrpFreePersistentMemoryBlockRoutinePointer = 0;
    KsrpEnumeratePersistentMemoryRoutinePointer = 0;
    KsrpQueryMetadataRoutinePointer             = 0;          // 0x1C0007F04
    // ... page-database teardown ...
}
ExReleasePushLockExclusiveEx(&KsrpLoaderInterfaceLock, 0);   // 0x1C0007F88

// PATCHED (0x14000B080 onward): drain the reference count first,
// then install concrete default handlers instead of clearing.
while (true) {
    ExAcquirePushLockExclusiveEx(&KsrpLoaderInterfaceLock, 0);
    if (KsrpLoaderInterfaceRefCount == 0) break;
    ExReleasePushLockExclusiveEx(&KsrpLoaderInterfaceLock, 0);
    ExBlockOnAddressPushLock(&KsrpLoaderInterfaceEvent,
                             &KsrpLoaderInterfaceRefCount, ...); // 0x14000B134
}
if (arg1 == NULL) {
    KsrpPersistMemoryWithMetadataRoutinePointer = KsrDbPersistPagesWithMetadata; // 0x14000B2D4
    // ... concrete default handlers installed at 0x14000B2D4..0x14000B34C ...
}
```

### Consumer read/invoke pattern (unpatched, e.g. `KsrPersistMemoryWithMetadata`)

```c
ExAcquirePushLockSharedEx(&KsrpLoaderInterfaceLock, 0);        // 0x1C00071D5
rax = KsrpPersistMemoryWithMetadataRoutinePointer;            // 0x1C00071E1
if (rax == NULL) { status = 0xC00000BB; }                     // NULL-checked, no deref
else status = rax(...);        /* guard_dispatch_icall */    // 0x1C0007218 (lock still held)
ExReleasePushLockSharedEx(&KsrpLoaderInterfaceLock, 0);        // 0x1C0007229 (after the call)
```

### `KsrMmAllocatePagesForMdlEx` (allocation size — unchanged arithmetic)

```c
// UNPATCHED (0x1C0008B7A):
r15 = TotalBytes >> 0xC;
mdl = ExAllocatePoolWithTag(0x200, (r15 << 3) + 0x30, 'Boot');  // 0x1C0008B8C

// PATCHED (0x14000BFF9): same size expression, different allocator API.
r15 >>= 0xC;
mdl = ExAllocatePool2(0x42, (r15 << 3) + 0x30, 'Boot');         // 0x14000C010
```

---

## 4. Assembly Analysis

### `KsrRegisterLoaderCallbacks` unregister path (unpatched @ `0x1C0007ECD`)

```assembly
00000001C0007ECD  mov     cs:KsrpLoaderRegistered, bl        ; bl = 0
00000001C0007EDA  mov     cs:KsrpPersistMemoryWithMetadataRoutinePointer, rbx  ; rbx = 0
00000001C0007EE1  mov     cs:KsrpPersistMemoryPartitionRoutinePointer, rbx
00000001C0007EE8  mov     cs:KsrpClaimPersistentMemoryRoutinePointer, rbx
00000001C0007EEF  mov     cs:KsrpFreePersistentMemoryRoutinePointer, rbx
00000001C0007EF6  mov     cs:KsrpFreePersistentMemoryBlockRoutinePointer, rbx
00000001C0007EFD  mov     cs:KsrpEnumeratePersistentMemoryRoutinePointer, rbx
00000001C0007F04  mov     cs:KsrpQueryMetadataRoutinePointer, rbx
; all under KsrpLoaderInterfaceLock held exclusive (acquired 0x1C0007DB3)
```

### Consumer read/invoke ordering (unpatched @ `0x1C00071D5`)

```assembly
00000001C00071D5  call    cs:__imp_ExAcquirePushLockSharedEx
00000001C00071E1  mov     rax, cs:KsrpPersistMemoryWithMetadataRoutinePointer
00000001C00071F0  test    rax, rax
00000001C00071F3  jnz     short loc_1C00071FC        ; NULL-checked
00000001C0007218  call    cs:__guard_dispatch_icall_fptr   ; invoked while lock still held
00000001C0007229  call    cs:__imp_ExReleasePushLockSharedEx ; released only after the call
```

### `KsrMmAllocatePagesForMdlEx` allocation (unpatched @ `0x1C0008B7A`, patched @ `0x14000BFF9`)

```assembly
; UNPATCHED:
00000001C0008B7A  shr     r15, 0Ch
00000001C0008B75  mov     ecx, 200h                  ; PoolType
00000001C0008B7E  mov     r8d, 746F6F42h             ; 'Boot'
00000001C0008B84  lea     edx, ds:30h[r15*8]         ; (page_count << 3) + 0x30
00000001C0008B8C  call    cs:__imp_ExAllocatePoolWithTag

; PATCHED (same size expression at 0x14000C008):
000000014000BFF9  shr     r15, 0Ch
000000014000BFFD  mov     ecx, 42h
000000014000C002  mov     r8d, 746F6F42h             ; 'Boot'
000000014000C008  lea     edx, ds:30h[r15*8]         ; identical arithmetic
000000014000C010  call    cs:__imp_ExAllocatePool2
```

---

## 5. Reachability and Impact

- The loader-callback interface is a kernel-to-kernel Soft Restart interface. In the unpatched build the read-and-invoke sequence runs entirely under the shared pushlock and the teardown runs under the exclusive pushlock, so the pointer cannot be cleared mid-use. A cleared pointer is NULL-checked by every consumer, so there is no NULL dereference either. No attacker-reachable primitive is present or removed.
- `KsrMmAllocatePagesForMdlEx` computes its MDL size identically in both builds; the allocator swap does not alter that arithmetic. The physical page-fill loop only writes as many PFN entries as pages are actually available from the reserve, so the size expression is not turned into an out-of-bounds write. No attacker-reachable primitive is present or removed.

---

## 6. Exploit Primitive

None identified. Neither change corresponds to a demonstrable, reachable memory-safety defect in the unpatched build, so no exploit primitive is described.

---

## 7. Verification Notes

- The unpatched unregister path clears the routine pointers with individual stores under the exclusive `KsrpLoaderInterfaceLock`; consumers read and invoke under the shared form of the same lock and release only after the call returns (`call` at `0x1C0007218` precedes `ExReleasePushLockSharedEx` at `0x1C0007229`, and the same ordering holds for the other six consumers). Because the two lock modes are mutually exclusive, the suspected read/clear/call race window does not exist.
- The patched build replaces the lock-across-callback pattern with `KsrpAcquireLoaderInterfaceReference` / `KsrpReleaseLoaderInterfaceReference` around each invocation and drains `KsrpLoaderInterfaceRefCount` via `ExBlockOnAddressPushLock` before modifying the table. This preserves the existing safety property under a different strategy.
- The `KsrMmAllocatePagesForMdlEx` size expression `lea edx, ds:30h[r15*8]` is identical in both builds; only the allocator API differs. `ExAllocatePool2` is used at 46 sites across the patched build (0 in the unpatched build), consistent with a driver-wide modernization.

---

## 8. Changed Functions — Full Triage

- **`KsrRegisterLoaderCallbacks`**: Not security-relevant. Locking refactor from lock-across-callback to a reference-count drain (`ExBlockOnAddressPushLock` on `KsrpLoaderInterfaceRefCount`); default handlers installed on unregister instead of clearing; callback table expanded (structure size check `0x58` → `0x88`). Both builds are safe against the pointer read/clear/call race.
- **`KsrMmAllocatePagesForMdlEx`**: Not security-relevant. `ExAllocatePoolWithTag` → `ExAllocatePool2` with an identical size expression; added bit-31 flag routing and 2 MB large-page support (`KsrpAllocateLargePagesFromMemoryRange`).
- **`KsrpMmReplenishPages`** (unpatched @ `0x1C0008574`): Behavioral. Adjusted reserve-replenishment starting physical addresses and migrated allocations to `ExAllocatePool2`. Affects which physical pages populate the reserve; no attacker-reachable memory-safety impact.
- **`KsrMmFreePagesFromMdl`**: Behavioral. Added large-page (MDL flag `0xB`) handling via `MmFreeMemoryRanges`; locking moved to helper functions.
- **`KsrConnectSecureLoader`**: Behavioral. Unified the MDL unlock/cleanup path and migrated to `ExAllocatePool2`. Single-page MDL pointer computation is correct in both builds.
- **`KsrQueryMetadata`**: Behavioral. Rewritten to use the reference-count helpers; added a flag-bit check before the metadata helper.
- **`KsrPersistMemoryPartition`**: Behavioral. Locking moved to helpers; migrated to `ExAllocatePool2`.
- **`KsrCleanupPageDatabase`**: Behavioral. Pushlock use moved to helpers; added a flag check before `ExNotifyCallback`.
- **`KsrClaimPersistedMemory`**: Behavioral. Reference-count helpers; added parameter validation rejecting `arg5` values with any bit other than bit 0 set (`test ebp, 0xFFFFFFFE` at `0x14000A18E`). Defensive contract check, not a memory-safety fix.
- **`sub_1c0001010` (bitmap operation)**: Cosmetic. Register-allocation and code-generation differences only.

---

## 9. Unmatched Functions
- **Removed:** None.
- **Added:** None.
- All matched functions were correlated by content; modifications were applied in place.

---

## 10. Confidence & Caveats
- **Confidence:** High that neither suspected pattern is a delivered security fix. The unpatched consumers invoke callbacks while holding the shared pushlock across all seven consumers, so the read/clear/call race is not present; and the MDL size arithmetic is byte-identical across builds, so the `ExAllocatePool2` migration does not alter overflow behaviour.
- **Caveat:** `KsrMmAllocatePagesForMdlEx` is a kernel-internal Soft Restart allocator; its arguments originate from the secure kernel / loader path, not from a user-mode IOCTL surface in this driver. A reviewer wishing to bound the `TotalBytes` argument can trace cross-references from `securekernel.exe` / `ntoskrnl.exe`, but the arithmetic itself is unchanged by this patch.
