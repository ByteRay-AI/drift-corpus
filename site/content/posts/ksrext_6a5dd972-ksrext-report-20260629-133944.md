Title: ksrext.sys — No security-relevant change (KSR persistence-subsystem feature expansion, no reachable vulnerability)
Date: 2026-06-29
Slug: ksrext_6a5dd972-ksrext-report-20260629-133944
Category: Corpus
Author: Argus
Summary: KB5075912
Severity: None
KBDate: 2026-02-10

## 1. Overview

- **Unpatched Binary:** `ksrext_unpatched.sys`
- **Patched Binary:** `ksrext_patched.sys`
- **Overall Similarity Score:** 0.4998
- **Diff Statistics (matcher-reported):**
  - Matched Functions: 149
  - Changed Functions: 74
  - Identical Functions: 75
  - Unmatched (Unpatched): 0
  - Unmatched (Patched): 0
- **Verified function counts:** the unpatched image defines 151 functions; the patched image defines 259. The patched build adds roughly 108 new functions. The matcher's "unmatched = 0" is an artifact of address-based folding; many new patched functions were matched onto reused unpatched addresses.
- **Verdict:** The patch is a **feature expansion** of the Kernel Soft Restart (KSR) memory-partition persistence subsystem, plus pool-API modernization. The patched build adds an entire persist/unpersist/reference-counted partition lifecycle (`KsrUnpersistMemoryPartition`, `KsrpAddPartitionToList`, and dozens of new `KsrDb*`, `KsrDbp*`, and `KsrPd*` routines). `KsrPersistMemoryPartition` was reworked to hold an exclusive lock across the check-and-insert and to take an explicit object reference so the new unpersist path can remove list entries safely. Neither build exposes any user-mode attack surface (no device object, no IOCTL dispatch, no symbolic link in either image), and no demonstrable attacker-reachable memory-safety vulnerability is present in the unpatched build or fixed by the patch. The three originally-suspected findings do not hold up against the binaries.

## 2. Vulnerability Summary

### Finding 1: KsrPersistMemoryPartition lock and object-reference rework
- **Severity:** None (object-lifetime/lock hardening accompanying a feature addition; no reachable primitive)
- **Vulnerability Class:** No security-relevant change (originally suspected CWE-367 / CWE-911 / CWE-404)
- **Affected Function:** `KsrPersistMemoryPartition` (unpatched `0x1C0008780`, patched `0x14000A820`)
- **What actually changed:**
  - **Locking:** the unpatched build acquires `ExAcquirePushLockSharedEx` on `KsrpPdDatabaseLock` (`0x1C0008856`) only to walk `KsrpMemoryPartitionList` and test whether the partition is already present, then releases it with `ExReleasePushLockSharedEx` (`0x1C000888D`) before doing the persist work. The patched build acquires `ExAcquirePushLockExclusiveEx` on `KsrpPartitionLock` (`0x14000A8EA`) and holds it across the check, the persist call, and the new `KsrpAddPartitionToList` insertion, releasing it only at `0x14000AB32`.
  - **Object reference:** the patched build adds `ObReferenceObjectByHandle(Handle, 2, PsPartitionType, KernelMode, &Object, NULL)` at `0x14000A98D` and performs the subsequent `ObQueryNameString` / `ObGetObjectSecurity` / `KsrpQueryMemoryRuns` / `KsrpQueryIoSpaceRuns` calls on that referenced object, later releasing it with `ObfDereferenceObjectWithTag` (`0x14000AB64`). The unpatched build performs the same calls using the caller-supplied object pointer (`r12`), which is kept alive for the duration of the work by the handle opened via `ObOpenObjectByPointerWithTag` (`0x1C00088DA`).
  - **List insertion:** the patched build inserts the partition explicitly via the new `KsrpAddPartitionToList` (`0x14000AB0A`) under the exclusive lock; the unpatched build has no such helper (insertion is performed by the persist routine reached through `KsrpPersistMemoryPartitionRoutinePointer`).
  - **Pool API:** `ExAllocatePoolWithTag` (`0x1C0008948`) is replaced by `ExAllocatePool2(0x102, ...)` (`0x14000A9FF`).
- **Why this is not a delivered vulnerability fix:**
  - **No "handle leak."** On the success path the unpatched build does not close the handle because it stores that handle into the persisted-partition record (handle from `var_148` copied to the record field `var_E8` at `0x1C0008A01`) and hands the record to the persist routine. The handle is transferred to the persistence record, not leaked. On the error path it is closed via `ZwClose` (`0x1C0008A83`). The patched build follows the same ownership model: on success the handle and the extra reference are transferred to the list by `KsrpAddPartitionToList` and the local copies are cleared (`0x14000AB15`, `0x14000AB1B`) so the cleanup skips them; on failure both are released.
  - **No reachable use-after-free.** The unpatched build contains no unpersist path (see Finding 3): the partition list is only built up, never torn down by an attacker-reachable operation, so the "free side" of the race the patch guards against does not exist in the unpatched image. During the persist work the object is referenced by the open handle, and the caller owns the object it passes in.
  - **No user-mode reachability.** Neither build creates a device object, registers an IOCTL/IRP dispatch, or exposes a symbolic link. `KsrPersistMemoryPartition` is KSR infrastructure invoked by the kernel during soft restart / servicing, not from an unprivileged context.
- **Assessment:** the exclusive lock and the explicit object reference are lifetime and concurrency hardening introduced to support the new persist/unpersist lifecycle. The direction is toward stricter locking, but there is no demonstrable, attacker-reachable vulnerability in the unpatched build that this remediates.

### Finding 2: KsrQueryPersistedMemoryPartition lock relaxation
- **Severity:** None
- **Vulnerability Class:** No security-relevant change (originally suspected CWE-911 / CWE-416)
- **Affected Function:** `KsrQueryPersistedMemoryPartition` (unpatched `0x1C0008BC0`, patched `0x14000AEE0`)
- **What actually changed:** the reference count is present in **both** builds. The unpatched function calls `ObfReferenceObject` on the located partition object at `0x1C0008C46` before returning it; the patched function calls the same `ObfReferenceObject` at `0x14000AF8D`. The only difference is the lock strength: the unpatched build takes `ExAcquirePushLockExclusiveEx` on `KsrpPdDatabaseLock` (`0x1C0008BF7`) for this read-only lookup, while the patched build takes `ExAcquirePushLockSharedEx` on `KsrpPartitionLock` (`0x14000AF0F`). This is a **relaxation** of the lock (shared readers now allowed), which is safe precisely because the returned object is reference-counted in both builds. There is no added or removed reference and no lifetime fix.

### Finding 3: KsrUnpersistMemoryPartition is new functionality, not a fixed function
- **Severity:** None
- **Vulnerability Class:** No security-relevant change (new feature; original CWE-404 / CWE-367 attribution was to the wrong function)
- **Affected Function:** `KsrUnpersistMemoryPartition` (patched `0x14000B450`) — **has no unpatched counterpart.** The unpatched image contains no unpersist function of any kind. Address `0x1C000B094`, previously attributed to unpersist, is actually `KsrpRestoreMemoryPartition`, an unrelated restore-path routine; the low-similarity "match" between it and the patched unpersist is an address-reuse artifact, not the same function. Because the unpersist capability did not exist in the unpatched build, there is no prior code with a lifetime or cleanup defect for the patch to remediate; the function is newly added feature code.

## 3. Code Behavior: Unpatched vs Patched `KsrPersistMemoryPartition`

The following describes the real control flow of both builds (no reconstructed pseudocode).

**Unpatched (`0x1C0008780`):**
1. `KeEnterCriticalRegion`, then `KsrpAcquireLoaderInterfaceReference`.
2. If `KsrpPersistMemoryPartitionRoutinePointer` is null, return `0xC00000BB`.
3. Acquire **shared** `KsrpPdDatabaseLock`; walk `KsrpMemoryPartitionList` testing `list_entry+0x10 == arg2` (`0x1C0008872`); release the shared lock (`0x1C000888D`).
4. If already present, return `STATUS_SUCCESS`.
5. Lock-free: `ObOpenObjectByPointerWithTag(arg2)` (handle → `var_148`), `ObQueryNameString(arg2)`, `ObGetObjectSecurity(arg2)`, `KsrpQueryMemoryRuns(arg2)`, `KsrpQueryIoSpaceRuns(arg2)`, then the persist call via `KsrpPersistMemoryPartitionRoutinePointer` with the handle embedded in the record (`var_E8`).
6. On error only, close the handle with `ZwClose` (`0x1C0008A83`); on success the handle is owned by the persisted record.

**Patched (`0x14000A820`):**
1. `KeEnterCriticalRegion`, then `KsrpAcquireLoaderInterfaceReference`.
2. Acquire **exclusive** `KsrpPartitionLock` (`0x14000A8EA`) and hold it throughout.
3. Walk `KsrpMemoryPartitionList` testing `list_entry+0x10 == arg2` (`0x14000A906`); if present, return `STATUS_SUCCESS`.
4. `ObOpenObjectByPointerWithTag(arg2)` then `ObReferenceObjectByHandle(...)` (`0x14000A98D`) to obtain a separately referenced object; perform `ObQueryNameString` / `ObGetObjectSecurity` / `KsrpQueryMemoryRuns` / `KsrpQueryIoSpaceRuns` on the referenced object.
5. Persist via `KsrpPersistMemoryPartitionRoutinePointer`, then insert with `KsrpAddPartitionToList` (`0x14000AB0A`); on full success clear the local handle and reference so cleanup skips them.
6. Release the exclusive lock (`0x14000AB32`); `ObfDereferenceObjectWithTag` / `ZwClose` any references not transferred to the list.

## 4. Assembly Evidence

Unpatched `KsrPersistMemoryPartition`:

```assembly
; --- shared-lock acquisition for the 'already persisted?' check ---
00000001C000884D  lea     rcx, KsrpPdDatabaseLock
00000001C0008856  call    cs:__imp_ExAcquirePushLockSharedEx
; --- list walk: compare list_entry+0x10 with arg2 (r12) ---
00000001C0008872  cmp     [rax+10h], r12
00000001C0008876  jz      short loc_1C0008882
; --- shared-lock release (matched acquire/release) before persist work ---
00000001C0008886  lea     rcx, KsrpPdDatabaseLock
00000001C000888D  call    cs:__imp_ExReleasePushLockSharedEx
; --- object opened; handle referenced object for the duration of the work ---
00000001C00088DA  call    cs:__imp_ObOpenObjectByPointerWithTag
00000001C000890A  call    cs:__imp_ObQueryNameString
00000001C0008980  call    cs:__imp_ObGetObjectSecurity
00000001C00089A2  call    KsrpQueryMemoryRuns
00000001C00089BD  call    KsrpQueryIoSpaceRuns
; --- handle transferred into the persisted record on success (var_148 -> var_E8) ---
00000001C00089E9  mov     rax, [rbp+0E0h+var_148]
00000001C0008A01  mov     [rbp+0E0h+var_E8], rax
; --- handle closed only on the error path ---
00000001C0008A76  test    ebx, ebx
00000001C0008A78  jns     short loc_1C0008A8F   ; success: handle already owned by record
00000001C0008A83  call    cs:__imp_ZwClose      ; error path only
```

Patched `KsrPersistMemoryPartition`:

```assembly
; --- exclusive lock held across check + insert ---
000000014000A8E3  lea     rcx, KsrpPartitionLock
000000014000A8EA  call    cs:__imp_ExAcquirePushLockExclusiveEx
000000014000A906  cmp     [rax+10h], rbx
; --- added: reference the object via the opened handle ---
000000014000A94F  call    cs:__imp_ObOpenObjectByPointerWithTag
000000014000A98D  call    cs:__imp_ObReferenceObjectByHandle
; --- work performed on the referenced object (rsi) ---
000000014000A9C1  call    cs:__imp_ObQueryNameString
000000014000AA3E  call    cs:__imp_ObGetObjectSecurity
000000014000AA61  call    KsrpQueryMemoryRuns
000000014000AA7C  call    KsrpQueryIoSpaceRuns
; --- explicit list insertion under the lock ---
000000014000AB0A  call    KsrpAddPartitionToList
000000014000AB32  call    cs:__imp_ExReleasePushLockExclusiveEx
000000014000AB64  call    cs:__imp_ObfDereferenceObjectWithTag
000000014000AB7A  call    cs:__imp_ZwClose
```

## 5. Reachability

`KsrPersistMemoryPartition`, `KsrQueryPersistedMemoryPartition`, and the new `KsrUnpersistMemoryPartition` are KSR (Kernel Soft Restart) infrastructure functions. Neither the unpatched nor the patched image creates a device object, registers an IRP/IOCTL dispatch, or exposes a symbolic link (no `IoCreateDevice`, `IRP_MJ*`, or `IoCreateSymbolicLink` references in either build). These routines are invoked by the kernel's soft-restart/servicing path, not from an unprivileged user-mode context. There is no demonstrated local trigger.

## 6. Exploit Primitive

No exploit primitive is demonstrable. The suspected use-after-free requires a "free side" (unpersist) that does not exist in the unpatched build; the object used during persist is referenced by the open handle; the suspected handle leak is an ownership transfer into the persisted-partition record; and there is no user-mode reachable entry point. No memory-corruption, information-disclosure, or denial-of-service primitive is supported by the binaries.

## 7. Debugger Notes

For anyone stepping the unpatched persist path in a kernel debugger:

- `ksrext!KsrPersistMemoryPartition` (`0x1C0008780`): entry; `rdx` holds the partition object pointer (`arg2`).
- `0x1C0008856`: `ExAcquirePushLockSharedEx` on `KsrpPdDatabaseLock` — shared lock for the list-presence check only.
- `0x1C000888D`: `ExReleasePushLockSharedEx` — matched release of the shared lock.
- `0x1C00088DA`: `ObOpenObjectByPointerWithTag` — opens the handle that references the object for the duration of the work.
- `0x1C0008A01`: the opened handle (`var_148`) is copied into the persisted record (`var_E8`), showing ownership transfer.
- `0x1C0008A78`/`0x1C0008A83`: `jns` skips `ZwClose` on success because the handle is owned by the record; `ZwClose` runs only on error.

Comparable patched call sites: exclusive lock `0x14000A8EA`, added `ObReferenceObjectByHandle` `0x14000A98D`, `KsrpAddPartitionToList` `0x14000AB0A`, exclusive release `0x14000AB32`.

## 8. Changed Functions — Full Triage

- **KsrPersistMemoryPartition (0x1C0008780 → 0x14000A820):** No security-relevant change. Shared `KsrpPdDatabaseLock` (released before work) reworked to exclusive `KsrpPartitionLock` held across check-and-insert; added `ObReferenceObjectByHandle`; added explicit `KsrpAddPartitionToList`; `ExAllocatePoolWithTag`→`ExAllocatePool2`. Lifetime/concurrency hardening supporting the new unpersist lifecycle, no reachable primitive. The handle is transferred to the persisted record on success in both builds (not leaked).
- **KsrQueryPersistedMemoryPartition (0x1C0008BC0 → 0x14000AEE0):** No security-relevant change. `ObfReferenceObject` present in both builds; only the lock is relaxed from exclusive to shared for read concurrency.
- **KsrUnpersistMemoryPartition (patched 0x14000B450):** New feature; no unpatched counterpart. The previously-cited `0x1C000B094` is `KsrpRestoreMemoryPartition`, an unrelated function.
- **KsrRegisterLoaderCallbacks:** Behavioral. Callback-registration structure and initialization/cleanup paths refactored; indirect (global function pointer) calls replaced with direct calls.
- **KsrClaimPersistedMemory (0x1C0008D90 → 0x14000A130):** Behavioral. `ExAllocatePoolWithTag`→`ExAllocatePool2`, `ExFreePoolWithTag`→`ExFreePool`, indirect→direct calls, relocated flag globals.
- **KsrpRestoreMemoryPartition / restore worker family:** Behavioral. Heavy restructuring; the patched build adds registry-query and NUMA-node-aware thread handling and additional restore worker routines.
- **KsrPdRetrieveMemoryRegion (0x1C000CD34) / KsrpPdBlockIdToKeyValueEntry (0x1C000CC94):** Behavioral, not security-relevant. The patched build moves a bounds check inline; the unpatched caller already performs the equivalent check before the call, so this is defense-in-depth, not a fix for an exploitable gap.
- **Cosmetic / library / compiler updates:** `KsrMmAllocateNumaPagesForMdlEx`, `KsrQueryMetadata`, `KsrFreePersistedMemory` / `KsrFreePersistedMemoryBlock`, `KsrConnectSecureLoader`, `KsrInitPageDatabase`, `KsrCleanupPageDatabase`, `KsrMdlToMemoryRuns`, `KsrMmAllocatePagesForMdlEx`, `KsrMmFreePagesFromMdl`, and others: low-severity changes from indirect→direct call conversion, `ExAllocatePoolWithTag`→`ExAllocatePool2` migration, relocated global data, and register reallocation.

## 9. New Functionality (not present in the unpatched build)

The patched image adds roughly 108 functions the unpatched image does not contain, forming a new persist/unpersist/query/database API surface: `KsrUnpersistMemoryPartition`, `KsrpAddPartitionToList`, and the `KsrDbp*` (`KsrDbpPersistMemoryPartition`, `KsrDbpUnpersistMemoryPartition`, `KsrDbpQueryPersistedMemoryPartitions`, …), `KsrDb*`, and `KsrPd*` (`KsrPdPersistMemoryPartition`, `KsrPdUnpersistMemoryPartition`, …) families, plus additional restore workers. This is the substance of the change: a feature expansion of the KSR persistence subsystem.

## 10. Confidence & Caveats

- **Confidence Level:** High. Both builds were read at the instruction level. The query function's `ObfReferenceObject` is present in both; the "handle leak" is a verified ownership transfer; the unpersist function is new; and neither build exposes a user-mode dispatch surface.
- **Assessment:** No security-relevant change. The patch is a KSR persistence-subsystem feature expansion plus pool-API modernization. The locking and object-reference changes in `KsrPersistMemoryPartition` are hardening introduced to support the new lifecycle, not a remediation of a demonstrable, attacker-reachable vulnerability in the unpatched build.
