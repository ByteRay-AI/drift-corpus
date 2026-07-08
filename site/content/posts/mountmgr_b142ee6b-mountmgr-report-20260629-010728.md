Title: mountmgr.sys — device-characteristic gate added to remote-database reconciliation
Date: 2026-06-29
Slug: mountmgr_b142ee6b-mountmgr-report-20260629-010728
Category: Corpus
Author: Argus
Summary: KB5087545
Severity: Unknown
KBDate: 2026-05-12

## 1. Overview

- **Unpatched Binary:** `mountmgr_unpatched.sys`
- **Patched Binary:** `mountmgr_patched.sys`
- **Overall Similarity Score:** 0.9587
- **Verdict:** The patch adds a second device-property test before the mount manager queues its "reconcile the on-disk mount-point database with master" work item, and adds the same test to the work-item callback. The tested byte is a *static device characteristic* latched once when the device is first examined, not a dynamic teardown flag, so the change is a behavioral filter that excludes one class of device from database reconciliation and volume onlining. It is **not** a use-after-free fix and does not create or remove any memory-safety primitive. Two unrelated changes are bundled in the same build: `GlobalCreateSymbolicLink` was switched from `IoCreateSymbolicLink` to `IoCreateSymbolicLink2`, and `QueryDeviceSortOrderInternal`'s device-signature comparison table was updated.

## 2. Change Summary

**Severity:** None (no demonstrable security impact)
**Vulnerability Class:** N/A — behavioral change
**Affected Functions:** `ReconcileThisDatabaseWithMaster` (work-item queue routine, `0x1C0016FBC` unpatched / `0x1C0016FFC` patched) and `ReconcileThisDatabaseWithMasterWorker` (its callback, `0x1C00170E0` unpatched / `0x1C0017130` patched).

**What actually changed:**
`ReconcileThisDatabaseWithMaster` receives a device extension (`rcx`) and a per-device volume entry (`rdx`). Before it allocates a work-item context and queues `ReconcileThisDatabaseWithMasterWorker`, it tests a flag byte in the entry. In the unpatched build it tests only the byte at offset `0x7c`; the patched build additionally tests the byte at offset `0x7d` and bails out if either is non-zero.

Both bytes are set once, in `QueryDeviceInformation` (`0x1C00157D0` unpatched / `0x1C00157F8` patched), directly from the target device object's `Characteristics` field:
- `0x7c` = `Characteristics & 1` (FILE_REMOVABLE_MEDIA). Present in both builds.
- `0x7d` = `BYTE2(Characteristics) & 1` (bit `0x10000` of `Characteristics`). This field is **new** in the patched build.

Because `0x7d` is derived from a device characteristic latched at device-examination time and never mutated afterward, checking it cannot guard against a concurrent free/teardown. The patch simply skips remote-database reconciliation (and the subsequent `OnlineMountedVolumes` call) for devices that have this characteristic bit set.

**No race / no use-after-free:** the work-item callback already re-validates the entry under the device mutex before touching it. `ReconcileThisDatabaseWithMasterWorker` acquires the mutex at `Context+56` (`KeWaitForSingleObject`) and calls `MntMgrFindDevice` (`0x1C000E1A4`), which walks the device list at `Context+16` and returns the entry only if it is still linked, comparing node pointers without dereferencing the candidate. If the entry has been unlinked (and freed), the lookup returns the list head and the callback releases the mutex and exits without dereferencing it. This re-lookup, plus the pre-existing `0x7c` bail-out inside the callback, is present and behaviorally identical in **both** builds; it is the actual protection against a stale entry pointer, and the patch did not add or change it.

## 3. Pseudocode Diff

```c
// UNPATCHED ReconcileThisDatabaseWithMaster @ 0x1C0016FBC
void ReconcileThisDatabaseWithMaster(PDEVICE_OBJECT *Context, __int64 a2) {
    if ( *(BYTE*)(a2 + 0x7c) == 0 ) {                 // skip removable media
        _QWORD *ctx = ExAllocatePoolWithTag(NonPagedPoolNx, 0x38, 'MntA');
        if (ctx) {
            ctx[2] = IoAllocateWorkItem(*Context);
            if (ctx[2]) {
                ctx[6] = a2;                           // raw entry pointer into work-item ctx
                ctx[3] = ReconcileThisDatabaseWithMasterWorker;
                ctx[5] = Context;
                QueueWorkItem(Context, ctx, ctx + 5);
                if ( ... ) OnlineMountedVolumes(Context, a2);
            }
        }
    }
}

// PATCHED ReconcileThisDatabaseWithMaster @ 0x1C0016FFC
void ReconcileThisDatabaseWithMaster(PDEVICE_OBJECT *Context, __int64 a2) {
    if ( *(WORD*)(a2 + 0x7c) == 0 ) {                 // skip if 0x7c OR new 0x7d byte set
        // ... identical body ...
    }
}
```

The two byte compares are emitted separately in assembly (see Section 4); the decompiler folds them into a single 16-bit compare of the two adjacent bytes `0x7c`/`0x7d`.

## 4. Assembly Analysis

```assembly
--- UNPATCHED ReconcileThisDatabaseWithMaster @ 0x1C0016FBC ---
00000001C0016FBC  mov     [rsp+arg_0], rbx
00000001C0016FC1  mov     [rsp+arg_8], rsi
00000001C0016FC6  push    rdi
00000001C0016FC7  sub     rsp, 20h
00000001C0016FCB  cmp     byte ptr [rdx+7Ch], 0      ; only the removable-media byte is tested
00000001C0016FCF  mov     rsi, rdx
00000001C0016FD2  mov     rbx, rcx
00000001C0016FD5  jnz     loc_1C00170C5             ; if 0x7c != 0, go to epilogue
00000001C0016FDB  mov     edx, 38h                  ; work-item context size (0x38)
00000001C0016FE0  mov     ecx, 200h                 ; NonPagedPoolNx
00000001C0016FE5  mov     r8d, 41746E4Dh            ; tag 'MntA'
00000001C0016FEB  call    cs:__imp_ExAllocatePoolWithTag
...
00000001C001707E  lea     rax, ReconcileThisDatabaseWithMasterWorker
00000001C0017085  mov     [rdi+30h], rsi            ; store entry pointer into work-item context
00000001C001708D  mov     [rdi+18h], rax            ; store callback
00000001C001709A  call    QueueWorkItem

--- PATCHED ReconcileThisDatabaseWithMaster @ 0x1C0016FFC ---
00000001C0016FFC  mov     [rsp+arg_0], rbx
00000001C0017001  mov     [rsp+arg_8], rsi
00000001C0017006  push    rdi
00000001C0017007  sub     rsp, 20h
00000001C001700B  cmp     byte ptr [rdx+7Ch], 0      ; removable-media byte
00000001C001700F  mov     rsi, rdx
00000001C0017012  mov     rbx, rcx
00000001C0017015  jnz     loc_1C001710F
00000001C001701B  cmp     byte ptr [rdx+7Dh], 0      ; NEW: the added device-characteristic byte
00000001C001701F  jnz     loc_1C001710F             ; if either byte != 0, go to epilogue
00000001C0017025  mov     edx, 38h                  ; identical allocation and queue path below
00000001C001702A  mov     ecx, 200h
00000001C001702F  mov     r8d, 41746E4Dh
00000001C0017035  call    cs:__imp_ExAllocatePoolWithTag
```

The only functional delta is the added `cmp byte ptr [rdx+7Dh], 0` / `jnz` pair at `0x1C001701B`. The `0x38`-byte `NonPagedPoolNx` `'MntA'` allocation is the *work-item context* structure, not the volume entry; the volume entry (`rdx`/`rsi`) is allocated elsewhere and only its address is stored into the context.

The new byte at offset `0x7d` is written in `QueryDeviceInformation`:

```assembly
--- PATCHED QueryDeviceInformation @ 0x1C00157F8 (decompiled) ---
*(_BYTE *)(a2 + 124) = v4->Characteristics & 1;          // 0x7c, unchanged
*(_BYTE *)(a2 + 125) = BYTE2(v4->Characteristics) & 1;   // 0x7d, NEW field (Characteristics bit 0x10000)
```

Inserting this byte shifted the fields that previously followed it up by one (e.g. the nested-virtual-disk word `257` moved from offset `0x7d` to `0x7e`), which is why roughly two dozen functions show a mechanical `+1` offset shift with no behavioral change.

## 5. Trigger Conditions

Not applicable. There is no vulnerable condition to trigger. The added check gates a benign background reconciliation work item on a static device property; no attacker-controlled input reaches an unsafe operation as a result of the difference between the two builds.

## 6. Exploit Primitive & Development Notes

None. The change does not free memory, does not extend a lifetime past a free, and does not relax any bound, lock, or access check. The work-item callback re-looks-up the volume entry under the device mutex before use in both builds, so no stale-pointer primitive exists in either build along this path.

## 7. Debugger PoC Playbook

Not applicable — there is no vulnerability to reproduce. For anyone confirming the behavioral difference, the observable delta is only that in the patched build `ReconcileThisDatabaseWithMaster` returns early (no work item queued, no `OnlineMountedVolumes` call) for devices whose target device object `Characteristics` has bit `0x10000` set.

## 8. Changed Functions — Full Triage

The two builds share 156 named functions; the patched build additionally contains four compiler/CFG helper stubs (`__cpu_features_init`, `_guard_xfg_dispatch_icall_nop`, `__memset_query`, `__memset_repmovs`) that are build-tooling artifacts, not code changes.

Functions with a genuine (non-noise) delta:

- **`ReconcileThisDatabaseWithMaster`** (`0x1C0016FBC` → `0x1C0016FFC`): added the `0x7d` device-characteristic test before queuing the reconcile work item (and before the guarded `OnlineMountedVolumes` call). Behavioral filter, not a security fix.
- **`ReconcileThisDatabaseWithMasterWorker`** (`0x1C00170E0` → `0x1C0017130`): the callback's early bail-out condition gained the same `0x7d` test alongside the existing `MntMgrFindDevice` re-lookup and `0x7c` test. Behavioral filter.
- **`QueryDeviceInformation`** (`0x1C00157D0` → `0x1C00157F8`): initializes the new `0x7d` byte from `BYTE2(Characteristics) & 1`. Supporting field initialization.
- **`MountMgrDriverReinitialization`** (`0x1C000F2D0` → `0x1C000F350`): a caller-side `0x7c` guard was removed and the equivalent test relocated into the callee. Refactor; behavior preserved.
- **`OnlineMountedVolumes`** (`0x1C0014C24` → `0x1C0014C1C`): its internal early-return `0x7c` guard was removed; callers now perform the equivalent gate before invoking it. Refactor; behavior preserved.
- **`GlobalCreateSymbolicLink`** (`0x1C000DDC0` → `0x1C000DE30`): switched from `IoCreateSymbolicLink(&SymbolicLinkName, a2)` to `IoCreateSymbolicLink2(...)` with an inline flags/target structure. API modernization; the flag semantics are not determinable from the binary, and no relaxation of behavior is evident.
- **`QueryDeviceSortOrderInternal`** (`0x1C0015B44` → `0x1C0015B78`): several 128-bit device-signature GUID entries in its comparison table were added/removed. Device-compatibility data update, not memory safety.

All remaining differences between the builds are relocation noise: changed call-target and global-data addresses, WPP tracing identifiers, decompiler variable renumbering, and the mechanical `+1` field-offset shift caused by the inserted `0x7d` byte. Functions in this category include `MountMgrDeviceControl`, `MountMgrMountedDeviceArrival`, `MountMgrVolumeArrivalNotification`, `MountMgrVolumeRemovalNotification`, `OpenRemoteDatabase`, `QueryUniqueIdInternal`, and the many `MountMgr*`/`Query*`/`WPP_SF_*` helpers; each was inspected and shows no added or removed check, lock, bound, or lifetime change.

## 9. Unmatched Functions

No functions were removed. The patched build adds four compiler/CFG helper stubs (listed in Section 8); these are build-tooling artifacts, not new driver logic.

## 10. Confidence & Caveats

- **Confidence Level:** High that this is not a security fix. The added byte (`0x7d`) is written exactly once, in `QueryDeviceInformation`, directly from the target device object's `Characteristics` field, and is never modified afterward; a static property cannot serve as a concurrent-teardown guard. The work-item callback's mutex-protected `MntMgrFindDevice` re-lookup — the real protection against a freed entry — is present and unchanged in both builds.
- **What is verifiable:** the exact instruction added (`cmp byte ptr [rdx+7Dh], 0` at `0x1C001701B`), the source of both `0x7c` and `0x7d` in `QueryDeviceInformation`, the field-offset shift caused by the inserted byte, and the two unrelated bundled changes.
- **What is not determinable from the binary:** the precise product meaning of `Characteristics` bit `0x10000`, the semantics of the `IoCreateSymbolicLink2` flag value, and the intent behind the `QueryDeviceSortOrderInternal` table update. None of these show a security impact from the code alone, so no security claim is made about them.
