Title: mountmgr.sys — Cluster-Shared-Volume characteristic tracking field + IoCreateSymbolicLink2 modernization
Date: 2026-06-29
Slug: mountmgr_747a1dd0-mountmgr-report-20260629-011531
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Unknown
KBDate: 2026-06-09

## 1. Overview

- **Unpatched Binary:** `mountmgr_unpatched.sys`
- **Patched Binary:** `mountmgr_patched.sys`
- **Overall Similarity Score:** 0.9587
- **Diff Statistics:**
  - Matched Functions: 156
  - Changed Functions: 36
  - Identical Functions: 120
  - Unmatched (Added/Removed): 0
- **Verdict:** No security-relevant change was found. The patch adds one new byte field at offset `0x7d` in the mounted-device information structure that records whether a volume carries the `FILE_CHARACTERISTIC_CSV` (Cluster Shared Volume) characteristic, and uses that field to exclude such volumes from the remote-database reconciliation path. It also switches `GlobalCreateSymbolicLink` from `IoCreateSymbolicLink` to `IoCreateSymbolicLink2`. Neither change fixes a demonstrable memory-safety, privilege, or input-validation defect that is reachable from an attacker-controlled entry point.

---

## 2. Change Summary

### Finding 1: New CSV-characteristic field gates remote-database reconciliation
- **Severity:** Informational (no security-relevant change)
- **Class:** State-management / correctness change; not a memory-safety or access-control fix
- **Affected Functions:** `QueryDeviceInformation` (@ `0x1C00157D0` unpatched), `ReconcileThisDatabaseWithMasterWorker` (@ `0x1C00170E0` unpatched / `0x1C0017130` patched)

**What actually changed:**
1. **New byte field at offset `0x7d`.** In `QueryDeviceInformation`, the patched build adds `*(a2 + 0x7d) = BYTE2(DeviceObject->Characteristics) & 1`, i.e. it records bit `0x10000` of the device `Characteristics` (`FILE_CHARACTERISTIC_CSV`, Cluster Shared Volume). The pre-existing byte at `0x7c` continues to record bit `0x1` (`FILE_REMOVABLE_MEDIA`). Inserting this byte shifts the structure fields at offset `0x7d` and above by `+1` (e.g. the word previously written at `0x82` is written at `0x83`), which is why many functions that touch this structure show a mechanical `+1` offset change.
2. **New flag consulted before reconciliation.** In `ReconcileThisDatabaseWithMasterWorker`, the unpatched skip condition
   `if (MntMgrFindDevice(...) == listHead || *(entry + 0x7c) != 0)` gains a third term in the patched build:
   `|| *(entry + 0x7d) != 0`. When any term is true the function releases its locks and returns **without** calling `IoGetDeviceObjectPointer` and without reconciling the entry. The added term therefore causes CSV volumes to be **skipped**, not processed.

**Why this is not a security fix:**
- The direction is a *tightening of a skip/bail-out condition*: the patched build reconciles fewer entries, not more. It does not add or remove any bounds check, ACL check, or pointer validation.
- The return value of `IoGetDeviceObjectPointer` is checked identically in **both** builds (see Section 4). There is no unchecked-pointer path in either build.
- The new field is derived from a device characteristic bit reported by the storage stack, not from attacker-supplied IOCTL data.

### Finding 2: `GlobalCreateSymbolicLink` switched to `IoCreateSymbolicLink2`
- **Severity:** Informational (defense-in-depth / API modernization)
- **Affected Function:** `GlobalCreateSymbolicLink` (@ `0x1C000DDC0` unpatched / `0x1C000DE30` patched)

The unpatched build calls `IoCreateSymbolicLink(&SymbolicLinkName, TargetName)`. The patched build calls `IoCreateSymbolicLink2(&SymbolicLinkName, &params)` where `params` is a small structure whose leading dword is `1` and whose remaining 16 bytes carry the target `UNICODE_STRING`. This is an API modernization; the surrounding logic (string construction, error tracing, pool free) is unchanged. No reachable pre/post difference in what link is created or who may create it was demonstrated, so this is classified as defense-in-depth rather than a vulnerability fix.

---

## 3. Source Diff (decompilation)

`ReconcileThisDatabaseWithMasterWorker` — the added `0x7d` term in the skip condition:

```c
// === UNPATCHED (0x1C00170E0) ===
Device = MntMgrFindDevice(v1, (_QWORD *)v2);
if ( Device == v9 || *(_BYTE *)(v2 + 124) != 0 )          // 124 = 0x7c
{
    KeReleaseMutex((PRKMUTEX)(v1 + 56), 0);
    return KeReleaseSemaphore((PRKSEMAPHORE)(v1 + 112), 0, 1, 0);
}
DeviceObjectPointer = IoGetDeviceObjectPointer((PUNICODE_STRING)(v2 + 80), 0x80u, &FileObject, &DeviceObject);
if ( DeviceObjectPointer < 0 )                            // return value IS checked
    ...bail out...

// === PATCHED (0x1C0017130) ===
Device = MntMgrFindDevice(v1, (_QWORD *)v2);
if ( Device == v9 || *(_BYTE *)(v2 + 124) != 0 || *(_BYTE *)(v2 + 125) != 0 )  // added 125 = 0x7d
{
    KeReleaseMutex((PRKMUTEX)(v1 + 56), 0);
    return KeReleaseSemaphore((PRKSEMAPHORE)(v1 + 112), 0, 1, 0);
}
DeviceObjectPointer = IoGetDeviceObjectPointer((PUNICODE_STRING)(v2 + 80), 0x80u, &FileObject, &DeviceObject);
if ( DeviceObjectPointer < 0 )                            // return value IS checked (unchanged)
    ...bail out...
```

`QueryDeviceInformation` — where the `0x7d` field is populated:

```c
// === UNPATCHED (0x1C00157D0) ===
*(_BYTE *)(a2 + 124) = v4->Characteristics & 1;           // 0x7c = FILE_REMOVABLE_MEDIA bit

// === PATCHED ===
v8 = v4->Characteristics & 1;
*(_BYTE *)(a2 + 124) = v8;                                 // 0x7c unchanged
*(_BYTE *)(a2 + 125) = BYTE2(v4->Characteristics) & 1;    // 0x7d = FILE_CHARACTERISTIC_CSV (bit 0x10000)
```

`GlobalCreateSymbolicLink` — API modernization:

```c
// === UNPATCHED (0x1C000DDC0) ===
v3 = IoCreateSymbolicLink(&SymbolicLinkName, a2);

// === PATCHED (0x1C000DE30) ===
LODWORD(v10[0]) = 1;
*(_OWORD *)&v10[1] = *a2;
StringWithGlobal = IoCreateSymbolicLink2(P, v10);
```

---

## 4. Assembly Analysis

Real disassembly for the added `0x7d` gate and the return-value check in `ReconcileThisDatabaseWithMasterWorker`.

**Unpatched (`0x1C00170E0`):**

```nasm
00000001C0017216  call    MntMgrFindDevice
00000001C0017226  cmp     [r15+7Ch], al            ; only the 0x7c flag is tested
00000001C001723F  call    cs:__imp_IoGetDeviceObjectPointer
00000001C001724E  mov     esi, eax
00000001C0017250  test    eax, eax                 ; return value IS checked
00000001C0017252  jns     short loc_1C0017290      ; branch on success
```

**Patched (`0x1C0017130`):**

```nasm
00000001C0017264  call    MntMgrFindDevice
00000001C0017274  cmp     [r15+7Ch], al            ; 0x7c flag
00000001C001727E  cmp     [r15+7Dh], al            ; NEW: 0x7d (CSV) flag also tested
00000001C0017297  call    cs:__imp_IoGetDeviceObjectPointer
00000001C00172A3  mov     esi, eax
00000001C00172A5  test    eax, eax                 ; return value checked (unchanged)
00000001C00172A7  jns     short loc_1C00172E2
```

The only assembly-level difference on this path is the added `cmp [r15+7Dh], al` at `0x1C001727E`. The `test eax, eax` / `jns` pair after the call is present in **both** builds, so there is no unchecked-return-value path in either binary.

The `0x7d` field is written in `QueryDeviceInformation` at `0x1C00158D3` (`mov [rbx+7Dh], al`).

---

## 5. Trigger / Reachability

The changed reconciliation path is reachable at driver initialization and during volume arrival/removal handling, but the behavioral difference is limited to whether a Cluster-Shared-Volume device (as reported by the storage stack via `FILE_CHARACTERISTIC_CSV`) is included in remote-database reconciliation. This value is not attacker-controlled from a user-mode IOCTL, and skipping reconciliation for such volumes does not create or remove any memory-safety or access-control condition. No user-mode trigger produces a security-relevant divergence between the two builds.

---

## 6. Exploit Primitive

None. No use-after-free, uninitialized-pointer use, out-of-bounds access, or privilege boundary crossing was demonstrated in either build on the changed paths. The unpatched build validates the `IoGetDeviceObjectPointer` return value before dereferencing the returned device object, and both builds bound the mount-point buffers they process.

---

## 7. Analyst Notes

For an analyst comparing the two builds:

- `ReconcileThisDatabaseWithMasterWorker`: unpatched `0x1C00170E0`, patched `0x1C0017130`. Compare the skip condition at the `cmp [r15+7Ch]` / `cmp [r15+7Dh]` sequence just before the `IoGetDeviceObjectPointer` call.
- `QueryDeviceInformation`: unpatched `0x1C00157D0`. The store `mov [rbx+7Dh], al` at `0x1C00158D3` (patched) records the CSV characteristic bit.
- Structure fields at offset `0x7d` and above shift by `+1` between builds because of the inserted byte; a raw per-offset comparison must account for this shift.

---

## 8. Changed Functions — Triage

Out of 36 changed functions, none is a security fix. The only semantically meaningful, non-cosmetic changes are the two above; the remainder are the mechanical `+1` structure-offset shift propagated across functions that touch the mounted-device structure, WPP tracing/global-data reshuffling, and CRT/intrinsic churn (a new vectorized `memset` dispatch plus CRT helper functions `__cpu_features_init`, `__memset_query`, `__memset_repmovs`, `_guard_xfg_dispatch_icall_nop`).

### Genuinely changed logic
- **`QueryDeviceInformation` (@ `0x1C00157D0`):** Populates the new `0x7d` byte from `FILE_CHARACTERISTIC_CSV`; also keeps writing the pre-existing `0x7c` removable-media byte. Not security-relevant.
- **`ReconcileThisDatabaseWithMasterWorker` (@ `0x1C00170E0`):** Adds `|| *(entry + 0x7d)` to the reconciliation skip condition. Remote-database reconciliation, not volume-arrival processing. Not security-relevant.
- **`GlobalCreateSymbolicLink` (@ `0x1C000DDC0`):** `IoCreateSymbolicLink` -> `IoCreateSymbolicLink2`. Defense-in-depth / API modernization.
- **`MountMgrDriverReinitialization` (@ `0x1C000F2D0`):** Removes an init-time `if (byte==0)` guard before `ReconcileThisDatabaseWithMaster`; the reconcile is now always called during driver reinitialization. Reached only from the boot/reinitialization callback, not from an IOCTL. Not security-relevant.
- **`WorkerThread` (@ `0x1C0002DF0`):** Shutdown-detection loop reads a different global after data-section reorganization. Not security-relevant.

### Offset-shift / cosmetic changes
The following changed only through the `+1` structure-offset shift, register reallocation, control-flow layout, WPP tracing, or CRT churn, with no logic change: `MountMgrMountedDeviceArrival` (@ `0x1C000F7E4`), `MountMgrMountedDeviceNotification`, `MountMgrMountedDeviceRemoval`, `QueryDeviceSortOrderInternal` (@ `0x1C0015B44`, adds device type `0xEF` to a sort-order table plus `memset` size shift), `MountMgrNextDriveLetter` (bounds check `len+2 <= buflen` present in both, branch inverted), `MountMgrNotifyNameChange`, `MountMgrPrepareVolumeDelete`, `MountMgrQueryDosVolumePath`, `MountMgrQueryDosVolumePaths`, `QueryPointsFromMemory`, `QueryPointsFromSymbolicLinkName`, `MountMgrVolumeArrivalNotification`, `MountMgrVolumeMountPointChanged`, `MountMgrVolumeMountPointCreated`, `MountMgrVolumeMountPointDeleted`, `OnlineMountedVolumes`, `OpenRemoteDatabase`, `CreateRemoteDatabase`, `CreateNewDriveLetterName`, `GetDriveLayoutInternal`, `IsUniqueIdPresent`, `MountMgrCheckUnprocessedVolumes`, `MountMgrCleanup`, `MountMgrCreatePoint`, `MountMgrDeviceControl` (IOCTL dispatch), `MountMgrValidateBackPointer`, `RedirectSavedLink`, `RemoveSavedLinks`, `SendLinkDeleted`, `VerifyEpoch`, the `WPP_SF_*` tracing helpers, `WppInitKm`, `WppLoadTracingSupport`, and `memset`.

---

## 9. Unmatched Functions

- **Added:** 0 (the CRT helpers `__cpu_features_init`, `__memset_query`, `__memset_repmovs`, `_guard_xfg_dispatch_icall_nop` appear as split-outs of the rebuilt `memset`/CFG intrinsics)
- **Removed:** 0

This is a targeted in-place rebuild, not an architectural rewrite.

---

## 10. Confidence & Caveats

- **Confidence Level:** High. Both builds' decompilation and disassembly were compared directly. The `IoGetDeviceObjectPointer` return value is checked in both builds (`test eax, eax; jns` at `0x1C0017250` unpatched and `0x1C00172A5` patched), and the sole path-level difference is the added `cmp [r15+7Dh], al` CSV-flag test at `0x1C001727E`.
- **Caveat:** The `IoCreateSymbolicLink2` switch is a hardened-API adoption whose full behavioral contract is internal to `ntoskrnl`; it is reported here as defense-in-depth. No attacker-reachable difference in symbolic-link creation between the two builds was demonstrated.
