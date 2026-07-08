Title: mountmgr.sys — No security-relevant change (new device-characteristic field and reconcile gate)
Date: 2026-06-29
Slug: mountmgr_aae997a7-mountmgr-report-20260629-141300
Category: Corpus
Author: Argus
Summary: KB5082142
Severity: None

## 1. Overview

| Item | Value |
|------|-------|
| Unpatched binary | `mountmgr_unpatched.sys` |
| Patched binary | `mountmgr_patched.sys` |
| Overall similarity | **0.9587** |
| Matched functions | 156 |
| Changed | 36 |
| Identical | 120 |
| Added in patched | 4 (compiler/CRT helpers) |
| Removed | 0 |

**Verdict:** The patch adds a new one-byte field to the volume-entry structure at offset `0x7D`. That byte is populated in `QueryDeviceInformation` from a `DEVICE_OBJECT` characteristic bit, and the database-reconcile path (`ReconcileThisDatabaseWithMaster` and its work-item worker `ReconcileThisDatabaseWithMasterWorker`) now skips a volume entry when this new byte is set, in addition to the existing `0x7C` device-characteristic byte. Inserting the byte shifts several later structure fields by one byte, which is why many functions show a `+1` offset ripple. This is a behavioral/functional change that excludes an additional class of volume from the reconcile / auto-online path. No locking, allocation, free ordering, or bounds behavior changes. There is no race condition, use-after-free, or double-free introduced or removed.

---

## 2. What actually changed

### 2.1 New field at volume-entry offset `0x7D`

`QueryDeviceInformation` computes two per-device booleans from the underlying `DEVICE_OBJECT`. In both builds offset `0x7C` is set from `Characteristics & 1` (the `FILE_REMOVABLE_MEDIA` bit). The patched build adds a second byte at offset `0x7D` set from bit 16 of the same field (`Characteristics & 0x10000`, the documented `FILE_CHARACTERISTIC_CSV` cluster-shared-volume bit).

Unpatched `QueryDeviceInformation` (@ `0x1C00157D0`), decompiled:

```c
v8 = (v4->Characteristics & 1) == 0;
*(_BYTE *)(a2 + 124) = v4->Characteristics & 1;   // 0x7C  (removable-media bit)
// ... offset 0x7D is not written from a characteristic here ...
if ( *(_BYTE *)(a2 + 128) == 0 )                  // 0x80
{
    if ( FsRtlGetVirtualDiskNestingLevel(...) >= 0 && (NestingFlags & 6) != 0 )
        *(_WORD *)(a2 + 125) = 257;               // 0x7D/0x7E  (nesting marker 0x0101)
}
```

Patched `QueryDeviceInformation` (@ `0x1C00157F8`), decompiled:

```c
v8 = v4->Characteristics & 1;
*(_BYTE *)(a2 + 124) = v8;                          // 0x7C  (removable-media bit)
*(_BYTE *)(a2 + 125) = BYTE2(v4->Characteristics) & 1;  // 0x7D  NEW (Characteristics & 0x10000)
if ( v8 == 0 ) { ... *(_BYTE *)(a2 + 127) = 1; ... } // was 0x7E, now 0x7F
if ( *(_BYTE *)(a2 + 129) == 0 )                    // was 0x80, now 0x81
{
    if ( FsRtlGetVirtualDiskNestingLevel(...) >= 0 && (NestingFlags & 6) != 0 )
        *(_WORD *)(a2 + 126) = 257;                 // nesting marker, was 0x7D/0x7E, now 0x7E/0x7F
}
```

Assembly confirming the new byte (patched `QueryDeviceInformation`):

```asm
00000001C00158C5  mov     cl, [rdi+34h]        ; DEVICE_OBJECT.Characteristics low byte
00000001C00158C8  and     cl, 1
00000001C00158CB  mov     [rbx+7Ch], cl        ; 0x7C = Characteristics & 1
00000001C00158CE  mov     al, [rdi+36h]        ; Characteristics byte 2 (bits 16-23)
00000001C00158D1  and     al, 1
00000001C00158D3  mov     [rbx+7Dh], al        ; 0x7D = Characteristics & 0x10000  (NEW)
```

In the unpatched build offset `0x7D` was not a device-characteristic byte; it was one byte of the `0x0101` virtual-disk nesting marker (`mov word ptr [rbx+7Dh], 101h` @ `0x1C0015915`). That marker moves to `0x7E/0x7F` in the patched build (`mov word ptr [rbx+7Eh], 101h` @ `0x1C0015948`). This is the source of the one-byte field shift seen elsewhere.

### 2.2 Reconcile path now gates on `0x7D` as well as `0x7C`

`ReconcileThisDatabaseWithMaster` allocates a `0x38`-byte descriptor (`ExAllocatePoolWithTag`, `NonPagedPoolNx`, tag `'MntA'`), attaches the callback `ReconcileThisDatabaseWithMasterWorker`, and queues it with a work-item queue routine. In the unpatched build the routine's only entry guard is the `0x7C` byte; the patched build adds a `0x7D` guard immediately after it.

Unpatched `ReconcileThisDatabaseWithMaster` (@ `0x1C0016FBC`):

```asm
00000001C0016FCB  cmp     byte ptr [rdx+7Ch], 0
00000001C0016FD5  jnz     loc_1C00170C5        ; skip if 0x7C set
00000001C0016FDB  mov     edx, 38h ; NumberOfBytes
00000001C0016FE0  mov     ecx, 200h; PoolType (NonPagedPoolNx)
00000001C0016FE5  mov     r8d, 41746E4Dh; Tag 'MntA'
00000001C0016FEB  call    cs:__imp_ExAllocatePoolWithTag
```

Patched `ReconcileThisDatabaseWithMaster` (@ `0x1C0016FFC`):

```asm
00000001C001700B  cmp     byte ptr [rdx+7Ch], 0
00000001C0017015  jnz     loc_1C001710F        ; skip if 0x7C set
00000001C001701B  cmp     byte ptr [rdx+7Dh], 0
00000001C001701F  jnz     loc_1C001710F        ; ADDED: skip if 0x7D set
00000001C0017025  mov     edx, 38h ; NumberOfBytes
00000001C001702A  mov     ecx, 200h; PoolType
00000001C001702F  mov     r8d, 41746E4Dh; Tag 'MntA'
00000001C0017035  call    cs:__imp_ExAllocatePoolWithTag
```

The decompiler renders the two byte checks as a single word compare of the adjacent `0x7C`/`0x7D` bytes:

```c
// patched ReconcileThisDatabaseWithMaster @ 0x1C0016FFC
if ( *(_WORD *)(a2 + 124) == 0 )   // both 0x7C and 0x7D must be zero
{
    PoolWithTag = ExAllocatePoolWithTag((POOL_TYPE)512, 0x38u, 0x41746E4Du);
    ...
}
```

The worker callback adds the same `0x7D` check to its early-exit guard, after it has already acquired the device mutex.

Unpatched `ReconcileThisDatabaseWithMasterWorker` (@ `0x1C00170E0`):

```asm
00000001C0017200  call    cs:__imp_KeWaitForSingleObject   ; take device mutex
00000001C0017216  call    MntMgrFindDevice
00000001C001721B  cmp     rax, r8
00000001C001721E  jz      loc_1C00183B3        ; bail if entry not in list
00000001C0017224  xor     eax, eax
00000001C0017226  cmp     [r15+7Ch], al
00000001C001722A  jnz     loc_1C00183B3        ; bail if 0x7C set
```

Patched `ReconcileThisDatabaseWithMasterWorker` (@ `0x1C0017130`):

```asm
00000001C001724E  call    cs:__imp_KeWaitForSingleObject   ; take device mutex
00000001C0017264  call    MntMgrFindDevice
00000001C0017269  cmp     rax, r8
00000001C001726C  jz      loc_1C00183D0        ; bail if entry not in list
00000001C0017272  xor     eax, eax
00000001C0017274  cmp     [r15+7Ch], al
00000001C0017278  jnz     loc_1C00183D0        ; bail if 0x7C set
00000001C001727E  cmp     [r15+7Dh], al
00000001C0017282  jnz     loc_1C00183D0        ; ADDED: bail if 0x7D set
```

The mutex acquisition (`KeWaitForSingleObject` on the device extension mutex) and the subsequent mount-point list teardown are byte-for-byte the same shape in both builds; only the extra `0x7D` comparison is new.

### 2.3 Reconcile guard folded from caller into callee

`MountMgrDriverReinitialization` previously filtered entries with a local `0x7C` check before calling `ReconcileThisDatabaseWithMaster`. Since the guard now lives inside `ReconcileThisDatabaseWithMaster` (and was extended with `0x7D`), the caller no longer needs its own filter and calls unconditionally.

Unpatched `MountMgrDriverReinitialization` (@ `0x1C000F2D0`):

```asm
00000001C000F343  cmp     [rbx+7Ch], r14b
00000001C000F347  jnz     short loc_1C000F354  ; skip Reconcile if 0x7C set
00000001C000F34F  call    ReconcileThisDatabaseWithMaster
```

Patched `MountMgrDriverReinitialization` (@ `0x1C000F350`):

```asm
00000001C000F3C8  call    ReconcileThisDatabaseWithMaster  ; called unconditionally
```

This is a straight refactor: the same `0x7C` gate is now enforced one call-level deeper, alongside the new `0x7D` gate. Net eligibility is unchanged for the `0x7C` case and additionally excludes `0x7D`-flagged volumes.

### 2.4 Symbolic-link creation modernized to `IoCreateSymbolicLink2`

Independent of the `0x7D` field work, `GlobalCreateSymbolicLink` changed the kernel API it uses to create symbolic links. The unpatched build calls `IoCreateSymbolicLink(name, target)`; the patched build calls `IoCreateSymbolicLink2(name, params)`, where `params` is a small structure whose first dword is `1` (a flags value) followed by the target `UNICODE_STRING`.

Unpatched (@ `0x1C000DDC0`):

```c
v3 = IoCreateSymbolicLink(&SymbolicLinkName, a2);
```

Patched (@ `0x1C000DE30`):

```c
v7 = *a2;                     // target UNICODE_STRING
LODWORD(v10[0]) = 1;          // params.Flags = 1
*(_OWORD *)&v10[1] = v7;      // params.Target = target
StringWithGlobal = IoCreateSymbolicLink2(P, v10);
```

Patched assembly:

```asm
00000001C000DE85  movups  xmm0, xmmword ptr [rdi]      ; target UNICODE_STRING
00000001C000DE88  lea     rdx, [rsp+58h+var_28]        ; params struct
00000001C000DE8D  mov     dword ptr [rsp+58h+var_28], 1; params.Flags = 1
00000001C000DE95  lea     rcx, [rsp+58h+P]             ; symbolic link name
00000001C000DE9A  movdqu  [rsp+58h+var_28+8], xmm0     ; params.Target
00000001C000DEA0  call    cs:__imp_IoCreateSymbolicLink2
```

`GlobalCreateSymbolicLink` is the common helper used for the symbolic links mountmgr creates (the `\Device\MountPointManager` link, drive-letter links, volume names, mount points, redirected saved links). The change of its second parameter type is what produces the cast-only, logic-identical diffs in the callers (`DriverEntry`, `MountMgrCreatePointWorker`, `MountMgrCreatePointWorkerLegacy`, `RedirectSavedLink`, and the arrival-handler call sites).

Error handling, WPP trace ids, and buffer cleanup around the call are otherwise identical between builds. This is an API modernization: `IoCreateSymbolicLink2` is the newer flags-taking variant, and the flag value `1` is passed for every link. The precise security semantics of that flag are not documented and are not determinable from the binary, so no vulnerability class or CWE can be justified from the diff. It is plausibly a defense-in-depth / namespace-hardening modernization, but the binary provides no demonstrable memory-safety, access-control, or reachability change to substantiate a security finding.

---

## 3. Why this is not a security fix

The finding originally proposed here — a missing "WorkPending" flag causing a work-item double-queue race, double-free, and use-after-free — is not supported by the binaries:

- **`0x7D` is not a work-in-progress flag.** It is written exactly once, in `QueryDeviceInformation`, from a static `DEVICE_OBJECT` characteristic bit (`BYTE2(Characteristics) & 1`). It is never set to `1` immediately before `IoQueueWorkItem` and cleared afterwards. There is no "mark pending before queue" write in the patched `ReconcileThisDatabaseWithMaster`; the queue routine only *reads* `0x7D`.
- **`0x7C` is not an "Offline" flag set after the callback starts.** In both builds it is set from `Characteristics & 1` during device-information query, not during work-item execution. There is no temporal check-then-set window of the kind an attacker would race.
- **No locking change.** The worker takes the device-extension mutex via `KeWaitForSingleObject` before touching the mount-point list in both builds. The list-unlink and `ExFreePoolWithTag` teardown execute under that mutex in both builds. Adding a `0x7D` early-exit inside the already-held-mutex region changes which entries are processed, not how they are synchronized.
- **No free-ordering change.** The mount-point list teardown (`mov [rax], rcx` / `mov [rcx+8], rax` at `0x1C0017327`/`0x1C001732C`, then `ExFreePoolWithTag` at `0x1C0017334`) is a single-free list cleanup and is identical in both builds. There is no second free of the same node and no address at `0x1C001732F` or `0x1C001733C` that corresponds to a free instruction.

The change is best characterized as adding handling for an additional device characteristic (excluding those volumes from database reconcile / auto-online), implemented via a new struct byte and two extra guard comparisons.

---

## 4. Assembly Analysis

The load-bearing evidence is quoted in Section 2. In summary:

| Location | Unpatched | Patched | Meaning |
|---|---|---|---|
| `QueryDeviceInformation` | `0x7C = Characteristics & 1`; `0x7D` used by nesting marker | `0x7C = Characteristics & 1`; **`0x7D = Characteristics & 0x10000` (new)** | New device-characteristic byte |
| `ReconcileThisDatabaseWithMaster` | `cmp [rdx+7Ch],0` only | adds `cmp [rdx+7Dh],0` | Extra queue-time gate |
| `ReconcileThisDatabaseWithMasterWorker` | `cmp [r15+7Ch],al` only | adds `cmp [r15+7Dh],al` | Extra worker-time gate (under existing mutex) |
| `MountMgrDriverReinitialization` | local `cmp [rbx+7Ch]` before call | unconditional call | Guard folded into callee |

### Structure layout shift (one inserted byte)

| Offset (unpatched) | Offset (patched) | Meaning |
|---|---|---|
| `0x7C` | `0x7C` | `Characteristics & 1` (removable-media bit) |
| — | `0x7D` | **`Characteristics & 0x10000` (NEW)** |
| `0x7D/0x7E` | `0x7E/0x7F` | virtual-disk nesting marker (`0x0101`) |
| `0x7E` | `0x7F` | flag set from IOCTL `0x560038` result |
| `0x80` | `0x81` | boolean state (read in `MountMgrMountedDeviceArrival`, `sub_1C00110C8`) |
| `0x85` | `0x86` | disposition byte (read in `sub_1C00152E4`) |

Allocation size of the volume entry remains `0xB8`.

---

## 5. Entry points (informational)

For completeness, the reconcile work item is reachable through the IOCTL device-control dispatcher (`sub_1C0009010`) and the mounted-device-arrival handler (`MountMgrMountedDeviceArrival` @ `0x1C000F7E4` / patched `0x1C000F854`), as well as the driver-reinitialization path (`MountMgrDriverReinitialization`). None of these paths gained or lost an input-length or authorization check in this patch. The device DACL of `\\.\MountPointManager` is not determinable from the binary and is not affected by this change.

---

## 6. Changed Functions — Full Triage

### Functionally relevant

| Function | Change |
|---|---|
| `QueryDeviceInformation` (`0x1C00157D0` → `0x1C00157F8`) | Adds the new `0x7D` device-characteristic byte; later fields shift by one byte. |
| `ReconcileThisDatabaseWithMaster` (`0x1C0016FBC` → `0x1C0016FFC`) | Adds `0x7D` guard before queueing the work item. |
| `ReconcileThisDatabaseWithMasterWorker` (`0x1C00170E0` → `0x1C0017130`) | Adds `0x7D` guard to the worker early-exit; `+1` field shift for `0x82→0x83`. |
| `MountMgrDriverReinitialization` (`0x1C000F2D0` → `0x1C000F350`) | Removes local `0x7C` filter; calls reconcile unconditionally (guard folded into callee). |
| `MountMgrMountedDeviceArrival` (`0x1C000F7E4` → `0x1C000F854`) | `+1` field shift (`0x80→0x81`); local init size change from struct-layout adjustment. |
| `GlobalCreateSymbolicLink` (`0x1C000DDC0` → `0x1C000DE30`) | Switches symbolic-link creation from `IoCreateSymbolicLink` to `IoCreateSymbolicLink2(name, {flags=1, target})`. API modernization; security impact not determinable from the binary. Callers change only by a parameter-type cast. |

### Field-shift ripple only (no behavioral change beyond the `+1` offset)

`sub_1C00152E4` (`0x85→0x86`), `sub_1C00110C8` (`0x80→0x81`, plus for→while loop normalization), and `ProcessSuggestedDriveLetters`.

### Compiler / codegen churn

The following changed only in compiler codegen (register allocation, `for`→`while` loop normalization, memset SIMD variant, WPP trace message ids, global-address drift), not in behavior:

`sub_1C00014C0` (memset variant), `sub_1C0001010` (IRP_MJ_CLEANUP cancel routine), `sub_1C000F390`, `sub_1C0019120`, `sub_1C00183D4`, `sub_1C0016760`, `sub_1C0002DF0` (global-address drift), `sub_1C000D898`, `sub_1C0014C24`, `sub_1C000E458`, `sub_1C00162A0`, `sub_1C00091D0` (IOCTL dispatcher — register/init-order only, no new input validation).

---

## 7. Added / Removed Functions

The patched image contains four functions not present in the unpatched image, all compiler/CRT helpers introduced by the rebuild, none security-relevant:

- `__cpu_features_init`
- `_guard_xfg_dispatch_icall_nop`
- `__memset_query`
- `__memset_repmovs`

No functions were removed. (The earlier claim of zero added/removed functions was incorrect; these four account for the 156 → 160 function-count difference.)

---

## 8. Confidence & Caveats

**Confidence: High** that this patch contains no security-relevant fix.

- The new `0x7D` byte is written from a static device characteristic in `QueryDeviceInformation`, not toggled around work-item queueing, so it cannot function as a concurrency guard.
- The device mutex and the list-teardown free sequence in the worker are the same in both builds; the patch only adds an early-exit comparison inside the already-synchronized region.
- The one-byte structure insertion is corroborated by the consistent `+1` offset ripple across `QueryDeviceInformation`, `MountMgrMountedDeviceArrival`, `sub_1C00110C8`, and `sub_1C00152E4`.
- An independent function-by-function diff of all differing functions found no added or removed locking, no changed free ordering, no bounds/length/probe changes, and no security-descriptor/ACL changes anywhere. Neither build calls `ProbeForRead`/`ProbeForWrite`, `IoCreateDeviceSecure`, or any SDDL/security-descriptor API. The IOCTL dispatch set (`MountMgrDeviceControl`) is byte-for-byte identical (same 24 control codes to the same handlers); its extra `KeReleaseMutex` tails are branch duplication from a host-silo predicate inversion, not a synchronization change.
- The only behavioral change outside the `0x7D` field work is the `IoCreateSymbolicLink2` modernization in `GlobalCreateSymbolicLink` (Section 2.4), which the binary does not substantiate as a security fix.

**Interpretation of the new characteristic:** bit `0x10000` of `DEVICE_OBJECT.Characteristics` is documented as `FILE_CHARACTERISTIC_CSV` (cluster shared volume). The observable effect of the patch is that volumes reporting this characteristic (and, as before, removable-media volumes) are excluded from the database-reconcile and auto-online path. This is a behavioral/correctness adjustment, not a memory-safety fix.
