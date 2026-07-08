Title: csvfs.sys — TOCTOU Race Condition / Use-After-Free (CWE-362, CWE-416) in CsvCamSetSecurityInfo fixed
Date: 2026-06-28
Slug: csvfs_adb6dbff-csvfs-report-20260628-221951
Category: Corpus
Author: Argus
Summary: KB5078752

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `csvfs_unpatched.sys` |
| Patched binary | `csvfs_patched.sys` |
| Overall similarity | 0.9921 |
| Matched functions | 1766 |
| Changed functions | 1 |
| Identical functions | 1765 |
| Unmatched (unpatched) | 0 |
| Unmatched (patched) | 0 |

**Verdict:** The patch fixes a single, surgical defect in `csvfs!CsvCamSetSecurityInfo` (`sub_1C00BCAAC`) — an unlocked read of the global `EncryptionManager` pointer that can be freed concurrently by an exclusive writer, producing a TOCTOU / Use-After-Free on a 0x28-byte `PagedPool` (`'CVCA'`) `Encryption` object.

---

## 2. Vulnerability Summary

### Finding #1 — TOCTOU / Use-After-Free in `CsvCamSetSecurityInfo` (`sub_1C00BCAAC`)

- **Severity:** High
- **Vulnerability class:** CWE-362 (Race Condition) / CWE-416 (Use-After-Free)
- **Affected function:** `csvfs!CsvCamSetSecurityInfo` (`sub_1C00BCAAC`, `0x1C00BCAAC` in both builds)
- **Affected object:** The global `Encryption*` pointer `EncryptionManager` (`?EncryptionManager@@3PEAVEncryption@@EA`), a 0x28-byte object, tag `'CVCA'` (`0x41435643`).

**Root cause (plain English):**

`CsvCamSetSecurityInfo` updates the global `Encryption` signing manager used for Cluster Shared Volumes. It touches two globals:

- `EncryptionManager` — a small (0x28-byte) `Encryption` object (the **unprotected** read).
- `ReplayCacheManagerObject` — a larger (0x1010-byte) object (already read under `SigningLock` shared in both builds).

When the caller supplies a non-empty encryption input (`*(context + 0xe8) != 0`), the **unpatched** version reads `EncryptionManager` and dereferences its stored-size (`+0x20`) and stored-buffer (`+0x18`) fields, then `memcmp`'s the caller's input buffer (`context + 0xec`) against the stored buffer — all **without acquiring `SigningLock`**. Later in the same function, the exclusive-write path takes `KeEnterCriticalRegion` + `ExAcquireResourceExclusiveLite` on `SigningLock` (`?SigningLock@@3PEAVRWLock@@EA`), frees the old object via `Encryption::`scalar deleting destructor`` (`??_GEncryption`, `sub_1C0058100` → `ExFreePoolWithTag`), and replaces the global with a freshly allocated object. Because the read side never shares the lock, the writer can free the object mid-read, leaving the reader holding a dangling pointer.

The patch wraps the read+dereference in `RWLock::AcquireShared` (`?AcquireShared@RWLock@@QEAAXXZ`) / `RWLock::ReleaseShared` (`?ReleaseShared@RWLock@@QEAAXXZ`) — the shared side of `SigningLock` — closing the window. Two incidental codegen differences accompany the fix and are not themselves security changes: the entry-cached `eax` copy of `*(context+0xe8)` is dropped in favor of an in-memory re-read (`cmp [rsi+0xe8], eax`), and the length test changes from `test eax, eax; jz` to `cmp [rcx+0xe8], ebp; jbe`. For a length field (never negative) the two tests are equivalent — the `jbe` form does not reject any additional value.

> Note on the shared-lock helper: `RWLock::AcquireShared` (`0x1C0018818`) and `RWLock::ReleaseShared` (`0x1C0018850`) are **new functions in the patched build** — they do not exist in the unpatched build. Their bodies hardcode the global `SigningLock`: `AcquireShared` performs `mov rbx, cs:SigningLock; KeEnterCriticalRegion; ExAcquireResourceSharedLite([rbx], 1)`, and `ReleaseShared` performs `ExReleaseResourceLite([SigningLock]); KeLeaveCriticalRegion`. Because they reference the global directly, the caller's `this` (`rcx`) is irrelevant — every call acquires the same `SigningLock` shared. In the unpatched build this exact shared sequence was emitted **inline** for the `ReplayCacheManagerObject` read; the patch factors it into these helpers and additionally applies it to the previously-unprotected `EncryptionManager` read. At the address `0x1C0018818` the unpatched build instead contains `__GSHandlerCheck` (an unrelated function relocated a few bytes later in the patched build to make room for the new helpers).

**Attacker-reachable entry point and data flow:**

1. `GsDriverEntry` (`sub_1C00BF010`) — driver entry stub.
2. `DriverEntry` (`sub_1C00BF078`) — driver initialization (init path, not the runtime dispatch of this call).
3. `CsvFsNotificationQueueInitialize` (`sub_1C004800C`).
4. `CsvFsHandleMessage` (`sub_1C0005F50`) — message dispatcher; calls `CsvFsHandleSetSecurityInfo`.
5. `CsvFsHandleSetSecurityInfo` (`sub_1C0046974`) — validates buffers, then calls `CsvCamSetSecurityInfo` at `0x1C00469D6`.
6. `CsvCamSetSecurityInfo` (`sub_1C00BCAAC`) — vulnerable `EncryptionManager` update.

The context field at `+0xe8` is the caller-supplied encryption input length; `+0xec` is the input buffer, compared via `memcmp` against the stored buffer read from the unlocked `EncryptionManager`.

---

## 3. Pseudocode Diff

```c
// ============ UNPATCHED (vulnerable) ============
int32_t len = *(context + 0xe8);            // cached in eax at function entry
if (len != 0)                               // signed != 0 test
{
    Encryption* rdx_1 = EncryptionManager;  // <<<< NO LOCK — unprotected global read
    r14 = 1;
    if (rdx_1) {
        int32_t size = *(rdx_1 + 0x20);          // <<<< UAF: deref stored size (+0x20)
        if (len == size &&
            memcmp(context + 0xec,               // caller input
                   *(rdx_1 + 0x18),              // <<<< UAF: deref stored buffer (+0x18)
                   size) == 0)
            r14 = 0;                             // input matches existing manager
    }
}
// ...later in this function:
//   KeEnterCriticalRegion();
//   ExAcquireResourceExclusiveLite(*SigningLock, 1);
//   if (EncryptionManager) __GEncryption(EncryptionManager); // <<<< ExFreePoolWithTag of old object
//   EncryptionManager = new_object;
//   ExReleaseResourceLite(*SigningLock);
//   KeLeaveCriticalRegion();
```

```c
// ============ PATCHED (fixed) ============
if (*(context + 0xe8) > 0)                   // unsigned > 0 test (cmp [rcx+0xe8], ebp; jbe)
{
    r14 = 1;
    RWLock::AcquireShared();                 // <<<< SHARED LOCK ACQUIRE (SigningLock shared)
    Encryption* rdx_1 = EncryptionManager;   // read under lock
    if (rdx_1)
    {
        int32_t size = *(rdx_1 + 0x20);      // safe deref under shared lock
        if (*(context + 0xe8) == size &&     // <<<< re-read from memory (no stale eax)
            memcmp(context + 0xec, *(rdx_1 + 0x18), size) == 0)
            r14 = 0;
    }
    RWLock::ReleaseShared();                 // <<<< SHARED LOCK RELEASE
    // ...allocate replacement / exclusive swap as before...
}
```

**What the diff tells us:**

- The unpatched read of `EncryptionManager` has *no* `KeEnterCriticalRegion` / `ExAcquireResourceSharedLite` around it.
- The exclusive writer (same function, later in execution, or another thread) does correctly take `ExAcquireResourceExclusiveLite` on `SigningLock` and frees the object inside that critical region — but that lock is meaningless when the reader never shares it.
- The patch *adds* the matching shared-lock acquire/release (`RWLock::AcquireShared` / `ReleaseShared`). The accompanying re-read of the length from memory and the `test`→`cmp/jbe` codegen change are incidental and functionally equivalent for a length value; the lock is the security-relevant change.

---

## 4. Assembly Analysis

### 4.1 Unpatched — `sub_1C00BCAAC` (`CsvCamSetSecurityInfo`)

```asm
0x1C00BCAAC: mov     [rsp+0x8], rbx
0x1C00BCAB1: mov     [rsp+0x10], rbp
0x1C00BCAB6: mov     [rsp+0x18], rsi
0x1C00BCABB: push    rdi
0x1C00BCABC: push    r14
0x1C00BCABE: push    r15
0x1C00BCAC0: sub     rsp, 0x30
0x1C00BCAC4: mov     eax, [rcx+0xe8]         ; cache input length in eax  <-- PATCH REMOVES THIS CACHE
0x1C00BCACA: xor     ebp, ebp
0x1C00BCACC: xor     r14b, r14b
0x1C00BCACF: mov     rsi, rcx
0x1C00BCAD2: mov     r15b, 0x1
0x1C00BCAD5: test    eax, eax               ; signed != 0  <-- PATCH uses 'cmp [rcx+0xe8], ebp; jbe'
0x1C00BCAD7: jz      0x1C00BCC2E

; === RACE WINDOW START — NO LOCK ===
0x1C00BCADD: mov     rdx, cs:EncryptionManager  ; <<<< UNLOCKED read of Encryption global
0x1C00BCAE4: mov     r14b, r15b
0x1C00BCAE7: test    rdx, rdx
0x1C00BCAEA: jz      0x1C00BCB63
0x1C00BCAEC: mov     ecx, [rdx+0x20]        ; <<<< UAF SINK: deref stored size (+0x20)
0x1C00BCAEF: cmp     eax, ecx
0x1C00BCAF1: jnz     0x1C00BCB3A
0x1C00BCAF3: mov     rdx, [rdx+0x18]        ; <<<< UAF SINK: deref stored buffer (+0x18)
0x1C00BCAF7: mov     r8d, ecx               ; Size
0x1C00BCAFA: lea     rcx, [rsi+0xec]        ; Buf1 (caller input)
0x1C00BCB01: call    memcmp                 ; sub_1C0018950 — compares input vs stored buffer

; --- Exclusive-lock path that frees the object Thread A may be reading ---
0x1C00BCBD0: mov     rbx, cs:SigningLock
0x1C00BCBD7: call    KeEnterCriticalRegion
0x1C00BCBE3: mov     rcx, [rbx]             ; Resource
0x1C00BCBE6: mov     dl, 0x1
0x1C00BCBE8: call    ExAcquireResourceExclusiveLite
0x1C00BCBF4: mov     rcx, cs:EncryptionManager   ; old object
0x1C00BCBFB: test    rcx, rcx
0x1C00BCC00: call    ??_GEncryption         ; <<<< scalar deleting destructor -> ExFreePoolWithTag (sub_1C0058100)
0x1C00BCC0C: mov     cs:EncryptionManager, rdi   ; replace global with new object
0x1C00BCC16: call    ExReleaseResourceLite
0x1C00BCC22: call    KeLeaveCriticalRegion

; --- ReplayCacheManagerObject read — CORRECTLY under SigningLock SHARED in BOTH versions ---
0x1C00BCC2E: mov     rbx, cs:SigningLock
0x1C00BCC35: call    KeEnterCriticalRegion
0x1C00BCC41: mov     rcx, [rbx]
0x1C00BCC44: mov     dl, 0x1
0x1C00BCC46: call    ExAcquireResourceSharedLite   ; <-- SHARED LOCK
0x1C00BCC52: mov     rax, cs:ReplayCacheManagerObject
...
0x1C00BCCD0: call    ExReleaseResourceLite
0x1C00BCCDC: call    KeLeaveCriticalRegion

; --- Free helper ??_GEncryption (sub_1C0058100) ---
0x1C0058109: call    ?ReleaseAll@Encryption@@AEAAXXZ   ; Encryption::ReleaseAll
0x1C0058113: call    ExFreePoolWithTag                 ; deallocate the object
```

### 4.2 Patched — relevant change block

```asm
0x1C00BCACF: cmp     [rcx+0xe8], ebp           ; unsigned > 0
0x1C00BCAD5: jbe     0x1C00BCC40
0x1C00BCADE: call    ?AcquireShared@RWLock@@QEAAXXZ  ; <<<< SigningLock shared acquire (sub_1C0018818)
0x1C00BCAE3: mov     rdx, cs:EncryptionManager  ; read under lock
0x1C00BCAEA: test    rdx, rdx
0x1C00BCAED: jz      0x1C00BCB67
0x1C00BCAEF: mov     eax, [rdx+0x20]           ; safe deref under lock
0x1C00BCAF2: cmp     [rsi+0xe8], eax           ; re-read context+0xe8 from memory
0x1C00BCAFA: mov     rdx, [rdx+0x18]
0x1C00BCB08: call    memcmp                    ; sub_1C00189C0
...
0x1C00BCB67: call    ?ReleaseShared@RWLock@@QEAAXXZ  ; <<<< SigningLock shared release (sub_1C0018850)
```

### 4.3 Key takeaways from the assembly

- The unprotected read is a single `mov rdx, cs:EncryptionManager` with no preceding `KeEnterCriticalRegion` and no preceding `ExAcquireResource*` / `RWLock::AcquireShared` call.
- The exclusive-write path does correctly serialize against itself (it takes both critical region and exclusive resource) — but the missing shared-lock on the read makes the entire exclusive critical region useless for protecting against the racing reader.
- The `ReplayCacheManagerObject` read shows the correct pattern already in place: `KeEnterCriticalRegion → ExAcquireResourceSharedLite → read → ExReleaseResourceLite → KeLeaveCriticalRegion`. The patch replicates this (via the `RWLock` wrapper) for the `EncryptionManager` read.
- Address/symbol reuse across builds: `0x1C0018818` = `RWLock::AcquireShared` (patched) vs `__GSHandlerCheck` (unpatched); `sub_1C0018950` (unpatched) / `sub_1C00189C0` (patched) = `memcmp`; `sub_1C0058100` = `Encryption::`scalar deleting destructor`` (`??_GEncryption`).

---

## 5. Trigger Conditions

1. **Target environment.** The victim machine must have the Cluster Shared Volume File System driver loaded — i.e., a node of a Windows Server Failover Cluster with at least one CSV enabled. Verify with `fltmc filters` (look for `csvfs`) or `sc query csvfs`.
2. **Volume handle.** Open a handle reaching the CSV set-security-info path.
3. **Message routing.** Drive a set-security-info operation that routes through `CsvFsHandleMessage` (`sub_1C0005F50`) → `CsvFsHandleSetSecurityInfo` (`sub_1C0046974`).
4. **Input validation.** `CsvFsHandleSetSecurityInfo` (`sub_1C0046974`) validates the input before calling `CsvCamSetSecurityInfo`.
5. **Trigger flag.** The context field at `+0xe8` (encryption input length) must be `> 0` — supply a non-empty encryption input so the `EncryptionManager` path is taken.
6. **Racing threads.** Fire at least two concurrent operations from separate threads targeting the *same* CSV volume. Ideally many threads (8–32) to amplify the probability of hitting the narrow race window.
7. **Race window.** Thread A executes `0x1C00BCADD` (read pointer) → `0x1C00BCAEC` (deref +0x20) → `0x1C00BCAF3` (deref +0x18) → `0x1C00BCB01` (`call memcmp`). Thread B must enter the exclusive-write path (`0x1C00BCBD0` → `0x1C00BCC00`) and free the object Thread A read.
8. **Widen the window.** Pin threads to specific CPUs via `SetThreadAffinityMask`, lower priority on the racing thread, or use `NtYieldExecution` to encourage preemption. Stagger the threads so Thread B reaches the free path while Thread A is between the read and the first deref.
9. **Confirm.** If no pool reclamation occurs: BSOD `PAGE_FAULT_IN_NONPAGED_AREA (0x50)` or an invalid pool read, faulting address inside a freed PagedPool block, caller `csvfs!CsvCamSetSecurityInfo+0x40`. With Driver Verifier Special Pool enabled: bug check `DRIVER_VERIFIER_DETECTED_VIOLATION` or `SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION`, with parameter 1 = the freed pool address. If the freed slot is reclaimed with controlled data, the reader instead dereferences an attacker-influenced `+0x18` pointer and `+0x20` size inside `memcmp`; note the `memcmp` result is consumed only as a match/no-match boolean (it sets `r14`), so it is not a data-return channel.

---

## 6. Exploit Primitive & Development Notes

**Primitive.** The bug is a narrow-window UAF on a 0x28-byte PagedPool allocation tagged `'CVCA'` (`0x41435643`) holding an `Encryption` object. After a concurrent thread frees the object at `0x1C00BCC00`, the racing reader dereferences the freed object's stored-size (`+0x20`) and stored-buffer pointer (`+0x18`) at `0x1C00BCAEC` / `0x1C00BCAF3` and passes them to `memcmp` at `0x1C00BCB01`.

**Demonstrable impact:**

- **Denial of service (kernel crash).** If the freed 0x28 block is unmapped or poisoned (e.g., Driver Verifier Special Pool), the dereference at `0x1C00BCAEC` faults, bugchecking the machine. This is the directly reproducible outcome.
- **Attacker-influenced dereference.** If the freed slot is reclaimed with controlled data before the dereference, the `+0x18` pointer and `+0x20` size read from the reclaimed object are attacker-influenced. The size (`+0x20`) becomes the `memcmp` length and the pointer (`+0x18`) becomes the `memcmp` source, so `memcmp` reads `size` bytes from an attacker-influenced address — an out-of-bounds read against kernel memory. The `memcmp` result is consumed only as a match/no-match boolean that decides whether the manager is rebuilt (`r14`); it is not returned to the caller, so this is not by itself an information-disclosure channel.

**Constraints on weaponization (not demonstrated here):**

- Winning the race requires two concurrent invocations reaching the `EncryptionManager` path (`*(context+0xe8) > 0`) on the same globals, with one freeing the object during the other's read window (`0x1C00BCADD` → `0x1C00BCB01`). The operation runs at `PASSIVE_LEVEL`.
- Turning the attacker-influenced dereference into anything beyond a crash requires reclaiming the freed 0x28 PagedPool slot with controlled contents, which is not established against these binaries and is out of scope for this report.

---

## 7. Debugger PoC Playbook

Below is the playbook for an analyst with `kd`/`WinDbg` attached to the **unpatched** driver, building a PoC for the UAF in `CsvCamSetSecurityInfo`.

### 7.1 Symbols / module setup

```
!load mex                       ; (optional) helpful
.reload /f csvfs.sys=............
lm csvfs                        ; confirm base
u csvfs!CsvCamSetSecurityInfo L40   ; sanity check entry
```

Replace `............` with the loaded base — typically obtainable from `lm csvfs`.

### 7.2 Breakpoints

| # | Command | Why |
|---|---|---|
| 1 | `bp csvfs!CsvCamSetSecurityInfo` | Function entry. `rcx` = arg1 = security context. Check `[rcx+0xe8]` (input length). |
| 2 | `bp csvfs!CsvCamSetSecurityInfo+0x31` (`0x1C00BCADD`) | Unlocked read of `EncryptionManager`. `rdx` will hold the `Encryption` object pointer — the dangling-pointer-in-waiting. |
| 3 | `bp csvfs!CsvCamSetSecurityInfo+0x40` (`0x1C00BCAEC`) | Vulnerable dereference `mov ecx, [rdx+0x20]` (stored size). If the pool has been reclaimed, `ecx` contains attacker-controlled or stale data. |
| 4 | `bp csvfs!CsvCamSetSecurityInfo+0x47` (`0x1C00BCAF3`) | Second vulnerable dereference `mov rdx, [rdx+0x18]` (stored buffer). |
| 5 | `bp csvfs!CsvCamSetSecurityInfo+0x154` (`0x1C00BCC00`) | The free: `call ??_GEncryption`. `rcx` = object being freed. Compare against the `rdx` value captured at BP #2 on the racing thread. |
| 6 | `bp csvfs!__GEncryption` (`sub_1C0058100`) | The `Encryption` scalar deleting destructor (`ReleaseAll` then `ExFreePoolWithTag`). Confirms the pool address freed. |

A conditional break to skip the boring path:

```
bp csvfs!CsvCamSetSecurityInfo ".if (poi(@rcx+0xe8) == 0) { gc } .else { .echo ENTERING VULNERABLE PATH; kn; }"
```

### 7.3 What to inspect at each breakpoint

| BP | Register / Expression | Meaning |
|---|---|---|
| #1 | `rcx`, `[rcx+0xe8]`, `[rcx+0xe0]`, `[rcx+0xe4]` | Security context, input length, volume IDs. |
| #2 | `rdx`, `!pool rdx 2` | The `EncryptionManager` pointer just read unlocked. Tag should be `CVCA`, size `0x28`. |
| #3 | `ecx` after `mov`, `!pte rdx` | The stored size read from the potentially freed object. |
| #5 | `rcx` | The pointer being freed. **If this equals the `rdx` from BP #2 on another thread → UAF confirmed.** |
| Global watch | `EncryptionManager` | The Encryption global pointer itself. Break whenever any thread reads/writes it. |

Useful pool inspection commands:

```
!poolfind 0x41435643 4       ; enumerate all live 'CVCA' allocations
!pool <faulting_addr> 2      ; tag / size of faulting address
```

### 7.4 Key instruction offsets

- `0x1C00BCAC4` — `mov eax, [rcx+0xe8]` — caches the input length in `eax`. (Patch removes this caching.)
- `0x1C00BCAD5` — `test eax, eax` — signed `!= 0` predicate. (Patch: `cmp [rcx+0xe8], ebp; jbe` — unsigned `> 0`.)
- `0x1C00BCADD` — `mov rdx, cs:EncryptionManager` — **UNLOCKED** global read. (Patch inserts `call ?AcquireShared@RWLock` at `0x1C00BCADE` just before.)
- `0x1C00BCAEC` — `mov ecx, [rdx+0x20]` — **UAF sink #1** (stored size).
- `0x1C00BCAF3` — `mov rdx, [rdx+0x18]` — **UAF sink #2** (stored buffer).
- `0x1C00BCB01` — `call memcmp` (`sub_1C0018950`) — consumes the leaked/reclaimed data.
- `0x1C00BCC00` — `call ??_GEncryption` (`sub_1C0058100`) — Encryption scalar deleting destructor / `ExFreePoolWithTag` of the old object.
- `0x1C00BCC0C` — `mov cs:EncryptionManager, rdi` — replaces global after free.

### 7.5 Trigger setup (from user mode)

1. Ensure CSV is enabled and `csvfs` is loaded: `fltmc filters` from an elevated cmd.
2. Open a handle reaching the CSV set-security-info path.
3. Drive a set-security-info operation that routes to `CsvFsHandleSetSecurityInfo` via `CsvFsHandleMessage` (`sub_1C0005F50`) with a non-empty encryption input so the context field `+0xe8` is `> 0`.
4. Race: spawn 16–32 threads all issuing the same operation against the same volume, at high rate. Optionally throttle the racing thread with `SetThreadAffinityMask` to a different logical processor.
5. Observe: the BSOD or, with controlled reclamation, the controlled `+0x18`/`+0x20` data feeding `memcmp`.

### 7.6 Expected observations

- **Crash without reclamation:** Bug check `0x50 PAGE_FAULT_IN_NONPAGED_AREA`. `Parameter 2` = freed PagedPool address. Call stack ends in `csvfs!CsvCamSetSecurityInfo+0x40` (`0x1C00BCAEC`) reading `[rdx+0x20]`.
- **Crash with Special Pool:** Bug check `0xC4 DRIVER_VERIFIER_DETECTED_VIOLATION` (code `0x20` use-after-free) or `0xCC SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION`. Parameter 1 = pool address.
- **No crash (controlled reuse):** `memcmp` runs against attacker-supplied `+0x18` / `+0x20` — an attacker-directed kernel read.

### 7.7 Struct / offset notes

```
Security context (arg1) layout:
  +0x000  : (header / context fields)
  +0x0e0  : volume identifier A (32-bit, used to build ReplayCacheManager)
  +0x0e4  : volume identifier B (32-bit)
  +0x0e8  : encryption input length (int32) — must be > 0 to hit the EncryptionManager path
  +0x0ec  : encryption input buffer (compared via memcmp)

Encryption object (EncryptionManager), size 0x28, tag 'CVCA':
  +0x18  : stored buffer pointer (Buf2 for memcmp)
  +0x20  : stored size (int32; compared with *(context+0xe8) and used as memcmp Size)

SigningLock : ?SigningLock@@3PEAVRWLock@@EA — a C++ RWLock wrapping an ERESOURCE.
              exclusive = ExAcquireResourceExclusiveLite (guards the free)
              shared    = RWLock::AcquireShared / ReleaseShared (added by the patch around the read)
Pool tag constant : 0x41435643 ('CVCA')
```

---

## 8. Changed Functions — Full Triage

Only one function changed between the two binaries.

### `CsvCamSetSecurityInfo` (`sub_1C00BCAAC`, similarity 0.9638, change_type = security_relevant)

- **What changed:** The unprotected read+dereference of the global `EncryptionManager` pointer was wrapped in `RWLock::AcquireShared` / `RWLock::ReleaseShared` (the shared side of `SigningLock`). Incidentally, the entry-cached `eax` copy of `*(context+0xe8)` was replaced by an in-memory re-read, and the length test changed from `test eax, eax; jz` to `cmp [rcx+0xe8], ebp; jbe`; for a length value these two tests are equivalent and are not security-relevant on their own.
- **Helper functions introduced by the patch:** `RWLock::AcquireShared` (`0x1C0018818`) and `RWLock::ReleaseShared` (`0x1C0018850`) exist only in the patched build. Their bodies reference the global `SigningLock` directly (`AcquireShared`: `KeEnterCriticalRegion` + `ExAcquireResourceSharedLite([SigningLock], 1)`; `ReleaseShared`: `ExReleaseResourceLite` + `KeLeaveCriticalRegion`). In the unpatched build this identical shared-lock sequence was emitted inline around the `ReplayCacheManagerObject` read; the patch factors it into these two helpers, reuses them for that read and the `UpdateGlobalSequenceNumber` path, and newly applies them to the previously-unprotected `EncryptionManager` read.
- **Address/symbol reuse:** At `0x1C0018818` the unpatched build contains `__GSHandlerCheck` (an unrelated function that the patched build relocates a few bytes later to `0x1C0018888` to make room for the new helpers). `sub_1C0058100` = `Encryption::`scalar deleting destructor`` (`??_GEncryption`), whose body calls `Encryption::ReleaseAll` (`0x1C0058109`) then `ExFreePoolWithTag` (`0x1C0058113`). `sub_1C0018950` (unpatched) / `sub_1C00189C0` (patched) = `memcmp`.

`CsvCamSetSecurityInfo` is the only function whose behavior changed; the two RWLock helpers are the newly-emitted code that implements the fix.

---

## 9. Unmatched Functions

- **Removed:** none.
- **Added:** `RWLock::AcquireShared` (`0x1C0018818`) and `RWLock::ReleaseShared` (`0x1C0018850`). These two helper functions exist only in the patched build; they encapsulate the `SigningLock` shared acquire/release sequence that the unpatched build emitted inline. (The aggregate table in §1 pairs functions by address, so these two are counted against the `__GSHandlerCheck` / `__GSHandlerCheckCommon` functions that occupy those addresses in the unpatched build rather than reported as unmatched; by content they are genuinely new.)

No added sanitizers and no removed mitigations. The behavioral fix is confined to `CsvCamSetSecurityInfo`: a `SigningLock` shared lock (via the two new helpers) is added around the previously-unprotected `EncryptionManager` read. This makes the diff easy to audit and confirms that the patch targets the UAF in `CsvCamSetSecurityInfo`.

---

## 10. Confidence & Caveats

**Confidence:** High.

- The diff is unambiguous: one function, two inserted `RWLock::AcquireShared` / `ReleaseShared` calls around a read that was previously unlocked, plus a tightened predicate and a re-read from memory. The pattern mirrors the protection already present on the `ReplayCacheManagerObject` read, which serves as an internal reference implementation.
- The assembly at `0x1C00BCADD` through `0x1C00BCB01` is unambiguously an unprotected read-then-deref-then-`memcmp`, and `0x1C00BCC00` is unambiguously a free of the same object under a `SigningLock` exclusive lock the reader does not share.
- The vulnerable function is reachable from `CsvFsHandleMessage` (`sub_1C0005F50`) → `CsvFsHandleSetSecurityInfo` (`sub_1C0046974`) → `CsvCamSetSecurityInfo`.

**Assumptions to verify manually before PoC:**

1. **Message/FSCTL code.** Confirm via dynamic tracing which user-mode operation routes into `CsvFsHandleSetSecurityInfo` (case handling inside `CsvFsHandleMessage`).
2. **Privilege requirement.** Whether a low-privileged user can reach the set-security-info path, or whether local-administrators-only access is required, depends on the cluster's security descriptor. Verify with `!sd` on the device object.
3. **Pre-conditioning `*(context+0xe8)`.** Confirm what supplies the non-empty encryption input that flips this length positive.
4. **Pool-reclamation primitive choice.** The 0x28 PagedPool size class is small enough for many spray primitives; the optimal one depends on the target Windows build and pool allocator.
5. **Race timing.** The window is a few instructions plus the `memcmp`. On a multi-core system the race is winnable but requires many threads or careful CPU pinning. Validate empirically with DV Special Pool first to confirm reachability, then disable DV for the real attempt.
6. **Address changes.** The addresses reflect this specific build. If you reverse a different build, rebase — the *pattern* (unlocked `EncryptionManager` read vs `SigningLock`-protected exclusive free) is what matters.
