Title: clusdisk.sys — Exclusive lock held across a subsystem callback in Pool::PendDefenseIrp (CWE-662) fixed
Date: 2026-06-25
Slug: clusdisk_c039dcbb-clusdisk-report-20260625-213045
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Medium
KBDate: 2026-01-13

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched Binary** | `clusdisk_unpatched.sys` |
| **Patched Binary** | `clusdisk_patched.sys` |
| **Overall Similarity** | 0.7793 |
| **Matched Functions** | 220 |
| **Changed Functions** | 153 |
| **Identical Functions** | 67 |
| **Unmatched (unpatched)** | 0 |
| **Unmatched (patched)** | 0 |

**Verdict:** The patch narrows the critical section in `Pool::PendDefenseIrp` so that the `SpacePortCallbackProxy::PrmGetNumberOfDevices` callback no longer runs while the exclusive ERESOURCE at `this+0x40` is held: the unpatched build acquires that lock before the callback, the patched build runs the callback first and only acquires the lock afterward. The remaining changed functions modernize pool allocation from `ExAllocatePoolWithTag(NonPagedPoolNx)` to `ExAllocatePool2` (zero-initialized) and restructure error-path cleanup in the PR-key reading functions and `Pool::Arbitrate`. Those latter changes are defensive refactors; the binaries do not show an exploitable use-after-free, double-free, or information leak in them.

---

## 2. Vulnerability Summary

### Finding 1 — Pool::PendDefenseIrp (MEDIUM)

- **Severity:** Medium
- **Class:** Improper synchronization — critical section spans an external callback (CWE-662)
- **Function:** `Pool::PendDefenseIrp` (unpatched: `0x1c000ab5c`; patched: `0x14000caf8`)

**Root Cause:** The unpatched version acquires the exclusive ERESOURCE lock at `this+0x40` via `ExAcquireResourceExclusiveLite` *before* calling `SpacePortCallbackProxy::PrmGetNumberOfDevices`, so the callback into the storage-spaces proxy runs while the pool's exclusive resource is held. The patched version reorders the code: it calls `PrmGetNumberOfDevices` first with no lock held, returns immediately if the callback fails (`< 0`), and only then acquires the exclusive lock (`this+0x40`) followed by the shared lock (`this+0x178`). The net effect is that the exclusive resource is no longer held across the external callback, shrinking the critical section.

Both builds acquire the two locks in the same order (`this+0x40` exclusive, then `this+0x178` shared), so this is a change in lock *scope*, not lock *ordering*. The sibling function `Pool::Arbitrate` still calls `PrmGetNumberOfDevices` while holding `this+0x40` exclusive in **both** builds, so the binaries do not demonstrate that this callback can re-enter and self-deadlock on the same resource; that remains an unproven hypothesis rather than a confirmed deadlock.

**Reachable Entry Point:** IOCTL sent to the ClusDisk device and routed to `Pool::PendDefenseIrp` via the pool device-control path. The specific IOCTL numeric value is not established from the diff (see Confidence & Caveats).

**Call Chain (as far as the binaries confirm):**
1. `ClusDskDeviceControl` (IRP_MJ_DEVICE_CONTROL dispatch)
2. `ClusPoolDeviceControl` (IOCTL routing)
3. `Pool::PendDefenseIrp` — **unpatched: acquires `this+0x40` exclusive, then calls the callback under the lock**
4. `SpacePortCallbackProxy::PrmGetNumberOfDevices`

---

### Finding 2 — ClusPoolReadRegistrationKeys / ClusPoolReadReservationKeys (LOW)

- **Severity:** Low (refactor / hardening — no demonstrable memory-safety bug)
- **Class:** Allocation-API modernization and error-path restructuring (CWE-457 avoidance via zero-init)
- **Functions:** `ClusPoolReadRegistrationKeys` (`0x1c000fb28`), `ClusPoolReadReservationKeys` (`0x1c000fcfc`)

**Root Cause:** The unpatched realloc loop keeps a single cleanup pointer (`v4`). Each iteration allocates a new buffer, frees the previous `v4` at the top of the next iteration, then sets `v4 =` the new buffer. On the success path it sets `v4 = nullptr` before handing the buffer to the caller (`*a2 = buffer`), so the returned buffer is not freed; on every error path the current `v4` is freed once at the common exit label. Traced end-to-end, both the success and error paths free correctly and there is no double-free or use-after-free in single-threaded execution. The patched version restructures this into per-path handling — it frees the current buffer immediately on each error path and returns, and returns the buffer directly on success — and switches the allocator from `ExAllocatePoolWithTag(NonPagedPoolNx)` to `ExAllocatePool2` (`POOL_FLAG_NON_PAGED`, zero-initialized). This is a clarity/robustness refactor plus zero-initialization; the binaries do not show an exploitable aliasing window.

**Entry Point:** The disk device object is passed in and queried via `ClusPoolSendIoctl3` with control code `0x2d5018`. The loop starts with an initial buffer of `0x808` bytes for registrations (`i = 2056`) and `0x18` bytes for reservations (`i = 24`); if the returned PR data reports a key-list length larger than the current buffer, the loop reallocates (up to a `0x8000` cap) and retries. The reported length is a big-endian 32-bit value read from bytes `[4..7]` of the returned buffer.

**Call Chain:**
1. `ClusPoolReadRegistrationKeys` / `ClusPoolReadReservationKeys`
2. `ClusPoolSendIoctl3` (control code `0x2d5018`)
3. Disk storage stack → returns PR data

---

### Finding 3 — Pool::Arbitrate (LOW)

- **Severity:** Low (refactor / hardening — no demonstrable disclosure)
- **Class:** Allocation-API modernization; zero-initialization (CWE-457 avoidance)
- **Function:** `Pool::Arbitrate` (unpatched: `0x1c000addc`; patched: `0x140009778`)

**Root Cause:** The unpatched version allocates its handle arrays with `ExAllocatePoolWithTag((POOL_TYPE)0x200, ...)` (`NonPagedPoolNx`, tags `CdP4`/`CdP5`/`CdP6` = `0x34506443`/`0x35506443`/`0x36506443`), which does not zero the allocation. Immediately after a successful allocation the code stores the element count at offset 0, sets the element pointer to offset 8, and `memset`s the element region to zero when the count is non-zero. There is no path between the allocation and this initialization that returns the raw buffer to a caller, so the binaries do not show an actual disclosure of stale pool content. The patched version uses `ExAllocatePool2(POOL_FLAG_NON_PAGED = 0x40, ...)` (zero-initialized) and uses `CAutoArrayMemPtr` constructor/destructor calls to manage the arrays. This is an allocation-API modernization plus zero-init, not a fix for an observed leak.

Note: in **both** builds `Pool::Arbitrate` calls `SpacePortCallbackProxy::PrmGetNumberOfDevices` while holding the exclusive lock `this+0x40`. The lock-scope change described in Finding 1 was applied only to `Pool::PendDefenseIrp`, not here.

**Entry Point / Call Chain:** Reached through the pool device-control path (`ClusDskDeviceControl` → `ClusPoolDeviceControl`), which routes into `Pool::StartDefense` and then `Pool::Arbitrate`. The specific IOCTL numeric value is not established from the diff.

---

### Finding 4 — ClusPoolSendIoctl3 (INFORMATIONAL — not exploitable)

- **Severity:** Informational (no leak present in the unpatched build)
- **Class:** Refactor / allocation-API change (originally suspected CWE-401)
- **Function:** `ClusPoolSendIoctl3` (unpatched: `0x1c000f8e8`)

**Root Cause:** The unpatched `ClusPoolSendIoctl3` (`0x1c000f8e8`) frees its IRP through a single common `IoFreeIrp` at `0x1c000faf6`, so error paths converge on that free and the IRP is not leaked. The patched build (`0x140011xxx`) splits this into explicit per-path `IoFreeIrp` calls (`0x1400119d2`, `0x1400119fe`) and also changes the function's call signature (the callers pass 5 arguments instead of 8). This is a refactor and allocation-API change, not a leak fix. Treat as not exploitable.

---

## 3. Pseudocode Diff

### Pool::PendDefenseIrp — Before vs. After

```c
// ===== UNPATCHED (0x1c000ab5c) =====
__int64 Pool::PendDefenseIrp(Pool* this, _IRP* a2) {
    v2 = (char*)this + 64;                                   // this+0x40 (exclusive ERESOURCE)
    ExAcquireResourceExclusiveLite((char*)this + 64, 1);     // <--- LOCK FIRST
    v22 = 0; v21 = 0;
    NumberOfDevices = SpacePortCallbackProxy::PrmGetNumberOfDevices(
                          *((...***)this + 67),              // this+0x218 callback proxy
                          (_GUID*)((char*)this + 40),        // this+0x28
                          &v22, &v21);                       // <--- CALLBACK UNDER LOCK
    v7 = NumberOfDevices;
    if (NumberOfDevices < 0) {
        DoTraceReturn("Pool::PendDefenseIrp", 1637, NumberOfDevices);
        goto release_exclusive;                             // v8 = this+0x40 released at exit
    }
    v8 = (char*)this + 376;                                 // this+0x178 (shared ERESOURCE)
    v9 = (v21 + 1) >> 1;
    ExAcquireResourceSharedLite((char*)this + 376, 1);      // second lock
    // ... validate disk counts, queue defense IRP under ClusDskSpinLock ...
    if (v8) ExReleaseResourceLite(v8);
release_exclusive:
    if (v2) ExReleaseResourceLite(v2);
    return v7;
}

// ===== PATCHED (0x14000caf8) =====
__int64 Pool::PendDefenseIrp(Pool* this, _IRP* a2) {
    v21 = 0; v20 = 0;
    NumberOfDevices = SpacePortCallbackProxy::PrmGetNumberOfDevices(
                          *((SpacePortCallbackProxy**)this + 67),  // this+0x218
                          (_GUID*)((char*)this + 40),              // this+0x28
                          &v21, &v20);                             // <--- CALLBACK FIRST, NO LOCK
    v5 = NumberOfDevices;
    if (NumberOfDevices < 0) {
        DoTraceReturn("Pool::PendDefenseIrp", 98, NumberOfDevices);
        return v5;                                          // <--- early return, no lock taken
    }
    v7 = (char*)this + 64;                                  // this+0x40
    v8 = (v20 + 1) >> 1;
    ExAcquireResourceExclusiveLite((char*)this + 64, 1);    // <--- LOCK AFTER callback
    v9 = (char*)this + 376;
    ExAcquireResourceSharedLite((char*)this + 376, 1);      // this+0x178
    // ... validate disk counts, queue defense IRP under ClusDskSpinLock ...
    // both resources released before return
    return v5;
}
```

### ClusPoolReadRegistrationKeys — Before vs. After (realloc loop)

```c
// ===== UNPATCHED (0x1c000fb28) =====
v4 = nullptr;                                  // single cleanup pointer
for (i = 2056; ; i = keycount + 8) {           // initial buffer 0x808
    memset(scratch, 0, 48);
    buf = ExAllocatePoolWithTag((POOL_TYPE)512, i, 'CdS0');  // 0x30536443, NOT zeroed
    if (v4) ExFreePoolWithTag(v4, 0);          // free previous buffer
    v4 = buf;
    if (!buf) { rc = -1073741670; goto trace_exit; }
    rc = ClusPoolSendIoctl3(DeviceObject, 0x2D5018, ..., buf, i, &outlen);
    if (rc < 0) goto trace_exit;               // v4 (== buf) freed at exit
    keycount = be32(buf[4..7]);                // big-endian length
    if (keycount + 8 <= i) break;              // enough space -> validate below
    if (keycount + 8 > 0x8000) { rc = -1073741670; goto trace_exit; }
    // else loop and reallocate at size keycount+8
}
if (outlen >= 8 && be32(buf[4..7]) <= outlen - 8) {
    v4 = nullptr;                              // so returned buffer is NOT freed
    *a2 = buf;                                 // hand buffer to caller
    rc = 0;
}                                              // else rc = STATUS_INVALID_PARAMETER
trace_exit:
    if (v4) ExFreePoolWithTag(v4, 0);          // frees current buffer on error paths
    return rc;

// ===== PATCHED (0x140010e00) =====
v2 = nullptr;
for (i = 2056; ; i = keycount + 8) {
    buf = ExAllocatePool2(64, i, 0x30536443);  // POOL_FLAG_NON_PAGED, zero-init
    if (v2) ExFreePoolWithTag(v2, 0);          // free previous buffer
    v2 = buf;
    if (!buf) break;                           // -> trace + return at bottom
    rc = ClusPoolSendIoctl3(DeviceObject, 48, buf, i, scratch);  // 5-arg form
    if (rc < 0) goto free_and_return;          // frees buf, returns
    keycount = be32(buf[4..7]);
    if (keycount + 8 <= i) {
        if (outlen >= 8 && be32(buf[4..7]) <= outlen - 8) {
            *a2 = buf;                          // hand to caller (not freed)
            return 0;
        }
        rc = -1073741823; goto free_and_return; // validation failure frees buf
    }
    if (keycount + 8 > 0x8000) {
free_and_return:
        DoTraceReturn("ClusPoolReadRegistrationKeys", ...);
        ExFreePoolWithTag(buf, 0);             // immediate free on each error path
        return rc;
    }
}
DoTraceReturn("ClusPoolReadRegistrationKeys", 158, -1073741670);
return -1073741670;                            // allocation-failure exit
```

### Pool::Arbitrate — Allocation Difference

```c
// ===== UNPATCHED (0x1c000addc) =====
buf = ExAllocatePoolWithTag((POOL_TYPE)512, NumberOfBytes, 'CdP4'); // 0x34506443, NOT zeroed
if (buf) {
    *buf = count;                  // store count at offset 0
    elems = &buf[1];               // array data at offset 8
    if (count)
        memset(elems, 0, count << 3); // zero the element region
}
// buf is not returned raw to any caller before this initialization runs.

// ===== PATCHED (0x140009778) =====
// Two CAutoArrayMemPtr handle-array wrappers are default-constructed first:
v17 = &wrapperA;
do {
    CAutoArrayMemPtr<CAutoHandle<_FILE_OBJECT*>>::CAutoArrayMemPtr(v17++);
} while (--n != 0);
// ... then the element buffer is allocated zero-initialized:
buf = ExAllocatePool2(64, NumberOfBytes, 0x34506443);  // POOL_FLAG_NON_PAGED, zero-init
if (buf)
    *buf = count;                  // store count at offset 0
```

---

## 4. Assembly Analysis

### Pool::PendDefenseIrp — Unpatched Assembly (annotated)

```asm
; Unpatched: 0x1C000AB5C
00000001C000AB5C  push    rbx
00000001C000AB5E  push    rbp
00000001C000AB5F  push    rsi
00000001C000AB60  push    rdi
00000001C000AB61  push    r14
00000001C000AB63  sub     rsp, 30h
00000001C000AB67  lea     rdi, [rcx+40h]        ; rdi = this+0x40 (exclusive ERESOURCE)
00000001C000AB6B  mov     r14, rdx              ; r14 = a2 (IRP)
00000001C000AB6E  mov     rbp, rcx              ; rbp = this
00000001C000AB71  mov     dl, 1                 ; Wait
00000001C000AB73  mov     rcx, rdi              ; Resource = this+0x40
00000001C000AB76  call    cs:__imp_ExAcquireResourceExclusiveLite  ; *** EXCLUSIVE LOCK ACQUIRED ***
00000001C000AB82  mov     rcx, [rbp+218h]       ; SpacePort callback proxy context
00000001C000AB89  lea     rdx, [rbp+28h]        ; this+0x28 (_GUID*)
00000001C000AB92  lea     r9, [rsp+58h+arg_8]
00000001C000AB9C  lea     r8, [rsp+58h+arg_10]
00000001C000ABA1  mov     rbx, [r14+0B8h]
00000001C000ABA8  call    ?PrmGetNumberOfDevices@SpacePortCallbackProxy@@...  ; *** callback runs under exclusive lock ***
00000001C000ABAD  mov     esi, eax
00000001C000ABAF  test    eax, eax
00000001C000ABB1  jns     short loc_1C000ABCC   ; continue if success
; ... error path: DoTraceReturn, then release this+0x40 and return ...

; At 0x1C000ABCC (success continuation) — second lock is the SHARED resource this+0x178:
00000001C000ABD0  lea     rbx, [rbp+178h]       ; this+0x178 (shared ERESOURCE)
00000001C000ABD9  mov     dl, 1                 ; Wait
00000001C000ABDB  mov     rcx, rbx              ; Resource = this+0x178
00000001C000ABE0  call    cs:__imp_ExAcquireResourceSharedLite
```

### Pool::PendDefenseIrp — Patched Assembly (annotated)

```asm
; Patched: 0x14000CAF8
000000014000CAF8  mov     rax, rsp
000000014000CAFB  push    rbx
000000014000CAFC  push    rbp
000000014000CAFD  push    rsi
000000014000CAFE  push    rdi
000000014000CAFF  push    r14
000000014000CB01  sub     rsp, 30h
000000014000CB05  mov     rdi, [rdx+0B8h]
000000014000CB0C  lea     r9, [rax+10h]
000000014000CB10  mov     r14, rdx              ; r14 = a2 (IRP)
000000014000CB1A  lea     rdx, [rcx+28h]        ; this+0x28 (_GUID*)
000000014000CB25  mov     rbp, rcx              ; rbp = this
000000014000CB28  lea     r8, [rax+18h]
000000014000CB2C  mov     rcx, [rcx+218h]       ; SpacePort callback proxy context
000000014000CB33  call    ?PrmGetNumberOfDevices@SpacePortCallbackProxy@@...  ; *** NO LOCK HELD ***
000000014000CB38  mov     ebx, eax
000000014000CB3A  test    eax, eax
000000014000CB3C  jns     short loc_14000CB60   ; continue if success
000000014000CB3E  mov     r8d, eax
000000014000CB41  lea     rcx, aPoolPenddefens  ; "Pool::PendDefenseIrp"
000000014000CB48  mov     edx, 662h
000000014000CB4D  call    ?DoTraceReturn@@YAXPEBDIJ@Z
000000014000CB52  mov     eax, ebx
000000014000CB54  add     rsp, 30h              ; *** early return on callback failure ***
000000014000CB58  pop     r14
;      ... pop rdi/rsi/rbp/rbx ; retn

; loc_14000CB60 — only AFTER callback success are the locks taken:
000000014000CB64  lea     rbx, [rbp+40h]        ; this+0x40 (exclusive ERESOURCE)
000000014000CB6A  mov     dl, 1                 ; Wait
000000014000CB6C  mov     rcx, rbx              ; Resource = this+0x40
000000014000CB71  call    cs:__imp_ExAcquireResourceExclusiveLite  ; *** LOCK AFTER callback ***
000000014000CB7D  lea     rdi, [rbp+178h]       ; this+0x178 (shared ERESOURCE)
000000014000CB86  mov     rcx, rdi
000000014000CB89  call    cs:__imp_ExAcquireResourceSharedLite
```

### Pool::Arbitrate — Unpatched Allocation Path

```asm
; Unpatched: first handle-array allocation (0x1C000AF01..)
00000001C000AF01  mov     r8d, 34506443h        ; Tag 'CdP4'
00000001C000AF07  cmovo   rax, rcx
00000001C000AF0B  add     rax, 8
00000001C000AF0F  cmovb   rax, rcx
00000001C000AF13  mov     ecx, 200h             ; PoolType = NonPagedPoolNx (no zero-init)
00000001C000AF18  mov     rdx, rax              ; NumberOfBytes
00000001C000AF1B  call    cs:__imp_ExAllocatePoolWithTag
00000001C000AF27  test    rax, rax
00000001C000AF2A  jz      short loc_1C000AF49
00000001C000AF2C  mov     [rax], rsi            ; store count at offset 0
00000001C000AF2F  lea     r12, [rax+8]          ; array data at offset 8
00000001C000AF33  test    rsi, rsi
00000001C000AF36  jz      short loc_1C000AF49
00000001C000AF38  shl     rsi, 3
00000001C000AF3C  xor     edx, edx              ; Val = 0
00000001C000AF3E  mov     r8, rsi               ; Size = count*8
00000001C000AF41  mov     rcx, r12
00000001C000AF44  call    memset                ; zero the element region
```

### Pool::Arbitrate — Patched Allocation Path

```asm
; Patched: CAutoArrayMemPtr construction loop, then zero-init allocation
0000000140009873  lea     rdi, [rbp+57h+var_C8]
0000000140009877  mov     rcx, rdi
000000014000987A  call    ??0?$CAutoArrayMemPtr@...@@QEAA@XZ   ; CAutoArrayMemPtr<CAutoHandle<_FILE_OBJECT*>> ctor
000000014000987F  add     rdi, 8
0000000140009883  sub     r12, 1
0000000140009887  jnz     short loc_140009877   ; loop over the wrappers
; ... element buffer allocation:
000000014000992E  mov     r8d, 34506443h        ; Tag 'CdP4'
0000000140009940  mov     ecx, 40h              ; POOL_FLAG_NON_PAGED — zero-init by default
0000000140009945  mov     rdx, rax              ; NumberOfBytes
0000000140009948  call    cs:__imp_ExAllocatePool2
0000000140009954  mov     r12, rax
0000000140009959  test    r12, r12
000000014000995C  jz      short loc_14000998A
000000014000995E  mov     [r12], r14            ; store count at offset 0
```

---

## 5. Trigger Conditions

### Finding 1 — Pool::PendDefenseIrp Callback Under Lock

What the binaries establish is only the structural change: in the unpatched build the exclusive resource `this+0x40` is held across `SpacePortCallbackProxy::PrmGetNumberOfDevices`, and in the patched build it is not. A concrete trigger for observable misbehavior is **not** established by the diff, for two reasons:

1. **Re-entrancy is unproven.** Whether `PrmGetNumberOfDevices` can synchronously re-enter `clusdisk.sys` on a path that re-acquires `this+0x40` is not visible in this diff.
2. **The sibling contradicts a hard deadlock.** `Pool::Arbitrate` holds `this+0x40` exclusive across the same callback in both the unpatched and patched builds. If that pattern reliably self-deadlocked, `Pool::Arbitrate` would deadlock too and would not have been left unchanged.

To observe the difference in a lab, one would reach `Pool::PendDefenseIrp` through the pool device-control path and break at `0x1C000AB76` (lock) and `0x1C000ABA8` (callback) to confirm the lock is held across the callback in the unpatched build, versus the patched order at `0x14000CB33` (callback) then `0x14000CB71` (lock). Contention or a hang would only appear if a second thread on the same `Pool` blocks on `this+0x40` while the callback runs — which requires the re-entrancy in point 1 to actually exist.

### Finding 2 — ClusPoolReadRegistrationKeys / ReservationKeys

The realloc loop can be exercised by returning PR data whose reported key-list length (big-endian dword at buffer bytes `[4..7]`) exceeds the current buffer (`0x808` for registrations, `0x18` for reservations) but stays `≤ 0x8000`. Doing so forces the loop to reallocate and retry. Tracing both builds, the previous buffer is freed at the top of the next iteration, the returned buffer is not double-freed, and error paths free exactly once. No bugcheck is expected in either build from this path; the patched change is a refactor plus zero-initialized allocation, not a memory-safety fix.

### Finding 3 — Pool::Arbitrate

The unpatched handle-array allocation (`ExAllocatePoolWithTag`, `NonPagedPoolNx`) is initialized immediately after a successful allocation: the count is stored at offset 0 and the element region is `memset` to zero. There is no path that returns the raw buffer to a caller before this initialization, so no stale-pool disclosure is demonstrable. The patched change swaps the allocator to `ExAllocatePool2` (zero-initialized) and wraps the arrays in `CAutoArrayMemPtr` — a hardening/refactor, not a fix for an observed leak.

---

## 6. Exploit Primitive & Development Notes

### Finding 1 — Lock scope change

- **What the patch does:** Removes the exclusive resource `this+0x40` from being held across the `PrmGetNumberOfDevices` callback. This shortens the critical section and avoids holding a pool-wide exclusive lock across an external subsystem call.
- **Primitive:** None demonstrated. A denial of service via re-entrant self-deadlock is conceivable but is not proven by the binaries, and is contradicted by `Pool::Arbitrate` retaining the lock-across-callback pattern in both builds. No state-corruption or write primitive is supported by the diff.

### Finding 2 — Allocation refactor

- **Primitive:** None. Both builds free the PR-key buffers correctly; there is no use-after-free or double-free to leverage. The patched build additionally zero-initializes via `ExAllocatePool2`.

### Finding 3 — Allocation refactor

- **Primitive:** None demonstrated. The unpatched handle array is initialized (count stored, elements `memset` to zero) immediately after allocation and is not exposed raw to a caller. The patched build zero-initializes via `ExAllocatePool2`.

---

## 7. Debugger PoC Playbook

### Finding 1 — Pool::PendDefenseIrp

**Breakpoints:**

```windbg
; Break at function entry
bp clusdisk_unpatched!Pool::PendDefenseIrp
; Alternative by offset:
bp 0x1c000ab5c

; Break at the vulnerable callback (lock held at this point)
bp clusdisk_unpatched!SpacePortCallbackProxy::PrmGetNumberOfDevices
; Alternative by offset:
bp 0x1c0008fa8

; Break at the lock acquisition to confirm ordering
bp 0x1c000ab76    ; call ExAcquireResourceExclusiveLite
```

**What to inspect:**

| Breakpoint | Register/Memory | Purpose |
|---|---|---|
| `0x1c000ab5c` (entry) | `rcx` = `this` (Pool object) | Confirm Pool object pointer |
| `0x1c000ab76` (lock acquire) | `rcx` = `this+0x40` (ERESOURCE) | Verify lock target |
| `0x1c000aba8` (callback) | `rcx` = `[this+0x218]` (callback proxy ctx) | Callback runs here; in the unpatched build `this+0x40` is held |
| Post-callback | `!thread` on all threads | Check whether any other thread blocks in `ExAcquireResourceExclusiveLite` on the same ERESOURCE |

**Key command at the lock breakpoint (`0x1c000ab76`, `rcx` = `this+0x40`):**

```windbg
!locks @rcx                  ; dump ERESOURCE state — note ExclusiveOwnerThread
dt _ERESOURCE @rcx           ; ActiveCount, ExclusiveOwnerThread, ContentionCount
```

**Key offsets:**

| Offset | Instruction | Significance |
|---|---|---|
| `0x1c000ab76` | `call cs:__imp_ExAcquireResourceExclusiveLite` | Exclusive lock acquired (`this+0x40`) |
| `0x1c000aba8` | `call PrmGetNumberOfDevices` | Callback runs while `this+0x40` is held |
| `0x1c000abe0` | `call cs:__imp_ExAcquireResourceSharedLite` | Second lock (`this+0x178`, shared) |

Compare with the patched build: callback at `0x14000cb33` (no lock), exclusive lock at `0x14000cb71`, shared lock at `0x14000cb89`.

**Trigger:** Reach `Pool::PendDefenseIrp` through the pool device-control path. The exact IOCTL numeric value and input-structure layout are not established from this diff and would have to be recovered from the routing in `ClusPoolDeviceControl` before writing a user-mode trigger.

**Expected observation:** The lock is held across the callback in the unpatched build and not in the patched build. Whether this produces a hang depends on a second thread blocking on `this+0x40` during the callback, which in turn depends on re-entrancy that this diff does not confirm. No specific bugcheck is asserted.

---

### Finding 2 — ClusPoolReadRegistrationKeys

**Breakpoints:**

```windbg
bp clusdisk_unpatched!ClusPoolReadRegistrationKeys   ; 0x1c000fb28
bp clusdisk_unpatched!ClusPoolReadReservationKeys    ; 0x1c000fcfc
bp 0x1c000fb7f    ; ExAllocatePoolWithTag — allocation (rax -> rsi)
bp 0x1c000fb98    ; ExFreePoolWithTag — free of previous buffer (rcx = rbx)
bp 0x1c000fba4    ; mov rbx, rsi — cleanup pointer set to new buffer
bp 0x1c000fc31    ; mov r14d, eax — realloc size (keycount+8)
bp 0x1c000fc00    ; key length read from buffer bytes [4..7]
```

**What to inspect:**

| Register | Meaning |
|---|---|
| `r14d` | Current buffer allocation size (starts `0x808` reg / `0x18` res) |
| `rsi` | Pool pointer for the current buffer (`rax` from the allocation, moved to `rsi`) |
| `[rsi+4]..[rsi+7]` | Big-endian key-list length read back from the buffer |
| `[rsp+0x54]` (`var_5C`) | IOCTL output length from the storage stack |

**Key command at the length read (`0x1c000fc00`):**

```windbg
db @rsi L8             ; dump buffer header — length is the big-endian dword at offset 4
; keycount = (rsi[4]<<24)|(rsi[5]<<16)|(rsi[6]<<8)|rsi[7]
```

**Trigger:** Return PR data where the big-endian length at bytes `[4..7]` makes `keycount + 8 > current_buffer_size` but `≤ 0x8000`, forcing the loop to reallocate at `keycount + 8`.

**Expected observation:** The loop reallocates and retries; the previous buffer is freed once at the top of the next iteration and the final buffer is freed once (or handed to the caller). No double-free or use-after-free occurs in either build. Pool tag `0x30536443` ("CdS0") for registrations, `0x31536443` ("CdS1") for reservations.

---

### Finding 3 — Pool::Arbitrate

**Breakpoints:**

```windbg
bp clusdisk_unpatched!Pool::Arbitrate              ; 0x1c000addc
bp 0x1c000af1b    ; ExAllocatePoolWithTag — first handle array
bp 0x1c000af44    ; memset — element zeroing (check pre-zero state)
bp 0x1c000af9e    ; second allocation (tag 0x35506443)
bp 0x1c000b085    ; third allocation (tag 0x36506443)
```

**What to inspect at `0x1c000af1b` (post-allocation):**

```windbg
db @rax L40          ; dump first 64 bytes — look for stale kernel pointers
!pool @rax           ; pool header info
```

Between `0x1c000af1b` (allocation returns) and `0x1c000af44` (memset) the element region is uninitialized, but the code path in between only stores the count and computes the element pointer — it does not return the buffer to a caller. The `memset` runs before any use of the elements.

**Trigger:** Reach `Pool::Arbitrate` through the pool device-control path (`Pool::StartDefense`). The exact IOCTL numeric value is not established from this diff.

**Expected observation:** The allocated element region is zeroed by the `memset` at `0x1c000af44` before use. The patched build allocates with `ExAllocatePool2` (`0x1400099x`), which zero-initializes, removing the transient uninitialized window. No leak to a caller is demonstrable in either build.

---

## 8. Changed Functions — Full Triage

| Function | Similarity | Change Type | Note |
|---|---|---|---|
| `Pool::PendDefenseIrp` | 0.841 | **Security** | Exclusive lock `this+0x40` no longer held across the `PrmGetNumberOfDevices` callback (callback moved before the lock; early return on failure) |
| `Pool::Arbitrate` | 0.5074 | Hardening | `ExAllocatePoolWithTag(NonPagedPoolNx)`→`ExAllocatePool2` (zero-init); handle arrays wrapped in `CAutoArrayMemPtr`. Still holds `this+0x40` across the callback in both builds |
| `ClusPoolReadRegistrationKeys` | 0.8423 | Hardening | Error-path free restructured (frees per path instead of at a common exit); `ExAllocatePool2`. No memory-safety bug in either build |
| `ClusPoolReadReservationKeys` | 0.843 | Hardening | Same pattern as registration keys; initial buffer only `0x18` bytes |
| `ClusPoolDeviceControl` | 0.759 | Behavioral | Changed function; not analyzed in detail in this report |
| `ClusDskDeviceControl` | 0.8066 | Behavioral | Changed function; not analyzed in detail in this report |
| `Disk::IncrementDirtyPrCount` | 0.726 | Behavioral | Changed function; not analyzed in detail in this report |
| `Disk::ScrubRegistrations` | 0.829 | Behavioral | Changed function; not analyzed in detail in this report |
| `ClusPoolSendIoctl3` | 0.8341 | Behavioral | Allocation-API change and a changed call signature (5-arg form in the patched build); see Finding 4 |
| `Pool::StartDefense` | 0.6988 | Behavioral | Restructuring alongside `Pool::Arbitrate`; allocation-API and cleanup changes |
| `Disk::PreemptAbort` | 0.5228 | Cosmetic | Changed function; not analyzed in detail in this report |
| `ClusDskpDetachDisk` | 0.9514 | Cosmetic | Changed function; not analyzed in detail in this report |

The similarity values above are carried from the diff summary. Only `Pool::PendDefenseIrp` shows a clear security-relevant behavioral change; the remaining rows are allocation-API modernization, refactoring, or changes not analyzed in depth here.

---

## 9. Unmatched Functions

**Removed:** None.
**Added:** None.

No functions were entirely added or removed. All changes are within existing function bodies, confirming this is a targeted patch of existing logic rather than introduction of new security modules.

---

## 10. Confidence & Caveats

| Finding | Confidence | Rationale |
|---|---|---|
| `Pool::PendDefenseIrp` lock-scope change | **High (change), Low (impact)** | The before/after is unambiguous: the exclusive lock `this+0x40` is held across `PrmGetNumberOfDevices` in the unpatched build and acquired after the callback in the patched build. The security impact (deadlock/contention) is unproven and is undercut by `Pool::Arbitrate` keeping the same lock-across-callback pattern in both builds. |
| `ClusPoolReadRegistrationKeys/ReservationKeys` | **Low** | No use-after-free or double-free in either build; both free correctly. The change is error-path restructuring plus `ExAllocatePool2` zero-init. |
| `Pool::Arbitrate` allocation | **Low** | `NonPagedPoolNx` is non-zeroing, but the element region is `memset` before use and the raw buffer is not exposed to a caller. The change is allocation-API modernization plus `CAutoArrayMemPtr` wrappers. |
| `ClusPoolSendIoctl3` IRP leak | **Low** | The unpatched fall-through path reaches `IoFreeIrp`; likely a false positive. The observable change is the allocation API and a changed call signature. |

**Assumptions / not established by this diff:**
- The exact IOCTL numeric values and input-structure layouts that reach `Pool::PendDefenseIrp`, `Pool::Arbitrate`, and `Pool::StartDefense` are not recovered here; they would come from the routing in `ClusPoolDeviceControl` / `ClusDskDeviceControl`.
- Whether `SpacePortCallbackProxy::PrmGetNumberOfDevices` can synchronously re-enter `clusdisk.sys` on a path that re-acquires `this+0x40` is not visible in this diff. This is the crux of any deadlock/contention claim for Finding 1 and remains unconfirmed.
- Addresses prefixed `0x1c000xxxx` are from the unpatched image; `0x14000xxxx` from the patched image.

**Open questions:**
1. Confirm whether `PrmGetNumberOfDevices` can re-enter `clusdisk.sys` and re-acquire `this+0x40`; without this, Finding 1 is a lock-scope hardening rather than a deadlock fix.
2. Recover the IOCTL routing to establish which control codes reach the pool defense/arbitration functions.
