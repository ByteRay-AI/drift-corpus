Title: hvsocket.sys — Feature-gated loopback endpoint use-after-free / race in teardown (CWE-416/CWE-362) fixed
Date: 2026-06-29
Slug: hvsocket_d35b6e34-hvsocket-report-20260629-005917
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview

| Field | Value |
|-------|-------|
| Unpatched binary | `hvsocket_unpatched.sys` |
| Patched binary | `hvsocket_patched.sys` |
| Overall similarity | 0.9678 |
| Matched functions | 269 |
| Changed functions | 9 |
| Identical functions | 260 |
| Unmatched (unpatched) | 0 |
| Unmatched (patched) | 0 |

**Verdict:** The patch removes the WIL feature gate `EvaluateCurrentState` (`0x1C0001D78`) from 9 loopback-transport functions. In the unpatched build the gate selects between a legacy path that touches the single pending-loopback-entry pointer at `endpoint+0x2b8` **without a lock or a reference count**, and a newer path that reads that pointer under the endpoint spinlock and takes a reference before use. Removing the gate makes the reference-counted, spinlock-synchronized path the only path, closing a use-after-free / race window against concurrent loopback teardown (CWE-416 / CWE-362). This is a synchronization fix, not a double-free. Its real-world reachability depends on the runtime default of the feature, which cannot be determined from the static image alone.

---

## 2. Vulnerability Summary

### Finding 1 — Unsynchronized pending-entry access in `VmbusTlLoopbackDisconnect`

| Field | Detail |
|-------|--------|
| **Severity** | Medium |
| **Class** | Race condition / use-after-free (CWE-362 / CWE-416) |
| **Function** | `VmbusTlLoopbackDisconnect` (unpatched `0x1C0006C30`, patched `0x1C00068B0`) |

**What actually changed.** In the unpatched build the endpoint spinlock at `endpoint+0x48` is acquired and released only when `EvaluateCurrentState` returns true. The read-and-clear of the pending loopback entry pointer at `endpoint+0x2b8` (`mov rsi, [rbx+2B8h]` / `and qword [rbx+2B8h], 0`) therefore runs without the spinlock on the legacy path. The patch removes the gate and acquires/releases the spinlock unconditionally, and unconditionally clears the peer back-reference `*(entry+0x68)`.

**No double-free is present.** On both builds the function reads two **distinct** objects and releases each exactly once:

- `rsi = *(endpoint+0x2b8)` — call it object **A** (the pending loopback entry).
- `rbp = *(A+0x68)` — call it object **B** (the peer object A points to at offset `0x68`).

A and B are separate `'Vnpi'`-tagged allocations with the same layout. The function decrements A's reference count (`lock xadd [rsi+8]`) and frees A at `0x1C0006EBC` only if A's count reaches zero, and independently decrements B's reference count (`lock xadd [rbp+8]`) and frees B at `0x1C0006DF1` only if B's count reaches zero. Neither pointer is freed twice. The `and qword [rsi+68h], 0` instruction zeroes A's `+0x68` field (its pointer to B); it does **not** zero `rsi` itself, which continues to hold object A through its own teardown.

**Entry point and data flow:**

1. A user-mode application closes an `AF_HYPERV` socket that has a pending loopback entry stored at `endpoint+0x2b8`.
2. `hvsocket.sys` endpoint teardown reaches `VmbusTlLoopbackDisconnect`.
3. On the legacy (gate-false) path, `endpoint+0x2b8` is read and cleared without the endpoint spinlock, so a concurrent thread that reads the same slot (see Findings 2–3) can observe or race the teardown.

---

### Finding 2 — Unreferenced pending-entry read in `VmbusTlLoopbackNotifyReceiveConsumed`

| Field | Detail |
|-------|--------|
| **Severity** | Medium |
| **Class** | Use-after-free / race condition (CWE-416 / CWE-362) |
| **Function** | `VmbusTlLoopbackNotifyReceiveConsumed` (unpatched `0x1C0006F50`, patched `0x1C0006BB0`) |

**Root cause.** When `EvaluateCurrentState` returns true, the function calls `VmbusTlLoopbackReferenceEndpointDeliveryQueue` (`0x1C0007128`), which acquires the endpoint spinlock, reads `endpoint+0x2b8`, increments the entry's reference count under the lock, and releases the lock. When the gate returns false (legacy path at `0x1C00070A3`), the function instead reads `rdi = *(endpoint+0x2b8)` directly, dereferences `*(rdi+0x68)` (the peer object), acquires that peer's spinlock at `+0x48`, and sets `*(peer+0x210) |= 2` — all without taking a reference on the entry first. A concurrent `VmbusTlLoopbackDisconnect` can drop the last reference and free the entry between the unlocked read and the dereference. The patch always uses the referenced path.

---

### Finding 3 — Unreferenced pending-entry read in `VmbusTlLoopbackSend`

| Field | Detail |
|-------|--------|
| **Severity** | Medium |
| **Class** | Use-after-free / race condition (CWE-416 / CWE-362) |
| **Function** | `VmbusTlLoopbackSend` (unpatched `0x1C00065EC`, patched `0x1C00062A4`) |

**Root cause.** Same pattern. On the gate-true path, `rbx = VmbusTlLoopbackReferenceEndpointDeliveryQueue(endpoint)` returns a referenced entry (with a null check). On the legacy gate-false path at `0x1C0006640`, `rbx = *(endpoint+0x2b8)` is read raw with no reference and no null check, then later dereferenced (`mov rax, [rbx+68h]` at `0x1C00066CD`). A concurrent disconnect/close can free the entry mid-operation. The patch always uses the referenced path.

---

### Finding 4 — Feature-gated single-slot store in `VmbusTlLoopbackAcceptConnection` / `VmbusTlLoopbackSetupConnection`

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Class** | Race condition (CWE-362) |
| **Functions** | `VmbusTlLoopbackAcceptConnection` (`0x1C001B630`), `VmbusTlLoopbackSetupConnection` (`0x1C001B1D0`) |

**Root cause.** These functions create the `0x70`-byte `'Vnpi'` entry (`VmbusTlCreateObject`, size `0x70`) and publish it into `endpoint+0x2b8`. `EvaluateCurrentState` gates parts of the setup/teardown around this store (2 gate calls in `VmbusTlLoopbackSetupConnection`, 3 in `VmbusTlLoopbackAcceptConnection`). Removing the gate makes the surrounding critical-region and mutex handling unconditional so publication and teardown of the slot follow one consistent locking discipline. This is the write side of the same synchronization change addressed in Findings 1–3.

---

### Finding 5 — Feature-gated cleanup path in `VmbusTlLoopbackSetupConnection` / `VmbusTlLoopbackAcceptConnection`

| Field | Detail |
|-------|--------|
| **Severity** | Informational (defense-in-depth) |
| **Class** | Lock-handling consistency |
| **Functions** | `VmbusTlLoopbackSetupConnection` (`0x1C001B1D0`), `VmbusTlLoopbackAcceptConnection` (`0x1C001B630`) |

**Root cause.** The gate also guarded cleanup-time `ExReleaseFastMutexUnsafe` / `KeLeaveCriticalRegion` and object dereference in the setup/accept paths. Removing the gate makes acquisition and release unconditional and symmetric. A lock imbalance would require the gate to evaluate differently between the matched acquire and release within a single call; because both are guarded by the same runtime feature evaluation, this is not a demonstrable imbalance in either build. The change is best read as making the locking discipline unconditional (defense-in-depth), not fixing a live deadlock.

---

## 3. Pseudocode Diff

### Finding 1 — `VmbusTlLoopbackDisconnect`

```c
// ==================== UNPATCHED ====================
void VmbusTlLoopbackDisconnect(ENDPOINT* ep)
{
    KeEnterCriticalRegion();
    ExAcquireFastMutexUnsafe(&ep->mutex);            // ep+0x10

    if (EvaluateCurrentState())                      // WIL feature gate
        oldirql = KeAcquireSpinLockRaiseToDpc(&ep->spinlock); // ep+0x48

    ENTRY* A = *(ep + 0x2b8);                         // pending loopback entry
    *(ep + 0x2b8) = NULL;

    ENTRY* B;
    if (A != NULL) {
        B = *(A + 0x68);                              // peer object (DISTINCT from A)
        if (EvaluateCurrentState())
            *(A + 0x68) = NULL;                       // clear back-reference (gated)
    } else {
        B = NULL;
    }

    if (EvaluateCurrentState())
        KeReleaseSpinLock(&ep->spinlock, oldirql);
    ExReleaseFastMutexUnsafe(&ep->mutex);
    KeLeaveCriticalRegion();

    // B teardown: decrement B refcount; free B (0x1C0006DF1) only if it hits zero
    // A teardown: decrement A refcount; free A (0x1C0006EBC) only if it hits zero
    // A and B are separate allocations, each freed at most once.
}

// ==================== PATCHED ====================
void VmbusTlLoopbackDisconnect(ENDPOINT* ep)
{
    KeEnterCriticalRegion();
    ExAcquireFastMutexUnsafe(&ep->mutex);
    oldirql = KeAcquireSpinLockRaiseToDpc(&ep->spinlock);  // always

    ENTRY* A = *(ep + 0x2b8);
    *(ep + 0x2b8) = NULL;

    ENTRY* B;
    if (A != NULL) {
        B = *(A + 0x68);
        *(A + 0x68) = NULL;                           // always cleared
    } else {
        B = NULL;
    }

    KeReleaseSpinLock(&ep->spinlock, oldirql);        // always
    ExReleaseFastMutexUnsafe(&ep->mutex);
    KeLeaveCriticalRegion();

    // identical B and A teardown as above
}
```

### Finding 2 — `VmbusTlLoopbackNotifyReceiveConsumed`

```c
// ==================== UNPATCHED ====================
void VmbusTlLoopbackNotifyReceiveConsumed(ENDPOINT* ep)
{
    if (EvaluateCurrentState()) {                     // gate true: safe path
        ENTRY* e = VmbusTlLoopbackReferenceEndpointDeliveryQueue(ep); // locked + refcounted
        if (!e) return;
        void* peer = *(e + 0x68);
        KeAcquireSpinLockRaiseToDpc(peer + 0x48);
        *(peer + 0x210) |= 2;
        // ... release reference ...
    } else {                                          // gate false: legacy path
        void* e = *(ep + 0x2b8);                       // UNLOCKED, UNREFERENCED read
        if (e) {
            void* peer = *(e + 0x68);                   // may already be freed
            KeAcquireSpinLockRaiseToDpc(peer + 0x48);
            *(peer + 0x210) |= 2;
        }
    }
}

// ==================== PATCHED ====================
void VmbusTlLoopbackNotifyReceiveConsumed(ENDPOINT* ep)
{
    ENTRY* e = VmbusTlLoopbackReferenceEndpointDeliveryQueue(ep); // always locked + refcounted
    if (!e) return;
    // ... safe access with proper lock + refcount ...
}
```

---

## 4. Assembly Analysis

### Finding 1 — `VmbusTlLoopbackDisconnect` (unpatched `0x1C0006C30`)

```
; ---- prologue ----
00000001C0006C30  mov     rax, rsp
00000001C0006C4D  mov     rbx, rcx                    ; rbx = endpoint
00000001C0006C50  xor     dil, dil
00000001C0006C53  call    cs:__imp_KeEnterCriticalRegion
00000001C0006C5F  lea     rcx, [rbx+10h]              ; FastMutex
00000001C0006C63  call    cs:__imp_ExAcquireFastMutexUnsafe
00000001C0006C6F  call    EvaluateCurrentState        ; WIL feature gate #1
00000001C0006C74  test    eax, eax
00000001C0006C76  jz      short loc_1C0006C8B         ; gate false -> skip spinlock
00000001C0006C78  lea     rcx, [rbx+48h]              ; SpinLock
00000001C0006C7C  call    cs:__imp_KeAcquireSpinLockRaiseToDpc
00000001C0006C88  mov     dil, al                     ; save old IRQL

; ---- read/clear pending entry (A) and read peer (B) ----
00000001C0006C8B  mov     rsi, [rbx+2B8h]             ; rsi = A = *(endpoint+0x2b8)
00000001C0006C92  and     qword ptr [rbx+2B8h], 0     ; clear slot
00000001C0006C9A  test    rsi, rsi
00000001C0006C9D  jz      short loc_1C0006CB3
00000001C0006C9F  mov     rbp, [rsi+68h]             ; rbp = B = *(A+0x68)  (DISTINCT object)
00000001C0006CA3  call    EvaluateCurrentState        ; gate #2
00000001C0006CA8  test    eax, eax
00000001C0006CAA  jz      short loc_1C0006CB5
00000001C0006CAC  and     qword ptr [rsi+68h], 0      ; clear A's back-ref to B (gated)
00000001C0006CB1  jmp     short loc_1C0006CB5
00000001C0006CB3  xor     ebp, ebp                    ; B = NULL

; ---- release locks ----
00000001C0006CB5  call    EvaluateCurrentState        ; gate #3
00000001C0006CBA  test    eax, eax
00000001C0006CBC  jz      short loc_1C0006CD1
00000001C0006CC1  lea     rcx, [rbx+48h]
00000001C0006CC5  call    cs:__imp_KeReleaseSpinLock
00000001C0006CD1  lea     rcx, [rbx+10h]
00000001C0006CD5  call    cs:__imp_ExReleaseFastMutexUnsafe
00000001C0006CE1  call    cs:__imp_KeLeaveCriticalRegion

; ---- B (rbp) teardown: refcount then conditional free ----
00000001C0006D6A  lock xadd [rbp+8], rax              ; decrement B refcount
00000001C0006D73  test    rax, rax
00000001C0006D76  jg      loc_1C0006E0A               ; still referenced -> skip free
00000001C0006DE9  mov     edx, 69706E56h              ; tag 'Vnpi'
00000001C0006DEE  mov     rcx, rbp
00000001C0006DF1  call    cs:__imp_ExFreePoolWithTag  ; free B (only if count hit zero)

; ---- A (rsi) teardown: refcount then conditional free ----
00000001C0006E0A  test    rsi, rsi
00000001C0006E0D  jz      loc_1C0006EC8
00000001C0006E3C  lock xadd [rsi+8], rax              ; decrement A refcount
00000001C0006E45  test    rax, rax
00000001C0006E48  jg      short loc_1C0006EC8
00000001C0006EB4  mov     edx, 69706E56h              ; tag 'Vnpi'
00000001C0006EB9  mov     rcx, rsi
00000001C0006EBC  call    cs:__imp_ExFreePoolWithTag  ; free A (distinct object)
00000001C0006EE6  retn
```

The two `ExFreePoolWithTag` sites operate on different pointers (`rbp` = object B, `rsi` = object A), each guarded by its own reference-count check. There is no path on which the same pointer is passed to `ExFreePoolWithTag` twice.

### Finding 1 — Patched equivalent (`0x1C00068B0`)

```
00000001C00068E7  lea     rcx, [rbx+48h]
00000001C00068EB  call    cs:__imp_KeAcquireSpinLockRaiseToDpc   ; always acquired
00000001C00068F7  mov     rsi, [rbx+2B8h]                        ; rsi = A
00000001C00068FE  and     qword ptr [rbx+2B8h], 0
00000001C0006906  test    rsi, rsi
00000001C0006909  jz      short loc_1C0006916
00000001C000690B  mov     rbp, [rsi+68h]                         ; rbp = B
00000001C000690F  and     qword ptr [rsi+68h], 0                 ; back-ref always cleared
00000001C0006916  xor     ebp, ebp
00000001C0006918  mov     dl, al
00000001C000691A  lea     rcx, [rbx+48h]
00000001C000691E  call    cs:__imp_KeReleaseSpinLock             ; always released
```

No `call EvaluateCurrentState` appears anywhere in the patched function; the spinlock is always acquired and released and the back-reference is always cleared.

### Finding 2 — safe-path helper `VmbusTlLoopbackReferenceEndpointDeliveryQueue` (`0x1C0007128`)

```
00000001C0007137  lea     rdi, [rcx+48h]                          ; endpoint spinlock
00000001C0007141  call    cs:__imp_KeAcquireSpinLockRaiseToDpc    ; lock held for read+ref
00000001C000714D  mov     rbx, [rbx+2B8h]                         ; read entry under lock
00000001C0007157  test    rbx, rbx
00000001C000715A  jz      short loc_1C00071A4
00000001C000718E  lock xadd [rbx+8], rdx                          ; take a reference
00000001C00071AA  call    cs:__imp_KeReleaseSpinLock
00000001C00071C8  retn                                            ; returns referenced entry
```

### Finding 2 — legacy path in `VmbusTlLoopbackNotifyReceiveConsumed` (unpatched `0x1C00070A3`)

```
00000001C00070A3  mov     rdi, [rbx+2B8h]                         ; UNLOCKED, UNREFERENCED read
00000001C00070AA  test    rdi, rdi
00000001C00070AD  jz      short loc_1C00070EA
00000001C00070AF  mov     rdi, [rdi+68h]                         ; deref peer (may be freed)
00000001C00070B3  lea     rcx, [rdi+48h]
00000001C00070B7  call    cs:__imp_KeAcquireSpinLockRaiseToDpc
00000001C00070C3  or      dword ptr [rdi+210h], 2                ; write to peer object
```

### Finding 3 — legacy path in `VmbusTlLoopbackSend` (unpatched `0x1C0006640`)

```
00000001C0006622  test    eax, eax                                ; gate result
00000001C0006624  jz      short loc_1C0006640
00000001C0006629  call    VmbusTlLoopbackReferenceEndpointDeliveryQueue  ; safe path (gate true)
...
00000001C0006640  mov     rbx, [r15+2B8h]                         ; legacy: raw, no ref, no null check
...
00000001C00066CD  mov     rax, [rbx+68h]                          ; later deref of the raw pointer
```

---

## 5. Trigger Conditions

### Findings 1–3 — race / use-after-free on the legacy path

1. **Obtain a socket handle.** Open an `AF_HYPERV` socket from a process with access to the Hyper-V socket provider. `hvsocket.sys` must be loaded.
2. **Establish a loopback endpoint** so that the pending loopback entry at `endpoint+0x2b8` is populated (via the accept/setup path in `VmbusTlLoopbackAcceptConnection` / `VmbusTlLoopbackSetupConnection`).
3. **Feature gate must select the legacy path.** `EvaluateCurrentState` (`0x1C0001D78`) returns false when the evaluated feature state equals 1. Whether this is the runtime default cannot be determined from the static image and must be confirmed on the target build.
4. **Race two operations on the same endpoint:**
   - Thread A issues a receive-consumed notification or a send (`VmbusTlLoopbackNotifyReceiveConsumed` / `VmbusTlLoopbackSend`), which on the legacy path reads `endpoint+0x2b8` without a lock or reference.
   - Thread B closes/disconnects the endpoint (`VmbusTlLoopbackDisconnect`), which reads, clears, and reference-decrements the same entry.
5. **Observable result.** If the entry's last reference is dropped by Thread B in the window between Thread A's unlocked read and its dereference, Thread A operates on freed pool memory (`PAGE_FAULT_IN_NONPAGED_AREA (0x50)` or pool corruption), or the disconnect and notify paths race on the same slot.

The double `ExFreePoolWithTag` observation described in earlier drafts does not occur: the two free sites in `VmbusTlLoopbackDisconnect` free two distinct objects (A and B), each once.

---

## 6. Impact Assessment

- **Class:** Use-after-free / race condition on a kernel pool object reachable from the Hyper-V socket loopback path.
- **Object:** `0x70`-byte allocation (`VmbusTlCreateObject`, size `0x70`), NonPagedPool, tag `'Vnpi'` (`0x69706E56`). Confirmed layout: `+0x08` reference count, `+0x48` spinlock, `+0x50` destructor function pointer (called via `__guard_dispatch_icall_fptr`), `+0x58` disposition counter, `+0x60` SLIST head, `+0x68` peer back-reference, `+0x210` flags.
- **Primitive.** A use-after-free of the entry object if the legacy path is live and the race is won. Turning this into a stronger primitive (controlled reclamation, information disclosure, or code execution) is not demonstrable from this diff and is not claimed here.
- **Reachability caveat.** The vulnerable behavior exists only on the gate-false legacy path. The runtime default of the `EvaluateCurrentState` feature is not encoded in a way that can be read out of the static image, so exploitability in a given deployment cannot be asserted from the binaries alone.

---

## 7. Debugger Aids

### Finding 1 — `VmbusTlLoopbackDisconnect`

```windbg
; Entry to the function; RCX (arg1) = endpoint object
bp hvsocket_unpatched+0x6c30

; The two free sites operate on DIFFERENT objects
bp hvsocket_unpatched+0x6df1  ".echo B free (rbp); r rcx; gc"
bp hvsocket_unpatched+0x6ebc  ".echo A free (rsi); r rcx; gc"
```

| Location | Register/Memory | Significance |
|----------|-----------------|--------------|
| `0x1C0006C4D` | `RBX` | `RBX = RCX` = endpoint; inspect `dq rbx+2B8 l1` for the pending entry |
| `0x1C0006C8B` | `RSI` | `RSI = *(endpoint+0x2b8)` = entry A |
| `0x1C0006C9F` | `RBP` | `RBP = *(A+0x68)` = peer object B (distinct allocation) |
| `0x1C0006D6A` | `[RBP+8]` | B reference-count decrement |
| `0x1C0006DF1` | `RCX` | pointer freed = B (only if B's count reached zero) |
| `0x1C0006E3C` | `[RSI+8]` | A reference-count decrement |
| `0x1C0006EBC` | `RCX` | pointer freed = A (distinct from B) |

To confirm A and B are different objects, compare `RSI` at `0x1C0006C8B` with `RBP` at `0x1C0006C9F`; `RBP` is loaded from `[RSI+0x68]`, a separate allocation.

### Findings 2–3 — legacy unlocked read

```windbg
; NotifyReceiveConsumed entry; RCX = endpoint
bp hvsocket_unpatched+0x6f50
; Legacy read of the entry without a reference
bp hvsocket_unpatched+0x70a3  ".echo unref read of endpoint+0x2b8; r rdi; gc"
```

Break at the legacy read, then use `!pool @rdi` to check whether the entry's pool block is still valid, and race a concurrent disconnect to observe the freed access.

---

## 8. Changed Functions — Full Triage

All nine changed functions differ solely by removal of `EvaluateCurrentState` guard sequences and the register/line-number churn that follows. `EvaluateCurrentState` is called 19 times across these functions in the unpatched build and 0 times in the patched build.

| Function (unpatched addr) | Similarity | Change Type | Summary |
|---------------------------|-----------|-------------|---------|
| `VmbusTlLoopbackDisconnect` (`0x1C0006C30`) | 0.9128 | Security | Spinlock acquire/release and back-reference clear made unconditional. No double-free. |
| `VmbusTlLoopbackNotifyReceiveConsumed` (`0x1C0006F50`) | 0.8389 | Security | Always uses referenced, spinlock-protected entry read. Closes UAF/race. |
| `VmbusTlLoopbackSend` (`0x1C00065EC`) | 0.8832 | Security | Always uses referenced entry read; legacy raw read removed. |
| `VmbusTlLoopbackAcceptConnection` (`0x1C001B630`) | 0.6072 | Security | Setup/teardown around the `endpoint+0x2b8` store made unconditional. |
| `VmbusTlLoopbackSetupConnection` (`0x1C001B1D0`) | 0.4819 | Security | Cleanup mutex/critical-region handling made unconditional. |
| `VmbusTlNotifyListenerAccept` (`0x1C0005F18`) | 0.8043 | Behavioral | Refcount-increment path made unconditional; no isolated memory-safety issue. |
| `VmbusTlCommonConnectCompletion` (`0x1C0002670`) | 0.9609 | Behavioral | Condition simplified from `if (gate() && x[0x42] < 0)` to `if (x[0x42] < 0)`. |
| `VmbusTlProviderListen` (`0x1C001E420`) | 0.5765 | Behavioral | Gate removed from listen path; also rewires `VmbusTlCreateListenEndpoint` to `VmbusTlCreateEndpoint`. Core listen logic preserved. |
| `VmbusTlProcessNewConnectionForListener` (`0x1C0019E60`) | 0.9756 | Behavioral | Gate removed from partition-state reads; register allocation churn otherwise. |

---

## 9. Unmatched Functions

| Direction | Functions |
|-----------|-----------|
| Removed (unpatched only) | `VmbusTlCreateListenEndpoint` (folded into the existing `VmbusTlCreateEndpoint` by `VmbusTlProviderListen`); `EvaluateCurrentState` retained in the image but no longer called by these paths |
| Added (patched only) | None |

An independent content-level diff of both builds (matching functions by name across relocations) confirms that the nine functions above are the only ones with real logic changes. One additional function outside the connection path, `rbc_InitializeFeatureStaging`, changes so that its feature-descriptor table is empty in the patched build (its start marker is moved to equal its end marker), which is a build/feature-staging configuration change, not a fix to the loopback path. Twenty-four other functions differ only in `HvsocketTrace*` `__LINE__` immediates that shift because source lines were deleted upstream; these are byte-identical once the line-number operand is normalized.

---

## 10. Confidence & Caveats

**Confidence: High** on the mechanism, **conditional** on real-world reachability.

- The removed guard is the WIL feature gate `EvaluateCurrentState` (`0x1C0001D78`), which calls `EvaluateFeature` over `reg_FeatureDescriptors_a` and returns `(feature_state != 1)`. It is a feature-staging gate, not a dynamic capability resolver.
- The genuine security-relevant difference is that the legacy (gate-false) path in `VmbusTlLoopbackNotifyReceiveConsumed` and `VmbusTlLoopbackSend` reads `endpoint+0x2b8` without holding the endpoint spinlock and without incrementing the entry's reference count, while the retained path (`VmbusTlLoopbackReferenceEndpointDeliveryQueue`) does both. This is a use-after-free / race window closed by the patch. Direction confirmed: the patched build is strictly more synchronized.
- **There is no double-free.** `VmbusTlLoopbackDisconnect` frees two distinct objects (the entry A and its peer B at `A+0x68`), each guarded by its own reference count, each freed at most once, in both builds.
- **Reachability is unproven.** The vulnerable path is taken only when the feature evaluates false. The feature's runtime default is not determinable from the static image, so exploitability in a given deployment must be confirmed on the target build (`bp 0x1C0001D78; gu; r eax`).
- No claim is made about pool-spray reclamation, information disclosure, control-flow hijack, or privilege escalation; those are not supported by this diff.
