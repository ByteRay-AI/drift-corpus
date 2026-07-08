Title: hvsocket.sys — Use-after-free / race on loopback socket endpoint access (CWE-416 / CWE-362) fixed by removing a feature gate and making reference-counted endpoint access unconditional
Date: 2026-06-29
Slug: hvsocket_ee1a427a-hvsocket-report-20260629-004311
Category: Corpus
Author: Argus
Summary: KB5087538
Severity: Medium

## 1. Overview
- **Unpatched Binary:** `hvsocket_unpatched.sys`
- **Patched Binary:** `hvsocket_patched.sys`
- **Overall Similarity Score:** 0.9678
- **Verdict:** The patched build removes a Windows feature-staging gate (`EvaluateCurrentState` @ `0x1C0001D78`) that, in the unpatched build, selected between a legacy path that read the loopback endpoint pointer from the connection object without a spinlock or reference count, and a newer path that acquires the connection spinlock and takes a reference on the endpoint. The patch deletes the gate and the legacy path across the affected functions, so every access to the loopback endpoint now goes through the spinlock-protected, reference-counted helper. This closes a use-after-free / race window (CWE-416 / CWE-362) on the loopback endpoint object.

## 2. Vulnerability Summary

### Finding: UAF / race on loopback endpoint (feature-staged fix, Medium)
- **Severity:** Medium
- **Vulnerability Class:** Use-After-Free (CWE-416) / Race Condition (CWE-362)
- **Affected Functions:** `VmbusTlLoopbackSend` (`0x1C00065EC`), `VmbusTlLoopbackNotifyReceiveConsumed` (`0x1C0006F50`), `VmbusTlLoopbackDisconnect` (`0x1C0006C30`), `VmbusTlLoopbackAcceptConnection` (`0x1C001B630`), `VmbusTlNotifyListenerAccept` (`0x1C0005F18`), `VmbusTlCommonConnectCompletion` (`0x1C0002670`), `VmbusTlProcessNewConnectionForListener` (`0x1C0019E60`), `VmbusTlProviderListen` (`0x1C001E420`).

**Root Cause:**
`EvaluateCurrentState` (`0x1C0001D78`) is a Windows feature-staging check. It calls `EvaluateFeature` (`0x1C0001D00`), which resolves a cached feature descriptor via `EvaluateCurrentStateFromRegistry` and returns whether the cached feature state is not equal to `1`. It is **not** a loopback-vs-VMBus connection-type test; the same loopback endpoint field (`connection+0x2B8`) is used on both branches. In the unpatched build this gate is called 18 times across the functions listed above, each time selecting between two ways of reaching the loopback endpoint:

- **Feature on** (`eax != 0`): the endpoint is obtained through `VmbusTlLoopbackReferenceEndpointDeliveryQueue` (`0x1C0007128`), which acquires the connection spinlock at `connection+0x48`, reads `connection+0x2B8`, increments the endpoint reference count at `endpoint+0x8` while the lock is held, releases the lock, and returns the referenced endpoint. The caller later drops that reference (and frees the endpoint if it reaches zero).
- **Feature off** (`eax == 0`): the legacy path reads `connection+0x2B8` directly with no spinlock and no reference increment, and for teardown (`VmbusTlLoopbackDisconnect`) the read-and-null of `connection+0x2B8` is performed without the `connection+0x48` spinlock.

On the legacy path, a thread operating on the endpoint (send, receive-notify, accept) holds only a raw pointer with no reference. A concurrent teardown that nulls `connection+0x2B8` and drops the last reference can free the endpoint (pool tag `'Vnpi'`, `0x69706E56`) while the first thread still dereferences it — a use-after-free.

The patched build removes `EvaluateCurrentState` entirely (all 18 call sites and the function itself are gone) and keeps only the spinlock-protected, reference-counted path, deleting the legacy raw-access code.

**Feature-staging caveat:** The safe path already exists in the unpatched build; it is merely gated behind the feature flag. Whether the vulnerable legacy path executes at runtime on the unpatched build depends on the feature's default state, which is stored in feature metadata and is not determinable from the binary alone. The patched build is the point at which the fix is made unconditional and the legacy path is deleted.

**Attacker-Reachable Entry Point & Data Flow:**
1. A local user creates Hyper-V sockets (`AF_HYPERV`, address family 34) that form a same-partition (loopback) connection.
2. A socket operation (for example `send()`) dispatches through the Winsock Kernel transport-layer interface into `VmbusTlLoopbackSend` (`0x1C00065EC`).
3. When the feature gate selects the legacy path, the endpoint pointer is read at `0x1C0006640` (`mov rbx, [r15+2B8h]`) with no lock and no reference.
4. Concurrently, closing the socket drives `VmbusTlLoopbackDisconnect` (`0x1C0006C30`), whose legacy path nulls `connection+0x2B8` and drops the endpoint reference without the connection spinlock.
5. The first thread then dereferences the now-stale endpoint (for example `mov rax, [rbx+68h]` at `0x1C00066CD`), accessing freed pool memory.

## 3. Pseudocode Diff

Reference model: `VmbusTlLoopbackNotifyReceiveConsumed`.

```c
// --- UNPATCHED ---
NTSTATUS VmbusTlLoopbackNotifyReceiveConsumed(CONNECTION* conn) {
    if (EvaluateCurrentState()) {            // feature ON: safe path
        ENDPOINT* ep = VmbusTlLoopbackReferenceEndpointDeliveryQueue(conn);
        // ep read under connection spinlock, refcount incremented under lock
        if (ep) {
            /* ... operate on ep->deliveryQueue (ep+0x68) ... */
            // reference dropped after use (free if last)
        }
    } else {                                 // feature OFF: legacy path
        ENDPOINT* ep = conn->loopbackEndpoint;   // conn+0x2B8, NO lock, NO refcount
        if (ep) {
            void* dq = *(ep + 0x68);             // deref of unreferenced endpoint
            KeAcquireSpinLockRaiseToDpc(dq + 0x48);
            *(dq + 0x210) |= 2;
            /* ... no reference was ever held ... */
        }
    }
}

// --- PATCHED ---
NTSTATUS VmbusTlLoopbackNotifyReceiveConsumed(CONNECTION* conn) {
    ENDPOINT* ep = VmbusTlLoopbackReferenceEndpointDeliveryQueue(conn); // always
    if (ep) {
        void* dq = *(ep + 0x68);
        KeAcquireSpinLockRaiseToDpc(dq + 0x48);
        *(dq + 0x210) |= 2;
        /* ... reference held throughout; dropped after use (free if last) ... */
    }
}
```

## 4. Assembly Analysis

Unpatched `VmbusTlLoopbackNotifyReceiveConsumed` (`0x1C0006F50`). The feature gate at `0x1C0006F62` selects the legacy branch at `0x1C00070A3`, which reads the endpoint without a lock or reference:

```assembly
; --- UNPATCHED: VmbusTlLoopbackNotifyReceiveConsumed @ 0x1C0006F50 ---
00000001C0006F5F  mov     rbx, rcx                 ; rbx = connection object
00000001C0006F62  call    EvaluateCurrentState     ; feature-staging check
00000001C0006F67  test    eax, eax
00000001C0006F69  jz      loc_1C00070A3            ; feature OFF -> legacy path

; --- feature ON (safe) path ---
00000001C0006F6F  mov     rcx, rbx
00000001C0006F72  call    VmbusTlLoopbackReferenceEndpointDeliveryQueue ; lock + refcount++
00000001C0006F77  mov     rsi, rax
00000001C0006F83  mov     rdi, [rax+68h]
; ... operates, then at 0x1C0006FEB: lock xadd [rsi+8], rax  (reference drop) ...

; --- feature OFF (legacy) path ---
00000001C00070A3  mov     rdi, [rbx+2B8h]          ; endpoint read, NO lock / NO refcount
00000001C00070AA  test    rdi, rdi
00000001C00070AD  jz      short loc_1C00070EA
00000001C00070AF  mov     rdi, [rdi+68h]           ; deref of unreferenced endpoint
00000001C00070B3  lea     rcx, [rdi+48h]           ; SpinLock
00000001C00070B7  call    cs:__imp_KeAcquireSpinLockRaiseToDpc
00000001C00070C3  or      dword ptr [rdi+210h], 2  ; flag write
00000001C00070D4  call    VmbusTlTransitionDisconnectState
00000001C00070E1  call    VmbusTlFinishDisconnectStateTransition
```

Patched `VmbusTlLoopbackNotifyReceiveConsumed` (`0x1C0006BB0`) has no feature gate and no legacy branch; it unconditionally calls the reference-counted helper:

```assembly
; --- PATCHED: VmbusTlLoopbackNotifyReceiveConsumed @ 0x1C0006BB0 ---
00000001C0006BBF  mov     rdi, rcx
00000001C0006BC2  call    VmbusTlLoopbackReferenceEndpointDeliveryQueue ; always: lock + refcount++
00000001C0006BC7  mov     rsi, rax
00000001C0006BCA  test    rax, rax
00000001C0006BCD  jz      loc_1C0006CD2
00000001C0006BD3  mov     rdi, [rax+68h]
; ... operates, then at 0x1C0006C3B: lock xadd [rsi+8], rax  (reference drop) ...
```

The teardown side confirms the direction. Unpatched `VmbusTlLoopbackDisconnect` (`0x1C0006C30`) skips the connection spinlock on the legacy branch:

```assembly
00000001C0006C6F  call    EvaluateCurrentState
00000001C0006C74  test    eax, eax
00000001C0006C76  jz      short loc_1C0006C8B      ; feature OFF -> skip spinlock
00000001C0006C78  lea     rcx, [rbx+48h]           ; SpinLock (only taken when feature ON)
00000001C0006C7C  call    cs:__imp_KeAcquireSpinLockRaiseToDpc
00000001C0006C8B  mov     rsi, [rbx+2B8h]          ; endpoint read (unlocked on legacy path)
00000001C0006C92  and     qword ptr [rbx+2B8h], 0  ; endpoint null (unlocked on legacy path)
```

Patched `VmbusTlLoopbackDisconnect` (`0x1C00068B0`) acquires the connection spinlock unconditionally before the read-and-null:

```assembly
00000001C00068E7  lea     rcx, [rbx+48h]           ; SpinLock
00000001C00068EB  call    cs:__imp_KeAcquireSpinLockRaiseToDpc  ; always
00000001C00068F7  mov     rsi, [rbx+2B8h]          ; read under lock
00000001C00068FE  and     qword ptr [rbx+2B8h], 0  ; null under lock
00000001C000691E  call    cs:__imp_KeReleaseSpinLock
```

## 5. Trigger Conditions

1. **Environment:** Unpatched `hvsocket.sys`, with the feature-staging flag in the state that selects the legacy path (`EvaluateCurrentState` returns 0). The default state is held in feature metadata and cannot be read from the binary; if the feature is enabled, the unpatched build already runs the safe path.
2. **Socket Setup:** Create Hyper-V sockets (`AF_HYPERV`, address family 34) forming a same-partition (loopback) connection.
3. **Race Setup (Thread A):** Perform repeated `send()`/receive operations to drive `VmbusTlLoopbackSend` (`0x1C00065EC`) or `VmbusTlLoopbackNotifyReceiveConsumed` (`0x1C0006F50`) onto the legacy branch that reads `connection+0x2B8` without a reference.
4. **Race Setup (Thread B):** Concurrently close the socket to drive `VmbusTlLoopbackDisconnect` (`0x1C0006C30`), whose legacy branch nulls `connection+0x2B8` and drops the endpoint reference without the connection spinlock.
5. **Window:** Thread B must drop the last endpoint reference and free the pool block (`ExFreePoolWithTag`, tag `'Vnpi'`) in the interval between Thread A's unreferenced read and its subsequent dereference.
6. **Observable Effect:** A dereference of freed non-paged pool. With Driver Verifier Special Pool enabled for `hvsocket.sys`, the access to the freed page faults immediately.

## 6. Impact Assessment

- **Primitive:** Use-after-free on the loopback endpoint pool object (pool tag `'Vnpi'`, `0x69706E56`), reachable only when the feature gate selects the legacy path.
- **Demonstrable impact:** A dereference of freed non-paged pool memory, which under Special Pool is a deterministic fault. Beyond that, no concrete exploitation primitive (controlled reclaim, information disclosure, or control-flow hijack) is demonstrable from these two builds; the endpoint layout, allocation site, and reclaim behavior needed to make any such claim are not established here.
- **Reachability qualifier:** The safe (reference-counted) path is present in both builds. In the unpatched build the vulnerable legacy path is one branch of a feature gate, so its runtime reachability depends on the feature's default state, which is not encoded in the binary.

## 7. Debugger Notes (unpatched target)

These addresses are real instructions in the unpatched image (base `0x1C0000000` for analysis; add the runtime base from `lmvm hvsocket`).

- `0x1C0006F62` — `call EvaluateCurrentState` in `VmbusTlLoopbackNotifyReceiveConsumed`. `eax == 0` after this selects the legacy branch.
- `0x1C00070A3` — `mov rdi, [rbx+2B8h]`: the unreferenced endpoint read (`rbx` = connection object). This value becomes stale if a concurrent disconnect frees the endpoint.
- `0x1C00070AF` — `mov rdi, [rdi+68h]`: dereference of the unreferenced endpoint.
- `0x1C0006C6F` / `0x1C0006C76` — the disconnect feature check and the `jz 0x1C0006C8B` that skips the `connection+0x48` spinlock on the legacy path.
- `0x1C0006C8B` / `0x1C0006C92` — the disconnect read-and-null of `connection+0x2B8` on the legacy path.

Structure offsets:

- **Connection object:** `+0x48` = `KSPIN_LOCK`; `+0x2B8` = loopback endpoint pointer.
- **Endpoint object:** `+0x08` = reference count; `+0x50` = cleanup callback (dispatched via the guard-check indirect call); `+0x68` = delivery-queue / peer pointer; `+0x210` = flags dword.

## 8. Changed Functions — Full Triage

An independent content-level comparison of the two builds (matching by symbol name across relocations) shows the security-relevant change is the removal of the `EvaluateCurrentState` feature gate and its legacy path. The gate function `EvaluateCurrentState` and the helper `VmbusTlCreateListenEndpoint` (inlined into `VmbusTlProviderListen`; its trace string is retained at `0x1C001E59D`) are the only functions removed. The functions whose bodies change because the gate/legacy path was removed are:

- **`VmbusTlLoopbackNotifyReceiveConsumed` (`0x1C0006F50` → `0x1C0006BB0`):** Legacy unreferenced read at `0x1C00070A3` removed; now always uses `VmbusTlLoopbackReferenceEndpointDeliveryQueue`.
- **`VmbusTlLoopbackSend` (`0x1C00065EC`):** Legacy unreferenced read at `0x1C0006640` removed; now always references the endpoint before use.
- **`VmbusTlLoopbackDisconnect` (`0x1C0006C30` → `0x1C00068B0`):** The connection spinlock at `connection+0x48` is now acquired unconditionally around the read-and-null of `connection+0x2B8`; three `EvaluateCurrentState` calls removed.
- **`VmbusTlLoopbackAcceptConnection` (`0x1C001B630`):** Five `EvaluateCurrentState` calls removed; endpoint acquisition/release unified through the reference-counted helper.
- **`VmbusTlNotifyListenerAccept` (`0x1C0005F18`):** Feature-gated endpoint reference handling collapsed to the single reference-counted path.
- **`VmbusTlCommonConnectCompletion` (`0x1C0002670`):** The `EvaluateCurrentState`-gated branch around the connection reference decrement at `connection+0x130` is removed; the decrement is now handled without the gate.
- **`VmbusTlProcessNewConnectionForListener` (`0x1C0019E60` → `0x1C0019DB0`):** Two `EvaluateCurrentState` calls removed. This is a distinct but related synchronization hardening: the patched build now reads the listener readiness flag at `endpoint+0x1A9` unconditionally under the endpoint fast-mutex (`mov dil, [r14+1A9h]` at `0x1C0019FBA`) and refuses the connection (`STATUS_CONNECTION_REFUSED`, `0xC0000236`, at `0x1C0019FEF`) when it is not set. In the unpatched build the legacy branch skipped this check, so an inbound connection could be processed against a listener endpoint that had not finished association (the flag is set by `VmbusTlProviderListen` at `0x1C001E7EF` after `VmbusTlAssociateListenerToPartition`). This closes that window.
- **`VmbusTlProviderListen` (`0x1C001E420` → `0x1C001E290`):** Two `EvaluateCurrentState` calls removed and `VmbusTlCreateListenEndpoint` inlined. The unpatched build carried two near-identical copies of the listen-setup body (one per feature branch); the patched build keeps a single copy. The surviving path retains every validation (base-endpoint status, address-family `34`/subtype `0`, partition null-check, partition-id resolution, listener-to-partition association), so beyond the gate removal this is a de-duplication refactor rather than a removed check.

Other functions differ only in embedded trace-message line numbers and relocated data offsets (for example `HvSocketAcceptIncomingConnection`, `HvSocketProviderUpdateAddresses`, `VmbusTlProviderConnect`, `memset`); those are not security-relevant. `VmbusTlLoopbackPostprocessIoRequest` does not change in content between the two builds.

## 9. Unmatched Functions

`EvaluateCurrentState` (`0x1C0001D78`) and `VmbusTlCreateListenEndpoint` (`0x1C00198A0`) exist only in the unpatched build. `EvaluateCurrentState` is the removed feature gate; `VmbusTlCreateListenEndpoint` is inlined into `VmbusTlProviderListen`. No new functions are added.

## 10. Confidence & Caveats

- **Confidence:** High that the code change is real and correctly directed: the unpatched build gates endpoint access on `EvaluateCurrentState` with a legacy unreferenced path, and the patched build removes the gate and legacy path and always uses the spinlock-protected, reference-counted helper.
- **Nature of the change:** This is a feature-staged synchronization/lifetime hardening. The safe path is present in both builds; the patch finalizes the rollout by removing the gate and the legacy path.
- **Severity rationale:** Rated Medium. The class is a genuine UAF/race on a kernel pool object reachable from local user-mode socket operations, but the vulnerable path is one branch of a feature gate whose default state is not determinable from the binary, and no concrete exploitation primitive beyond a freed-pool dereference is established from these builds.
