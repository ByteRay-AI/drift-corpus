Title: bthpan.sys — feature-staged async request-lifetime refactor
Date: 2026-06-28
Slug: bthpan_0ad4ad12-bthpan-report-20260628-172631
Category: Corpus
Author: Argus
Summary: KB5094127
Severity: Unknown
KBDate: 2026-06-09

- **Unpatched Binary:** `bthpan_unpatched.sys`
- **Patched Binary:** `bthpan_patched.sys`
- **Overall Similarity Score:** 0.9805
- **Diff Statistics:** 328 matched functions, 8 changed functions, 320 identical functions. 0 unmatched functions in either direction.
- **Verdict:** The patch does not remediate a memory-safety vulnerability. It introduces a WIL feature-staged (`Feature_1769988411__private_IsEnabledDeviceUsage`) refactor of how the asynchronous Bluetooth PAN request context is created and tracked. The request-context allocation is extracted into a standalone helper (`BthpanReqCreate`), and per-connection list insertion is moved from queue time (`BthpanReqAdd`) to execution time (`BthpanReqNwi`), with an added worker-side reference/callback bracket. When the feature flag is disabled the legacy code path is retained unchanged in the else branch. The lifetime protection that the reworked path provides already exists in the unpatched build: `BthpanReqAdd` increments the per-connection reference count (`connection+0x50`) before the work item is queued and it is released only after the operation completes, so the connection object cannot be freed while a request for it is in flight.

### 2. Change Summary

- **Severity:** None (no security-relevant change)
- **Change Class:** Feature-staged code refactor of async request-context lifetime bookkeeping (CWE: none)
- **Affected Functions:** `BthpanReqNwi` (work-item dispatch handler), `BthpanReqAdd` (work-item queuing), `BthpanReqCreate` (extracted allocation helper), `BthpanConnectionNotificationRegister` (case-6 operation), plus five WIL feature-telemetry helpers.

**What the unpatched build already does (no missing reference count):**
The unpatched driver queues asynchronous work items (via `NdisQueueIoWorkItem`) to process Bluetooth PAN connection operations. `BthpanReqAdd (sub_1c00042b0)` allocates a `0x268`-byte request context (tag `BTPN`), increments the per-connection reference count at `connection+0x50` with a `lock xadd`, and links the request into the per-connection list at `connection+0x680` under the per-connection spinlock at `connection+0x670`, all before the work item is queued. The completion path `BthpanReqCompleteByRcb (sub_1c0003cb0)` unlinks the request under the same per-connection spinlock, and `BthpanReqDestroy (sub_1c0003bec)` decrements `connection+0x50`; the cleanup callback at `connection+0x60` runs and the object is torn down only when the count reaches zero. The reference taken at queue time is therefore held across the entire asynchronous dispatch. The per-connection reference count, the per-connection spinlock, the per-connection list, and the `__fastfail(3)` list-integrity guards all exist in both builds.

**What the patch changes:**
Under the `Feature_1769988411__private_IsEnabledDeviceUsage (sub_1c0003c08)` flag, `BthpanReqAdd (sub_1c000482c)` allocates the request context through the extracted helper `BthpanReqCreate (sub_1c0003c40)` (which performs the same `0x268`-byte allocation, zero-fill, and `connection+0x50` increment) and no longer links the request into the per-connection list at queue time. The hardened `BthpanReqNwi (sub_1c0004270)` performs the list insertion at execution time under the per-connection spinlock, brackets the dispatch with an additional `connection+0x50` reference and activation/cleanup callbacks (`connection+0x58` / `connection+0x60`), and unlinks under the same lock. `BthpanConnectionNotificationRegister (sub_1c0019828)` returns `STATUS_PENDING (0x103)` under the flag so the handler can drain the pending notification request via `BthpanReqDestroy` rather than leaving it linked. With the flag disabled, `BthpanReqNwi`, `BthpanReqAdd`, and `BthpanConnectionNotificationRegister` all fall through to legacy code paths that match the unpatched behavior.

### 3. Code Diff

The following is the reference-count and list-tracking bookkeeping in each build. Both builds take and hold the `connection+0x50` reference across the async dispatch; only the location of the list-linking moves.

```c
// --- UNPATCHED: BthpanReqAdd (sub_1c00042b0) ---
// Reference taken and request linked into the per-connection list AT QUEUE TIME.
status = BthpanReqAdd(...) {
    NdisAllocateMemoryWithTag(&req, 0x268, 'BTPN');
    memset(req, 0, 0x268);
    if (_InterlockedIncrement(conn + 0x50) == 1)   // take reference on connection
        activation_cb(conn + 0x50);                // conn+0x58 callback on 0->1
    // copy operation parameters into req...
    KeAcquireSpinLockRaiseToDpc(conn + 0x670);     // per-connection spinlock
    // link req into per-connection list at conn+0x680 (integrity-checked)
    KeReleaseSpinLock(conn + 0x670, irql);
    wi = NdisAllocateIoWorkItem(g_hMiniportHandle);
    if (!wi) { /* unlink under lock, then */ BthpanReqDestroy(req); return; }
    NdisQueueIoWorkItem(wi, BthpanReqNwi, req);
}

// --- PATCHED: BthpanReqAdd (sub_1c000482c) ---
// Feature-gated: allocation via helper; list-linking DEFERRED to the handler.
status = BthpanReqAdd(...) {
    if (Feature_1769988411__private_IsEnabledDeviceUsage()) {
        BthpanReqCreate(conn, &req);               // same 0x268 alloc + conn+0x50 increment
        // copy operation parameters into req...
        wi = NdisAllocateIoWorkItem(g_hMiniportHandle);
        if (!wi) { BthpanReqDestroy(req); return; }
        NdisQueueIoWorkItem(wi, BthpanReqNwi, req);
    } else {
        // legacy path: identical to the unpatched BthpanReqAdd above
    }
}

// --- PATCHED: BthpanReqNwi (sub_1c0004270) ---
// Feature-gated hardened path adds a worker-side reference/list bracket.
void BthpanReqNwi(void* req, void* workitem) {
    if (!Feature_1769988411__private_IsEnabledDeviceUsage())
        goto legacy_dispatch;                      // else branch == unpatched handler
    conn = req[0x20];
    if (_InterlockedIncrement(conn + 0x50) == 1)   // worker-side reference bracket
        activation_cb(conn + 0x58);
    KeAcquireSpinLockRaiseToDpc(conn + 0x670);
    // link req into per-connection list at conn+0x680 (integrity-checked)
    KeReleaseSpinLock(conn + 0x670, irql);
    // dispatch operation (case 6 -> BthpanConnectionNotificationRegister)
    // unlink req under conn+0x670; if not STATUS_PENDING, complete + destroy
    if (_InterlockedExchangeAdd(conn + 0x50, -1) == 1) {  // drop worker reference
        conn[0x60] = 0; conn[0x68] = 0;
        cleanup_cb(conn + 0x60);
    }
}
```

### 4. Assembly Analysis

**Unpatched `BthpanReqAdd (sub_1c00042b0)` — reference taken at queue time, then list-link under the per-connection lock:**
```assembly
00000001C0004376  lea     rcx, [rbp+50h]                 ; rbp = connection object; rcx = conn+0x50 (refcount)
00000001C000437A  mov     eax, 1
00000001C000437F  lock xadd [rcx], eax                   ; take reference on connection
00000001C0004383  inc     eax
00000001C0004385  cmp     eax, 1
00000001C0004388  jnz     short loc_1C0004399
00000001C000438A  mov     rax, [rcx+8]                   ; conn+0x58 activation callback
00000001C0004393  call    cs:__guard_dispatch_icall_fptr ; run on 0->1 transition
; ...
00000001C000446C  lea     rsi, [rbp+670h]                ; per-connection spinlock
00000001C000449F  call    cs:__imp_KeAcquireSpinLockRaiseToDpc
00000001C00044B1  lea     rax, [rbp+680h]                ; per-connection list head
00000001C00044C5  mov     [rbx+8], rcx                   ; link request into list
00000001C00044DC  call    cs:__imp_KeReleaseSpinLock
00000001C00044E8  mov     rcx, cs:g_hMiniportHandle
00000001C00044EF  call    cs:__imp_NdisAllocateIoWorkItem
00000001C00045B8  call    cs:__imp_NdisQueueIoWorkItem   ; queue BthpanReqNwi
00000001C0004616  int     29h                            ; __fastfail(3) list-integrity guard
```

**Unpatched `BthpanReqDestroy (sub_1c0003bec)` — reference released; object torn down only at zero:**
```assembly
00000001C0003C2E  mov     rcx, [rbx+20h]                 ; rbx = request; rcx = connection object
00000001C0003C32  add     rcx, 50h                       ; conn+0x50 (refcount)
00000001C0003C36  or      eax, 0FFFFFFFFh
00000001C0003C39  lock xadd [rcx], eax                   ; release reference
00000001C0003C3D  cmp     eax, 1                          ; last reference?
00000001C0003C40  jnz     short loc_1C0003C5B
00000001C0003C42  mov     rax, [rcx+10h]                 ; conn+0x60 cleanup callback
00000001C0003C55  call    cs:__guard_dispatch_icall_fptr ; run cleanup only at zero
00000001C0003C63  call    cs:__imp_NdisFreeMemory        ; free request context
```

**Patched `BthpanReqNwi (sub_1c0004270)` — feature gate selects hardened path, else falls through to the legacy dispatch:**
```assembly
00000001C0004299  call    Feature_1769988411__private_IsEnabledDeviceUsage
00000001C000429E  test    eax, eax
00000001C00042A0  jz      loc_1C00046A9                  ; flag disabled -> legacy path
; hardened path:
00000001C000434B  lea     r14, [rdi+50h]                 ; rdi = connection; r14 = conn+0x50
00000001C0004382  lock xadd [r14], eax                   ; worker-side reference bracket
00000001C00043EF  call    cs:__imp_KeAcquireSpinLockRaiseToDpc ; conn+0x670
00000001C00043FE  lea     rsi, [rdi+680h]                ; per-connection list head
00000001C000442F  call    cs:__imp_KeReleaseSpinLock
00000001C000443E  call    BthpanConnectionNotificationRegister ; case 6
00000001C0004446  cmp     eax, 103h                       ; STATUS_PENDING drives the drain
00000001C000466F  lock xadd [r14], eax                   ; drop worker reference
00000001C0004697  call    cs:__guard_dispatch_icall_fptr  ; conn+0x60 cleanup at zero
; legacy path (flag disabled): structurally identical to the unpatched handler
00000001C00046DE  mov     ecx, [rbx+28h]                 ; operation type
00000001C00046E1  mov     r10, [rbx+20h]                 ; connection object pointer
00000001C0004720  call    BthpanConnectionNotificationRegister
00000001C00047CE  call    cs:__imp_NdisFreeIoWorkItem
00000001C0004808  lock dec cs:g_lDriverUnload
```

The legacy dispatch at `0x1C00046DE`–`0x1C0004822` mirrors the unpatched `BthpanReqNwi (sub_1c0004110)` at `0x1C0004162`–`0x1C00042A7` (same operation switch, same `r10 = [rbx+0x20]` connection load, same `BthpanReqCompleteByRcb` / `NdisFreeIoWorkItem` / `g_lDriverUnload` tail).

### 5. Trigger Conditions

There is no memory-safety condition to trigger. In both builds the connection object referenced by an in-flight request is kept alive by the `connection+0x50` reference taken in `BthpanReqAdd` before the work item is queued; that reference is dropped only in `BthpanReqDestroy` after the operation completes, and the cleanup callback that tears the object down runs only when the count reaches zero. A rapid disconnect during pending work items decrements the reference but cannot free the connection while a request for it remains outstanding.

### 6. Exploit Primitive

None. The reworked path does not close a reachable primitive because no reachable primitive exists in the unpatched build. The connection object's lifetime is governed by the `connection+0x50` reference count in both builds, and the per-connection list operations at `connection+0x680` are performed under the per-connection spinlock at `connection+0x670` with `__fastfail(3)` integrity guards in both builds. The function pointers at `connection+0x58` / `connection+0x60` / `connection+0x68` are only invoked while a reference is held, so there is no attacker-controlled use-after-free through which to reach them.

### 7. Debugger Notes

For a researcher confirming the lifetime behavior in `bthpan_unpatched.sys`:

```text
bp bthpan_unpatched!BthpanReqAdd            ; observe conn+0x50 reference taken before queue
bp bthpan_unpatched!BthpanReqNwi            ; work-item dispatch on the NDIS worker thread
bp bthpan_unpatched!BthpanReqDestroy        ; conn+0x50 released; cleanup only at zero
```

- At `BthpanReqAdd (sub_1c00042b0)` `0x1C000437F`: watch `[rbp+0x50]` (connection reference count) increment before `NdisQueueIoWorkItem`.
- At `BthpanReqNwi (sub_1c0004110)` `0x1C0004165`: `r10 = [rbx+0x20]` is the connection object; it is backed by the reference taken in `BthpanReqAdd`, so it points to live pool for the duration of the dispatch.
- At `BthpanReqDestroy (sub_1c0003bec)` `0x1C0003C39`: watch `[conn+0x50]` decrement; the cleanup callback at `conn+0x60` (`0x1C0003C55`) runs only when the count reaches zero.

**Struct / Offset Notes (both builds):**
- `Request Context` (allocated `0x268` bytes, tag `BTPN`): `+0x20` connection object pointer, `+0x28` operation type, `+0x258`/`+0x260` completion callback context.
- `Connection Object`: `+0x44` teardown flag, `+0x50` reference count, `+0x58` activation callback, `+0x60` cleanup callback, `+0x68` notification-cancel callback, `+0x670` per-connection spinlock, `+0x680` per-connection request-list head.
- `Global Notification Entry` (`0x28` bytes, tag `BTPN`): `+0x00` prev, `+0x08` next, `+0x10` request-context pointer, `+0x18` connection handle, `+0x20` flags byte. This global list (`data_1c001d3d0` head, `data_1c001d3e0` lock) is present and functionally unchanged in both builds.

### 8. Changed Functions — Full Triage

- **`BthpanReqNwi` (`sub_1c0004110` -> `sub_1c0004270`)** (Sim: 0.7599, feature-staged refactor): The async work-item dispatch handler. The patched function gates on `Feature_1769988411__private_IsEnabledDeviceUsage (sub_1c0003c08)`. On the hardened path it copies operation parameters to a stack buffer, brackets the dispatch with an additional `connection+0x50` reference and activation/cleanup callbacks, performs per-connection list insertion (`connection+0x680`) and removal at execution time under the per-connection spinlock (`connection+0x670`) with a `__fastfail(3)` list-integrity guard, and uses `BthpanConnectionNotificationRegister` returning `STATUS_PENDING (0x103)` to drive the drain. With the flag disabled it runs the legacy dispatch path, which matches the unpatched handler. Not a memory-safety fix: the unpatched handler already operates on a connection kept alive by the reference taken in `BthpanReqAdd`.
- **`BthpanConnectionNotificationRegister` (`sub_1c00183e8` -> `sub_1c0019828`)** (Sim: 0.2611, feature-staged refactor): Retains the global notification list (`g_NotificationRequestList` / `data_1c001d3d0`) and global spinlock (`g_NotificationLock` / `data_1c001d3e0`) in both builds, storing a request-context pointer at entry `+0x10` and the connection handle at `+0x18`. Under the feature flag it returns `STATUS_PENDING (0x103)` on the teardown / duplicate-entry path so the reworked `BthpanReqNwi` drains the request from the per-connection list and destroys it rather than leaving it linked. The global list semantics are unchanged; this is not a security fix.
- **`BthpanReqAdd` (`sub_1c00042b0` -> `sub_1c000482c`)** (Sim: 0.7599, feature-staged refactor): The work-item queuing function. Adds the `Feature_1769988411__private_IsEnabledDeviceUsage` gate; on the hardened path it allocates the request context via `BthpanReqCreate (sub_1c0003c40)`, defers per-connection list insertion to the handler, and on `NdisAllocateIoWorkItem` failure calls `BthpanReqDestroy (sub_1c0003d4c)` to drop the reference. The legacy path retains the unpatched inline allocation, reference count, and queue-time list linking. Both builds take the `connection+0x50` reference before queuing.
- **`BthpanReqCreate` (`sub_1c0003c40`)** (Sim: 0.5173, behavioral): Extracted standalone helper for request-context allocation. Performs `NdisAllocateMemoryWithTag` for `0x268` bytes, zeroes the allocation, and increments the per-connection reference count (`connection+0x50`). Functionally equivalent to the unpatched inline allocation in `BthpanReqAdd`. No security impact.
- **Feature-usage telemetry functions** (`wil_details_FeatureReporting_ReportUsageToServiceDirect (sub_1c0019508)`, `wil_details_FeatureReporting_ReportUsageToService (sub_1c00195f8)`, `wil_details_IsEnabledFallback (sub_1c0019758)`, `wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath (sub_1c0019714)`, `Feature_2327586105__private_IsEnabledFallback (sub_1c00197e4)`): WIL feature-staging helpers. Refactored to accept per-instance context pointers rather than referencing global constants. No security impact.

### 9. Unmatched Functions

No functions were added or removed outright. All differences are structural modifications to existing functions.

### 10. Confidence & Caveats

- **Confidence:** High that this is not a memory-safety fix. In both builds the connection object referenced by an in-flight request is kept alive by the `connection+0x50` reference taken in `BthpanReqAdd` before the work item is queued and released only in `BthpanReqDestroy` after completion; the per-connection spinlock (`connection+0x670`), per-connection list (`connection+0x680`), and `__fastfail(3)` list-integrity guards are present in both builds. The change is gated behind a WIL feature flag with the legacy path retained in the else branch, which is the signature of a staged rollout rather than a delivered fix.
- **Nature of the change:** Refactor of the async request-context lifetime bookkeeping — request-context allocation extracted into `BthpanReqCreate`, per-connection list insertion moved from queue time to execution time, and a worker-side reference/callback bracket added — plus WIL feature-telemetry plumbing. The global notification list is unchanged.
- **Caveat:** Whether the hardened path is active at runtime depends on the WIL feature-staging state for `Feature_1769988411`; the driver ships both the hardened and legacy paths.
