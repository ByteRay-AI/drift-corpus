Title: bthport.sys — No security-relevant change (feature-staged advertising-request teardown refactor)
Date: 2026-06-28
Slug: bthport_bb6ad846-bthport-report-20260628-172759
Category: Corpus
Author: Argus
Summary: KB5094127
Severity: None
KBDate: 2026-06-09

## 1. Overview

- **Unpatched Binary:** `bthport_unpatched.sys`
- **Patched Binary:** `bthport_patched.sys`
- **Similarity Score:** 0.992
- **Diff Statistics:** 2782 matched, 4 changed, 2778 identical, 0 unmatched.
- **Verdict:** The patch reworks the HCI LE advertising-request coordinator teardown state entry (`MarkingAllAdvertisingRequestAsNewEntry`) for both the Legacy and Extended coordinators, plus two WIL feature-staging helper functions. The reworked teardown is placed behind a new WIL feature-staging flag, `Feature_1166795066__private_IsEnabledDeviceUsage`, with the pre-patch behaviour fully retained in the disabled (else) branch. The core synchronization — the coordinator spinlock and the atomic exchange used to claim the IRP cancel-routine field — is byte-for-byte equivalent between the two builds, and the operation-guard reference accounting is unchanged. No reachable memory-safety defect is fixed and none is introduced. This is staged-rollout / servicing churn, not a security fix.

## 2. Change Analysis

### Finding 1: Feature-staged teardown refactor (Legacy coordinator)
- **Severity:** None (informational)
- **Change Class:** Feature-staged refactor / code extraction
- **Affected Function:** `MarkingAllAdvertisingRequestAsNewEntry` — state entry for `HciLELegacyAdvertisingRequestCoordinator` (unpatched `0x1C0074D10`, patched `0x1C0074D60`)

**What actually changed:**
In the unpatched build the per-request teardown is performed inline: under the coordinator spinlock, for each pending request the code atomically reads-and-clears the IRP cancel-routine pointer at request `+0x68` (`xchg rax, [rdi-40h]` at `0x1C0074DD9`), compares it against `OnAdvertisementRequestCancelThunk` (`0x1C00719E0`) and `OnPendingAdvertisementRequestCancelThunk` (`0x1C00718A0`), and for a recognized thunk decrements the operation-guard reference count at `Event+0x18` (`lock xadd [rbp+18h]` at `0x1C0074DF6`, signalling via `KeSetEvent` on reaching zero). It then re-installs the pending cancel thunk at `+0x68` (`0x1C0074E1E`) and, if the byte flag at `+0x44` is set, clears it again.

The patched build extracts that exact read-clear-validate-and-release sequence into a new helper, `ClearRequestCancellationRoutine` (`0x1C0072854`), which performs the identical atomic exchange, the identical two-thunk comparison, and the identical `lock xadd [Event+0x18]` / `KeSetEvent` decrement. The call to the helper is placed behind `Feature_1166795066__private_IsEnabledDeviceUsage` (`0x1C0075A04`): the feature-enabled branch (`0x1C0074E1B`) and the feature-disabled legacy branch (`0x1C0074E4A`) both call the same helper and both re-install the pending thunk, differing only in whether the request's cancelled flag (bit `0x4`) is set when the cancel-routine field was already `NULL`, and in how the end-of-iteration guard release is selected. The guard is still acquired once (`lock inc [Event+0x18]`) and released at most once per iteration in every path.

The feature flag is new to the patched image (0 occurrences in the unpatched disassembly, 3 in the patched). Because the else branch preserves the pre-patch behaviour, when the flag is disabled the patched driver behaves as the unpatched driver.

### Finding 2: Feature-staged teardown refactor (Extended coordinator)
- **Severity:** None (informational)
- **Change Class:** Feature-staged refactor
- **Affected Function:** `MarkingAllAdvertisingRequestAsNewEntry` — state entry for `HciLEExtendedAdvertisingRequestCoordinator` (unpatched `0x1C0079990`, patched relocated to `0x1C0079AB0`)

**What actually changed:**
The Extended coordinator already factored the teardown into a helper, `ClearRequestCancellationRoutine` (unpatched `0x1C0076D38`, relocated to `0x1C0076E58` in the patched build). The only change here is the addition of the same `Feature_1166795066__private_IsEnabledDeviceUsage` (`0x1C0075A04`) gate at `0x1C0079B64`, splitting the existing helper call into a feature-enabled branch (`0x1C0079B73`) and a retained legacy branch (`0x1C0079BA2`). The helper logic (which thunks are recognized, the guard-reference decrement) is unchanged; the two builds' helpers recognize the coordinator's `OnAdvertisementRequestCancelThunk` / `OnPendingAdvertisementRequestCancelThunk` at their respective addresses. As with Finding 1, the disabled branch reproduces the pre-patch behaviour.

## 3. Why the pre-patch code is not a race / use-after-free

The teardown and the IRP cancel path are serialized by the coordinator spinlock, so the lock-free race the finding would require does not exist:

- `MarkingAllAdvertisingRequestAsNewEntry` acquires the coordinator spinlock at `coordinator+0x10` (`KeAcquireSpinLockRaiseToDpc`, e.g. Legacy `0x1C0074D3A`) and holds it across the entire request-list walk, releasing it only at the end (`kspin_lock_saved_irql::Release`).
- The cancel routine `OnAdvertisementRequestCancelThunk` (`0x1C00719E0`) first calls `IoReleaseCancelSpinLock` (`0x1C00719F5`) and then acquires the **same** coordinator spinlock at `coordinator+0x10` (`lea rsi, [rdi+10h]; KeAcquireSpinLockRaiseToDpc` at `0x1C0071A6C`) before it unlinks the request and decrements the operation-guard reference (`lock xadd [coordinator+0xF0+0x18]` at `0x1C0071AF2`). It therefore cannot run its critical section while the teardown holds the lock.
- The atomic `xchg` on the cancel-routine field at `+0x68` is the standard `IoSetCancelRoutine`-style handoff (reading the old routine while installing a new one to coordinate the brief window owned by the I/O cancel spinlock). This idiom is present **identically** in both builds and is not altered by the patch.
- The operation-guard reference count is incremented once per iteration and released at most once per iteration in the unpatched build and in both patched branches; the recognized-thunk decrement moved verbatim into the helper. No net accounting difference exists.

Consequently there is no demonstrable reference-count imbalance, no dangling pointer, and no attacker-reachable memory-safety primitive tied to this change.

## 4. Pseudocode Diff

### `MarkingAllAdvertisingRequestAsNewEntry` (Legacy, `0x1C0074D10` → `0x1C0074D60`)

```c
// --- UNPATCHED 0x1C0074D10 (inline teardown, under coordinator spinlock) ---
for (entry = list->Flink; entry != list; entry = entry->Flink) {
    req = *(entry - 0x30);
    if (req->Flags & 1) continue;            // already marked
    req->Flags |= 1;
    guard = coordinator + 0xE8;
    InterlockedIncrement(&guard->RefCount);  // acquire operation guard
    // ... (already-signalled fast path elided) ...
    void* cancel = InterlockedExchange64(&req->CancelRoutine, NULL);   // +0x68
    if (cancel == OnAdvertisementRequestCancelThunk ||
        cancel == OnPendingAdvertisementRequestCancelThunk) {
        if (--guard->RefCount == 0) KeSetEvent(guard, 0, 0);           // release IRP's ref
    }
    if (cancel != NULL) {
        InterlockedExchange64(&req->CancelRoutine, OnPendingAdvertisementRequestCancelThunk);
        if (req->FlagAt44 && InterlockedExchange64(&req->CancelRoutine, NULL) != NULL)
            req->Flags |= 4;                 // cancelled
    } else {
        req->Flags |= 4;                     // cancelled
    }
    if (req->Flags & 4) release_operation_guard_reference(guard);      // release own ref
}

// --- PATCHED 0x1C0074D60 (same work, gated) ---
for (...) {
    // identical mark + guard acquire
    if (Feature_1166795066__private_IsEnabledDeviceUsage()) {
        if (ClearRequestCancellationRoutine(this, req)) {             // extracted helper == inline block
            InterlockedExchange64(&req->CancelRoutine, OnPendingAdvertisementRequestCancelThunk);
            if (req->FlagAt44 && InterlockedExchange64(&req->CancelRoutine, NULL) != NULL)
                req->Flags |= 4;
            else guard_to_release = NULL;    // flag 0x4 not set when field was already NULL
        }
    } else {                                 // legacy path retained
        if (ClearRequestCancellationRoutine(this, req)) {
            InterlockedExchange64(&req->CancelRoutine, OnPendingAdvertisementRequestCancelThunk);
            if (req->FlagAt44 && InterlockedExchange64(&req->CancelRoutine, NULL) != NULL)
                req->Flags |= 4;
        } else {
            req->Flags |= 4;
        }
    }
    if (req->Flags & 4) release_operation_guard_reference(guard);
}
```

The extracted `ClearRequestCancellationRoutine` performs exactly the inline read-clear-validate-and-decrement of the unpatched block (see Section 5).

## 5. Assembly Analysis

### `MarkingAllAdvertisingRequestAsNewEntry` (Legacy) — disassembly

**Unpatched inline teardown (`0x1C0074D10`):**
```
0x1C0074D3A  call    __imp_KeAcquireSpinLockRaiseToDpc   ; coordinator spinlock (coordinator+0x8/0x10)
0x1C0074DD7  xor     eax, eax
0x1C0074DD9  xchg    rax, [rdi-40h]                      ; read-and-clear cancel routine at +0x68
0x1C0074DDD  test    rax, rax
0x1C0074DE0  jz      0x1C0074E33                         ; NULL -> set cancelled flag
0x1C0074DE2  lea     rcx, OnAdvertisementRequestCancelThunk (0x1C00719E0)
0x1C0074DE9  cmp     rax, rcx
0x1C0074DEC  jz      0x1C0074DF3
0x1C0074DEE  cmp     rax, rdx                            ; rdx = OnPendingAdvertisementRequestCancelThunk (0x1C00718A0)
0x1C0074DF1  jnz     0x1C0074E1B
0x1C0074DF3  or      eax, 0FFFFFFFFh
0x1C0074DF6  lock xadd [rbp+18h], eax                    ; decrement operation-guard reference
0x1C0074DFB  cmp     eax, 1
0x1C0074DFE  jnz     0x1C0074E1B
0x1C0074E08  call    __imp_KeSetEvent
0x1C0074E1B  mov     rax, rdx
0x1C0074E1E  xchg    rax, [rdi-40h]                      ; re-install pending cancel thunk
0x1C0074E22  cmp     byte ptr [rdi-64h], 0               ; byte flag at +0x44
0x1C0074E4F  call    release_operation_guard_reference   ; release own reference (if cancelled bit set)
```

**Patched, feature-gated (`0x1C0074D60`):**
```
0x1C0074DDF  lock inc dword ptr [rbx+18h]                ; acquire operation guard (unchanged)
0x1C0074E0C  call    Feature_1166795066__private_IsEnabledDeviceUsage   ; NEW gate (0x1C0075A04)
0x1C0074E17  test    eax, eax
0x1C0074E19  jz      0x1C0074E4A                          ; disabled -> legacy branch
0x1C0074E1B  call    ClearRequestCancellationRoutine (0x1C0072854)      ; enabled branch
0x1C0074E20  test    al, al
0x1C0074E22  jz      0x1C0074E80
0x1C0074E2B  xchg    rax, [rdi+68h]                       ; re-install pending cancel thunk
...
0x1C0074E4A  call    ClearRequestCancellationRoutine (0x1C0072854)      ; legacy branch (retained)
0x1C0074E4F  test    al, al
0x1C0074E51  jz      0x1C0074E6F                          ; not recognized -> set cancelled flag
0x1C0074E88  call    release_operation_guard_reference    ; release own reference
```

### `ClearRequestCancellationRoutine` (`0x1C0072854`) — extracted helper equals the unpatched inline block
```
0x1C0072854  sub     rsp, 28h
0x1C0072858  xor     eax, eax
0x1C007285A  xchg    rax, [rdx+68h]                       ; atomic read-and-clear cancel routine
0x1C007285E  test    rax, rax
0x1C0072861  jz      0x1C00728A2                          ; NULL -> return 0
0x1C0072863  lea     rdx, OnAdvertisementRequestCancelThunk (0x1C00719E0)
0x1C007286A  cmp     rax, rdx
0x1C007286D  jz      0x1C007287B
0x1C007286F  lea     rdx, OnPendingAdvertisementRequestCancelThunk (0x1C00718A0)
0x1C0072876  cmp     rax, rdx
0x1C0072879  jnz     0x1C00728A0                          ; unrecognized non-NULL -> return 1, no decrement
0x1C007287B  add     rcx, 0F0h                            ; Event
0x1C0072882  or      eax, 0FFFFFFFFh
0x1C0072885  lock xadd [rcx+18h], eax                     ; decrement operation-guard reference
0x1C0072894  call    __imp_KeSetEvent
0x1C00728A0  mov     al, 1                                ; return 1 (non-NULL cancel routine)
0x1C00728A6  retn
```

### Extended coordinator (`0x1C0079990` → `0x1C0079AB0`)
```
UNPATCHED 0x1C0079990:
0x1C0079A46  call    ClearRequestCancellationRoutine (0x1C0076D38)   ; no feature gate
0x1C0079A4F  lea     rax, OnPendingAdvertisementRequestCancelThunk
0x1C0079A56  xchg    rax, [rsi+68h]                                  ; re-install pending thunk

PATCHED 0x1C0079AB0:
0x1C0079B64  call    Feature_1166795066__private_IsEnabledDeviceUsage ; NEW gate
0x1C0079B71  jz      0x1C0079BA2                                      ; disabled -> legacy branch
0x1C0079B73  call    ClearRequestCancellationRoutine (0x1C0076E58)   ; enabled branch
0x1C0079BA2  call    ClearRequestCancellationRoutine (0x1C0076E58)   ; legacy branch (retained)
```

### Cancel routine shares the coordinator spinlock (refutes the race)
```
OnAdvertisementRequestCancelThunk (0x1C00719E0):
0x1C00719F5  call    __imp_IoReleaseCancelSpinLock
0x1C0071A6C  mov     rcx, rsi                             ; rsi = coordinator+0x10
0x1C0071A6F  call    __imp_KeAcquireSpinLockRaiseToDpc    ; SAME lock the teardown holds
0x1C0071AD5  call    CompleteRequest
0x1C0071AF2  lock xadd [rcx+18h], eax                     ; operation-guard decrement, under serialization
```

## 6. Exploitability

No exploit primitive is demonstrable. The pre-patch teardown holds the coordinator spinlock across the whole list walk, and the IRP cancel routine acquires the same lock before touching the request or the operation-guard reference, so the two paths are mutually exclusive. The atomic cancel-routine exchange and the guard-reference accounting are identical in both builds. There is no freed-then-reused object, no attacker-controlled dangling pointer, and therefore no memory-corruption primitive to develop.

## 7. Reachability & Trigger

The state entry is dispatched by the `HciLEAdvertisingRequestCoordinatorStateMachine` engine when the coordinator re-marks pending LE advertising requests, and advertising requests are submitted and cancelled as IRPs through the Bluetooth LE advertising interface. That surface is genuinely reachable, but exercising it does not expose any behavioural difference between the two builds when the feature flag is disabled, and no memory-safety fault in either build, because of the serialization described in Section 3. No crash or BSOD is reproducible from this change.

## 8. Changed Functions — Full Triage

- **`MarkingAllAdvertisingRequestAsNewEntry` (Legacy, `0x1C0074D10` → `0x1C0074D60`)**
  - **Similarity:** 0.5482
  - **Change Type:** Feature-staged refactor (not security-relevant)
  - **Note:** Extracted the inline read-clear-validate-and-decrement of the IRP cancel routine into `ClearRequestCancellationRoutine` (`0x1C0072854`, new in the patched image) and placed the call behind `Feature_1166795066__private_IsEnabledDeviceUsage` (`0x1C0075A04`) with the legacy behaviour retained in the else branch. Locking and guard-reference accounting unchanged.
- **`MarkingAllAdvertisingRequestAsNewEntry` (Extended, `0x1C0079990` → `0x1C0079AB0`)**
  - **Similarity:** 0.6965
  - **Change Type:** Feature-staged refactor (not security-relevant)
  - **Note:** Added the same feature gate around the already-existing helper `ClearRequestCancellationRoutine` (`0x1C0076D38`, relocated to `0x1C0076E58`). Helper logic and recognized thunks unchanged.
- **`wil_details_IsEnabledFallback` (`0x1C00F1474` → `0x1C0075954`)**
  - **Similarity:** 0.9493
  - **Change Type:** Behavioral (WIL feature-staging plumbing, not security-relevant)
  - **Note:** Signature changed to receive a feature-state data pointer as a parameter instead of referencing a hardcoded global, supporting the new feature-staging flag.
- **`Feature_2327586105__private_IsEnabledFallback` (`0x1C00F1510` → `0x1C00F15D4`)**
  - **Similarity:** 0.6483
  - **Change Type:** Cosmetic (WIL feature-staging plumbing, not security-relevant)
  - **Note:** Updated to thread the new feature-state parameter into `wil_details_IsEnabledFallback`.

All four changed functions belong to the same feature-staging rollout. No genuine security change is present in the changed set, and the diff reports no added or removed functions.

## 9. Unmatched Functions

No unmatched functions were reported (`unmatched_unpatched: 0`, `unmatched_patched: 0`). The newly extracted Legacy `ClearRequestCancellationRoutine` was matched by content to the pre-patch inline block rather than reported as a wholly new function.

## 10. Confidence & Caveats

- **Confidence:** High that this is feature-staging / servicing churn with no delivered security-relevant behavioural change. The feature flag is new to the patched image, the else branch reproduces the pre-patch behaviour, the coordinator spinlock and atomic cancel-routine handoff are identical in both builds, and the extracted helper reproduces the inline logic instruction-for-instruction including the guard-reference decrement.
- **Caveat:** The runtime default state of `Feature_1166795066__private_IsEnabledDeviceUsage` is not encoded in the binary. Even when enabled, the only observed behavioural delta is whether the request's cancelled flag (bit `0x4`) is set in the case where the cancel-routine field was already `NULL`, plus code extraction — neither alters the locking or the reference-count balance, and neither is a memory-safety fix.
