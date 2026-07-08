Title: mrxsmb.sys — Read-after-free of VNetRoot device-object pointer in tree-connect completion (CWE-416) fixed
Date: 2026-06-29
Slug: mrxsmb_9b5ecc54-mrxsmb-report-20260629-132319
Category: Corpus
Author: Argus
Summary: KB5094127

### 1. Overview
- **Unpatched Binary:** `mrxsmb_unpatched.sys`
- **Patched Binary:** `mrxsmb_patched.sys`
- **Overall Similarity:** 0.9909
- **Diff Statistics:** 1059 matched, 1 changed, 1058 identical, 0 unmatched (in both directions).
- **Verdict:** The patch adds a feature-gated hardening that caches a device-object pointer read from the VNetRoot context *before* that context can be dereferenced (and possibly freed) on the tree-connect error path. The underlying read-after-free (CWE-416) exists in the unpatched build. The delivered fix is gated behind a WIL feature flag and the unsafe live read is retained in the else-branch, so the mitigation is a staged rollout rather than an unconditional fix.

### 2. Vulnerability Summary
- **Severity:** Medium
- **Vulnerability Class:** Use-After-Free / read-after-free (CWE-416)
- **Affected Function:** `SmbCeCompleteVNetRootConstruction` @ `0x1C0019DB8`

**Root Cause:**
`SmbCeCompleteVNetRootConstruction` is the completion handler for an SMB tree-connect (VNetRoot construction) exchange. When the NTSTATUS argument is negative, the error path calls `SmbCeDecrementActiveVNetRootsOnVNetRootContext` and then `SmbCeDereferenceVNetRootContext(rsi)` at `0x1C0019FB3`, where `rsi` is the VNetRoot context (arg1). `SmbCeDereferenceVNetRootContext` decrements the context's reference count and, on the last reference, tears the object down and frees it. Execution then jumps to the merge point at `0x1C0019F03`, shared with the success path. At `0x1C0019F2D` the code executes `mov rcx, [rsi+18h]`, reading the `pMRxDeviceObject` pointer from the VNetRoot context that may already be freed, and passes it as the first argument to `RxPostToWorkerThread` at `0x1C0019F31`. On the error path this is a read of a potentially freed object (CWE-416).

The patched build pre-reads `[rdi+18h]` into a stack slot at function entry (`0x1C0019DF6`), before any dereference, and uses that cached copy at the merge point. This capture is only performed when `Feature_1585957178__private_IsEnabledDeviceUsage()` returns nonzero; when the feature is disabled the original live read from `[rdi+18h]` is retained at `0x1C001A0F2`.

**Reachability & Call Chain:**
1. A local user triggers access to an SMB share over a UNC path (e.g. `NtCreateFile("\\server\share")`, `net use`).
2. `rdbss.sys` dispatches to the mini-redirector callback `MRxSmbCreateVNetRoot` (`0x1C0017090`), which initiates an SMB tree-connect exchange.
3. On asynchronous exchange completion, `Smb2ConstructVNetRoot_Finalize` (`0x1C0019D90`) calls `SmbCeCompleteVNetRootConstruction(arg1=[rcx+50h], arg2=[rcx+1B8h], arg3=[rcx+8])`, where arg3 is the exchange NTSTATUS.
4. If the exchange completed with a negative NTSTATUS, the error path calls `SmbCeDereferenceVNetRootContext(rsi)` at `0x1C0019FB3`.
5. Execution reaches the merge point at `0x1C0019F03`; the read at `0x1C0019F2D` and the `RxPostToWorkerThread` call at `0x1C0019F31` consume the pointer from the potentially freed context.

Note: the synchronous call to `SmbCeCompleteVNetRootConstruction` from within `MRxSmbCreateVNetRoot` at `0x1C00174EF` sets `r8d = 0` (success status) before the call, so it does not take the error path and does not reach the dereference.

### 3. Pseudocode Diff

```c
// === UNPATCHED SmbCeCompleteVNetRootConstruction (rsi = arg1 = VNetRoot context) ===
NTSTATUS SmbCeCompleteVNetRootConstruction(void* rsi, void* r15 /*exchange*/, int ebp /*status*/) {
    // ...
    if (ebp < 0) {                       // 0x1C0019EBD/EBF: negative NTSTATUS -> error path
        *(r14 + 0x28) = 0;               // 0x1C0019F98
        *(rsi + 0x1e0) = 0;              // 0x1C0019FA0
        SmbCeDecrementActiveVNetRootsOnVNetRootContext(rsi, r14); // 0x1C0019FAB
        SmbCeDereferenceVNetRootContext(rsi);  // 0x1C0019FB3: may FREE rsi on last ref
        // jmp to merge point
    }
Merge_Point:                             // 0x1C0019F03 (shared success/error)
    void* device = *(rsi + 0x18);        // 0x1C0019F2D: read-after-free on error path
    RxPostToWorkerThread(device, 0, r15 + 0xc8, *(r15+0x110), r15);  // 0x1C0019F31
}

// === PATCHED SmbCeCompleteVNetRootConstruction (rdi = arg1 = VNetRoot context) ===
NTSTATUS SmbCeCompleteVNetRootConstruction(void* rdi, void* rsi /*exchange*/, int r14d /*status*/) {
    void* cached = NULL;                                     // 0x1C0019DD3: stack slot zeroed
    if (Feature_1585957178__private_IsEnabledDeviceUsage())  // 0x1C0019DED
        cached = *(rdi + 0x18);                              // 0x1C0019DF6: capture BEFORE deref
    // ...
    if (r14d < 0) {
        SmbCeDecrementActiveVNetRootsOnVNetRootContext(rdi, r15); // 0x1C001A0A8
        SmbCeDereferenceVNetRootContext(rdi);                    // 0x1C001A0B0
    }
Merge_Point:                                                 // 0x1C001A0B5
    void* device = cached;                                   // 0x1C001A0DD: use cached copy
    if (!Feature_1585957178__private_IsEnabledDeviceUsage()) // 0x1C001A0CA re-check
        device = *(rdi + 0x18);                              // 0x1C001A0F2: retained live read
    RxPostToWorkerThread(device, 0, rsi + 0xc8, *(rsi+0x110), rsi); // 0x1C001A0F8
}
```

### 4. Assembly Analysis

**Unpatched error path to merge point (`mrxsmb_unpatched.sys`):**
```
00000001C0019F98  and     qword ptr [r14+28h], 0                 ; clear context pointer
00000001C0019FA0  and     qword ptr [rsi+1E0h], 0                ; clear VNetRoot back-pointer
00000001C0019FA8  mov     rcx, rsi
00000001C0019FAB  call    SmbCeDecrementActiveVNetRootsOnVNetRootContext
00000001C0019FB0  mov     rcx, rsi                              ; rcx = VNetRoot context (arg1)
00000001C0019FB3  call    SmbCeDereferenceVNetRootContext       ; may free rsi on last reference
00000001C0019FB8  jmp     loc_1C0019F03                         ; to merge point

00000001C0019F03  mov     r9, [r15+110h]                        ; Routine
00000001C0019F0A  lea     r8, [r15+0C8h]                        ; pWorkQueueItem
00000001C0019F11  neg     r13b
00000001C0019F14  mov     [r15+118h], ebp                       ; store status in exchange
00000001C0019F1B  mov     [rsp+58h+pContext], r15
00000001C0019F20  sbb     eax, eax
00000001C0019F22  xor     edx, edx                              ; WorkQueueType = 0
00000001C0019F24  and     eax, ebp
00000001C0019F26  mov     [r15+11Ch], eax
00000001C0019F2D  mov     rcx, [rsi+18h]                        ; read pMRxDeviceObject (read-after-free on error path)
00000001C0019F31  call    cs:__imp_RxPostToWorkerThread         ; consumes the pointer
```

**Patched capture at entry and gated consumption (`mrxsmb_patched.sys`):**
```
00000001C0019DD3  and     [rsp+68h+arg_8], 0                    ; init cached ptr to NULL
00000001C0019DED  call    Feature_1585957178__private_IsEnabledDeviceUsage
00000001C0019DF2  test    eax, eax
00000001C0019DF4  jz      short loc_1C0019DFF                   ; skip capture if feature disabled
00000001C0019DF6  mov     rax, [rdi+18h]                        ; capture *(arg1+0x18) BEFORE any deref
00000001C0019DFA  mov     [rsp+68h+arg_8], rax                  ; save to stack slot

; error path deref (same structure as unpatched):
00000001C001A0A8  call    SmbCeDecrementActiveVNetRootsOnVNetRootContext
00000001C001A0B0  call    SmbCeDereferenceVNetRootContext       ; may free rdi

; merge point:
00000001C001A0CA  call    Feature_1585957178__private_IsEnabledDeviceUsage
00000001C001A0CF  mov     r9, [rsi+110h]
00000001C001A0D6  lea     r8, [rsi+0C8h]
00000001C001A0DD  mov     rcx, [rsp+68h+arg_8]                  ; use cached ptr
00000001C001A0E2  xor     edx, edx
00000001C001A0E4  test    eax, eax
00000001C001A0E6  mov     [rsp+68h+pContext], rsi
00000001C001A0EB  setnz   dl
00000001C001A0EE  test    edx, edx
00000001C001A0F0  jnz     short loc_1C001A0F6                   ; if feature enabled, keep cached ptr
00000001C001A0F2  mov     rcx, [rdi+18h]                        ; retained live read when feature disabled
00000001C001A0F8  call    cs:__imp_RxPostToWorkerThread
```

The feature helper is WIL feature-staging boilerplate:
```
Feature_1585957178__private_IsEnabledDeviceUsage():
    if (Feature_1585957178__private_featureState & <mask>)
        return Feature_1585957178__private_featureState & 1;
    else
        return Feature_1585957178__private_IsEnabledFallback(..., 3);
```

### 5. Trigger Conditions
1. A VNetRoot (tree-connect) construction exchange completes with a negative NTSTATUS. This occurs when connecting to an unreachable server, when the server denies access (e.g. `STATUS_NETWORK_ACCESS_DENIED` 0xC00000CB), when the share name is invalid (`STATUS_BAD_NETWORK_NAME` 0xC00000CC), on network timeout, or when the function itself sets an error status (NetRoot type byte at `[VNetRoot+0xBC]` not 0/1/3 sets 0xC00000CB; a caching-mode condition sets 0xC0410001).
2. The negative status flows through `Smb2ConstructVNetRoot_Finalize` (`0x1C0019D90`) into `SmbCeCompleteVNetRootConstruction` as arg3, taking the error path.
3. `SmbCeDereferenceVNetRootContext` must drop the last reference to the VNetRoot context for the object to actually be freed. If other references remain, the object survives and the read at `0x1C0019F2D` returns valid data (latent bug rather than a live memory-safety fault).
4. **Observable effect:** when the object is freed and the freed page/pointer is invalid, dereferencing the stale device-object pointer inside the worker path can crash the system (bugcheck such as 0x50 PAGE_FAULT_IN_NONPAGED_AREA).

### 6. Impact Assessment
- The read at `0x1C0019F2D` returns a pointer field from a possibly-freed VNetRoot context; that pointer is then handed to `RxPostToWorkerThread` as the device-object argument.
- Whether this is reachable in the wild depends on the reference-count state at the time of the error completion: the object is only actually freed when this dereference drops the last reference. This, together with the fix being feature-gated with the original live read retained in the else-branch, is why the severity is assessed as Medium rather than High.
- No exploit primitive beyond a stale kernel-pointer read/dereference is demonstrable from these two builds. Claims of pool grooming, controlled reclamation, function-pointer hijack, or code execution are not supported by the disassembly and are not asserted here.

### 7. Debugger Notes

**Breakpoints (unpatched):**
```text
bp mrxsmb!SmbCeCompleteVNetRootConstruction   ; 0x1C0019DB8 — inspect rcx (VNetRoot ctx), r8d (NTSTATUS)
bp 0x1C0019FB3                                 ; SmbCeDereferenceVNetRootContext(rsi) — the deref that may free
bp 0x1C0019F2D                                 ; mov rcx,[rsi+18h] — the read from the possibly-freed context
```

**What to inspect:**
- At `0x1C0019DB8`: confirm `r8d` (arg3/NTSTATUS) is negative so the error path is taken; note `[rcx+18h]`.
- At `0x1C0019FB3`: `rcx = rsi = VNetRoot context`. Run `!pool @rcx` before stepping over, then re-check `@rsi` state after return.
- At `0x1C0019F2D`: the value read from `[rsi+18h]`. If `!pool @rsi` shows the block freed or reallocated, the read-after-free occurred.

**Key offsets:**
- `0x1C0019EBF`: `js loc_1C0019F74` — branch dispatching negative NTSTATUS to the error path.
- `0x1C0019FB3`: `call SmbCeDereferenceVNetRootContext` — dereference that may free the context.
- `0x1C0019F2D`: `mov rcx, [rsi+18h]` — the read from the possibly-freed context.
- `0x1C0019F31`: `call cs:__imp_RxPostToWorkerThread` — consumes the pointer.

**Trigger setup:**
1. Stand up an SMB server that completes negotiation but returns an error in the TREE_CONNECT response (invalid/non-existent share, or an access-denied/bad-network-name status).
2. From the target (unpatched `mrxsmb.sys`), access a UNC path to that server, e.g. `net use \\attacker_ip\badshare`.
3. The negative NTSTATUS flows to `SmbCeCompleteVNetRootConstruction` with a negative arg3 and takes the error path.
4. Observe the pool state at `0x1C0019F2D` to confirm whether the VNetRoot context was freed at that point.

### 8. Changed Functions — Full Triage
- **`SmbCeCompleteVNetRootConstruction`** @ `0x1C0019DB8` (Similarity: 0.7977, Change Type: Security Relevant)
  - **Key Change:** Pre-captures `*(arg1+0x18)` into a stack slot at entry (`0x1C0019DF6`), gated by `Feature_1585957178__private_IsEnabledDeviceUsage`, and consumes the cached value at the merge point (`0x1C001A0DD`). When the feature is disabled, the original live read from `*(arg1+0x18)` is retained at `0x1C001A0F2`.
  - **Non-security changes:** Register allocation reorganized (`rbp` pushed instead of spilled; status held in `r14` instead of `rbp`); basic-block count grew from 50 to 55 for the gated caching logic.
- **Newly added helpers:** `Feature_1585957178__private_IsEnabledDeviceUsage` and `Feature_1585957178__private_IsEnabledFallback` — WIL feature-staging boilerplate supporting the gate above; no independent security logic.
- **Independent diff result:** Only `SmbCeCompleteVNetRootConstruction` changed logic. All other differences between the two builds are WPP tracing changes (a differing global trace GUID and renumbered trace/ETW message IDs) and decompiler register renaming. No other security-relevant change was found or omitted.

### 9. Unmatched Functions
- No unmatched functions were detected in either direction. The patch is an in-place logical change to one function plus the added feature-flag helpers.

### 10. Confidence & Caveats
- **Confidence Level:** High that the read-after-free exists in the unpatched build and that the patched build adds a pre-capture mitigation for it.
- **Caveats:** The fix is feature-gated (`Feature_1585957178__private_IsEnabledDeviceUsage`) with the original live read retained when the feature is off, so it is a staged rollout rather than an unconditional fix. Actual exploitability depends on `SmbCeDereferenceVNetRootContext` dropping the last reference to the VNetRoot context at the error completion; if other references remain, the object survives and the read is safe.
