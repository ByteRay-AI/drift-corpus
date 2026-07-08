Title: mrxsmb.sys — Use-after-free read of VNetRoot context in tree-connect completion (CWE-416), mitigated behind a feature flag
Date: 2026-07-03
Slug: mrxsmb_1a0fd87a-mrxsmb-report-20260703-153413
Category: Corpus
Author: Argus
Summary: KB5089549

## 1. Overview

- **Unpatched Binary:** `mrxsmb_unpatched.sys`
- **Patched Binary:** `mrxsmb_patched.sys`
- **Overall Similarity:** 0.9912
- **Diff Statistics:** One function has a security-relevant behavioral change (`SmbCeCompleteVNetRootConstruction`). All other function differences are WPP trace-GUID renaming, ETW/WPP trace-id renumbering, and decompiler variable-naming noise. The patched build adds two WIL feature-staging helpers (`Feature_1116195130__private_IsEnabledDeviceUsageNoInline`, `Feature_1116195130__private_IsEnabledFallback`).
- **Verdict:** The patched build adds a mitigation for a use-after-free read (CWE-416) in `SmbCeCompleteVNetRootConstruction`. On the tree-connect error path the handler reads `*(VNetRoot+0x18)` after dropping its reference to the VNetRoot context and passes the value to `RxPostToWorkerThread`. Because dropping the last reference queues an asynchronous teardown rather than freeing synchronously, the read is a use-after-free only when the teardown worker races ahead and frees the object first. The mitigation pre-captures the pointer at entry but is gated behind the feature flag `Feature_1116195130__private_IsEnabledDeviceUsageNoInline`, with the original re-read retained on the disabled branch (staged rollout).

## 2. Vulnerability Summary

### Medium-Severity Use-After-Free read (CWE-416) in `SmbCeCompleteVNetRootConstruction`

**Root Cause:**
`SmbCeCompleteVNetRootConstruction` (unpatched @ 0x140001840, patched @ 0x14002D130) processes SMB tree-connect (VNetRoot) construction completion. Its first argument is the VNetRoot context pointer (kept in `rbp` in the unpatched build). When the completion status is negative or the response ShareType at `*(config+0xBC)` is not a recognized value, execution enters the error-cleanup path.

That path calls `SmbCeDereferenceVNetRootContext(rbp)` at `0x14000197D`, which drops a reference on the VNetRoot context. After the call the code computes `lea rcx, [rbp+0x18]` at `0x140001989` and at the tail executes `mov rcx, [rcx]` at `0x140001ACE`, reading `*(rbp+0x18)` (the mini-redirector device object pointer) and passing it to `RxPostToWorkerThread` at `0x140001AD6`. Reading `*(rbp+0x18)` after the reference was dropped is a use-after-free read.

The free is asynchronous. `SmbCeDereferenceVNetRootContext @ 0x140001C10` decrements the reference count at `*(context+0x8)`; only when it reaches zero does it post `SmbCepTearDownVNetRootContext` to a worker thread via `RxPostToWorkerThread` (`0x140001D48`). The actual free occurs in that deferred teardown, so the tail read is a use-after-free only when the teardown wins the race against the read.

The patch captures `*(arg1+0x18)` into a stack slot at function entry when `Feature_1116195130__private_IsEnabledDeviceUsageNoInline` returns nonzero, and uses that captured value at the tail. When the feature is disabled, the tail re-reads `*(arg1+0x18)` exactly as the unpatched code does.

**Attacker-Reachable Entry Point & Data Flow:**
1. A victim accesses a network path (`\\server\share`) served by an attacker-controlled SMB endpoint.
2. `mrxsmb.sys` drives VNetRoot construction via `MRxSmbCreateVNetRoot @ 0x140035AB0`.
3. Construction completion calls `SmbCeCompleteVNetRootConstruction` (call sites `0x140001823`, `0x1400360AA`).
4. The server returns an error status or invalid ShareType, forcing the error-cleanup path.
5. `SmbCeDereferenceVNetRootContext` drops the reference; the last reference queues `SmbCepTearDownVNetRootContext`.
6. The tail reads `*(rbp+0x18)` for `RxPostToWorkerThread`; if the teardown has already freed the object, this is a use-after-free read.

## 3. Pseudocode Diff

```c
// === UNPATCHED SmbCeCompleteVNetRootConstruction @ 0x140001840 ===
// rbp = arg1 = VNetRoot context
// ... error-cleanup logic (inline spinlock, ActiveVNetRoots decrement) ...
SmbCeDereferenceVNetRootContext(rbp);   // drops a ref; last ref queues async teardown
*(arg2 + 0x118) = r14;
rcx = rbp + 0x18;                       // address into possibly-freed object
r9 = *(arg2 + 0x110);
*(arg2 + 0x11c) = r14;
return RxPostToWorkerThread(*rcx, 0, arg2 + 0xc8, r9, ...);   // reads *(rbp+0x18): potential UAF read

// === PATCHED SmbCeCompleteVNetRootConstruction @ 0x14002D130 ===
// r14 = arg1 = VNetRoot context
pMRxDeviceObject = 0;
if (Feature_1116195130__private_IsEnabledDeviceUsageNoInline())
    pMRxDeviceObject = *(arg1 + 0x18);  // pre-capture BEFORE any deref (mitigation ON)
// ... error-cleanup via pre-existing helper ...
SmbCeDereferenceVNetRootContext(arg1);  // drops a ref; last ref queues async teardown
if (Feature_1116195130__private_IsEnabledDeviceUsageNoInline())
    rcx = pMRxDeviceObject;             // mitigation ON: use pre-captured value
else
    rcx = *(arg1 + 0x18);               // mitigation OFF: same read as unpatched
return RxPostToWorkerThread(rcx, 0, ...);
```

## 4. Assembly Analysis

### Unpatched (`SmbCeCompleteVNetRootConstruction @ 0x140001840`)

```assembly
000000014000197A  mov     rcx, rbp
000000014000197D  call    SmbCeDereferenceVNetRootContext    ; drops a ref (async teardown on last ref)
0000000140001982  mov     [rbx+118h], r14d
0000000140001989  lea     rcx, [rbp+18h]                     ; address into possibly-freed object
000000014000198D  test    r13b, r13b
0000000140001990  jnz     loc_140001AB7
0000000140001996  jmp     loc_140001AB4
0000000140001AB4  xor     r14d, r14d
0000000140001AB7  mov     r9, [rbx+110h]
0000000140001ABE  lea     r8, [rbx+0C8h]
0000000140001AC5  mov     [rbx+11Ch], r14d
0000000140001ACC  xor     edx, edx
0000000140001ACE  mov     rcx, [rcx]                         ; reads *(rbp+0x18): potential UAF read
0000000140001AD6  call    cs:__imp_RxPostToWorkerThread
```

Deferred free inside `SmbCeDereferenceVNetRootContext @ 0x140001C10`:

```assembly
0000000140001C2B  lock xadd [rcx+8], esi                     ; decrement ref count at +0x8
0000000140001C50  test    esi, esi
0000000140001C52  jnz     loc_140001D59                      ; nonzero -> return, no teardown
0000000140001D36  lea     r9, SmbCepTearDownVNetRootContext  ; last ref: post teardown to worker
0000000140001D48  call    cs:__imp_RxPostToWorkerThread
```

### Patched (`SmbCeCompleteVNetRootConstruction @ 0x14002D130`)

```assembly
000000014002D156  mov     [rsp+78h+pMRxDeviceObject], 0
000000014002D16B  call    Feature_1116195130__private_IsEnabledDeviceUsageNoInline
000000014002D170  test    eax, eax
000000014002D172  jz      short loc_14002D180
000000014002D174  mov     rax, [r14+18h]                     ; pre-capture *(arg1+0x18)
000000014002D178  mov     [rsp+78h+pMRxDeviceObject], rax
000000014002D4C2  call    SmbCeDereferenceVNetRootContext
000000014002D4D9  call    Feature_1116195130__private_IsEnabledDeviceUsageNoInline
000000014002D4F3  test    eax, eax
000000014002D4F5  jnz     short loc_14002D4FD
000000014002D4F7  mov     rcx, [r14+18h]                     ; feature OFF: re-read (same as unpatched)
000000014002D4FB  jmp     short loc_14002D505
000000014002D4FD  mov     rcx, [rsp+78h+pMRxDeviceObject]    ; feature ON: use pre-captured value
000000014002D505  call    cs:__imp_RxPostToWorkerThread
```

## 5. Trigger Conditions

1. **Set up an SMB endpoint** the victim will connect to.
2. **Force the error path** by returning a negative NTSTATUS for the tree connect, or a ShareType byte at `*(config+0xBC)` that is not a recognized value (which sets internal status `0xC00000CB`, STATUS_INVALID_NETWORK_RESPONSE).
3. **Induce the victim to connect** (for example `dir \\server\share`), driving `MRxSmbCreateVNetRoot` and then `SmbCeCompleteVNetRootConstruction`.
4. **Drop the last reference:** `SmbCeDereferenceVNetRootContext` must bring `*(context+0x8)` to zero so `SmbCepTearDownVNetRootContext` is posted.
5. **Win the race:** the posted teardown must free the VNetRoot block before the tail `mov rcx, [rcx]` reads `*(rbp+0x18)`. There is no in-thread reclamation window between the dereference and the read.

## 6. Exploit Primitive & Development Notes

- **Demonstrable primitive:** A use-after-free read of one pointer field (`*(VNetRoot+0x18)`, the mini-redirector device object pointer) passed as the first argument to `RxPostToWorkerThread`. Touching freed memory requires losing a race against the asynchronous teardown worker; no synchronous free occurs at the read site.
- **Not demonstrated:** No controlled-write, arbitrary-read, or code-execution primitive is established from this bug. Reclaiming the freed VNetRoot pool block with attacker-controlled contents inside the race window is not shown, and claims of pool-spray-to-code-execution, KASLR/SMEP/SMAP defeat, or token theft are unsupported and out of scope.

## 7. Debugger PoC Playbook

Attach a kernel debugger to the unpatched build.

### Breakpoints
```text
bp mrxsmb!SmbCeCompleteVNetRootConstruction   ; entry: confirm r8d (status) is negative
bp 0x14000197D                                ; SmbCeDereferenceVNetRootContext call; dd rcx+0x8 L1 = refcount
bp 0x140001ACE                                ; mov rcx,[rcx]: reads *(rbp+0x18); !pool rbp to check the block
```

### What to Inspect
1. **At entry:** `rcx` = VNetRoot context; `r8d` = completion status (negative selects the error path).
2. **At `0x14000197D`:** `rcx` = VNetRoot context; `*(rcx+0x8)` = reference count. If it is 1, this call drops the last reference and posts the teardown worker.
3. **At `0x140001ACE`:** `rcx` = `rbp+0x18`; the loaded value is passed to `RxPostToWorkerThread`. `!pool rbp` shows whether the deferred teardown has already freed the block.

### Trigger Setup
1. Point a UNC path at an SMB server you control.
2. Have it reject the tree connect with a negative NTSTATUS or an unrecognized ShareType byte (valid recognized values are 0/1/3).
3. Access the path from the victim (`dir \\server\share`).

### Expected Observation
Because teardown is asynchronous, the tail read at `0x140001ACE` normally returns a still-valid device object pointer in a single-threaded observation. Driver Verifier special pool on `mrxsmb.sys` is the reliable way to catch the read against a freed block when the teardown worker frees it first.

## 8. Changed Functions — Full Triage

- **`SmbCeCompleteVNetRootConstruction`** (unpatched @ 0x140001840, patched @ 0x14002D130, Change Type: Security Relevant)
  - **Changes:** Added a `Feature_1116195130__private_IsEnabledDeviceUsageNoInline`-gated pre-capture of `*(arg1+0x18)` at entry and a matching check at the tail that uses the pre-captured value instead of re-reading `*(arg1+0x18)` after the reference is dropped. When the feature is disabled, the tail re-reads `*(arg1+0x18)`, identical to the unpatched code. The inline ActiveVNetRoots decrement was reorganized to call the pre-existing helper `SmbCeDecrementActiveVNetRootsOnVNetRootContext` (present and identical in both builds at unpatched 0x140001E00 / patched 0x140001810); no new helper was created, and this reorganization is not the security change.

*(Independent content diff confirms no other security-relevant change: all remaining differing functions differ only by WPP trace-GUID rename, ETW/WPP trace-id renumbering, or decompiler variable naming.)*

## 9. Unmatched Functions

- **Added:** `Feature_1116195130__private_IsEnabledDeviceUsageNoInline @ 0x14004C884` and `Feature_1116195130__private_IsEnabledFallback` (WIL feature-staging helpers backing the gate).
- **Removed:** None.

## 10. Confidence & Caveats

- **Confidence Level:** Medium. The unpatched read of `*(rbp+0x18)` after `SmbCeDereferenceVNetRootContext` and the patched pre-capture are both confirmed in the disassembly.
- **Deferred free:** `SmbCeDereferenceVNetRootContext` posts `SmbCepTearDownVNetRootContext` to a worker thread rather than freeing synchronously, so the use-after-free is a race, not a deterministic post-free read.
- **Staged rollout:** The mitigation is gated behind `Feature_1116195130__private_IsEnabledDeviceUsageNoInline` with the original re-read retained on the disabled branch. When the feature is off, the patched build is behaviorally identical to the unpatched build. ShareType values 0/1/3 are the recognized values; other values drive the internal `0xC00000CB` status.
