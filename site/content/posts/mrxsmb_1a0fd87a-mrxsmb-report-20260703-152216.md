Title: mrxsmb.sys — Use-after-free read of VNetRoot context in tree-connect completion (CWE-416), mitigated behind a feature flag
Date: 2026-05-12
Slug: mrxsmb_1a0fd87a-mrxsmb-report-20260703-152216
Category: Corpus
Author: Argus
Summary: KB5089549
Severity: Medium
KBDate: 2026-05-12

## 1. Overview
- **Unpatched Binary ID:** `mrxsmb_unpatched.sys`
- **Patched Binary ID:** `mrxsmb_patched.sys`
- **Overall Similarity:** 0.9912
- **Diff Statistics:** One function has a security-relevant behavioral change (`SmbCeCompleteVNetRootConstruction`). All other differences between the two builds are WPP trace-GUID renaming, ETW/WPP trace-id renumbering, and decompiler variable-naming noise (no logic change). Two new WIL feature-staging helpers are present in the patched build (`Feature_1116195130__private_IsEnabledDeviceUsageNoInline`, `Feature_1116195130__private_IsEnabledFallback`).
- **Verdict:** The patched build adds a mitigation for a use-after-free read (CWE-416) in the SMB VNetRoot construction-completion handler `SmbCeCompleteVNetRootConstruction`. In the tree-connect error path, the handler reads a pointer field from the VNetRoot context object after dropping its own reference to that object, and passes the value to `RxPostToWorkerThread`. Dropping the last reference queues an asynchronous teardown of the object, so the later read is a use-after-free only when that teardown races ahead and frees the object first. The mitigation pre-captures the pointer at function entry, but it is gated behind the WIL feature flag `Feature_1116195130__private_IsEnabledDeviceUsageNoInline` and the original (vulnerable) re-read is retained on the disabled branch. This is a staged rollout: when the feature is off, the patched code behaves exactly like the unpatched code.

## 2. Vulnerability Summary
- **Severity:** Medium
- **Vulnerability Class:** Use-After-Free read (CWE-416) — race read of a freed VNetRoot context field
- **Affected Function:** `SmbCeCompleteVNetRootConstruction` (unpatched @ 0x140001840, patched @ 0x14002D130)

**Root Cause:**
`SmbCeCompleteVNetRootConstruction` completes construction of an SMB VNetRoot (tree-connect) object. Its first argument (`rcx`, kept in `rbp` in the unpatched build) is the VNetRoot context pointer. When the completion status is negative, or when the response ShareType field at `*(config+0xBC)` is not one of the recognized values, execution takes the error-cleanup path.

On that path the function calls `SmbCeDereferenceVNetRootContext(rbp)` at `0x14000197D`, which drops one reference on the VNetRoot context. After that call the code computes `lea rcx, [rbp+0x18]` at `0x140001989` and, at the tail, executes `mov rcx, [rcx]` at `0x140001ACE` to load `*(rbp+0x18)` (the mini-redirector device object pointer). That value is passed as the first argument to `RxPostToWorkerThread` at `0x140001AD6`. Because `rbp` still points into the VNetRoot allocation, reading `*(rbp+0x18)` after the reference has been dropped is a use-after-free read.

The free is not synchronous. `SmbCeDereferenceVNetRootContext @ 0x140001C10` decrements the reference count at `*(context+0x8)`; only when it reaches zero does it unlink the object and post `SmbCepTearDownVNetRootContext` to a worker thread via `RxPostToWorkerThread` (at `0x140001D48`). The actual free happens in that deferred teardown. Therefore the read at `*(rbp+0x18)` is a use-after-free only if the teardown worker runs and frees the object during the short window before the tail read executes. It is a race, not a deterministic post-free read.

**Patch behavior:** The patched `SmbCeCompleteVNetRootConstruction` calls `Feature_1116195130__private_IsEnabledDeviceUsageNoInline` at entry (`0x14002D16B`); if it returns nonzero it reads `*(arg1+0x18)` into a stack slot (`0x14002D174`/`0x14002D178`) before any reference is dropped. At the tail it calls the feature check again (`0x14002D4D9`); if enabled it uses the pre-captured stack value (`0x14002D4FD`), otherwise it re-reads `*(arg1+0x18)` from the object (`0x14002D4F7`), which is the same operation as the unpatched code. The mitigation is therefore only active when the feature is enabled.

**Attacker-Reachable Entry Point & Call Chain:**
1. An application accesses a UNC path (e.g. `\\server\share`), driving `MRxSmbCreateVNetRoot @ 0x140035AB0`.
2. VNetRoot construction completes and calls `SmbCeCompleteVNetRootConstruction` (call sites at `0x140001823` and `0x1400360AA`).
3. If the completion status is negative or the ShareType is unrecognized, the error-cleanup path runs and calls `SmbCeDereferenceVNetRootContext @ 0x140001C10`.
4. The tail reads `*(rbp+0x18)` and passes it to `RxPostToWorkerThread`. If the deferred `SmbCepTearDownVNetRootContext` teardown has already freed the object, this read is a use-after-free.

## 3. Pseudocode Diff

The unpatched build reads the device object pointer from the VNetRoot after dropping its reference; the patched build pre-captures it under a feature flag and retains the old read on the disabled branch.

```c
// ==========================================
// UNPATCHED: SmbCeCompleteVNetRootConstruction @ 0x140001840
// ==========================================
// rbp = arg1 (VNetRoot context), rbx = arg2 (RX context)
if (status < 0) {                       // error-cleanup path
    // inline: acquire spinlock on *(rbp+0x18), decrement ActiveVNetRoots at *(rbp+0x1b0),
    //         release spinlock, optional teardown when the count reaches zero
    SmbCeDereferenceVNetRootContext(rbp);   // drops a ref; last ref queues async teardown
    *(arg2 + 0x118) = r14;
    rcx = rbp + 0x18;                       // address into the (possibly freed) object
}
r9 = *(arg2 + 0x110);
*(arg2 + 0x11c) = r14;
rcx = *rcx;                                 // reads *(rbp+0x18) -> potential UAF read
return RxPostToWorkerThread(rcx, 0, arg2 + 0xc8, r9, ...);

// ==========================================
// PATCHED: SmbCeCompleteVNetRootConstruction @ 0x14002D130
// ==========================================
// r14 = arg1 (VNetRoot context), rsi = arg2 (RX context)
pMRxDeviceObject = 0;
if (Feature_1116195130__private_IsEnabledDeviceUsageNoInline())
    pMRxDeviceObject = *(arg1 + 0x18);      // pre-capture BEFORE any deref (mitigation ON)

// ... error-cleanup path calls the pre-existing helper then drops the ref ...
SmbCeDecrementActiveVNetRootsOnVNetRootContext(arg1, ...);
SmbCeDereferenceVNetRootContext(arg1);      // drops a ref; last ref queues async teardown

if (Feature_1116195130__private_IsEnabledDeviceUsageNoInline())
    rcx = pMRxDeviceObject;                 // mitigation ON: use pre-captured value
else
    rcx = *(arg1 + 0x18);                   // mitigation OFF: same read as unpatched
return RxPostToWorkerThread(rcx, 0, ...);
```

## 4. Assembly Analysis

Unpatched error-cleanup and return sequence (`SmbCeCompleteVNetRootConstruction @ 0x140001840`):

```assembly
; error-cleanup path
0000000140001897  xor     r13b, r13b                         ; error path marker
00000001400018C6  mov     rdi, [rbp+18h]                     ; device object ptr (used for spinlock)
00000001400018D8  call    SmbCeAcquireSpinLock
00000001400018E2  lock xadd [rbp+1B0h], esi                  ; inline ActiveVNetRoots decrement
000000014000197A  mov     rcx, rbp
000000014000197D  call    SmbCeDereferenceVNetRootContext    ; drops a ref (async teardown on last ref)
0000000140001982  mov     [rbx+118h], r14d
0000000140001989  lea     rcx, [rbp+18h]                     ; address into possibly-freed object
000000014000198D  test    r13b, r13b
0000000140001990  jnz     loc_140001AB7
0000000140001996  jmp     loc_140001AB4

; tail / RxPostToWorkerThread dispatch
0000000140001AB4  xor     r14d, r14d
0000000140001AB7  mov     r9, [rbx+110h]
0000000140001ABE  lea     r8, [rbx+0C8h]
0000000140001AC5  mov     [rbx+11Ch], r14d
0000000140001ACC  xor     edx, edx
0000000140001ACE  mov     rcx, [rcx]                         ; reads *(rbp+0x18) -> potential UAF read
0000000140001AD6  call    cs:__imp_RxPostToWorkerThread
```

Deferred-free mechanism inside `SmbCeDereferenceVNetRootContext @ 0x140001C10`:

```assembly
0000000140001C1F  mov     rdi, [rcx+18h]
0000000140001C2B  lock xadd [rcx+8], esi                     ; decrement ref count at +0x8
0000000140001C50  test    esi, esi
0000000140001C52  jnz     loc_140001D59                      ; nonzero -> return, no teardown
0000000140001D36  lea     r9, SmbCepTearDownVNetRootContext  ; last ref: post teardown
0000000140001D48  call    cs:__imp_RxPostToWorkerThread      ; teardown/free runs asynchronously
```

Patched entry pre-capture and tail selection (`SmbCeCompleteVNetRootConstruction @ 0x14002D130`):

```assembly
000000014002D156  mov     [rsp+78h+pMRxDeviceObject], 0
000000014002D16B  call    Feature_1116195130__private_IsEnabledDeviceUsageNoInline
000000014002D170  test    eax, eax
000000014002D172  jz      short loc_14002D180
000000014002D174  mov     rax, [r14+18h]                     ; pre-capture *(arg1+0x18)
000000014002D178  mov     [rsp+78h+pMRxDeviceObject], rax
...
000000014002D4BA  call    SmbCeDecrementActiveVNetRootsOnVNetRootContext
000000014002D4C2  call    SmbCeDereferenceVNetRootContext
000000014002D4D9  call    Feature_1116195130__private_IsEnabledDeviceUsageNoInline
000000014002D4F3  test    eax, eax
000000014002D4F5  jnz     short loc_14002D4FD
000000014002D4F7  mov     rcx, [r14+18h]                     ; feature OFF: re-read (same as unpatched)
000000014002D4FB  jmp     short loc_14002D505
000000014002D4FD  mov     rcx, [rsp+78h+pMRxDeviceObject]    ; feature ON: use pre-captured value
000000014002D505  call    cs:__imp_RxPostToWorkerThread
```

**Key Instructions:**
- `0x14000197D`: `call SmbCeDereferenceVNetRootContext` — drops the reference; the last reference queues asynchronous teardown.
- `0x140001989`: `lea rcx, [rbp+0x18]` — computes an address into the object after the reference was dropped.
- `0x140001ACE`: `mov rcx, [rcx]` — reads `*(rbp+0x18)`; this is the use-after-free read when the teardown wins the race.
- `0x14002D174` / `0x14002D4FD`: the patched pre-capture and its use, active only when the feature flag returns nonzero.

## 5. Trigger Conditions

1. **Establish Context:** Access a UNC path served by an SMB endpoint under the attacker's control, e.g. `CreateFile(L"\\\\server\\share")`, driving `MRxSmbCreateVNetRoot`.
2. **Force the error path:** Have the server return a negative NTSTATUS for the tree connect, or return a ShareType byte at `*(config+0xBC)` that is not one of the recognized values (which sets an internal status of `0xC00000CB`, STATUS_INVALID_NETWORK_RESPONSE). Either drives `SmbCeCompleteVNetRootConstruction` down the error-cleanup path.
3. **Drop the last reference:** For the read to touch freed memory, `SmbCeDereferenceVNetRootContext` must drop the last reference (`*(context+0x8)` reaches zero), which posts `SmbCepTearDownVNetRootContext` to a worker thread.
4. **Win the race:** The posted teardown must free the VNetRoot allocation before the tail `mov rcx, [rcx]` reads `*(rbp+0x18)`. This is a timing-dependent window; there is no in-thread reclamation opportunity between the dereference and the read.

## 6. Exploit Primitive & Development Notes

- **Demonstrable primitive:** A use-after-free read of a single pointer field (`*(VNetRoot+0x18)`, the mini-redirector device object pointer) that is passed as the first argument to `RxPostToWorkerThread`. Reaching a freed object requires losing a race against the deferred teardown worker; no synchronous free occurs at the read site.
- **Not demonstrated:** This report does not establish a controlled-write, arbitrary-read, or code-execution primitive from this bug. Turning the read into anything beyond a stale/garbage device object pointer would require reclaiming the freed VNetRoot pool block with attacker-controlled contents inside the race window, which is not shown here. Claims of pool-spray-to-code-execution, KASLR/SMEP/SMAP defeat, or token theft are not supported by the code and are out of scope.

## 7. Debugger PoC Playbook

Use a kernel debugger attached to the unpatched build to observe the read-after-free window.

**Breakpoints:**
- `bp mrxsmb!SmbCeCompleteVNetRootConstruction` — entry. Confirm `r8d` (completion status) is negative to select the error path.
- `bp 0x14000197D` — the `SmbCeDereferenceVNetRootContext` call. Inspect `*(rcx+0x8)` (the reference count). If it is 1, this call drops the last reference and posts the teardown worker.
- `bp 0x140001ACE` — the `mov rcx, [rcx]` read of `*(rbp+0x18)`. Inspect `rbp` with `!pool rbp` to see whether the deferred teardown has already freed the block.

**What to Inspect:**
- **At entry:** `rcx` = VNetRoot context pointer; `r8d` = completion status (negative selects the error path).
- **At `0x14000197D`:** `rcx` = VNetRoot context; `dd rcx+0x8 L1` = reference count.
- **At `0x140001ACE`:** `rcx` = `rbp+0x18`; the value loaded is passed to `RxPostToWorkerThread`. `!pool rbp` shows whether the block is still allocated.

**Trigger Setup:**
1. Point a UNC path at an SMB server you control.
2. Configure it to reject the tree connect with a negative NTSTATUS or an unrecognized ShareType byte.
3. Access the path (for example `dir \\server\share`).

**Expected Observation:**
Because the teardown is asynchronous, the read at `0x140001ACE` typically returns a still-valid device object pointer in a single-threaded observation. Enabling Driver Verifier special pool on `mrxsmb.sys` is the reliable way to catch the read against a freed block if the teardown worker frees it first; without the race being won, the read completes normally.

**Struct/Offset Notes (VNetRoot Context Object):**
- `+0x08`: Reference count decremented by `SmbCeDereferenceVNetRootContext`.
- `+0x18`: Mini-redirector device object pointer (the value read at the tail and passed to `RxPostToWorkerThread`).
- `+0x1A0`: Associated NET_ROOT object pointer.
- `+0x1A8`: Connect configuration object (`*(config+0xBC)` = ShareType, `*(config+0xB0)` = flags).
- `+0x1B0`: ActiveVNetRoots count (decremented inline on the error path).
- `+0x1E0`: Current exchange/context pointer.

## 8. Changed Functions — Full Triage

- **`SmbCeCompleteVNetRootConstruction`** (unpatched @ 0x140001840, patched @ 0x14002D130)
  - **Change Type:** Security Relevant
  - **Notes:** The patched build adds a `Feature_1116195130__private_IsEnabledDeviceUsageNoInline` check at entry that pre-captures `*(arg1+0x18)` into a stack slot, and a matching check at the tail that uses the pre-captured value in place of re-reading `*(arg1+0x18)` after the reference is dropped. When the feature is disabled, the tail re-reads `*(arg1+0x18)`, identical to the unpatched behavior. The inline ActiveVNetRoots decrement on the error path was reorganized to call the pre-existing helper `SmbCeDecrementActiveVNetRootsOnVNetRootContext` (present and identical in both builds at unpatched 0x140001E00 / patched 0x140001810); this reorganization is not the security change and does not create a new helper.

*(Independent content diff: every other differing function — `MRxSmbCreateVNetRoot`, `MRxSmbFinalizeVNetRoot`, `SmbCeDereferenceExchange`, `SmbCeDereferenceVNetRootContext`, `SmbCeFindVNetRootContext`, `SmbCeReferenceVNetRootContext`, `SmbCepTearDownVNetRootContext`, several `WPP_SF_*` wrappers, and others — differs only by a WPP trace-GUID rename, ETW/WPP trace-id renumbering, or decompiler variable naming. None carry a logic change.)*

## 9. Unmatched Functions

- **Added:** `Feature_1116195130__private_IsEnabledDeviceUsageNoInline @ 0x14004C884` and `Feature_1116195130__private_IsEnabledFallback` — WIL feature-staging helpers that back the feature gate.
- **Removed:** None.

## 10. Confidence & Caveats

- **Confidence:** Medium. The unpatched read of `*(rbp+0x18)` after `SmbCeDereferenceVNetRootContext` is present and confirmed in the disassembly, and the patched pre-capture is confirmed. The practical impact is limited by the deferred-free design and by the feature gate.
- **Deferred free:** `SmbCeDereferenceVNetRootContext` does not free the object synchronously; it posts `SmbCepTearDownVNetRootContext` to a worker thread. The use-after-free is a race against that worker, not a deterministic post-free read.
- **Staged rollout:** The mitigation is gated behind `Feature_1116195130__private_IsEnabledDeviceUsageNoInline`, and the original re-read is retained on the disabled branch. When the feature is off, the patched build is behaviorally identical to the unpatched build.
