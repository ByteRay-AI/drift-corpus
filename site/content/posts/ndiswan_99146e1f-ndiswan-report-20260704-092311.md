Title: ndiswan.sys — No security-relevant change (PPP multilink receive return-value / frame-ownership refactor)
Date: 2026-07-04
Slug: ndiswan_99146e1f-ndiswan-report-20260704-092311
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview

| Field | Value |
|---|---|
| Title | ndiswan.sys — PPP Multilink receive return-value / frame-ownership refactor (no reachable vulnerability) |
| Unpatched binary | `ndiswan_unpatched.sys` |
| Patched binary | `ndiswan_patched.sys` |
| Overall similarity | 0.9924 |
| Matched functions | 425 |
| Changed functions | 2 |
| Identical functions | 423 |
| Unmatched (either direction) | 0 |

**Verdict.** The patch changes the return-value contract between two PPP receive functions in `ndiswan.sys`: `DoMultilinkProcessing` (`0x1C002BE9C`, the Multilink Protocol reassembly routine) is changed from returning an `NTSTATUS`-style code to `void`, and its sole caller `ReceivePPP` (`0x1C002D820`) now returns a hardcoded `0x103` (`NDIS_STATUS_SUCCESS`) for the multilink path instead of propagating the reassembly routine's return value. This makes `DoMultilinkProcessing` the sole owner of the received-frame descriptor and stops the upstream dispatcher from ever freeing a multilink frame.

The originally suspected double-free is **not reachable in the unpatched build**. The unpatched free/return contract is self-consistent: every code path in `DoMultilinkProcessing` that frees the frame internally returns `0x103`, and the only path that returns a non-`0x103` value (`0xC0000001`) does not free the frame. The upstream dispatcher `ProtoCoReceiveNetBufferListChain` (`0x1C0008A60`) frees the frame only when the returned status is not `0x103`. Consequently the frame is released exactly once on every path. The change is a defensive simplification of the ownership contract, not a fix for a demonstrable memory-safety bug.

---

## 2. Summary of the Change

| Severity | Class | Primary functions |
|---|---|---|
| **None (no reachable vulnerability)** | Return-value / ownership-contract refactor (defense-in-depth) | `ReceivePPP` (`0x1C002D820`), `DoMultilinkProcessing` (`0x1C002BE9C`) |

### What the code actually does (plain English)

`DoMultilinkProcessing` (`0x1C002BE9C`) is the PPP Multilink Protocol (MP) reassembly routine. It parses the MP sequence number and either inserts the received-frame descriptor into a sorted reorder list, replaces it with a freshly allocated copy, or frees/rejects it. It reports its outcome to its only caller, `ReceivePPP`.

`ReceivePPP` (`0x1C002D820`) is the PPP receive handler. For MP frames it calls `DoMultilinkProcessing`; for non-MP PPP frames it calls `ProcessPPPFrame` (`0x1C002D488`). It returns the callee's status to its own caller.

The upstream dispatcher `ProtoCoReceiveNetBufferListChain` (`0x1C0008A60`) invokes the receive handler through a guarded indirect call on the per-connection function pointer at `+0x78`, then frees the frame descriptor with `NdisWanFreeRecvDesc` (`0x1C00062FC`) only if the returned status is not `0x103`:

```c
result = handler(ctx, frame);   // handler = ReceivePPP for PPP framing
if (result != 0x103)
    NdisWanFreeRecvDesc(frame);
```

**The unpatched contract is consistent.** In `DoMultilinkProcessing` (unpatched):

- Every path that calls `NdisWanFreeRecvDesc` on the frame descriptor reaches `mov eax, 103h` (`0x1C002C44E`) and returns `0x103`. The dispatcher therefore does **not** free again.
- The only non-`0x103` return is `0xC0000001` at `0x1C002BF10`, taken on early length-rejection paths (frame shorter than the MP header, or no payload after the header). Those paths do **not** free the frame, so the dispatcher's follow-up free is the frame's single release.
- Paths that retain the descriptor in the reorder list (direct insert, or realloc-and-replace) also return `0x103`, so the dispatcher does not free a descriptor that is still referenced.

Because "frame was freed/retained internally" is exactly equivalent to "returned `0x103`," the dispatcher never frees a descriptor that `DoMultilinkProcessing` already freed, and never fails to free a descriptor that was rejected without being freed. No double-free (and no leak) is reachable in the unpatched build.

### What changed

The patch removes the return-value channel between the two functions:

- `DoMultilinkProcessing` becomes `void`. The `mov eax, 103h` and `mov eax, 0C0000001h` writes are gone; all exits fall through to a common epilogue at `0x1C002C458` without setting a return code.
- `ReceivePPP` no longer propagates the reassembly result. After `call DoMultilinkProcessing` it executes `mov ebx, 103h` (`0x1C002D95A`), so the MP path always reports success and the dispatcher never frees an MP frame.

This transfers sole lifecycle ownership of MP frames to `DoMultilinkProcessing`. It is a robustness/hardening change (the dispatcher can no longer be told to free a frame that reassembly already consumed, even if reassembly were later modified), not the repair of a present, reachable defect.

### Entry point and data flow (for context)

1. `ProtoCoReceiveNetBufferListChain` (`0x1C0008A60`) — NDIS WAN protocol receive path; per inbound frame, calls the framing handler via the guarded indirect call at `+0x78`.
2. `ReceivePPP` (`0x1C002D820`) — PPP receive handler; detects MP by the PPP protocol field (`0x3D` short form, `0x00 0x3D` long form) when MP is enabled (connection flag `+0x124` bit 4) and routes to reassembly.
3. `DoMultilinkProcessing` (`0x1C002BE9C`) — MP reassembly / reorder queue; inserts, replaces, or rejects the frame and calls `NdisWanFreeRecvDesc` on the free/replace/reject paths.
4. `NdisWanFreeRecvDesc` (`0x1C00062FC`) — frame free routine.

`ReceivePPP` is also invoked directly by the framing-detection path (`0x1C002B353`); that caller only propagates the status upward and does not itself free, so it introduces no additional free of the descriptor.

---

## 3. Pseudocode Diff

### `ReceivePPP` (`0x1C002D820`) — the change

```c
// ---------------- UNPATCHED ----------------
// (MP branch)
    *(_DWORD *)(a2 + 80) = v15;          // payload length after MP header
    *(_QWORD *)(a2 + 72) = v11;
    v12 = DoMultilinkProcessing(a1, a2); // return value propagated
    v9  = v12;
    // ...
    return v9;                            // v9 may be 0xC0000001 (early reject,
                                          //   frame NOT freed) or 0x103 (freed/retained)

// ---------------- PATCHED ----------------
// (MP branch)
    *(_DWORD *)(a2 + 80) = v14;
    *(_QWORD *)(a2 + 72) = v11;
    DoMultilinkProcessing(a1, a2);        // return value IGNORED
    v9 = 259;                             // 0x103, hardcoded NDIS_STATUS_SUCCESS
    // ...
    return v9;                            // MP path always reports success
```

### Upstream dispatch logic (unchanged, in `ProtoCoReceiveNetBufferListChain` `0x1C0008A60`)

```c
result = handler(ctx, frame);            // handler = ReceivePPP
if (result != 0x103)
    NdisWanFreeRecvDesc(frame);          // single free on non-consumed frames
```

### `DoMultilinkProcessing` (`0x1C002BE9C`) — signature change and free sites

```c
// UNPATCHED: __int64  DoMultilinkProcessing(a1, a2)
// PATCHED:   void     DoMultilinkProcessing(a1, a2)

// Two internal free sites, identical in both builds:

// Reject / allocation-failure path (unpatched 0x1C002C1D9, patched 0x1C002C1E3)
NdisWanFreeRecvDesc(frame);              // then reaches the success epilogue
                                         // (unpatched returns 0x103)

// Realloc-and-replace path (unpatched 0x1C002C213, patched 0x1C002C21D)
memmove(new_buf, old_data, len);
NdisWanFreeRecvDesc(old_frame);          // old freed, new descriptor inserted
                                         // (unpatched returns 0x103)
```

In the unpatched build both free sites fall through to `mov eax, 103h` (`0x1C002C44E`), so the caller does not free again. The rejection convergence label `loc_1C002C1D6` (which the duplicate / out-of-window detection blocks branch to) is simply the setup for the free at `0x1C002C1D9`; it, too, returns `0x103`.

### Free routine `NdisWanFreeRecvDesc` (`0x1C00062FC`, unchanged, for reference)

```c
void NdisWanFreeRecvDesc(frame) {
    if (*(frame + 0x58) != NULL)
        ExFreeToNPagedLookasideList(&RecvHeaderLookaside, *(frame + 0x58));
    NBL = *(frame + 0x70);
    if (*(frame + 0x38) & 1)
        NdisFreeNetBufferList(NBL);                 // driver-allocated NBL
    else {
        NdisFreeNetBufferListContext(NBL, 0x90);
        NdisReturnNetBufferLists(binding, NBL, 0);  // return NBL to miniport
    }
}
```

---

## 4. Assembly Analysis

### Unpatched `ReceivePPP` — MP dispatch (propagates reassembly status)

```asm
; --- ReceivePPP @ 0x1C002D820 (unpatched) ---
0x1C002D951  mov  rdx, rbx          ; rdx = arg2 (frame descriptor)
0x1C002D954  call DoMultilinkProcessing
0x1C002D959  jmp  loc_1C002D8D3     ; -> 'mov ebx, eax'
...
0x1C002D8D3  mov  ebx, eax          ; propagate reassembly return
```

### Patched `ReceivePPP` — MP dispatch (forces success)

```asm
; --- ReceivePPP @ 0x1C002D820 (patched) ---
0x1C002D952  mov  rcx, rdi
0x1C002D955  call DoMultilinkProcessing   ; now void
0x1C002D95A  mov  ebx, 103h               ; always NDIS_STATUS_SUCCESS
0x1C002D95F  jmp  loc_1C002D8D5           ; epilogue (skips 'mov ebx, eax')
```

### Unpatched `DoMultilinkProcessing` — free sites and returns

```asm
; --- @ 0x1C002BE9C (unpatched) ---

; Only non-0x103 return: early length rejection, NO free
0x1C002BF10  mov  eax, 0C0000001h   ; STATUS_UNSUCCESSFUL
0x1C002BF15  jmp  loc_1C002C453     ; epilogue (frame not freed)

; Reject / allocation-failure free  (loc_1C002C1D6 convergence)
0x1C002C1D6  mov  rcx, r14          ; rcx = frame descriptor
0x1C002C1D9  call NdisWanFreeRecvDesc
0x1C002C1DE  jmp  loc_1C002C44E     ; -> 'mov eax, 103h'

; Realloc-and-replace: free old descriptor, keep new
0x1C002C1F7  call memmove
0x1C002C204  mov  rcx, r14          ; rcx = OLD frame descriptor
0x1C002C213  call NdisWanFreeRecvDesc
0x1C002C222  mov  r14, [rsp+98h+arg_18]  ; r14 = NEW descriptor (inserted below)

; Shared success return (reached by both free paths and the insert paths)
0x1C002C44E  mov  eax, 103h
0x1C002C453  add  rsp, 58h
0x1C002C457  pop  r15 ... pop rbx
0x1C002C463  retn
```

### Patched `DoMultilinkProcessing` — no return code

```asm
; --- @ 0x1C002BE9C (patched) ---
; Free sites unchanged (0x1C002C1E3 reject/alloc-fail, 0x1C002C21D realloc).
; Early rejection now jumps straight to the epilogue with no 'mov eax':
0x1C002BF1C  jmp  loc_1C002C458
...
0x1C002C458  add  rsp, 58h          ; common epilogue, eax undefined (void)
0x1C002C45C  pop  r15 ... pop rbx
0x1C002C468  retn
```

### Dispatcher `ProtoCoReceiveNetBufferListChain` (`0x1C0008A60`) — single free site

```asm
0x1C0008E98  mov  rax, [rsi+78h]                 ; handler pointer (ReceivePPP)
0x1C0008E9C  call cs:__guard_dispatch_icall_fptr ; guarded indirect call
0x1C0008EA2  cmp  eax, 103h
0x1C0008EA7  jz   loc_1C0008EE9                  ; consumed -> skip free
0x1C0008EE1  mov  rcx, rbx                        ; rcx = frame descriptor
0x1C0008EE4  call NdisWanFreeRecvDesc             ; single free (non-0x103 only)
0x1C0008EE9  ...
```

The frame descriptor is freed here only for statuses other than `0x103`. Since the unpatched `DoMultilinkProcessing` returns a non-`0x103` value exclusively on paths that did not free the frame, this call is the frame's first and only release on those paths. There is no second free of an already-freed descriptor.

---

## 5. Path Analysis — Why No Double-Free Is Reachable

This section enumerates the exit paths of the unpatched `DoMultilinkProcessing` and the corresponding dispatcher behavior. The frame descriptor (`arg2`) is released exactly once on every path.

| `DoMultilinkProcessing` exit | Internal free? | Return | Dispatcher frees? | Net frees |
|---|---|---|---|---|
| Early length reject (`0x1C002BF10`) | no | `0xC0000001` | yes (`0x1C0008EE4`) | 1 |
| Duplicate / out-of-window reject (via `loc_1C002C1D6` → `0x1C002C1D9`) | yes | `0x103` | no | 1 |
| Allocation failure (`0x1C002C1D9`) | yes | `0x103` | no | 1 |
| Realloc-and-replace (`0x1C002C213`, old freed, new inserted) | yes (old) | `0x103` | no | 1 (old) |
| Direct insert into reorder list (`0x1C002C22A`) | no (retained) | `0x103` | no | 0 (retained) |

The report's originally hypothesized "free-internally-then-return-failure" path does not exist: no path that calls `NdisWanFreeRecvDesc` returns anything other than `0x103`. There are exactly two `NdisWanFreeRecvDesc` call sites inside `DoMultilinkProcessing` (`0x1C002C1D9` and `0x1C002C213`); the addresses `0x1C002C087` and `0x1C002C131` are counter-increment and WPP-trace blocks for out-of-window detection, not free sites, and they converge on the single free at `0x1C002C1D9`.

**Behavioral note on the patched build.** Because the patched `ReceivePPP` forces `0x103`, the dispatcher no longer frees on the early length-rejection path (`DoMultilinkProcessing` returns without freeing there). In the unpatched build that malformed-frame path was cleaned up by the dispatcher. This is the only observable net difference and it moves in the direction of *retaining* rather than *double-freeing* a descriptor. It is not a double-free and is not the memory-safety condition originally posited.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive is present. A double-free requires a code path that frees a descriptor and then causes a second free of the same descriptor. As shown in Section 5, no such path exists in the unpatched build: internal frees are exactly the paths that report `0x103`, and the dispatcher frees only on non-`0x103` statuses, which never free internally. There is no attacker-controlled state that makes reassembly free a descriptor while reporting a status that induces the dispatcher to free it again.

Accordingly, the previously described pool-spray / reallocation / arbitrary-write / token-stealing chain does not apply to this change and is not supported by the binaries.

---

## 7. Reference — Receive Path Structures and Verification Points

The change is a return-value/ownership refactor with no reachable vulnerability, so there is no proof-of-concept trigger. The following are accurate structural references for the affected receive path, retained for anyone auditing the same functions.

### Verification breakpoints

```text
bp ndiswan!ReceivePPP                 ; 0x1C002D820  MP receive handler
bp ndiswan+0x2BE9C                    ; DoMultilinkProcessing entry
bp ndiswan+0x2C1D9                    ; internal free (reject / alloc-fail)  [unpatched]
bp ndiswan+0x2C213                    ; internal free (realloc-and-replace)  [unpatched]
bp ndiswan+0x8EA7                     ; dispatcher: 'cmp eax, 103h' region
bp ndiswan+0x8EE4                     ; dispatcher's single NdisWanFreeRecvDesc
bp ndiswan!NdisWanFreeRecvDesc        ; 0x1C00062FC  frame free routine
```

To confirm the single-free property empirically, log the `rcx` value (frame descriptor) at each `NdisWanFreeRecvDesc` entry: on the unpatched build no descriptor is passed twice across an internal free and the dispatcher's follow-up free.

### Frame descriptor (`arg2`)

| Offset | Meaning |
|---|---|
| `+0x38` | Flags — bit 0 = driver-allocated NBL |
| `+0x40` | PPP protocol type (`0x3D`, `0x003D`) |
| `+0x48` | Frame data pointer |
| `+0x50` | Frame data length |
| `+0x58` | Header pointer (freed here via `ExFreeToNPagedLookasideList`) |
| `+0x70` | `NET_BUFFER_LIST*` |

### Connection context (`arg1`)

| Offset | Meaning |
|---|---|
| `+0x50` | Link/bundle context pointer |
| `+0x78` | Framing receive-handler pointer (`ReceivePPP` for PPP) |
| `+0x124` | Protocol flags — bit 4 = MP enabled |
| `+0x264` | Error counter |

### Link/bundle context (`*(arg1+0x50)`)

| Offset | Meaning |
|---|---|
| `+0x40` | MP window size |
| `+0x48` | MP options — bit 5 = short sequence; bit 6 = multiclass |
| `+0xF8` | Sequence window mask |
| `+0xFC` | Sequence window validity mask |
| `+0x66C` | Error counter |

Addresses are RVAs from image base `0x1C000000`; the two builds share the same base. On a live target, resolve the actual base with `lm ndiswan`.

---

## 8. Changed Functions — Full Triage

### `DoMultilinkProcessing` (`0x1C002BE9C`, MP reassembly / reorder queue)
- **Similarity:** 0.9589
- **Change type:** Return-type / ownership refactor (not a memory-safety fix)
- **What changed:** Return type changed from `__int64` (returning `0x103` or `0xC0000001`) to `void`. The `mov eax, 103h` (`0x1C002C44E`) and `mov eax, 0C0000001h` (`0x1C002BF10`) writes are removed; all exits fall through to a common epilogue at `0x1C002C458`. The two internal `NdisWanFreeRecvDesc` call sites (`0x1C002C1E3` reject/alloc-fail, `0x1C002C21D` realloc-and-replace) and the reorder-queue logic are unchanged. Block reordering shifts jump targets by a few bytes. In the unpatched build every internal free path already returned `0x103`; the return value carried no state that could cause a double-free.

### `ReceivePPP` (`0x1C002D820`, PPP receive handler)
- **Similarity:** 0.9652
- **Change type:** Return-value refactor (defense-in-depth)
- **What changed:** After the MP branch's `call DoMultilinkProcessing`, the handler now executes `mov ebx, 103h` (`0x1C002D95A`) instead of `mov ebx, eax`, so the MP path unconditionally reports `NDIS_STATUS_SUCCESS`. The non-MP path (`ProcessPPPFrame`, `0x1C002D488`) still propagates its return value. A `rcx`/`rdx` swap for the frame-data pointer is a cosmetic register-allocation difference. Net effect: the dispatcher never frees an MP frame after reassembly, making `DoMultilinkProcessing` the sole owner.

### Cosmetic / register-allocation changes
Only the two functions above were modified. Within them the non-behavioral differences are the `rcx`/`rdx` swap in `ReceivePPP` and the few-byte jump-target shifts in `DoMultilinkProcessing` caused by the smaller (void) epilogue.

---

## 9. Unmatched Functions

| Direction | Count | Notes |
|---|---|---|
| Removed | 0 | No functions deleted. |
| Added | 0 | No new helpers, sanitizers, or mitigations introduced. |

An independent function-by-function comparison of both builds (matching by content across relocations) confirms that exactly two functions differ — `DoMultilinkProcessing` and `ReceivePPP` — and no other function contains a security-relevant change. No defensive scaffolding was added or removed.

---

## 10. Confidence & Caveats

**Confidence:** **High** that the change is a return-value/ownership refactor and that no double-free is reachable in the unpatched build. The two changed functions and the unchanged dispatcher and free routine were read in full in both builds; the free/return contract is self-consistent in the unpatched build (internal free ⇔ `0x103`; the sole non-`0x103` return does not free), and the dispatcher frees only on non-`0x103`.

**Basis for the verdict.**

- `DoMultilinkProcessing` has exactly two `NdisWanFreeRecvDesc` call sites (`0x1C002C1D9`, `0x1C002C213` unpatched), both of which reach the `0x103` success return.
- The only non-`0x103` return (`0xC0000001` at `0x1C002BF10`) is an early length rejection that does not free the frame.
- `DoMultilinkProcessing` has a single caller, `ReceivePPP` (`0x1C002D954`). `ReceivePPP` reaches the dispatcher `ProtoCoReceiveNetBufferListChain` via the `+0x78` guarded indirect call, and also a direct call at `0x1C002B353` that only propagates status without freeing.
- The dispatcher's single free site (`0x1C0008EE4`) runs only when the returned status is not `0x103`.

**Net difference.** The one observable behavioral change is that the patched build no longer frees a malformed MP frame on the early length-rejection path (it now returns success and retains ownership in reassembly without freeing). This trends toward retaining rather than double-freeing a descriptor and does not constitute a reachable memory-safety vulnerability of the class originally claimed.
