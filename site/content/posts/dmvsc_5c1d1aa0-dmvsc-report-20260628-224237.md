Title: dmvsc.sys — No security-relevant change (non-security refactor / code reorganization)
Date: 2026-06-28
Slug: dmvsc_5c1d1aa0-dmvsc-report-20260628-224237
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Informational
KBDate: 2026-03-10

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `dmvsc_unpatched.sys` |
| Patched binary | `dmvsc_patched.sys` |
| Overall similarity | **0.9888** |
| Matched functions | 92 |
| Changed functions | **1** |
| Identical functions | 91 |
| Unmatched (unpatched → patched) | 0 / 1 |

**Verdict:** The patch modifies a single function — the VMBus channel close callback `DmcEvtChannelClosed` (`sub_1C000CCA0`) — by moving its inline MDL cleanup into a newly introduced helper, `PkUninitializeRingBuffer` (`sub_1c0001dd4`). The behavior is identical before and after the patch. This is a non-security refactor: no synchronization is added or removed, no free routine changes behavior, and there is no race, double-free, or use-after-free in either build.

---

## 2. Change Summary

### Finding 1: MDL Cleanup Refactored into a Helper (No Security Change)

| Attribute | Detail |
|---|---|
| **Severity** | Informational |
| **Vulnerability class** | None (non-security refactor / code reorganization) |
| **Affected function** | `DmcEvtChannelClosed` (`sub_1C000CCA0`), VMBus channel close state-change callback |
| **Entry point** | Host-initiated VMBus channel teardown via `VmbChannelInitSetStateChangeCallbacks` (registered in `DmcChannelCreate`, `sub_1c000cd50`) |

#### What Changed

The Dynamic Memory VSC driver (`dmvsc.sys`) maintains a per-channel context that stores two MDL pointers at offsets `+0x70` and `+0x78`. These MDLs describe double-mapped ring buffer pages allocated during channel open.

When the channel is closed, the state-change callback `DmcEvtChannelClosed` (`sub_1C000CCA0`) runs. In **both** builds it:

1. Acquires the fast mutex at `ctx+0x100`.
2. Clears the channel-active flag at `ctx+0x18` to zero.
3. **Releases** the fast mutex.
4. Frees the two MDLs at `ctx+0x70` / `ctx+0x78` and zeroes the pointers.

The only difference is **how step 4 is expressed**:

- **Unpatched:** the two MDLs are freed with inline code that calls `PkpFreeDoubleMappedBuffer` (`sub_1c000cff0`) once per MDL, then zeroes each pointer.
- **Patched:** the two inline blocks are replaced by a single call `PkUninitializeRingBuffer(ctx+0x40)` (`sub_1c0001dd4`). That helper reads `substruct+0x30` (= `ctx+0x70`) and `substruct+0x38` (= `ctx+0x78`), frees each via `PkpFreeDoubleMappedBuffer` (`sub_1c0001c98`), and zeroes the same fields.

`PkpFreeDoubleMappedBuffer` is the **same function** in both builds (identical instruction-for-instruction, only relocated from `0x1c000cff0` to `0x1c0001c98`). The two builds therefore free the same MDLs, in the same order, with the same routine, at the same point after the mutex is released.

#### Why This Is Not a Vulnerability

There is no second code path that concurrently frees these MDLs. The hot-add page range handler `DmcHotAddPageRange` (`sub_1c0005298`) does **not** free these MDLs: it calls only `MmAddPhysicalMemory` and WPP tracing, and it never invokes `PkUninitializeRingBuffer` or `PkpFreeDoubleMappedBuffer`. `PkUninitializeRingBuffer` (`sub_1c0001dd4`) is new in the patched build and is called **only** from `DmcEvtChannelClosed`.

Because there is a single free path for these MDLs in both builds, there is no race window, no double-free, and no use-after-free either before or after the patch. The fast mutex guards only the channel-active flag clear in both builds; the patch does not extend it over the MDL cleanup, and it did not need to.

---

## 3. Pseudocode Diff

### `DmcEvtChannelClosed` (`sub_1C000CCA0`) — Channel Close Callback

**Unpatched:**

```c
void __fastcall DmcEvtChannelClosed(void* channelHandle)
{
    ctx = VmbChannelGetPointer(channelHandle);      // rdi = ctx

    ExAcquireFastMutex(&ctx->FastMutex_0x100);
    ctx->ChannelActive_0x18 = 0;
    ExReleaseFastMutex(&ctx->FastMutex_0x100);

    // Inline MDL cleanup
    if (ctx->Mdl1_0x70) { PkpFreeDoubleMappedBuffer(ctx->Mdl1_0x70); ctx->Mdl1_0x70 = NULL; }
    if (ctx->Mdl2_0x78) { PkpFreeDoubleMappedBuffer(ctx->Mdl2_0x78); ctx->Mdl2_0x78 = NULL; }

    /* ... WPP trace ... */
}
```

**Patched:**

```c
void __fastcall DmcEvtChannelClosed(void* channelHandle)
{
    ctx = VmbChannelGetPointer(channelHandle);

    ExAcquireFastMutex(&ctx->FastMutex_0x100);
    ctx->ChannelActive_0x18 = 0;
    ExReleaseFastMutex(&ctx->FastMutex_0x100);

    // Same cleanup, extracted into a helper
    PkUninitializeRingBuffer(&ctx->Substruct_0x40);

    /* ... WPP trace ... */
}
```

**Extracted helper** `PkUninitializeRingBuffer` (`sub_1c0001dd4`), new in the patched build, called only by the close callback:

```c
void PkUninitializeRingBuffer(Substruct* s)   // s = ctx + 0x40
{
    if (s->Mdl1_0x30) { PkpFreeDoubleMappedBuffer(s->Mdl1_0x30); s->Mdl1_0x30 = NULL; }  // == ctx+0x70
    if (s->Mdl2_0x38) { PkpFreeDoubleMappedBuffer(s->Mdl2_0x38); s->Mdl2_0x38 = NULL; }  // == ctx+0x78
}
```

> **Key point:** The unpatched inline free (`PkpFreeDoubleMappedBuffer` at `0x1c000cff0`) and the routine the helper calls (`PkpFreeDoubleMappedBuffer` at `0x1c0001c98`) are the **same function**, identical instruction-for-instruction, only relocated between builds. The change is code organization, not behavior.

---

## 4. Assembly Analysis

### Unpatched `DmcEvtChannelClosed` (`sub_1C000CCA0`) — Full Listing

```asm
; === PROLOG ===
0x1c000cca0: mov [rsp+8], rbx
0x1c000cca5: push rdi
0x1c000cca6: sub rsp, 0x20

; === Get channel context ===
0x1c000ccaa: call cs:__imp_VmbChannelGetPointer
0x1c000ccb6: mov rdi, rax                         ; rdi = ctx
0x1c000ccb9: lea rbx, [rax+0x100]                 ; rbx = &ctx->FastMutex

; === Acquire mutex, clear active flag, release mutex ===
0x1c000ccc0: mov rcx, rbx
0x1c000ccc3: call cs:__imp_ExAcquireFastMutex
0x1c000cccf: mov rcx, rbx
0x1c000ccd2: mov byte [rdi+0x18], 0               ; ctx->ChannelActive = 0
0x1c000ccd6: call cs:__imp_ExReleaseFastMutex

; === Inline MDL cleanup ===
0x1c000cce2: mov rcx, [rdi+0x70]                  ; MDL1
0x1c000cce6: test rcx, rcx
0x1c000cce9: jz 0x1c000ccf5
0x1c000cceb: call PkpFreeDoubleMappedBuffer       ; sub_1c000cff0
0x1c000ccf0: and qword [rdi+0x70], 0
0x1c000ccf5: mov rcx, [rdi+0x78]                  ; MDL2
0x1c000ccf9: test rcx, rcx
0x1c000ccfc: jz 0x1c000cd08
0x1c000ccfe: call PkpFreeDoubleMappedBuffer       ; sub_1c000cff0
0x1c000cd03: and qword [rdi+0x78], 0

; === WPP trace / epilog ===
0x1c000cd08: mov rcx, cs:WPP_GLOBAL_Control
0x1c000cd0f: lea rax, WPP_GLOBAL_Control
0x1c000cd16: cmp rcx, rax
0x1c000cd19: jz 0x1c000cd3d
0x1c000cd1b: mov eax, [rcx+0x2c]
0x1c000cd1e: test al, 4
0x1c000cd20: jz 0x1c000cd3d
0x1c000cd22: cmp byte [rcx+0x29], 4
0x1c000cd26: jb 0x1c000cd3d
0x1c000cd28: mov rcx, [rcx+0x18]
0x1c000cd2c: lea r8, WPP_Traceguids
0x1c000cd33: mov edx, 0x20
0x1c000cd38: call WPP_SF_
0x1c000cd3d: mov rbx, [rsp+0x30]
0x1c000cd42: add rsp, 0x20
0x1c000cd46: pop rdi
0x1c000cd47: retn
```

### Patched `DmcEvtChannelClosed` (`sub_1C000CCA0`) — Changed Region Only

```asm
; ... prolog + mutex acquire/release + flag clear IDENTICAL to unpatched ...

0x1c000cce2: lea rcx, [rdi+0x40]                  ; substruct base (ctx+0x40)
0x1c000cce6: call PkUninitializeRingBuffer        ; sub_1c0001dd4

; ... WPP trace / epilog IDENTICAL ...
```

### `PkpFreeDoubleMappedBuffer` — MDL Free Routine (identical in both builds)

Unpatched at `0x1c000cff0`, patched at `0x1c0001c98` (same bytes, relocated):

```asm
0x1c000cff0: push rbx
0x1c000cff2: sub rsp, 0x20
0x1c000cff6: mov rbx, rcx                         ; rbx = MDL
0x1c000cff9: mov rdx, rcx
0x1c000cffc: mov rcx, [rcx+0x18]                  ; MDL->MappedSystemVa
0x1c000d000: call cs:__imp_MmUnmapLockedPages
0x1c000d00c: shr dword [rbx+0x28], 1              ; MDL->ByteCount >>= 1
0x1c000d00f: mov rcx, rbx
0x1c000d012: call cs:__imp_MmUnlockPages
0x1c000d01e: mov rcx, rbx
0x1c000d021: call cs:__imp_IoFreeMdl
0x1c000d02d: add rsp, 0x20
0x1c000d031: pop rbx
0x1c000d032: retn
```

### `PkUninitializeRingBuffer` (`sub_1c0001dd4`) — Extracted Helper (patched only)

```asm
0x1c0001dd4: push rbx
0x1c0001dd6: sub rsp, 0x20
0x1c0001dda: mov rbx, rcx
0x1c0001ddd: mov rcx, [rcx+0x30]                  ; ctx+0x70 (MDL1)
0x1c0001de1: test rcx, rcx
0x1c0001de4: jz 0x1c0001df0
0x1c0001de6: call PkpFreeDoubleMappedBuffer       ; sub_1c0001c98
0x1c0001deb: and qword [rbx+0x30], 0
0x1c0001df0: mov rcx, [rbx+0x38]                  ; ctx+0x78 (MDL2)
0x1c0001df4: test rcx, rcx
0x1c0001df7: jz 0x1c0001e03
0x1c0001df9: call PkpFreeDoubleMappedBuffer       ; sub_1c0001c98
0x1c0001dfe: and qword [rbx+0x38], 0
0x1c0001e03: add rsp, 0x20
0x1c0001e07: pop rbx
0x1c0001e08: retn
```

> **Note:** `PkUninitializeRingBuffer` reproduces the unpatched inline cleanup exactly. Its two frees go through the same relocated `PkpFreeDoubleMappedBuffer`. The `substruct+0x30` / `substruct+0x38` offsets (with `substruct = ctx+0x40`) equal `ctx+0x70` / `ctx+0x78`.

---

## 5. Concurrency / Reachability Check

> The channel close path frees the two ring-buffer MDLs identically in both builds. To rule out a concurrent-free race, the other reachable paths were checked.

- `DmcHotAddPageRange` (`sub_1c0005298`), reached from `DmcHotAddPageRanges` (`sub_1c0005544`): calls `MmAddPhysicalMemory` and WPP tracing only. It does **not** read or free `ctx+0x70` / `ctx+0x78` and does **not** call `PkUninitializeRingBuffer` or `PkpFreeDoubleMappedBuffer`.
- `PkUninitializeRingBuffer` (`sub_1c0001dd4`) is called **only** from `DmcEvtChannelClosed` in the patched build.
- The MDLs are allocated during channel open (`DmcEvtChannelOpened`, `sub_1c000cb50`, via the ring-buffer initialization path) and freed only on channel close.

There is a single free path for these MDLs in both builds, so no race, double-free, or use-after-free arises from this diff.

---

## 6. Changed Functions — Full Triage

| Function | Similarity | Change Type | Note |
|---|---|---|---|
| `DmcEvtChannelClosed` (`sub_1C000CCA0`) | 0.6798 | **Refactor** | Inline MDL cleanup replaced by a call to the new helper `PkUninitializeRingBuffer` (`sub_1c0001dd4`). Identical behavior. No security impact. |

**No other functions changed in logic.** The remaining 91 matched functions are functionally identical; the only differences are relocation artifacts (shifted internal jump/call targets from the code being moved), not changes in behavior. Several functions are relocated between builds (for example `PkpFreeDoubleMappedBuffer` at `0x1c000cff0` → `0x1c0001c98`), and one address is reused across builds for different functions (`0x1c0007008` is `PkpDoubleMapBuffer` in the unpatched build and `PkInitializeDoubleMappedRingBuffer` in the patched build), but those are relocations, not behavioral changes.

---

## 7. Unmatched Functions

| Direction | Functions |
|---|---|
| Removed (unpatched only) | None |
| Added (patched only) | `PkUninitializeRingBuffer` (`sub_1c0001dd4`) — the helper holding the extracted cleanup |

The patched build introduces `PkUninitializeRingBuffer` to hold the cleanup previously inlined in `DmcEvtChannelClosed`. `PkpFreeDoubleMappedBuffer` remains present in both builds (relocated).

---

## 8. Confidence & Caveats

**Confidence: High**

- The diff is a clean single-function change: `DmcEvtChannelClosed` (`sub_1C000CCA0`).
- The unpatched inline cleanup and the patched helper (`PkUninitializeRingBuffer`, `sub_1c0001dd4`) free the same two MDLs, in the same order, via the same relocated routine `PkpFreeDoubleMappedBuffer`.
- The offset relationships (`ctx+0x70` = substruct `+0x30`, `ctx+0x78` = substruct `+0x38`) are consistent between the inline access pattern and the helper's `s+0x30` / `s+0x38` pattern.
- The hot-add handler `DmcHotAddPageRange` (`sub_1c0005298`) was checked and does not free these MDLs, confirming there is no concurrent free path and therefore no race, double-free, or use-after-free.

**Assessment:** This change is a non-security refactor. A race-condition / use-after-free / double-free reading is not supported by the binaries: both builds perform the same single MDL free during channel close, after the fast mutex is released, and no second concurrent path frees these MDLs.
