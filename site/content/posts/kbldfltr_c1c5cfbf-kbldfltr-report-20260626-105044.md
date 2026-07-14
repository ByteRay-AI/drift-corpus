Title: kbldfltr.sys — modifier-key state-tracking feature, lock-scope refactor, and debug tracing
Date: 2026-01-13
Slug: kbldfltr_c1c5cfbf-kbldfltr-report-20260626-105044
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Unknown
KBDate: 2026-01-13

---

## 1. Overview

| Field | Value |
|------|-------|
| Unpatched binary | `kbldfltr_unpatched.sys` |
| Patched binary | `kbldfltr_patched.sys` |
| Overall similarity | **0.8977** |
| Matched functions | 28 |
| Changed functions | 8 |
| Identical functions | 20 |
| Added in patched | 2 (`KeyboardFilter::IsBlockedKey`, `KeyboardFilter::FilterBlockedModifierKeys`) |
| Removed in unpatched | 0 |

**Verdict:** The patch does **not** fix a memory-safety or attacker-reachable security vulnerability. It adds one functional feature — tracking a new per-filter word, `m_blockedModifierKeyState` (`gFilter+0x42`), so that a blocked modifier key can be force-released on its break event — together with two new helper functions (`IsBlockedKey`, `FilterBlockedModifierKeys`), a relocation of an already-existing WDF wait lock from `KeyboardFilter::SwapBlockList` into its caller `KeyboardFilter::Set` (so the lock also covers the new recompute), and pervasive `DbgPrintEx` tracing. Every bounds check and validation on attacker-controlled IOCTL input is byte-for-byte identical between the two builds, and the block-list swap/free sequence has the same synchronization discipline in both builds.

The three items examined below (block-list swap/free, IOCTL input-buffer retrieval, and modifier-state tracking) are each documented against both binaries and none of them is a delivered security fix.

---

## 2. Vulnerability Summary

### Finding 1 — No security-relevant change: block-list swap/free in `KeyboardFilter::Set`

- **Severity:** None (informational)
- **Original hypothesis:** TOCTOU race / Use-After-Free (CWE-362 / CWE-416)
- **Disposition:** Not a vulnerability. The unpatched code is memory-safe.
- **Affected function:** `KeyboardFilter::Set` (unpatched @ `0x1c0007574`, patched @ `0x1c0007628`)
- **Entry point:** IOCTL `0xba404` via `DeviceIoControl` to the KbldFltr control device

**What the code actually does (both builds):**

`KeyboardFilter::Set` allocates a new block list, calls `KeyboardFilter::SwapBlockList` to install it into `gFilter+0x48` and obtain the old pointer, and then frees the old pointer with `ExFreePoolWithTag`. The question is whether the old block list can be freed while another thread is still dereferencing it.

It cannot, and the reason is that access to the block list is serialized by the WDF wait lock at `gFilter+0x8`:

1. **`KeyboardFilter::Apply` holds the lock across its entire block-list iteration.** In the unpatched build, `Apply` (@ `0x1c0001008`) calls `WdfWaitLockAcquire` at `0x1c0001053` (function entry) and does not call `WdfWaitLockRelease` until `0x1c00012c0` (function exit). Every read of the block-list pointer `gFilter+0x48` (at `0x1c000110f` and `0x1c00011a0`) and every dereference of it happens *inside* that lock hold. `Apply` never captures the pointer under the lock and then dereferences it after releasing.

2. **The swap is mutually exclusive with `Apply`.** In the unpatched build, `SwapBlockList` (@ `0x1c00013b8`) itself acquires the same lock (`WdfWaitLockAcquire` at `0x1c00013fd`), performs the pointer swap (`mov [rdi+48h], rbp` at `0x1c000145a`), then releases it (`WdfWaitLockRelease` at `0x1c0001473`) and returns the old pointer. Because `Apply` holds the lock for its whole iteration, `SwapBlockList` blocks until `Apply` has finished and released. Once the swap completes, `gFilter+0x48` points at the *new* list, so any subsequent `Apply` call reads the new pointer, never the old one.

3. **The free is outside the lock in BOTH builds — and that is safe.** In the unpatched build `Set` frees the old pointer at `0x1c0007608` with no lock held. In the patched build `Set` releases the lock at `0x1c0007734` and *then* frees at `0x1c0007747` — i.e. the free is *also* outside the lock. Freeing outside the lock is safe in both builds because after the swap no other thread can obtain the old pointer (readers only ever load `gFilter+0x48` under the lock, and it now holds the new pointer).

**What actually changed:** In the patched build the wait lock was moved out of `SwapBlockList` (which no longer takes it) and into `Set`, so a single lock hold now spans `SwapBlockList` + the new `FilterBlockedModifierKeys` recompute. This widening exists to keep the *new* modifier-state computation atomic with the swap. It does not change the synchronization of the swap or the free relative to `Apply`. There is no use-after-free in either build and no race was closed.

### Finding 2 — No security-relevant change: input-buffer retrieval in `KbfEvtIoDeviceControl`

- **Severity:** None (informational)
- **Original hypothesis:** Missing/Incorrect WDF Request parameter (CWE-628)
- **Disposition:** Not a bug. The unpatched call passes the correct Request handle.
- **Affected function:** `KbfEvtIoDeviceControl` (unpatched @ `0x1c00071d0`, IOCTL `0xba404` path from `0x1c0007222`)

**What the code actually does:** In the WDF `EvtIoDeviceControl` callback the Request handle arrives in `rdx` (arg2). At function entry the unpatched build copies it into `rdi` (`mov rdi, rdx` at `0x1c00071f1`) and never overwrites `rdx` along the `0xba404` path. At the `WdfRequestRetrieveInputMemory` call site (`WdfFunctions+0x858`, called at `0x1c000725e`), `rdx` therefore still holds the original Request handle. The call is correct.

The patched build (`0xba404` path from `0x1c0007282`) inserts a `DbgPrintEx` at `0x1c0007290` ("Enter IOCTL_KBFILTR_SET_KEYBOARD…"). That call clobbers `rdx`, so the compiler reloads it with `mov rdx, rdi` at `0x1c00072d1` immediately before the retrieval call at `0x1c00072db`. The added `mov rdx, rdi` compensates for the newly-inserted tracing call; it does not fix a pre-existing missing-argument bug. The unpatched path never needed the reload because nothing clobbered `rdx` there.

Note also that the WDF function at offset `0x858` is `WdfRequestRetrieveInputMemory` (confirmed by the patched build's own error string "WdfRequestRetrieveInputMemory failed %x"), and its result is a WDFMEMORY that is subsequently passed to `WdfMemoryGetBuffer` (`WdfFunctions+0x610`).

### Finding 3 — No security-relevant change: modifier-key state tracking in `KeyboardFilter::Apply` / `Set`

- **Severity:** None (informational; behavioral feature)
- **Vulnerability class:** None — functional feature addition
- **Affected functions:** `KeyboardFilter::Apply`, `KeyboardFilter::Set`, and the two new helpers `IsBlockedKey` / `FilterBlockedModifierKeys`

**What actually changed:** The patch introduces a new per-filter word `m_blockedModifierKeyState` at `gFilter+0x42` (adjacent to the existing `m_ModifierKeyState` at `gFilter+0x40`). Its purpose is keyboard-filter policy, not memory safety:

- `Set` (patched) calls `FilterBlockedModifierKeys` (@ `0x1c00015d4`) after the swap and stores the result at `gFilter+0x42` (store at `0x1c00076eb`), under the wait lock, so the modifier state stays consistent with the newly installed block list.
- `Apply` (patched) reads `gFilter+0x42` at the top of each iteration and, when the current key is a blocked modifier whose bit is set, clears that bit and forces the break-flag bit on the emitted key event.
- The two helpers are bounded: `FilterBlockedModifierKeys` iterates the fixed 10-entry modifier table at `gFilter+0x10` (loop cap `0x0A` at `0x1c000160e`); `IsBlockedKey` (@ `0x1c00013b0`) iterates the block list up to the count at `gFilter+0x38`, exactly as the existing `Apply` loop does. No new attacker-controlled index or size is introduced.

This is a keyboard-lockdown policy refinement (correctly releasing a held blocked modifier). It changes filtering behavior but does not add or remove any security boundary and is not a memory-corruption or bypass primitive.

---

## 3. Pseudocode Diff

### `KeyboardFilter::Set` — UNPATCHED vs PATCHED

```c
// ===== UNPATCHED (@ 0x1c0007574) =====
long KeyboardFilter::Set(KeyboardFilter* this,
                         _KBF_KEYBOARDLAYOUT const* layout,
                         uint64_t inputBufferLength)
{
    int64_t keyDataCount = *(int32_t*)(layout + 0x28);
    _KBF_KEYDATA* newBuf;

    if (keyDataCount) {
        uint64_t numberOfBytes = keyDataCount * 6;          // 32-bit count; product fits 64-bit
        if (numberOfBytes + 0x2c > inputBufferLength)
            return STATUS_BUFFER_TOO_SMALL;                 // 0xC0000023
        newBuf = ExAllocatePoolWithTag(NonPagedPoolNx, numberOfBytes, 'Kblf');
        if (!newBuf) return STATUS_INSUFFICIENT_RESOURCES;
        memmove(newBuf, layout + 0x2c, numberOfBytes);
    } else {
        newBuf = nullptr;
    }

    // SwapBlockList acquires+releases the wait lock internally around the swap.
    _KBF_KEYDATA* oldBuf = KeyboardFilter::SwapBlockList(this, layout, newBuf);

    if (oldBuf)
        ExFreePoolWithTag(oldBuf, 'Kblf');   // outside the lock; safe (no other thread holds oldBuf)
    return STATUS_SUCCESS;
}

// ===== PATCHED (@ 0x1c0007628) =====
long KeyboardFilter::Set(/* same args */)
{
    /* ... allocate newBuf, memmove: identical size check and copy ... */

    WdfWaitLockAcquire(WdfDriverGlobals, this->m_lock);        // lock moved out of SwapBlockList
    _KBF_KEYDATA* oldBuf = KeyboardFilter::SwapBlockList(this, layout, newBuf);  // no internal lock now

    if (newBuf)                                               // NEW feature bookkeeping
        this->m_blockedModifierKeyState =                    // gFilter+0x42
            KeyboardFilter::FilterBlockedModifierKeys(this, this->m_ModifierKeyState);
    // DbgPrintEx("m_ModifierKeyState == ..., m_blockedM...")
    WdfWaitLockRelease(WdfDriverGlobals, this->m_lock);       // released BEFORE the free

    if (oldBuf)
        ExFreePoolWithTag(oldBuf, 'Kblf');                   // still outside the lock, same as unpatched
    return STATUS_SUCCESS;
}
```

The free is outside the lock in both builds. The lock scope was widened only to cover the newly-added `FilterBlockedModifierKeys` recompute.

### `KeyboardFilter::SwapBlockList` — lock relocation

```c
// UNPATCHED (@ 0x1c00013b8): takes the wait lock internally
//   WdfWaitLockAcquire(...)          @ 0x1c00013fd
//   old = *(this+0x48); *(this+0x48) = newBuf;   // swap
//   WdfWaitLockRelease(...)          @ 0x1c0001473
//   return old;

// PATCHED (@ 0x1c0001518): NO internal lock; caller (Set) now holds it.
//   old = *(this+0x48); *(this+0x48) = newBuf;
//   return old;
// (Also: the "layout cleared" path zeroes a DWORD at this+0x40, clearing both
//  m_ModifierKeyState and the new m_blockedModifierKeyState word.)
```

Net synchronization is preserved, not added or removed.

### `KeyboardFilter::Apply` — modifier-state feature (patched only)

```c
// PATCHED adds at loop top (feature, not a fix):
int16_t blockedModState = this->m_blockedModifierKeyState;    // gFilter+0x42
if (blockedModState && KeyboardFilter::IsBlockedKey(this, makeCode, flags)
        && _bittest(&blockedModState, bit)) {
    this->m_blockedModifierKeyState = blockedModState & ~(1 << bit);  // clear on release
    // force the break-flag bit on the emitted key event
}
```

### `KbfEvtIoDeviceControl` — IOCTL 0xba404 input retrieval

```c
// UNPATCHED (@ 0x1c00071d0): rdi = Request at entry (0x1c00071f1); rdx never clobbered
//   -> rdx still holds Request at the WdfRequestRetrieveInputMemory call (0x1c000725e). Correct.

// PATCHED (@ 0x1c0007210): a DbgPrintEx (0x1c0007290) clobbers rdx, so:
//   mov rdx, rdi   ; 0x1c00072d1  -- reload Request before the call. Compensates for the trace call.
```

---

## 4. Assembly Analysis

### `KeyboardFilter::Set` (UNPATCHED, @ `0x1c0007574`)

```asm
00000001C0007574  mov     [rsp+arg_0], rbx
00000001C0007583  push    rdi
00000001C0007584  sub     rsp, 20h
00000001C0007588  movsxd  rax, dword ptr [rdx+28h]     ; KeyDataCount from layout
00000001C000758C  mov     rsi, rdx                      ; save layout
00000001C000758F  mov     rbp, cs:?gFilter              ; gFilter
00000001C0007596  test    eax, eax
00000001C0007598  jnz     short 0x1C000759E
00000001C000759A  xor     ebx, ebx                      ; newBuf = NULL (zero entries)
00000001C000759C  jmp     short 0x1C00075ED
00000001C000759E  lea     rdi, [rax+rax*2]              ; KeyDataCount * 3
00000001C00075A2  add     rdi, rdi                      ; * 6
00000001C00075A5  lea     rax, [rdi+2Ch]                ; 0x2c + KeyDataCount*6
00000001C00075A9  cmp     rax, r8                       ; vs InputBufferLength
00000001C00075AC  jbe     short 0x1C00075B5
00000001C00075AE  mov     eax, 0C0000023h               ; STATUS_BUFFER_TOO_SMALL
00000001C00075B3  jmp     short 0x1C0007616
00000001C00075B5  mov     r8d, 666C624Bh                ; PoolTag 'Kblf'
00000001C00075BB  mov     rdx, rdi
00000001C00075BE  mov     ecx, 200h                     ; NonPagedPoolNx
00000001C00075C3  call    cs:__imp_ExAllocatePoolWithTag
00000001C00075CF  mov     rbx, rax                      ; newBuf
00000001C00075D2  test    rax, rax
00000001C00075D5  jnz     short 0x1C00075DE
00000001C00075D7  mov     eax, 0C000009Ah               ; STATUS_INSUFFICIENT_RESOURCES
00000001C00075DC  jmp     short 0x1C0007616
00000001C00075DE  lea     rdx, [rsi+2Ch]                ; src = layout+0x2c
00000001C00075E2  mov     r8, rdi
00000001C00075E5  mov     rcx, rax
00000001C00075E8  call    memmove
00000001C00075ED  mov     r8, rbx                       ; arg3 = newBuf
00000001C00075F0  mov     rdx, rsi                      ; arg2 = layout
00000001C00075F3  mov     rcx, rbp                      ; arg1 = gFilter
00000001C00075F6  call    ?SwapBlockList                ; takes+releases wait lock internally
00000001C00075FB  test    rax, rax                      ; rax = old block list ptr
00000001C00075FE  jz      short 0x1C0007614
00000001C0007600  mov     edx, 666C624Bh                ; 'Kblf'
00000001C0007605  mov     rcx, rax                      ; old block list
00000001C0007608  call    cs:__imp_ExFreePoolWithTag    ; free outside the lock (safe, see Finding 1)
00000001C0007614  xor     eax, eax                      ; STATUS_SUCCESS
00000001C0007616  mov     rbx, [rsp+28h+arg_0]
00000001C000762A  retn
```

### `KeyboardFilter::SwapBlockList` (UNPATCHED, @ `0x1c00013b8`) — internal lock present

```asm
00000001C00013DB  mov     rax, cs:WdfFunctions_01015
00000001C00013E5  mov     rdx, [rcx+8]                  ; gFilter+0x8 = wait lock handle
00000001C00013EC  mov     rcx, cs:WdfDriverGlobals
00000001C00013F6  mov     rax, [rax+9E0h]               ; WdfWaitLockAcquire
00000001C00013FD  call    cs:__guard_dispatch_icall_fptr   ; ACQUIRE
...                                                       ; (compare layout header, update state)
00000001C0001436  mov     rbx, [rdi+48h]                ; old block list ptr
00000001C000145A  mov     [rdi+48h], rbp                ; install new block list ptr  (the swap)
00000001C000145E  mov     rcx, cs:WdfFunctions_01015
00000001C0001465  mov     rax, [rcx+9E8h]               ; WdfWaitLockRelease
00000001C000146C  mov     rcx, cs:WdfDriverGlobals
00000001C0001473  call    cs:__guard_dispatch_icall_fptr   ; RELEASE
00000001C0001479  mov     rax, rbx                      ; return old block list ptr
```

### `KeyboardFilter::Apply` (UNPATCHED, @ `0x1c0001008`) — lock spans the whole iteration

```asm
00000001C000102A  mov     rbx, cs:?gFilter
00000001C0001048  mov     rdx, [rbx+8]                  ; wait lock handle
00000001C000104C  mov     rax, [rax+9E0h]               ; WdfWaitLockAcquire
00000001C0001053  call    cs:__guard_dispatch_icall_fptr   ; ACQUIRE at function entry
...
00000001C000110F  mov     r11, [rbx+48h]                ; load block list ptr (under lock)
00000001C00011A0  mov     r11, [rbx+48h]                ; load block list ptr (under lock)
...                                                       ; iterate/dereference r11 (still under lock)
00000001C00012A7  mov     rax, cs:WdfFunctions_01015
00000001C00012AE  mov     rdx, [rbx+8]
00000001C00012B9  mov     rax, [rax+9E8h]               ; WdfWaitLockRelease
00000001C00012C0  call    cs:__guard_dispatch_icall_fptr   ; RELEASE at function exit
```

Because acquire (`0x1c0001053`) and release (`0x1c00012c0`) bracket the entire iteration, `Apply` and `SwapBlockList` cannot overlap on the block list.

### `KeyboardFilter::Set` (PATCHED, @ `0x1c0007628`) — lock relocated here; free still after release

```asm
00000001C00076A7  mov     rax, cs:WdfFunctions_01015
00000001C00076AE  mov     rdx, [rbx+8]                  ; wait lock handle
00000001C00076B9  mov     rax, [rax+9E0h]               ; WdfWaitLockAcquire
00000001C00076C0  call    cs:__guard_dispatch_icall_fptr   ; ACQUIRE (moved into Set)
00000001C00076CF  call    ?SwapBlockList                ; no internal lock now
00000001C00076D4  movzx   edi, word ptr [rbx+40h]       ; m_ModifierKeyState
00000001C00076D8  mov     rbp, rax                      ; old block list ptr
00000001C00076DB  test    rsi, rsi                      ; newBuf != 0 ?
00000001C00076DE  jz      short 0x1C00076F1
00000001C00076E6  call    ?FilterBlockedModifierKeys    ; NEW recompute
00000001C00076EB  mov     [rbx+42h], ax                 ; store m_blockedModifierKeyState
...                                                       ; DbgPrintEx
00000001C000771B  mov     rax, cs:WdfFunctions_01015
00000001C0007722  mov     rdx, [rbx+8]
00000001C000772D  mov     rax, [rax+9E8h]               ; WdfWaitLockRelease
00000001C0007734  call    cs:__guard_dispatch_icall_fptr   ; RELEASE
00000001C000773A  test    rbp, rbp                      ; old block list ptr
00000001C000773D  jz      short 0x1C0007753
00000001C000773F  mov     edx, 666C624Bh
00000001C0007744  mov     rcx, rbp
00000001C0007747  call    cs:__imp_ExFreePoolWithTag    ; FREE happens AFTER release (same as unpatched)
```

### `KbfEvtIoDeviceControl` — IOCTL 0xba404 input retrieval

```asm
; UNPATCHED (@ 0x1c00071d0): rdx = Request throughout the 0xba404 path
00000001C00071F1  mov     rdi, rdx                      ; rdi = Request (arg2)
...                                                       ; rdx never overwritten on this path
00000001C0007245  mov     rax, cs:WdfFunctions_01015
00000001C000724C  lea     r8, [rbp+var_20]              ; &WDFMEMORY out
00000001C0007250  mov     rcx, cs:WdfDriverGlobals
00000001C0007257  mov     rax, [rax+858h]               ; WdfRequestRetrieveInputMemory
00000001C000725E  call    cs:__guard_dispatch_icall_fptr   ; rdx still = Request

; PATCHED (@ 0x1c0007210): DbgPrintEx clobbers rdx, so it is reloaded
00000001C0007290  call    cs:__imp_DbgPrintEx           ; "Enter IOCTL_KBFILTR_SET_KEYBOARD..." (clobbers rdx)
...
00000001C00072C6  lea     r8, [rbp+var_20]
00000001C00072CA  mov     rcx, cs:WdfDriverGlobals
00000001C00072D1  mov     rdx, rdi                      ; reload Request (compensates for the trace call)
00000001C00072D4  mov     rax, [rax+858h]               ; WdfRequestRetrieveInputMemory
00000001C00072DB  call    cs:__guard_dispatch_icall_fptr
```

---

## 5. Trigger Conditions

There is no vulnerability to trigger. For completeness, the reachable surface is:

1. `KeyboardFilter::Set` is reached via `DeviceIoControl(handle, 0xba404, inputBuffer, ...)` → `KbfEvtIoDeviceControl` → `WdfRequestRetrieveInputMemory` → `WdfMemoryGetBuffer` → `Set(gFilter, buffer, inputBufferLength)` (call at `0x1c0007298` unpatched).
2. `KbfEvtIoDeviceControl` validates the `0xba404` input in the same way in both builds: `InputBufferLength <= 0x179C`, `InputBufferLength >= 0x2c`, and `Set` additionally rejects `0x2c + KeyDataCount*6 > InputBufferLength` with `STATUS_BUFFER_TOO_SMALL`. `KeyDataCount` is a 32-bit field, so `KeyDataCount*6` cannot overflow the 64-bit size computation, and the input is already capped at `0x179C`.
3. `KeyboardFilter::Apply` runs from the keyboard read-completion path (`KbfEvtReadCompletionRoutine`) and from IOCTL `0xb2408`. It serializes all block-list access under the `gFilter+0x8` wait lock in both builds.

None of these paths yields a memory-safety primitive.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive is present. The block-list swap and free are correctly serialized against the only reader (`Apply`) by the `gFilter+0x8` wait lock in both builds, and the free occurs after the swap when no other thread can hold the old pointer. The input length is validated and the allocation arithmetic cannot overflow. The modifier-state feature operates only on the fixed 10-entry modifier table and the already-bounded block list.

Because there is no reachable memory-corruption or bypass primitive, there is nothing to develop into an exploit, and considerations such as pool grooming, KASLR defeat, or token replacement do not apply to this patch.

---

## 7. Debugger Playbook

The following breakpoints let a reviewer confirm the synchronization discipline described above. They are for behavioral confirmation, not for reproducing a crash (there is no crash to reproduce).

| # | Address (unpatched) | What it shows |
|---|---------------------|---------------|
| 1 | `0x1c0001053` | `WdfWaitLockAcquire` at the top of `Apply` — lock is held before any block-list read. |
| 2 | `0x1c00011a0` | `mov r11, [rbx+0x48]` in `Apply` — block-list pointer loaded while the lock is held. |
| 3 | `0x1c00012c0` | `WdfWaitLockRelease` at the bottom of `Apply` — lock released only after iteration completes. |
| 4 | `0x1c00013fd` | `WdfWaitLockAcquire` inside `SwapBlockList` — confirms the swap waits for `Apply` to release. |
| 5 | `0x1c000145a` | `mov [rdi+0x48], rbp` — the pointer swap itself, under the lock. |
| 6 | `0x1c0007608` | `ExFreePoolWithTag` in `Set` — old pointer freed after the swap; by this point no thread can hold it. |
| 7 | `0x1c000725e` | `WdfRequestRetrieveInputMemory` in the `0xba404` path — inspect `rdx`; it already equals `rdi` (the Request handle). |

A reviewer stepping these will observe that `Apply` never dereferences the block-list pointer outside the lock, so freeing the old list after the swap does not produce a dangling access.

### `gFilter` field notes (as evidenced by the code)

| Offset | Field |
|--------|-------|
| `+0x00` | dword blocking state |
| `+0x08` | WDFWAITLOCK (`m_lock`) |
| `+0x10` | 0x2c-byte modifier-key table (10 entries) |
| `+0x38` | dword key-data count |
| `+0x40` | word `m_ModifierKeyState` |
| `+0x42` | word `m_blockedModifierKeyState` (written only in the patched build via `FilterBlockedModifierKeys`) |
| `+0x48` | ptr block list (`m_keyData`) |

`_KBF_KEYDATA` is 6 bytes. `_KBF_KEYBOARDLAYOUT` input is a `0x2c`-byte header followed by `KeyDataCount * 6` bytes.

**IOCTL codes:** `0xb2408` SEND_INPUT, `0xb240c` GET_KEYBOARD_LAYOUT, `0xb2410` GET_KEYBOARD_ID, `0xba404` SET_KEYBOARD_LAYOUT. WDF calls dispatch through `__guard_dispatch_icall_fptr`; `WdfWaitLockAcquire = WdfFunctions[0x9e0/8]`, `WdfWaitLockRelease = WdfFunctions[0x9e8/8]`, `WdfRequestRetrieveInputMemory = WdfFunctions[0x858/8]`, `WdfMemoryGetBuffer = WdfFunctions[0x610/8]`.

---

## 8. Changed Functions — Full Triage

| Function | Similarity | Change Type | Note |
|----------|-----------:|-------------|------|
| `KeyboardFilter::Set` | 0.8708 | feature + refactor | Wait lock relocated here from `SwapBlockList`; adds the `FilterBlockedModifierKeys` recompute of `gFilter+0x42`; adds `DbgPrintEx`. Free still occurs after the lock release. No security fix. |
| `KeyboardFilter::SwapBlockList` | 0.9242 | refactor | Internal wait lock removed (moved to caller `Set`); "layout cleared" path now zeroes both `m_ModifierKeyState` and the new `m_blockedModifierKeyState`; adds `DbgPrintEx`. Net synchronization unchanged. |
| `KeyboardFilter::Apply` | 0.7004 | feature | Adds `m_blockedModifierKeyState` (`gFilter+0x42`) tracking via the new `IsBlockedKey` helper and forces the break-flag bit on released blocked modifiers. Bounds and locking unchanged. |
| `KbfEvtIoDeviceControl` | 0.9678 | tracing | Adds `DbgPrintEx` at IOCTL entry/exit; the `mov rdx, rdi` in the `0xba404` path merely reloads the Request handle that the added trace call clobbered. Input validation identical to unpatched. |
| `KbfEvtDeviceAdd` | 0.8148 | tracing | Adds `DbgPrintEx` on `WdfDeviceCreate` / `WdfIoQueueCreate` failure paths. Logic identical. |
| `KbfEvtIoRead` | 0.9807 | tracing | Adds `DbgPrintEx` on `WdfRequestSend` failure. |
| `KbfEvtDriverCleanup` | 0.9804 | tracing | Adds `DbgPrintEx`. |
| `DriverEntry` | 0.9506 | tracing + feature init | Adds `DbgPrintEx`; zero-initializes the filter modifier state with a DWORD write (byte 0x40) so it also clears the new `gFilter+0x42` word. |

All eight changes are debug tracing, the modifier-state feature, or the lock relocation that supports it. None is a security fix.

---

## 9. Added / Removed Functions

The patched build adds two standalone helper functions that do not exist in the unpatched build:

- `KeyboardFilter::IsBlockedKey` (@ `0x1c00013b0`) — scans the block list (bounded by the count at `gFilter+0x38`) for a key that matches and passes `CheckModifiers`.
- `KeyboardFilter::FilterBlockedModifierKeys` (@ `0x1c00015d4`) — iterates the fixed 10-entry modifier table, calls `IsBlockedKey` per set modifier bit, and builds the `m_blockedModifierKeyState` bitmask.

No functions were removed. Both new functions exist solely to support the modifier-state tracking feature and are bounded; neither introduces an attacker-controlled index or length.

---

## 10. Confidence & Caveats

**Confidence: HIGH** that the patch contains no security-relevant fix.

Rationale, all anchored to both binaries:

- **No use-after-free.** `Apply` acquires the wait lock at `0x1c0001053` and releases at `0x1c00012c0`, bracketing every block-list dereference; `SwapBlockList` acquires the same lock at `0x1c00013fd` before swapping. The swap therefore cannot run concurrently with `Apply`'s iteration, and the old pointer freed at `0x1c0007608` is unreachable by any other thread at that point. The patched build frees at `0x1c0007747`, *after* releasing the lock at `0x1c0007734` — i.e. the free is outside the lock in both builds, so the patch did not move the free under the lock.

- **No missing-parameter bug.** In the unpatched `0xba404` path, `rdx` holds the Request handle continuously from entry (`mov rdi, rdx` at `0x1c00071f1`) to the retrieval call at `0x1c000725e`; nothing clobbers it. The patched `mov rdx, rdi` at `0x1c00072d1` only restores `rdx` after the newly-added `DbgPrintEx` at `0x1c0007290`.

- **Input validation is identical.** The `0xba404` handler applies the same `0x2c <= InputBufferLength <= 0x179C` bounds in both builds, and `Set`'s `0x2c + KeyDataCount*6 > InputBufferLength` check is unchanged. The 32-bit `KeyDataCount` cannot overflow the 64-bit size arithmetic.

- **The only behavioral change is a feature.** The `m_blockedModifierKeyState` tracking (new `gFilter+0x42` word, `IsBlockedKey`, `FilterBlockedModifierKeys`, and the `Apply` break-flag logic) is a keyboard-filter policy refinement over bounded, fixed-size data. It adds no security boundary and removes none.

**Caveat:** This analysis covers only the two supplied builds. The pervasive `DbgPrintEx` additions indicate the patched binary is a debug/traced build of the same source revision as the modifier-state feature; the presence of tracing is itself consistent with a servicing/feature build rather than a security update.
