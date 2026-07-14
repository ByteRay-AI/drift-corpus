Title: ndistapi.sys — Uninitialized pool fields passed to TAPI provider callback (CWE-908) fixed
Date: 2026-01-13
Slug: ndistapi_26456c1b-ndistapi-report-20260626-051805
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Low
KBDate: 2026-01-13

## 1. Overview

- **Unpatched Binary:** `ndistapi_unpatched.sys`
- **Patched Binary:** `ndistapi_patched.sys`
- **Overall Similarity Score:** `0.8228` (82.28%)
- **Diff Statistics:**
  - Matched Functions: 49
  - Changed Functions: 40
  - Identical Functions: 9
  - Unmatched (Unpatched): 0
  - Unmatched (Patched): 0
- **Verdict:** The patch migrates the driver's own non-paged pool allocations from the non-zeroing `ExAllocatePoolWithTag` to the zero-initializing `ExAllocatePool2`. At two allocation sites (`DoIoctlQuerySetWork`, `SendProviderShutdown`) the driver builds a request structure, leaves several header fields uninitialized, and hands that structure to an in-kernel TAPI provider's request-handler callback. The unpatched code therefore exposes uninitialized non-paged pool bytes to the provider callback (CWE-908). The patch closes this by zero-initializing the buffer. This is a low-severity hardening fix: the uninitialized bytes are only reachable by the registered kernel provider driver, and no path returns them to the user-mode caller.

---

## 2. Vulnerability Summary

### Finding 1: DoIoctlQuerySetWork (Low Severity)

- **Vulnerability Class:** Use of Uninitialized Memory (CWE-908)
- **Affected Function:** `DoIoctlQuerySetWork` (IOCTL `0x8FFF23C8` / `0x8FFF23CC` handlers)
- **Root Cause:** The unpatched code allocates the request buffer with `ExAllocatePoolWithTag(516 /* NonPagedPoolNxCacheAligned */, arg2[0xC]+0xEC, 'TAPI')`, which does **not** zero-initialize memory. The driver populates specific header fields and the trailing data region but leaves gaps within the header uninitialized (offsets `0x28-0x4F`, `0x54-0x57`, `0x5C-0x5F`, `0x6C-0xE7`). The structure at offset `+0x30` is then passed to the TAPI provider's request-handler callback, so these uninitialized non-paged pool bytes are read by the provider.
- **Scope of exposure:** The data region at `P+0xE8` (the part copied back to the user-mode `SystemBuffer` on synchronous success) is fully initialized before the callback: the driver `memmove`s `arg2[0xC]` bytes of user input into `P+0xE8`. Only the uninitialized *header* gaps (`0x30`..`0xE7`) reach the provider callback; they are not copied back to user mode by this driver. There is no demonstrable user-mode information disclosure in this function; the residual exposure is uninitialized pool data visible to the in-kernel provider.
- **The Fix:** The patch replaces the allocation with `ExAllocatePool2(0x48, ...)` (`POOL_FLAG_NON_PAGED | POOL_FLAG_CACHE_ALIGNED`), which zero-initializes the allocation by default, so the header gaps are zero when the structure reaches the provider.
- **Not part of the fix:** The indirect call to the provider handler is Control-Flow-Guard protected in **both** builds (unpatched `__guard_dispatch_icall_fptr`, patched out-of-line `_guard_dispatch_icall` thunk). CFG was not added by this patch.
- **Attacker-Reachable Entry Point:** `\Device\NdisTapi` via `IRP_MJ_DEVICE_CONTROL` (METHOD_BUFFERED).
- **Data Flow (Call Chain):**
  1. `NdisTapiDispatch` receives `IRP_MJ_DEVICE_CONTROL`.
  2. `DoIoctlQuerySetWork` validates the TAPI sub-code, allocates buffer `P`, and initializes the header fields it uses plus the `P+0xE8` data region (from user input).
  3. The provider request handler is called via a CFG-guarded indirect call with `P+0x30`; the provider reads a structure whose header gaps are uninitialized pool data in the unpatched build.

### Finding 2: SendProviderShutdown (Low Severity)

- **Vulnerability Class:** Use of Uninitialized Memory (CWE-908)
- **Affected Function:** `SendProviderShutdown` (invoked during `IRP_MJ_CLOSE` via `DoIrpMjCloseWork`, and during `NdisTapiDeregisterProvider`)
- **Root Cause:** In the unpatched build the caller allocates a `0xF0`-byte buffer with `ExAllocatePoolWithTag(516, 0xF0, 'TAPI')` (not zeroed) and passes it to `SendProviderShutdown`. The function initializes only specific fields (`0x10`, `0x18`, `0x20`, `0x24`, `0x50`, `0x58`, `0x60`, `0x68`, `0xE8`) and passes the structure at offset `+0x30` to the provider callback, exposing the uninitialized gaps.
- **The Fix:** Allocation is pushed down into `SendProviderShutdown` itself using `ExAllocatePool2(0x48, 0xF0, 'TAPI')` (zero-initialized), with a null-check that returns `STATUS_INSUFFICIENT_RESOURCES`.
- **Not part of the fix:** The provider callback is CFG-guarded in both builds.
- **Scope of exposure:** This path runs during handle close / provider deregistration and returns nothing to user mode. The uninitialized bytes are only visible to the in-kernel provider callback. Low severity.
- **Attacker-Reachable Entry Point:** Closing the last handle to `\Device\NdisTapi` triggers `IRP_MJ_CLOSE`, invoking `DoIrpMjCloseWork`.
- **Data Flow (Call Chain):**
  1. `DoIrpMjCloseWork` (unpatched) allocates the unzeroed `0xF0`-byte buffer and calls `SendProviderShutdown`.
  2. `SendProviderShutdown` populates selective fields and passes `P + 0x30` to the TAPI provider callback.

---

## 3. Pseudocode Diff

### `DoIoctlQuerySetWork`

```c
// === UNPATCHED ===
// Allocates pool WITHOUT zero-initialization (NonPagedPoolNxCacheAligned = 516)
PoolWithTag = ExAllocatePoolWithTag((POOL_TYPE)516, *(_DWORD *)(a2 + 12) + 236, 'IPAT');
v23 = PoolWithTag;

// Explicit field population (leaving header gaps uninitialized)
v23[9]  = 0;               // offset 0x24
v23[2..3] (qwords) = a1, v13;   // offset 0x10 (IRP), 0x18 (provider)
v23[8]  = requestId;       // offset 0x20
memmove(v23 + 58, (a2 + 16), *(a2 + 12));  // offset 0xE8: user data (data region)
v23[20] = boolFlag;        // offset 0x50
v23[22] = *(a2 + 4);       // offset 0x58 (TAPI sub-code)
v23[12] (qword) = v23 + 58;// offset 0x60 -> data region
v23[26] = *(a2 + 12);      // offset 0x68 (data size)
// GAPS NOT INITIALIZED: [0x28-0x4F], [0x54-0x57], [0x5C-0x5F], [0x6C-0xE7]

// Structure at +0x30 passed to provider via CFG-guarded indirect call:
v33 = ((__int64 (__fastcall *)(__int64, _DWORD *))v13[3])(v13[2], v23 + 12);  // v23+12 == P+0x30

// On synchronous success the DATA region (already user-initialized) is copied back:
memmove(v37 + 4, v23 + 58, (unsigned int)v37[3]);   // src = P+0xE8, not the header gaps

// === PATCHED ===
// ExAllocatePool2 zero-initializes the allocation by default
v23 = ExAllocatePool2(0x48, *(_DWORD *)(a2 + 12) + 236, 'IPAT');
// Same field population; header gaps are now zero. Same CFG-guarded indirect call.
```

### `SendProviderShutdown`

```c
// === UNPATCHED ===
// Caller (DoIrpMjCloseWork / NdisTapiDeregisterProvider) allocates an unzeroed buffer
void *P = ExAllocatePoolWithTag((POOL_TYPE)516, 0xF0, 'IPAT');
SendProviderShutdown(Provider, &newIrql, P);

// Inside SendProviderShutdown (arg3 == P):
*(P + 0x10) = 0;
*(P + 0x18) = Provider;
*(P + 0x24) = 1;
*(P + 0x50) = 1;
*(P + 0x58) = 0x7030119;
*(P + 0x60) = P + 0xE8;
*(P + 0x68) = 4;
// header gaps [0x28-0x4F], [0x54-0x57], [0x5C-0x5F], [0x6C-0xE7] NOT set
handler(Provider->ctx, P + 0x30);   // CFG-guarded, receives uninitialized gaps

// === PATCHED ===
// Allocation moved inside SendProviderShutdown and zero-initialized
void *P = ExAllocatePool2(0x48, 0xF0, 'IPAT');
if (!P) return STATUS_INSUFFICIENT_RESOURCES;
// same field population; header gaps are now zero
```

---

## 4. Assembly Analysis

### `DoIoctlQuerySetWork` (Unpatched, `0x1C000247C`)

```assembly
; Allocation (does NOT zero):
0x1C0002626  mov     edx, ecx                  ; NumberOfBytes = data size + 0xEC
0x1C0002628  mov     r8d, 49504154h            ; Tag 'TAPI'
0x1C000262E  mov     ecx, 204h                 ; PoolType = NonPagedPoolNxCacheAligned
0x1C0002633  call    cs:__imp_ExAllocatePoolWithTag
0x1C000263F  mov     r14, rax                  ; r14 = P
; Selective header initializations:
0x1C00026C9  mov     [r14+24h], edi            ; = 0
0x1C00026CD  mov     [r14+10h], r13            ; IRP pointer
0x1C00026D1  mov     [r14+18h], r15            ; provider pointer
0x1C00026EA  mov     [r14+20h], eax            ; request ID
0x1C00026F2  call    memmove                   ; user data -> [r14+0E8h] (data region)
0x1C0002711  mov     [r14+50h], eax            ; flag
0x1C0002718  mov     [r14+58h], eax            ; TAPI sub-code
0x1C0002723  mov     [r14+60h], rax            ; -> [r14+0E8h]
0x1C000272F  mov     [r14+68h], eax            ; data size
; header gaps [r14+28h..4Fh], [r14+54h..57h], [r14+5Ch..5Fh], [r14+6Ch..E7h] left uninitialized
; Provider callback (CFG-guarded), structure passed at r14+30h:
0x1C00027AA  lea     rdx, [r14+30h]
0x1C00027B2  call    cs:__guard_dispatch_icall_fptr
; Copy-back to user on synchronous success reads the DATA region only:
0x1C00028B7  lea     rdx, [r14+0E8h]           ; Src = data region (user-initialized)
0x1C00028BE  call    memmove
```

### `DoIoctlQuerySetWork` (Patched, `0x1400013D0`)

```assembly
; Zero-initializing allocation:
0x140001557  mov     edx, eax                  ; NumberOfBytes = data size + 0xEC
0x140001559  mov     ecx, 48h                  ; POOL_FLAG_NON_PAGED | POOL_FLAG_CACHE_ALIGNED
0x14000155E  mov     r8d, 49504154h            ; Tag 'TAPI'
0x140001564  call    cs:__imp_ExAllocatePool2  ; zero-initialized by default
0x140001570  mov     r14, rax
; Same field population; header gaps are now zero.
; Provider callback (still CFG-guarded), structure passed at r14+30h:
0x1400016D5  lea     rdx, [r14+30h]
0x1400016DD  call    _guard_dispatch_icall
```

### `SendProviderShutdown` (Unpatched, `0x1C00020D8`) and caller `DoIrpMjCloseWork`

```assembly
; Caller DoIrpMjCloseWork allocates the unzeroed 0xF0 buffer:
0x1C0002222  mov     edx, 0F0h                 ; NumberOfBytes
0x1C000222A  mov     r8d, 49504154h            ; Tag
0x1C0002233  mov     ecx, 204h                 ; NonPagedPoolNxCacheAligned
0x1C0002238  call    cs:__imp_ExAllocatePoolWithTag
0x1C0002254  call    SendProviderShutdown      ; r8 = buffer
; Inside SendProviderShutdown (arg3 = r8):
0x1C00020ED  and     qword ptr [r8+10h], 0     ; = 0
0x1C00020F9  mov     [r8+18h], rcx             ; provider
0x1C0002102  mov     [r8+24h], eax             ; = 1
0x1C0002118  mov     [r8+50h], eax             ; = 1
0x1C000211C  mov     dword ptr [r8+58h], 7030119h
0x1C0002124  mov     [r8+60h], r9             ; -> r8+0E8h
0x1C0002128  mov     dword ptr [r8+68h], 4
; header gaps [r8+28h..4Fh], [r8+54h..57h], [r8+5Ch..5Fh], [r8+6Ch..E7h] left uninitialized
; Provider callback (CFG-guarded), structure at r8+30h (rsi == r8):
0x1C0002153  lea     rdx, [rsi+30h]
0x1C000215B  call    cs:__guard_dispatch_icall_fptr
```

### `SendProviderShutdown` (Patched, `0x140002B84`)

```assembly
; Allocation moved inside the function, zero-initialized:
0x140002B9E  mov     edx, 0F0h
0x140002BA3  mov     ecx, 48h                  ; POOL_FLAG_NON_PAGED | POOL_FLAG_CACHE_ALIGNED
0x140002BA8  mov     r8d, 49504154h            ; Tag 'TAPI'
0x140002BAE  call    cs:__imp_ExAllocatePool2
0x140002BBA  mov     rdi, rax
0x140002BBD  test    rax, rax
0x140002BC0  jnz     short loc_140002BCC       ; else return STATUS_INSUFFICIENT_RESOURCES
; Provider callback (still CFG-guarded):
0x140002C2D  call    _guard_dispatch_icall
```

---

## 5. Trigger Conditions

To reach the uninitialized-header exposure in `DoIoctlQuerySetWork`:

1. Obtain a handle to `\Device\NdisTapi` (created via `WdmlibIoCreateDeviceSecure`; the device SDDL governs which callers may open it).
2. A TAPI provider (WAN miniport driver) must be registered and matched by device ID, otherwise the IOCTL fails before the allocation.
3. Construct an input buffer of at least `0x14` bytes.
4. Set `buffer[0x04]` (TAPI sub-code) to a valid value in the range `0x7030101`..`0x7030124`.
5. Set `buffer[0x08]` to a Device ID within a registered provider's range.
6. Set `buffer[0x0C]` (data size) to pass validation: `>= lookup_table_minimum`, `<= 0x10000000`, `data_size + 0x13` must not overflow 32-bit, and both `InputBufferLength` and `OutputBufferLength` must be `>= data_size + 0x13`.
7. Invoke `DeviceIoControl` with IOCTL `0x8FFF23C8` or `0x8FFF23CC` (METHOD_BUFFERED).

In the unpatched build, the allocated request structure has uninitialized header gaps when it is handed to the provider's request-handler callback. These bytes are not returned to the user output buffer by this driver; the output buffer receives only the `P+0xE8` data region, which is initialized from the caller's own input before the callback.

---

## 6. Exploit Primitive & Development Notes

- **Primitive:** None demonstrable from this driver. The uninitialized non-paged pool bytes in the request structure are read only by the in-kernel TAPI provider callback; the unpatched driver does not copy any uninitialized header bytes back to the user-mode caller. Whether a specific provider propagates those bytes anywhere is provider-dependent and outside this binary.
- **Nature of the fix:** Defense hardening against use of uninitialized pool memory (CWE-908). Zero-initialization removes stale non-paged pool contents from the structure before it crosses the driver/provider boundary.
- **What this is not:** There is no evidence in either binary of a user-mode kernel information-disclosure primitive, a KASLR bypass, or a privilege-escalation chain arising from this change. Those are not claimed.

---

## 7. Debugger Playbook

For an analyst using a kernel debugger against the **unpatched** binary:

- **Breakpoints:**
  - `bp ndistapi!DoIoctlQuerySetWork` — function entry.
  - `bp 0x1C0002633` — the `ExAllocatePoolWithTag` call (return value `rax`, moved to `r14`, is the non-zeroed buffer `P`).
  - `bp 0x1C00027B2` — the CFG-guarded indirect call to the provider handler; `rdx = P+0x30` is the structure the provider receives.
- **What to Inspect:**
  - At the allocation: capture `P` from `rax`/`r14`.
  - Before `0x1C00027B2`: `dq r14+0x28 L10` and `dq r14+0x6C` — in the unpatched build these header gaps contain stale non-paged pool data; in the patched build they are zero.
  - Note that the data region at `r14+0xE8` is already initialized (user input copied by the `memmove` at `0x1C00026F2`), so it does not exhibit uninitialized residue.
- **Key Instructions/Offsets:**
  - Buffer pointer: `r14` (or `P`).
  - Uninitialized header ranges: `r14+0x28..0x4F`, `r14+0x54..0x57`, `r14+0x5C..0x5F`, `r14+0x6C..0xE7`.
  - Vulnerable allocation: `0x1C0002633`. Provider callback: `0x1C00027B2`. Copy-back of data region: `0x1C00028BE`.
- **Trigger Setup:**
  ```c
  HANDLE h = CreateFileW(L"\\\\.\\NdisTapi", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  DWORD buf[16] = {0};
  buf[1] = 0x7030101; // valid TAPI sub-code
  buf[2] = DeviceID;  // target provider device ID
  buf[3] = 0x40;      // data size
  DWORD outBuf[256] = {0};
  DWORD bytesReturned;
  DeviceIoControl(h, 0x8FFF23C8, buf, sizeof(buf), outBuf, sizeof(outBuf), &bytesReturned, NULL);
  ```
- **Expected Observation:**
  On the unpatched binary the header gaps at `r14+0x28`..`0xE7` hold non-zero pool residue when the provider callback runs; on the patched binary those bytes are zero. The user-mode `outBuf` reflects only what the provider wrote into the data region, not the uninitialized header bytes.

---

## 8. Changed Functions — Full Triage

*The patch shifts the driver's own pool allocations from `ExAllocatePoolWithTag` to `ExAllocatePool2`, drops the now-redundant `memset` calls that follow zeroing allocations, modernizes lookaside-list handling (`ExAllocateFromNPagedLookasideList` / `ExFreeToNPagedLookasideList`), and uses out-of-line CFG dispatch thunks. CFG protection on indirect provider calls is present in both builds.*

- **DoIoctlQuerySetWork** (`0.9304`): **Security relevant (CWE-908, low).** Request buffer switched to zero-initializing `ExAllocatePool2`, so header gaps handed to the provider callback are no longer uninitialized pool data.
- **SendProviderShutdown** (`0.5648`): **Security relevant (CWE-908, low).** Allocation moved inside the function and switched to `ExAllocatePool2`, with an added null-check. Same uninitialized-header class as above.
- **DoProviderInitComplete** (`0.9519`): Replaced legacy pool allocation with `ExAllocatePool2`; the following `memset` is retained in both builds.
- **SendProviderInitRequest** (`0.9855`): Replaced legacy pool allocation with `ExAllocatePool2`. CFG-guarded indirect call present in both builds.
- **NdisTapiRegisterProvider** (`0.9440`): Replaced legacy pool allocation with `ExAllocatePool2`; removed the now-redundant `memset` of the zeroed allocation.
- **DriverEntry** (`0.6978`): Replaced a pool allocation with `ExAllocatePool2` and modernized lookaside-list cleanup.
- **NdisTapiUnload** (`0.7264`): Modernized lookaside-list cleanup; removed unused statistics counters.
- **NdisTapiDeregisterProvider** (`0.8410`): Refactored so the shutdown buffer is allocated inside `SendProviderShutdown` rather than here.
- **DoIrpMjCloseWork** (`0.7512`): Refactored; removed the `0xF0`-byte pool allocation (moved into `SendProviderShutdown`).
- **DoGetProviderEventsWork** (`0.9271`): Modernized lookaside-list freeing; removed statistics counters.
- **NdisTapiIndicateStatus** (`0.8733`): Modernized lookaside-list allocation; removed statistics counters.
- **NdisTapiDispatch** (`0.8603`): Control-flow restructuring around the `STATUS_PENDING` check; IOCTL dispatch codes unchanged.
- **NdisTapiCompleteRequest** (`0.9649`): Register renaming and field-assignment reordering; equivalent logic.
- **NdisTapiCleanup** (`0.9627`): Field-assignment reordering; equivalent logic.
- **NdisTapiCancel** (`0.8436`): Linked-list traversal restructured; equivalent logic.
- **DoIoctlConnectWork** (`0.9562`): Provider-state comparison rewritten to an equivalent unsigned form (same accepted states).
- **DoLineCreateWork** (`0.8988`): Lock re-acquire / counter re-read restructured; equivalent logic.
- **memcpy / memset**: Rebuilt by the compiler with different code generation.

---

## 9. Unmatched Functions

- **Removed:** None security-relevant.
- **Added:** None security-relevant. (The patched build additionally contains compiler-runtime and library helpers such as CPU-feature-dispatched `memset` variants and CFG dispatch thunks; these are code-generation artifacts, not driver logic.)

---

## 10. Confidence & Caveats

- **Confidence:** High on the mechanism (in both `.asm` and `.c`): the driver's own allocations move from non-zeroing `ExAllocatePoolWithTag` to zero-initializing `ExAllocatePool2`, and two of those buffers reach a provider callback with uninitialized header gaps in the unpatched build.
- **Severity:** Low. The uninitialized bytes are exposed only to the in-kernel TAPI provider callback. No path in this driver returns uninitialized header bytes to the user-mode caller; the user output buffer receives only the initialized data region.
- **Assumptions:**
  - Reaching the vulnerable allocation requires a registered, matching TAPI provider; without one the IOCTL fails early.
  - Any onward propagation of the uninitialized bytes depends on the specific provider driver and is outside these binaries.
