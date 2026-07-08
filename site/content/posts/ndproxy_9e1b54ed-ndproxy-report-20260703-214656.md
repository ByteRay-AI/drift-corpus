Title: ndproxy.sys — No security-relevant change (new IOCTL 0x8FFF23DC query handler added, returns an already-exposed counter)
Date: 2026-07-03
Slug: ndproxy_9e1b54ed-ndproxy-report-20260703-214656
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: None
KBDate: 2026-01-13

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `ndproxy_unpatched.sys` |
| **Patched binary** | `ndproxy_patched.sys` |
| **Overall similarity** | 0.9913 (99.13%) |
| **Matched functions** | 148 |
| **Changed functions** | 1 |
| **Identical functions** | 147 |
| **Unmatched (unpatched → patched)** | 0 / 0 |

**Verdict:** The patch adds a single new IOCTL handler (`0x8FFF23DC`) to the `IRP_MJ_DEVICE_CONTROL` dispatch routine `PxIODispatch` of `ndproxy.sys`. In the unpatched binary this IOCTL code is not recognized and falls through to the default path, which returns `STATUS_UNSUCCESSFUL` with no side effects. The new handler is bounds-checked and spinlock-protected, and returns the same global DWORD (`dword_1C0009738`) that the existing `0x8FFF23C0` handler already returns to the same callers. This is a functionality addition, not a security fix: no memory-corruption, use-after-free, type-confusion, or information-disclosure condition is created or removed, and the unpatched behavior for the missing code is safe. The change adds a small amount of readable IOCTL surface rather than removing any. No security-relevant change is delivered by this patch.

---

## 2. Vulnerability Summary

### Finding 1 — New IOCTL handler `0x8FFF23DC` (no security impact)

| Attribute | Detail |
|---|---|
| **Severity** | None (informational) |
| **Class** | New IOCTL dispatch handler added (feature/compatibility) |
| **Function** | `PxIODispatch` @ `0x1C0003B80` (IRP_MJ_DEVICE_CONTROL dispatch for `\Device\NDProxy`) |
| **Entry point** | `DeviceIoControl` on `\Device\NDProxy`, IOCTL `0x8FFF23DC`, METHOD_BUFFERED |

**Root cause:**

The unpatched `PxIODispatch` recognizes IOCTL codes `0x8FFF23C0`, `0x8FFF23C4`, the `0x8FFF23C8`/`0x8FFF23CC` pair, `0x8FFF23D0`, `0x8FFF23D4`, and `0x8FFF23D8`, but does **not** recognize `0x8FFF23DC`. When that code arrives, the dispatch chain tests every known code, fails all comparisons, and falls through to the default path at `0x1C0003C18`, which sets `ebx = 0xC000000D` (`STATUS_UNSUCCESSFUL`) and completes the IRP. No processing occurs, no output is written, no lock is held, and no state is mutated — the fall-through is benign.

The patch inserts a new comparison (`cmp ecx, 8FFF23DCh; jz loc_1C0003C2E`) at `0x1C0003C1C`, immediately before the default fall-through, redirecting `0x8FFF23DC` to a new handler block. That handler validates `InputBufferLength >= 8` and `OutputBufferLength >= 4` (else `STATUS_BUFFER_TOO_SMALL`, `0xC0000023`), acquires the global spin lock `qword_1C0009748`, reads the global DWORD `dword_1C0009738`, writes it to the METHOD_BUFFERED system buffer, sets `IoStatus.Information = 4`, and releases the spin lock. The same global DWORD is already returned by the existing `0x8FFF23C0` handler, so the new handler exposes no value that was not already reachable from user mode.

**Why this is not a security fix:** Adding a recognized IOCTL code enlarges the driver's readable IOCTL surface; it does not close any hole. The unpatched behavior for `0x8FFF23DC` (return `STATUS_UNSUCCESSFUL`, do nothing else) is safe. The new handler introduces no OOB access, no UAF, no type confusion, and no new information disclosure (the value it returns is already available via `0x8FFF23C0`). CWE-478 (missing default case) does not apply: both builds have a working default path; only a specific additional case was added. The direction of the change is toward *more* exposed functionality in the patched build, not a tightened check.

**Reachability (as delivered):**

1. A user-mode caller opens `\Device\NDProxy`. The device is created in `DriverEntry` (`0x1C00142BC`) via `WdmlibIoCreateDeviceSecure` (`0x1C001210C`) with a security descriptor.
2. `DriverEntry` sets `DriverObject->MajorFunction[14] = PxIODispatch` (14 = `IRP_MJ_DEVICE_CONTROL`), so device-control IRPs are delivered to `PxIODispatch`.
3. `PxIODispatch` checks `[r8] == 0x0E` (MajorFunction), validates the incoming device object against the stored `DeviceObject` at `DeviceExtension+0x10`, then dispatches on `IoControlCode` (`[r8+0x18]`).
4. In the unpatched build, `0x8FFF23DC` misses every comparison and reaches the default at `0x1C0003C18` (`mov ebx, 0xC000000D`), completing the IRP with `STATUS_UNSUCCESSFUL`.
5. In the patched build, the new comparison at `0x1C0003C1C` intercepts `0x8FFF23DC` and runs the new handler.

---

## 3. Pseudocode Diff

### `PxIODispatch` @ `0x1C0003B80` — IRP_MJ_DEVICE_CONTROL dispatch

```c
// ======================= UNPATCHED =======================
// (after the D8 comparison at 0x1C0003C10)

if (IoControlCode == 0x8FFF23D8) goto D8_handler;   // 0x1C0003C10/C16
// *** NO CHECK FOR 0x8FFF23DC ***
// Falls straight through:

label_C18:                              // default path, 0x1C0003C18
    status = 0xC000000D;                // STATUS_UNSUCCESSFUL
    goto complete;                      // 0x1C0004053


// ======================= PATCHED =======================
// (same area)

if (IoControlCode == 0x8FFF23D8) goto D8_handler;   // 0x1C0003C14/C1A
if (IoControlCode == 0x8FFF23DC) goto DC_handler;   // *** NEW: 0x1C0003C1C/C22 ***

label_C24:                              // default path (shifted), 0x1C0003C24
    status = 0xC000000D;
    goto complete;                      // 0x1C0004092

DC_handler:                             // *** NEW HANDLER, 0x1C0003C2E ***
    if (InputBufferLength < 8)  { status = 0xC0000023; goto complete; }  // STATUS_BUFFER_TOO_SMALL
    if (OutputBufferLength < 4) { status = 0xC0000023; goto complete; }
    KeAcquireSpinLockRaiseToDpc(&qword_1C0009748);
    byte_1C0009750 = savedIrql;
    *(ULONG*)SystemBuffer = dword_1C0009738;  // same value returned by 0x8FFF23C0
    Information = 4;
    KeReleaseSpinLock(&qword_1C0009748, savedIrql);  // shared tail at 0x1C0003C5D
    goto complete;
```

**Key change:** the inserted `cmp ecx, 8FFF23DCh; jz loc_1C0003C2E` at `0x1C0003C1C` and the DC handler body at `0x1C0003C2E`–`0x1C0003C78` are the only behavioral deltas. The DC handler's spin-lock release + completion tail at `0x1C0003C5D` is shared with the `0x8FFF23C0` handler, which jumps to it from `0x1C0004084`.

---

## 4. Assembly Analysis

### Unpatched dispatch tail and default path

```asm
; ---- PxIODispatch @ 0x1C0003B80 (unpatched) ----
00000001C0003BC9  mov     ecx, [r8+18h]            ; ecx = IoControlCode
00000001C0003BCD  mov     r14d, 103h               ; default status seed (STATUS_PENDING)
00000001C0003BD3  cmp     ecx, 8FFF23C0h
00000001C0003BD9  jz      loc_1C0003FA3            ; C0 handler
00000001C0003BDF  cmp     ecx, 8FFF23C4h
00000001C0003BE5  jz      loc_1C0003F0B            ; C4 handler
00000001C0003BEB  lea     eax, [rcx+7000DC38h]
00000001C0003BF1  test    eax, 0FFFFFFFBh
00000001C0003BF6  jz      loc_1C0003DC4           ; C8/CC range handler
00000001C0003BFC  cmp     ecx, 8FFF23D0h
00000001C0003C02  jz      loc_1C0003D07           ; D0 handler
00000001C0003C08  cmp     ecx, 8FFF23D4h
00000001C0003C0E  jz      short loc_1C0003C51     ; D4 handler
00000001C0003C10  cmp     ecx, 8FFF23D8h
00000001C0003C16  jz      short loc_1C0003C22     ; D8 handler
00000001C0003C18  mov     ebx, 0C000000Dh         ; STATUS_UNSUCCESSFUL  <- 0x8FFF23DC lands here
00000001C0003C1D  jmp     loc_1C0004053           ; -> IRP completion

; ===== D8 handler (semantically identical in both builds) =====
00000001C0003C22  cmp     edx, 8                  ; InputBufferLength >= 8?
00000001C0003C25  jnb     short loc_1C0003C31
00000001C0003C27  mov     ebx, 0C0000023h         ; STATUS_BUFFER_TOO_SMALL
00000001C0003C2C  jmp     loc_1C0004053
00000001C0003C31  mov     ecx, [rsi]              ; ecx = SystemBuffer[0] (user-controlled ID)
00000001C0003C33  lea     rdx, [rsp+58h+arg_10]
00000001C0003C38  call    IsTapiLineValid
00000001C0003C3D  test    al, al
00000001C0003C3F  jz      short loc_1C0003C18     ; not found -> error
00000001C0003C41  mov     rax, [rsp+58h+arg_10]   ; found object
00000001C0003C46  mov     ecx, [rsi+4]            ; SystemBuffer[1] (user-controlled value)
00000001C0003C49  mov     [rax+20h], ecx          ; write to object+0x20
00000001C0003C4C  jmp     loc_1C0004053

; ===== Completion path =====
00000001C0004053  mov     ecx, ebp
00000001C0004055  xor     edx, edx
00000001C0004057  mov     [rdi+38h], rcx          ; IoStatus.Information
00000001C000405B  mov     rcx, [rdi+0B8h]
00000001C0004062  mov     [rdi+30h], ebx          ; IoStatus.Status
00000001C0004065  and     byte ptr [rcx+3], 0FEh
00000001C0004069  mov     rcx, rdi
00000001C000406C  call    cs:__imp_IofCompleteRequest
```

### Patched-only insertion

```asm
; ---- PxIODispatch @ 0x1C0003B80 (patched) ----
00000001C0003C14  cmp     ecx, 8FFF23D8h
00000001C0003C1A  jz      short loc_1C0003C87     ; D8 handler (relocated)
00000001C0003C1C  cmp     ecx, 8FFF23DCh          ; *** NEW: DC IOCTL check ***
00000001C0003C22  jz      short loc_1C0003C2E     ; -> DC handler
00000001C0003C24  mov     ebx, 0C000000Dh         ; STATUS_UNSUCCESSFUL (default, shifted)
00000001C0003C29  jmp     loc_1C0004092

; ===== DC handler body (patched only) =====
00000001C0003C2E  cmp     edx, 8                  ; InputBufferLength >= 8?
00000001C0003C31  jb      short loc_1C0003C7D     ; -> STATUS_BUFFER_TOO_SMALL
00000001C0003C33  cmp     r15d, 4                 ; OutputBufferLength >= 4?
00000001C0003C37  jb      short loc_1C0003C7D
00000001C0003C39  lea     rsi, qword_1C0009748    ; &KSPIN_LOCK
00000001C0003C40  mov     rcx, rsi
00000001C0003C43  call    cs:__imp_KeAcquireSpinLockRaiseToDpc
00000001C0003C4F  mov     cs:byte_1C0009750, al   ; save IRQL
00000001C0003C55  mov     eax, cs:dword_1C0009738 ; global counter (same as 0x8FFF23C0)
00000001C0003C5B  mov     [rdi], eax              ; *SystemBuffer = counter

; ===== shared spin-lock release + Information, reached by C0 and DC =====
00000001C0003C5D  mov     dl, cs:byte_1C0009750   ; saved IRQL
00000001C0003C63  mov     r14d, 4                 ; IoStatus.Information = 4
00000001C0003C69  mov     rcx, rsi
00000001C0003C6C  call    cs:__imp_KeReleaseSpinLock
00000001C0003C78  jmp     loc_1C0004092           ; -> IRP completion

; ===== size-check failure target =====
00000001C0003C7D  mov     ebx, 0C0000023h         ; STATUS_BUFFER_TOO_SMALL
00000001C0003C82  jmp     loc_1C0004092
```

**Notes:**
- `0x1C0003C18` (unpatched): the default path — no bounds check, no spin lock, just `STATUS_UNSUCCESSFUL`. For `0x8FFF23DC` this is the terminal state, and it is side-effect-free.
- `0x1C0003C1C` (patched): the inserted comparison that intercepts `0x8FFF23DC` before it reaches the default path.
- `0x1C0003C5D` (patched): the shared spin-lock release + completion tail; the counter read/write happens just above it (`0x1C0003C55`–`0x1C0003C5B` for the DC path, `0x1C0004027`–`0x1C000402D` for the C0 path). The `0x8FFF23C0` handler reaches this tail via `jmp loc_1C0003C5D` at `0x1C0004084`.

---

## 5. Trigger Conditions

1. **Obtain a handle** to `\Device\NDProxy` (Win32 path `\\.\NDProxy`). The device is created in `DriverEntry` (`0x1C00142BC`) via `WdmlibIoCreateDeviceSecure` with a security descriptor.
2. **Prepare buffers**:
   - `lpInBuffer`: 8 bytes minimum (contents ignored by the DC handler).
   - `nInBufferSize` = 8.
   - `lpOutBuffer`: 4 bytes minimum.
   - `nOutBufferSize` = 4.
3. **Call `DeviceIoControl`**:
   ```c
   DeviceIoControl(hDevice,
                   0x8FFF23DC,        // METHOD_BUFFERED (low 2 bits = 0)
                   inBuf, 8,
                   outBuf, 4,
                   &bytesReturned,
                   NULL);
   ```
4. **No ordering or race constraints.** The dispatch is synchronous and stateless for this IOCTL.
5. **Observable difference:**
   - **Unpatched:** `DeviceIoControl` returns `FALSE`; the IRP completes with `STATUS_UNSUCCESSFUL` (`0xC000000D`); `bytesReturned == 0`; output buffer unchanged.
   - **Patched:** `DeviceIoControl` returns `TRUE`; `bytesReturned == 4`; output buffer contains the 4-byte value read from `dword_1C0009738`.

The differential is a behavior/compatibility change only. It demonstrates that `0x8FFF23DC` is now recognized; it does not demonstrate any exploitable primitive.

---

## 6. Exploit Primitive & Development Notes

**Primitive provided:** None. The unpatched behavior for `0x8FFF23DC` is a benign no-op that returns `STATUS_UNSUCCESSFUL` without touching kernel state. The patched handler returns a 4-byte value that is already returned by the existing `0x8FFF23C0` handler, so it discloses nothing new to a caller who can already reach `PxIODispatch`. There is no memory corruption, no information leak beyond what `0x8FFF23C0` already provides, and no privilege boundary crossed by this change.

**Adjacent code note (unchanged by this patch, both builds):** The `0x8FFF23D8` handler at `0x1C0003C22` (unpatched) / `0x1C0003C87` (patched) reads `SystemBuffer[0]` as an ID, calls `IsTapiLineValid` (`0x1C001014C`), and on a match writes the user-controlled `SystemBuffer[1]` to `object+0x20`. `IsTapiLineValid` acquires the NDIS RW-lock `qword_1C00096F8`, locates the matching object, takes the per-object spin lock at `object+0x78`, and increments the reference count at `object+0x10`. This increment and the `object+0x20` write are present and byte-for-byte equivalent in both builds; they are not modified by this patch and are outside its scope.

---

## 7. Debugger Notes

The following assumes a kernel debugger attached with `ndproxy.sys` loaded; substitute the actual loaded module base for the `0x1C00000000`-relative addresses below.

### Breakpoints

```text
bp ndproxy!PxIODispatch                 ; 0x1C0003B80 — dispatch entry, catch every DeviceIoControl
bp ndproxy!PxIODispatch+0x98            ; 0x1C0003C18 — unpatched default path (target for 0x8FFF23DC)
bp ndproxy!PxIODispatch+0xa2            ; 0x1C0003C22 — unpatched D8 handler entry (should NOT hit for DC)
```

### What to inspect

| Location | Register / Memory | Why |
|---|---|---|
| Entry (`0x1C0003B80`) | `rcx` = device object, `rdx` = IRP, `r8` = IoStackLocation | Confirm `MajorFunction` at `[r8] == 0x0E`. |
| After `mov ecx,[r8+0x18]` (`0x1C0003BC9`) | `ecx` = IoControlCode | Will hold `0x8FFF23DC` for the test IRP. |
| Entry | `edx` = `[r8+0x10]` (InputBufferLength); `r15d` = `[r8+0x8]` (OutputBufferLength) | Sizes the DC handler checks (`>= 8`, `>= 4`). |
| `rsi` (unpatched) / `rdi` (patched) | `IRP->AssociatedIrp.SystemBuffer` (`[rdx+0x18]`) | METHOD_BUFFERED kernel copy. |
| Default `0x1C0003C18` (unpatched) | `ebx == 0xC000000D` | Confirms the benign fall-through was taken for DC. |

### Key offsets (relative to module base)

| Offset | Address | Meaning |
|---|---|---|
| `+0x49` | `0x1C0003BC9` | `mov ecx, [r8+0x18]` — loads IoControlCode |
| `+0x90` | `0x1C0003C10` | `cmp ecx, 8FFF23D8h` (unpatched); DC fails this and falls through |
| `+0x98` | `0x1C0003C18` | **Unpatched default path**: `mov ebx, 0xC000000D` — where DC ends up |
| `+0x9c` | `0x1C0003C1C` | **Patched only**: `cmp ecx, 8FFF23DCh` — the inserted comparison |
| `+0xae` | `0x1C0003C2E` | **Patched only**: DC handler InputBufferLength check |
| `+0x4d3` | `0x1C0004053` | Unpatched common IRP completion (`IofCompleteRequest`) |
| `+0x512` | `0x1C0004092` | Patched common IRP completion (`IofCompleteRequest`) |

### Global variables (module-relative)

| Symbol | Address | Role |
|---|---|---|
| `DeviceExtension+0x10` | — | Stored `DeviceObject`, compared against the incoming device object at dispatch entry |
| `dword_1C0009738` | `+0x9738` | Global DWORD returned by `0x8FFF23C0` and (patched) `0x8FFF23DC` |
| `qword_1C0009748` | `+0x9748` | `KSPIN_LOCK` (initialized in `DriverEntry`) protecting the globals below |
| `byte_1C0009750` | `+0x9750` | Saved IRQL slot for the spin lock |
| `TspCB` (near `+0x9720`) | `+0x9720` | Global state (set to 1 in `DriverEntry`, 3 during the C4 path, 0 after the C0 path) |
| `qword_1C0009728` | `+0x9728` | Provider list head |
| `qword_1C00096F8` | `+0x96F8` | NDIS RW-lock |
| `dword_1C00096E4` | `+0x96E4` | Adapter array element count |

### Trigger setup (user mode)

```c
#include <windows.h>
#include <stdio.h>

int main(void) {
    HANDLE h = CreateFileW(L"\\\\.\\NDProxy",
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("open fail: %lu\n", GetLastError()); return 1; }

    UCHAR inBuf[8]  = { 0 };
    UCHAR outBuf[4] = { 0 };
    DWORD returned  = 0;

    BOOL ok = DeviceIoControl(h, 0x8FFF23DC,
                              inBuf, sizeof(inBuf),
                              outBuf, sizeof(outBuf),
                              &returned, NULL);

    printf("ok=%d  err=0x%lx  returned=%lu  out=0x%08x\n",
           ok, GetLastError(), returned, *(DWORD*)outBuf);
    CloseHandle(h);
    return 0;
}
```

### Expected observation

- **Unpatched:** `ok=0`; the IRP completes with `STATUS_UNSUCCESSFUL` (`0xC000000D`); `returned == 0`; output buffer unchanged.
- **Patched:** `ok=1`; `returned == 4`; output buffer contains the value from `dword_1C0009738`.

### Struct / offset notes

- `IO_STACK_LOCATION` offsets used here: `[+0x0]` = MajorFunction, `[+0x8]` = `OutputBufferLength`, `[+0x10]` = `InputBufferLength`, `[+0x18]` = `IoControlCode`.
- `IRP` offsets: `[+0x18]` = `AssociatedIrp.SystemBuffer`, `[+0x30]` = `IoStatus.Status`, `[+0x38]` = `IoStatus.Information`, `[+0xB8]` = current `IoStackLocation`.

---

## 8. Changed Functions — Full Triage

### `PxIODispatch` @ `0x1C0003B80` — IRP_MJ_DEVICE_CONTROL dispatch
- **Similarity:** 0.9555
- **Change type:** Behavioral (new IOCTL handler added)
- **What changed:** Added the `0x8FFF23DC` handler — dispatch check at `0x1C0003C1C`, size-validation at `0x1C0003C2E`/`0x1C0003C33`, spin-lock-protected read of `dword_1C0009738` at `0x1C0003C39`–`0x1C0003C5B`, and a spin-lock release + completion tail at `0x1C0003C5D` that is shared with the `0x8FFF23C0` handler.
- **Security note:** The new handler is bounds-checked and spin-lock-protected and returns a value already returned by `0x8FFF23C0`. It introduces no new memory-safety issue and no new information disclosure. The unpatched fall-through for `0x8FFF23DC` is side-effect-free. This is a functionality addition, not a security fix.

#### Cosmetic / register-allocation deltas (semantically neutral)
- Register reallocation throughout the function (for example the SystemBuffer pointer moves from `rsi` in the unpatched build to `rdi` in the patched build; the IRP pointer moves from `rdi` to `rbp`; the status seed register changes) — compiler choices with no behavioral effect. Because of these, most `loc_...` labels and the default/error/completion addresses are relocated in the patched build (default `0x1C0003C18` → `0x1C0003C24`, size-error `0x1C0003C27` → `0x1C0003C7D`, completion `0x1C0004053` → `0x1C0004092`).
- All six pre-existing IOCTL handlers (`C0`, `C4`, `C8/CC`, `D0`, `D4`, `D8`) are semantically equivalent between builds.

No other functions changed. An independent content-level diff of both builds (matching across relocations) confirms that every difference outside `PxIODispatch` is a shifted function-header address or a renumbered label caused by `PxIODispatch` growing; no other function body differs.

---

## 9. Unmatched Functions

| Removed (unpatched only) | Added (patched only) |
|---|---|
| None | None |

There are no added or removed functions. The patch is a strict in-place modification of `PxIODispatch`.

---

## 10. Confidence & Caveats

**Confidence: High.**

- **What is certain:** The patch inserts exactly one new IOCTL handler (`0x8FFF23DC`) into `PxIODispatch`. All other functions are semantically identical. The new handler is bounds-checked (`InputBufferLength >= 8`, `OutputBufferLength >= 4`), spin-lock-protected, and returns `dword_1C0009738` — the same global already returned by `0x8FFF23C0`. The unpatched path for `0x8FFF23DC` returns `STATUS_UNSUCCESSFUL` with no side effects.
- **What is inferred:** The precise semantic meaning of `dword_1C0009738` is not determinable from the binaries alone; what is verifiable is that it is the same DWORD the existing `0x8FFF23C0` handler returns. Which user-mode component issues `0x8FFF23DC` is likewise not determinable from these binaries.
- **Assessment:** This is a functionality/compatibility addition, not a security fix. It adds a small amount of readable IOCTL surface (a value already exposed elsewhere) rather than removing any vulnerable behavior. No CWE applies: both builds retain a working default path, and no memory-safety, information-disclosure, or privilege condition is created or closed by the change.
