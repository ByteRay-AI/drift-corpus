Title: modemcsa.sys — Uninitialized kernel stack buffer sent in KS streaming-state IOCTL (CWE-908) fixed
Date: 2026-06-29
Slug: modemcsa_41192ac1-modemcsa-report-20260629-142625
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Low

## 1. Overview

- **Unpatched Binary:** `modemcsa_unpatched.sys`
- **Patched Binary:** `modemcsa_patched.sys`
- **Overall Similarity Score:** 0.8972
- **Diff Statistics:** 72 functions matched by name across both builds; the patched build additionally contains 4 compiler/runtime helper stubs that are not present by name in the unpatched build (`__cpu_features_init`, `_guard_xfg_dispatch_icall_nop`, `__memset_query`, `__memset_repmovs`). By content, one function carries a security-relevant change; the remainder differ only by compiler code generation and pool-API modernization.
- **Verdict:** The patch resolves a use-of-uninitialized-stack-memory issue (CWE-908) in `WaveAction`. The unpatched function forwards a 0x24-byte stack buffer to a lower device via `KsSynchronousIoControlDevice` while leaving 28 of its 36 bytes uninitialized. The patch zero-initializes the full buffer before the call.

## 2. Vulnerability Summary

### Finding 1: Uninitialized Stack Memory in Streaming-State IOCTL
- **Severity:** Low
- **Vulnerability Class:** Use of Uninitialized Resource (CWE-908); potential kernel information disclosure (CWE-200) if the receiving device reflects the data
- **Affected Function:** `WaveAction` — unpatched `@ 0x1C00010D0`, patched `@ 0x1C00011D8`

**Root Cause:**
`WaveAction` builds a 0x24-byte (36-byte) buffer on the stack and passes it as both the input and output buffer to `KsSynchronousIoControlDevice` for IOCTL `0x2B0024`. In the unpatched build only two fields are written before the call: the DWORD at buffer offset `0x18` is set to `1`, and the DWORD at offset `0x1C` is set to the `a2` argument. Bytes `0x00`–`0x17` (24 bytes) and `0x20`–`0x23` (4 bytes) are never initialized and therefore contain whatever kernel stack residue was left by earlier calls on this thread's stack. Because the IOCTL uses `METHOD_BUFFERED`, the I/O manager copies all 0x24 input bytes into the system buffer that the lower device receives.

The receiving object is the lower device in the modem's device stack (the file object stored at `+0x58` of the pin context, obtained earlier via `IoGetDeviceObjectPointer`). It is a kernel-mode driver, not attacker-controlled. Whether the uninitialized bytes are observable to a lower-privileged caller depends on whether that lower device echoes, logs, or reflects the input buffer back toward user mode; that behavior is not present in this binary and is not demonstrated here. The concrete, provable defect is that uninitialized kernel stack memory is transmitted across a device boundary in an IOCTL buffer.

**Attacker-Reachable Entry Point & Call Chain:**
1. A user-mode process opens a handle to the modem KS device interface.
2. It issues a `KSPROPERTY_CONNECTION_STATE` set request (via `IOCTL_KS_PROPERTY` / `DeviceIoControl`) to change a pin's state.
3. The state handler `PinDeviceState` (`@ 0x1C0001010`) reads the requested state and dispatches: state `0` (`KSSTATE_STOP`) to `ReleaseDevice`, `1` (`KSSTATE_ACQUIRE`) to `AcquireDevice`, `2` (`KSSTATE_PAUSE`) to `StopStream`, `3` (`KSSTATE_RUN`) to `StartStream`.
4. `StartStream` (`@ 0x1C00019E4`, on the RUN path) calls `WaveAction(*(pin+0x58), 2)`; `StopStream` (`@ 0x1C0001C0C`, on the PAUSE path) calls `WaveAction(*(pin+0x58), 4)`.
5. `WaveAction` issues the synchronous IOCTL with the partially uninitialized stack buffer.

## 3. Decompilation Diff

The decompiled bodies of both builds:

```c
// UNPATCHED WaveAction @ 0x1C00010D0
NTSTATUS __fastcall WaveAction(struct _FILE_OBJECT *a1, int a2)
{
  NTSTATUS result;   // eax
  ULONG v3;          // [rbp-48h] BYREF  (BytesReturned)
  _DWORD v4[7];      // [rbp-40h] BYREF  (0x24-byte IO buffer, mostly UNINITIALIZED)
  int v5;            // [rbp-24h]        (buffer offset 0x1C)

  v5 = a2;           // buffer[0x1C] = a2
  v4[6] = 1;         // buffer[0x18] = 1  (the only other initialized field)
  // buffer[0x00..0x17] and [0x20..0x23] are never written
  result = KsSynchronousIoControlDevice(a1, 0, 0x2B0024u, v4, 0x24u, v4, 0x24u, &v3);
  if ( result >= 0 && v5 == 0 )
    return -1073741823;   // 0xC0000001 STATUS_UNSUCCESSFUL
  return result;
}

// PATCHED WaveAction @ 0x1C00011D8
NTSTATUS __fastcall WaveAction(struct _FILE_OBJECT *a1, int a2)
{
  NTSTATUS result;   // eax
  ULONG v3;          // [rbp-48h] BYREF
  __int64 v4;        // [rbp-40h] BYREF  (buffer[0x00..0x07])
  __int128 v5;       // [rbp-38h]        (buffer[0x08..0x17])
  int v6;            // [rbp-28h]        (buffer[0x18])
  int v7;            // [rbp-24h]        (buffer[0x1C])
  int v8;            // [rbp-20h]        (buffer[0x20..0x23])

  v4 = 0;            // zero buffer[0x00..0x07]
  v8 = 0;            // zero buffer[0x20..0x23]
  v3 = 0;            // zero BytesReturned
  v7 = a2;           // buffer[0x1C] = a2
  v6 = 1;            // buffer[0x18] = 1
  v5 = 0;            // zero buffer[0x08..0x17]
  result = KsSynchronousIoControlDevice(a1, 0, 0x2B0024u, &v4, 0x24u, &v4, 0x24u, &v3);
  if ( result >= 0 && v7 == 0 )
    return -1073741823;
  return result;
}
```

The two callers pass their action codes directly:

```c
// StartStream @ 0x1C00019E4 (RUN path):
v3 = WaveAction(*(struct _FILE_OBJECT **)(v1 + 88), 2);

// StopStream @ 0x1C0001C0C (PAUSE path):
WaveAction(*(struct _FILE_OBJECT **)(v2 + 88), 4);
```

## 4. Assembly Analysis

The buffer starts at `[r11-0x40]` (`r11` = entry `rsp`). Offsets into the 0x24-byte buffer: `0x18` is `[r11-0x28]`, `0x1C` is `[r11-0x24]`, `0x20` is `[r11-0x20]`, `0x08` is `[r11-0x38]`. The BytesReturned variable is `[r11-0x48]`.

### Unpatched `WaveAction @ 0x1C00010D0` (verbatim)
```asm
00000001C00010D0  mov     r11, rsp
00000001C00010D3  sub     rsp, 88h
00000001C00010DA  mov     rax, cs:__security_cookie
00000001C00010E1  xor     rax, rsp
00000001C00010E4  mov     [rsp+88h+var_18], rax
00000001C00010E9  lea     rax, [r11-48h]
00000001C00010ED  mov     [rsp+88h+var_24], edx        ; buffer[0x1C] = a2
00000001C00010F1  mov     [r11-50h], rax
00000001C00010F5  lea     r9, [r11-40h]                ; InBuffer = buffer start
00000001C00010F9  mov     edx, 24h
00000001C00010FE  mov     [rsp+88h+var_28], 1          ; buffer[0x18] = 1  (only other init)
00000001C0001106  mov     [rsp+88h+OutSize], edx       ; OutSize = 0x24
00000001C000110A  lea     rax, [r11-40h]
00000001C000110E  mov     [r11-60h], rax
00000001C0001112  mov     r8d, 2B0024h                 ; IoControl
00000001C0001118  mov     [rsp+88h+InSize], edx        ; InSize = 0x24
00000001C000111C  xor     edx, edx                     ; RequestorMode = KernelMode
00000001C000111E  call    cs:__imp_KsSynchronousIoControlDevice
;                 buffer[0x00..0x17] and [0x20..0x23] are still uninitialized here
00000001C0001125  nop     dword ptr [rax+rax+00h]
00000001C000112A  test    eax, eax
00000001C000112C  js      short loc_1C000113B
00000001C000112E  cmp     [rsp+88h+var_24], 0
00000001C0001133  mov     ecx, 0C0000001h
00000001C0001138  cmovz   eax, ecx
00000001C000113B  mov     rcx, [rsp+88h+var_18]
00000001C0001140  xor     rcx, rsp
00000001C0001143  call    __security_check_cookie
00000001C0001148  add     rsp, 88h
00000001C000114F  retn
```

### Patched `WaveAction @ 0x1C00011D8` — the added zero-initialization (verbatim)
```asm
00000001C00011F1  and     qword ptr [r11-40h], 0       ; zero buffer[0x00..0x07]
00000001C00011FA  and     [rsp+88h+var_20], 0          ; zero buffer[0x20..0x23]
00000001C0001203  and     [rsp+88h+var_48], 0          ; zero BytesReturned
00000001C0001208  xorps   xmm0, xmm0
00000001C0001238  movdqu  [rsp+88h+var_38], xmm0       ; zero buffer[0x08..0x17]
```
After these writes the patched build sets `buffer[0x18] = 1` and `buffer[0x1C] = a2` exactly as before, then issues the same `KsSynchronousIoControlDevice(a1, 0, 0x2B0024, &buf, 0x24, &buf, 0x24, &BytesReturned)` call at `0x1C000123E`. The security-cookie prologue/epilogue (`__security_cookie` / `__security_check_cookie`) is present in both builds and is unchanged in behavior.

## 5. Trigger Conditions

1. **Obtain a handle:** Open a handle to the modem Kernel Streaming (KS) device interface.
2. **Create a Pin:** Establish a pin object on the KS filter (`KsCreatePin` / `KSPROPERTY_CONNECTION`).
3. **Issue State Transition:** Send `IOCTL_KS_PROPERTY` with `KSPROPERTY_CONNECTION_STATE`.
4. **Reaching values:** Set the target state to `KSSTATE_RUN` (3) or `KSSTATE_PAUSE` (2). RUN routes through `StartStream`, PAUSE through `StopStream`; both call `WaveAction`. (State `KSSTATE_STOP` = 0 routes to `ReleaseDevice` and does **not** reach `WaveAction`.)
5. **Execution Flow:** `PinDeviceState` dispatches to the state handler, which calls `WaveAction`, which issues IOCTL `0x2B0024` to the lower device.
6. **Observable Effect:** No crash occurs from this path itself. The lower modem device receives a synchronous IOCTL whose input buffer contains uninitialized stack bytes in offsets `0x00`–`0x17` and `0x20`–`0x23`. This can be confirmed by breaking on the call in a kernel debugger and dumping the buffer pointed to by `r9`.

## 6. Impact Assessment

- **Provable primitive:** Use of uninitialized kernel stack memory (CWE-908). 28 of the 36 buffer bytes are uninitialized when the IOCTL is dispatched to the lower device.
- **Boundary crossed:** The uninitialized bytes leave `WaveAction` inside a `METHOD_BUFFERED` IOCTL and are copied into the lower device's system buffer.
- **Disclosure to an attacker is not demonstrated:** The recipient is a trusted lower device in the modem stack. For the residue to become an information leak an attacker could read, that lower device would have to reflect or return the input bytes toward user mode. No such reflection is present in this binary, so a kernel-address/KASLR disclosure primitive cannot be substantiated from these two builds. This is why the finding is rated Low rather than Medium/High.
- **What the patch changes:** the entire 0x24 buffer is zero-initialized before the call, so only the two intended fields (`0x18` and `0x1C`) carry non-zero values and no stack residue is transmitted.

## 7. Debugger Notes

To observe the uninitialized buffer on an unpatched system with a kernel debugger:

### Breakpoints
```text
bp modemcsa_unpatched!WaveAction            ; 0x1C00010D0, function entry
bp 0x1C000111E                              ; the KsSynchronousIoControlDevice call site
```

### What to Inspect
At `0x1C000111E`:
- **`r8d`** = `0x2B0024` (IOCTL code, confirms the call site).
- **`r9`** = pointer to the input buffer (`[r11-0x40]`).
- **`db r9 l24`** dumps the 36-byte buffer. Offsets `0x00`–`0x17` and `0x20`–`0x23` hold stack residue in the unpatched build (zero in the patched build); offset `0x18` reads `01 00 00 00`; offset `0x1C` holds the action code (`02` from the RUN path, `04` from the PAUSE path).

### Key Instructions/Offsets
- **`0x1C00010FE`** `mov [rsp+88h+var_28], 1` — the only pre-call write to the buffer besides the action code (`0x1C00010ED`).
- **`0x1C000111E`** `call cs:__imp_KsSynchronousIoControlDevice` — dispatches the IOCTL with the partially uninitialized buffer.

### Reaching the code
Drive a `KSPROPERTY_CONNECTION_STATE` set to `KSSTATE_RUN` (3) or `KSSTATE_PAUSE` (2) on an open pin; `PinDeviceState` will route to `StartStream` / `StopStream`, which call `WaveAction`.

## 8. Changed Functions — Full Triage

By content, the only security-relevant change is `WaveAction` (Section 2). The remaining differences are compiler code generation and pool-API modernization:

**Pool API modernization (`ExAllocatePoolWithTag` → `ExAllocatePool2`).** The newer form returns zeroed pool by default, so paired explicit `memset` calls are dropped. Observed in `AllocateIrpForModem`, `AllocateStreamIrp`, `InitializeDevIoPin`, `FilterDispatchCreate`, `GetModemDeviceName`, and `DriverEntry`. In `GetModemDeviceName` the allocation size is still the length returned by the first `QueryPdoInformation` call (`edx` from `[rsp+arg_10]` at `0x1C00095DC`); the decompiler's collapsed argument list is a display artifact, not a zero-size allocation.

**memset/memcpy recompiled to SIMD paths.** `memset`, `memmove`, and the added helper stubs `__memset_query` / `__memset_repmovs` reflect a library/runtime rebuild with CPU feature detection.

**Compiler restructuring (goto-chains → if/else, register reallocation, counter-based → pointer-based loops), no logic change.** `PinDeviceState` (state dispatch), `AcquireDevice` (control-flow reshuffle plus a `DeviceObject = nullptr` init of a BYREF out-param that is never read afterward), `ProcessReadStreamIrp` and `WriteStream` (audio sample conversion loops re-emitted with equivalent bounds), `ProcessWriteIrps` (inline `memset(...,0,0x38)` re-emitted as `_OWORD` stores of the same extent), `StartStream`, `OpenDuplexControl`, `PinDispatchCreate` (same `KsValidateConnectRequest` checks; `Connect` renamed and pre-nulled), `PnpAddDevice` (device-interface state check re-emitted as a short-circuit condition, same logic), `FilterReadCompletion`, `InitializeDuplexControl`, `InitializeBufferControl`, `QueryPdoInformation` (added stack-event zeroing before use), `FilterPinIntersection`, and `__GSHandlerCheckCommon`.

## 9. Unmatched / Added Functions

- **Removed:** 0
- **Added (patched only):** 4 compiler/runtime helper stubs — `__cpu_features_init`, `_guard_xfg_dispatch_icall_nop`, `__memset_query`, `__memset_repmovs`. These are toolchain/CFG-runtime artifacts of the newer build, not driver logic changes.

No driver functions were added or deleted; all logic differences are inline modifications within functions present in both builds.

## 10. Confidence & Caveats

- **Confidence Level:** High for the mechanism. The unpatched decompilation and disassembly both show only `buffer[0x18]` and `buffer[0x1C]` initialized before the IOCTL, and the patched build adds the zeroing of `buffer[0x00..0x17]` and `buffer[0x20..0x23]` (`and`/`xorps`/`movdqu`) directly resolving the CWE-908 issue. The unpatched build is the vulnerable one; the patched build is stricter.
- **Severity rationale:** Rated Low because, while uninitialized kernel stack memory demonstrably crosses a device boundary, disclosure of that memory to a lower-privileged attacker is not demonstrated in these binaries — it would require the lower device to reflect the input back toward user mode. If, in a specific deployment, the lower device is shown to return these bytes to an unprivileged caller, the impact would rise to Medium (kernel information disclosure, CWE-200).
