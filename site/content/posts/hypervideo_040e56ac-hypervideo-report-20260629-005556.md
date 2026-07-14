Title: hypervideo.sys — Uninitialized 7th argument to VMBus channel send on the bugcheck-display path (CWE-908) fixed
Date: 2026-03-10
Slug: hypervideo_040e56ac-hypervideo-report-20260629-005556
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Low
KBDate: 2026-03-10

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `hypervideo_unpatched.sys` |
| **Patched binary** | `hypervideo_patched.sys` |
| **Overall similarity** | 0.9918 |
| **Matched functions** | 71 |
| **Changed functions** | 2 |
| **Identical functions** | 69 |
| **Unmatched (unpatched / patched)** | 0 / 0 |

**Verdict:** Two functions changed between the builds.

- **Finding A — `CrashHvdSendMessage` (0x1C00018B0):** the patch adds explicit initialization (`= 0`) of a 7th outgoing stack argument (`[rsp+0x30]`) that the unpatched build never wrote before dispatching an indirect call to the VMBus channel-send function pointer. This matches the use-of-uninitialized-memory pattern (CWE-908). Its reachable impact is limited: the argument is a 32-bit slot, the call sits on the guest **bugcheck / crash-display** path (not routine rendering), and the callee is an external VMBus-library function reached through the channel object's function-pointer table, so whether that argument is actually consumed — and therefore whether any kernel data is disclosed — cannot be confirmed from this driver alone. Severity: **Low**.

- **Finding B — `HvdDdiStartDevice` (0x1C00074B0):** the patch grows a SynthVid IOCTL message from 8 to 16 bytes. In **both** builds every byte covered by `InputBufferLength` is fully initialized, so no uninitialized memory is transmitted in either direction. This is a **protocol message-size change**, not an information-disclosure fix. Downgraded to **No security-relevant change**.

---

## 2. Vulnerability Summary

### Finding A — Uninitialized 7th argument to VMBus channel send (`CrashHvdSendMessage` @ 0x1C00018B0)

| Field | Value |
|---|---|
| **Severity** | Low |
| **Class** | Use of uninitialized memory (CWE-908) |
| **Function** | `CrashHvdSendMessage` (0x1C00018B0) |
| **Primitive** | Initialization of a previously-unwritten outgoing stack argument; host-side disclosure unconfirmed |

**Root cause:** `CrashHvdSendMessage` sends a packet by loading a function pointer from the VMBus channel object (`rax = [rsi+0x10]`, where `rsi = [rcx+0x270]`) and dispatching it through the Control-Flow-Guard indirect-call dispatcher (`call cs:__guard_dispatch_icall_fptr`). Under the x64 calling convention the 7th argument lives at `[rsp+0x30]`. The unpatched build sets up only six outgoing arguments before the call: `rcx = *rsi`, `edx = 1`, `r8d = 0`, `r9 = packet data`, `[rsp+0x20] = packet size`, `[rsp+0x28] = 0`. The stack slot `[rsp+0x30]` is never written. The patch inserts `mov [rsp+0x30], ebx` (with `ebx` already zeroed) at 0x1C0001906, so the patched build passes a seventh argument equal to 0.

Because the callee is an external function reached only through the channel object's function-pointer table (populated by the VMBus channel library, not this module), the callee's true parameter count is not visible in these binaries. If the callee reads seven parameters, the unpatched build passed it up to four bytes of uninitialized kernel-stack data; if it reads six, the slot is harmless. That ambiguity is why this finding is rated Low and the disclosure is stated as unconfirmed rather than demonstrated.

**Entry point & data flow:**

1. `DriverEntry` (0x1C000C008) publishes the miniport callback table; `HvdDdiSystemDisplayWrite` is stored at table slot `[35]` and `HvdDdiStartDevice` at slot `[2]`.
2. `CrashHvdSendMessage` has exactly two in-module callers: `HvdDdiSystemDisplayWrite` (0x1C0001490) and `CrashHvdInitialize` (0x1C0001764). Both are part of the crash/bugcheck synthetic-video path (`DxgkDdiSystemDisplayWrite` is the callback the OS uses to paint the screen during a bugcheck, when the normal display pipeline is unavailable).
3. Inside `CrashHvdSendMessage`, the send is retried up to `0x4E20` (20000) times with a 50 µs `KeStallExecutionProcessor` stall between attempts. The 7th-argument slot is passed on each attempt.

### Finding B — SynthVid IOCTL message grown from 8 to 16 bytes (`HvdDdiStartDevice` @ 0x1C00074B0)

| Field | Value |
|---|---|
| **Severity** | None (no security-relevant change) |
| **Class** | Protocol/functional change |
| **Function** | `HvdDdiStartDevice` (0x1C00074B0) |
| **Primitive** | None — both builds send fully-initialized input |

**What actually changed:** During adapter start, `HvdDdiStartDevice` issues IOCTL `0x3EC080` (METHOD_BUFFERED; device type `0x3E`, function `0x20`) to the VMBus device object (`*(arg1+8)`). The unpatched build builds an 8-byte input `{DWORD 6, DWORD 6}` and passes `InputBufferLength = 8`; the patched build builds a 16-byte input `{6, 6, 0, 0}` and passes `InputBufferLength = 0x10`.

In both builds every byte the driver declares as input is explicitly initialized before the call. The unpatched build writes both dwords of its 8-byte buffer and declares length 8; the patched build zero-initializes all 16 bytes near the top of the function (`[rbp+0x1b0]` and `[rbp+0x1b8]` at 0x1C00074EC / 0x1C0007500), then sets the first qword to `0x600000006` and declares length 16. Under METHOD_BUFFERED the receiver reads exactly `InputBufferLength` bytes; the remaining bytes of the I/O-manager `SystemBuffer` (up to `OutputBufferLength = 0x20`) are output scratch owned by the receiver, not attacker-visible input. Consequently neither build transmits uninitialized kernel memory. The change is a SynthVid message-format extension (an 8-byte message became a 16-byte message with the new fields set to 0), i.e. a functional/protocol change with no information-disclosure content.

---

## 3. Pseudocode Diff

### Finding A — `CrashHvdSendMessage` (0x1C00018B0)

The decompiled C is byte-for-byte identical between the two builds because the decompiler models the indirect callee as a two-argument function pointer and cannot represent the extra outgoing stack arguments. The change is visible only in the disassembly (Section 4). For reference, the shared decompiler view is:

```c
// Identical in both builds (decompiler cannot see the stack-argument change)
__int64 __fastcall CrashHvdSendMessage(__int64 a1)
{
  __int64 v1 = *(_QWORD *)(a1 + 624);   // channel object
  unsigned int v2 = 0;
  int v3 = 20000;
  while ( (*(unsigned __int8 (__fastcall **)(_QWORD, __int64))(v1 + 16))(*(_QWORD *)v1, 1) == 0 )
  {
    if ( v3 <= 0 )
      return (unsigned int)-1073741823;   // STATUS_UNSUCCESSFUL
    --v3;
    KeStallExecutionProcessor(0x32u);      // 50 us
  }
  return v2;
}
```

### Finding B — `HvdDdiStartDevice` (0x1C00074B0)

```c
// ── UNPATCHED ──────────────────────────────────────────────
_DWORD InputBuffer[2];            // 8-byte buffer
InputBuffer[0] = 6;               // fully written
InputBuffer[1] = 6;               // fully written
KeInitializeEvent(&Event, NotificationEvent, 0);
Irp = IoBuildDeviceIoControlRequest(
    0x3EC080u, *(PDEVICE_OBJECT *)(a1 + 8),
    InputBuffer, 8u,              // InputBufferLength = 8, all 8 bytes valid
    *(PVOID *)(a1 + 624), 0x20u, 0, &Event, &IoStatusBlock);

// ── PATCHED ────────────────────────────────────────────────
_QWORD InputBuffer[2];            // 16-byte buffer
InputBuffer[0] = 0;               // zero-init near top of function
InputBuffer[1] = 0;               // zero-init near top of function
...
InputBuffer[0] = 0x600000006LL;   // {6, 6}; InputBuffer[1] stays 0
KeInitializeEvent(&Event, NotificationEvent, 0);
Irp = IoBuildDeviceIoControlRequest(
    0x3EC080u, *(PDEVICE_OBJECT *)(a1 + 8),
    InputBuffer, 0x10u,           // InputBufferLength = 16, all 16 bytes valid
    *(PVOID *)(a1 + 624), 0x20u, 0, &Event, &IoStatusBlock);
```

Both variants pass only fully-initialized input; the difference is the declared message length (8 vs 16 bytes).

---

## 4. Assembly Analysis

Instruction lines below are copied from the authoritative disassembly.

### Finding A — `CrashHvdSendMessage` (0x1C00018B0), call-site region

```
UNPATCHED
00000001C00018FC  mov     rcx, [rsi]                 ; arg1 = *channel
00000001C00018FF  xor     r8d, r8d                   ; arg3 = 0
00000001C0001902  mov     rax, [rsi+10h]             ; callee fptr = channel[+10h]
00000001C0001906  mov     [rsp+48h+var_20], rbx      ; [rsp+28h] arg6 = 0
00000001C000190B  mov     [rsp+48h+var_28], ebp      ; [rsp+20h] arg5 = packet size
00000001C000190F  lea     edx, [r8+1]                ; arg2 = 1
00000001C0001913  call    cs:__guard_dispatch_icall_fptr   ; [rsp+30h] (arg7) never written

PATCHED
00000001C00018FC  mov     rcx, [rsi]
00000001C00018FF  xor     r8d, r8d
00000001C0001902  mov     rax, [rsi+10h]
00000001C0001906  mov     [rsp+48h+var_18], ebx      ; [rsp+30h] arg7 = 0   <-- NEW
00000001C000190A  mov     [rsp+48h+var_20], rbx      ; [rsp+28h] arg6 = 0
00000001C000190F  lea     edx, [r8+1]                ; arg2 = 1
00000001C0001913  mov     [rsp+48h+var_28], ebp      ; [rsp+20h] arg5 = packet size
00000001C0001917  call    cs:__guard_dispatch_icall_fptr
```

The disassembly's frame reference is `rsp+0x48`, so `var_18 = [rsp+0x30]`, `var_20 = [rsp+0x28]`, `var_28 = [rsp+0x20]`. The only functional addition is `mov [rsp+0x30], ebx` (a dword store of 0) at 0x1C0001906; the `ebp` (arg5) store is rescheduled after the `lea`. The dispatch target itself is unchanged (`__guard_dispatch_icall_fptr`, which forwards to `rax = [rsi+0x10]`). Because the new instruction lengthens the block by 4 bytes, the loop epilogue labels shift accordingly (`jle` target `0x1C000191F → 0x1C0001923`, `jmp` target `0x1C0001924 → 0x1C0001928`).

### Finding B — `HvdDdiStartDevice` (0x1C00074B0), IOCTL construction

```
UNPATCHED
00000001C0007CF4  mov     eax, 6
00000001C0007CFE  xor     r8d, r8d
00000001C0007D01  mov     [rsp+340h+InputBuffer], eax   ; bytes [0:3] = 6
00000001C0007D07  mov     [rsp+340h+var_2E4], eax       ; bytes [4:7] = 6
00000001C0007D0B  call    cs:__imp_KeInitializeEvent
00000001C0007D25  lea     r8, [rsp+340h+InputBuffer]    ; 8-byte input, all written
00000001C0007D2F  mov     r9d, 8                        ; InputBufferLength = 8
00000001C0007D3A  mov     ecx, 3EC080h
00000001C0007D54  call    cs:__imp_IoBuildDeviceIoControlRequest

PATCHED
; zero-init near function top
00000001C00074EA  xor     eax, eax
00000001C00074EC  mov     [rbp+250h+InputBuffer], rax   ; bytes [0:7]  = 0
00000001C0007500  mov     [rbp+250h+var_98], rax        ; bytes [8:15] = 0
; message fields set later
00000001C0007D02  mov     eax, 6
00000001C0007D0F  mov     dword ptr [rbp+250h+InputBuffer], eax     ; bytes [0:3] = 6
00000001C0007D17  mov     dword ptr [rbp+250h+InputBuffer+4], eax   ; bytes [4:7] = 6
00000001C0007D1D  call    cs:__imp_KeInitializeEvent
00000001C0007D37  lea     r8, [rbp+250h+InputBuffer]    ; 16-byte input, all written
00000001C0007D43  mov     r9d, 10h                      ; InputBufferLength = 16
00000001C0007D4E  mov     ecx, 3EC080h
00000001C0007D68  call    cs:__imp_IoBuildDeviceIoControlRequest
```

The disassembly's frame reference is `rbp+0x250`, so `InputBuffer = [rbp+0x1b0]` and `var_98 = [rbp+0x1b8]` — the two qwords of the 16-byte buffer. Both are zeroed at 0x1C00074EC / 0x1C0007500 before the field writes. The unpatched build likewise writes both dwords of its 8-byte buffer. The stack frame grows `0x310 → 0x320` (`lea rbp,[rsp-0x210] → [rsp-0x220]`) to hold the wider buffer. No byte declared as input is left uninitialized in either build.

---

## 5. Trigger Conditions

### Finding A — `CrashHvdSendMessage` (0x1C00018B0)

1. The two callers are `HvdDdiSystemDisplayWrite` (0x1C0001490) and `CrashHvdInitialize` (0x1C0001764). `DxgkDdiSystemDisplayWrite` is invoked by the OS to paint the screen during a bugcheck, so this path is exercised on the guest crash/bugcheck display flow, not by ordinary window/mouse activity.
2. When reached, the function passes the `[rsp+0x30]` slot on each of up to 20000 retry iterations.
3. At `0x1C0001913` (unpatched) the slot `[rsp+0x30]` holds whatever residual stack data preceded the call; in the patched build (call at `0x1C0001917`) it is 0.

### Finding B — `HvdDdiStartDevice` (0x1C00074B0)

The IOCTL path is reached during adapter start after the version gate (`cmp edx, 0x30004`), successful channel creation (`SynthVidCreate`, 0x1C000984C), version query (`SynthVidRequestResolutions`, 0x1C0009CD0), mode negotiation, and a successful `ExAllocatePoolWithTag` for the 0x20-byte output buffer. Once reached, the IOCTL is issued with `InputBufferLength = 8` (unpatched) or `0x10` (patched). No uninitialized data is transmitted in either case, so there is no security-relevant trigger.

---

## 6. Exploit Primitive & Development Notes

### Primitive Assessment

| Finding | Primitive | Direction | Impact |
|---|---|---|---|
| A (`CrashHvdSendMessage`) | Initialization of a previously-unwritten 32-bit outgoing argument slot | Guest → Host (VMBus), if consumed | At most 4 bytes; disclosure only occurs if the external callee reads a 7th parameter — unconfirmed from this module |
| B (`HvdDdiStartDevice`) | None | n/a | Both builds send fully-initialized input; no leak |

### Context

Finding A is a data-initialization change on the guest bugcheck-display path. It is a read-only condition at most (no write, no UAF, no type confusion). Confirming whether it discloses any kernel data would require the parameter contract of the VMBus channel-send function pointer, which lives in the VMBus channel library and is not present in these binaries. Absent that, the impact cannot be raised above a Low, unconfirmed guest-to-host disclosure of up to four bytes.

Finding B carries no disclosure primitive: the receiver reads exactly `InputBufferLength` bytes, and those bytes are fully initialized in both builds.

### Mitigations

| Mitigation | Relevance |
|---|---|
| **CFG** | The send is dispatched through `__guard_dispatch_icall_fptr`; the change is to argument data, not to control flow |
| **Stack / pool zeroing** | Not the mechanism here; the fix is an explicit per-argument initialization |

---

## 7. Debugger Playbook

Addresses below are module-relative offsets into the respective binary.

### Finding A — `CrashHvdSendMessage` (0x1C00018B0)

```text
; Function entry
bp hypervideo_unpatched!CrashHvdSendMessage        ; 0x1c00018b0

; Indirect dispatch (unpatched call site)
bp <module_base>+0x1913                            ; call __guard_dispatch_icall_fptr
```

At the dispatch site inspect the 7th-argument slot:

```text
dd @rsp+0x30 l1
; Unpatched: residual stack contents (value depends on prior stack use)
; Patched (call at +0x1917): 0x00000000
```

Notes:
- The channel object is at `[device_context+0x270]`; the callee pointer is `[channel+0x10]`, dispatched via `__guard_dispatch_icall_fptr`.
- The retry loop counts down from `0x4E20` with 50 µs stalls (`KeStallExecutionProcessor`).
- Whether `[rsp+0x30]` is read depends on the external callee's parameter count, which is not determinable from this driver.

### Finding B — `HvdDdiStartDevice` (0x1C00074B0)

```text
bp hypervideo_unpatched!HvdDdiStartDevice          ; 0x1c00074b0
bp <module_base>+0x7d54                            ; call IoBuildDeviceIoControlRequest (unpatched)
```

At the IOCTL call site:

```text
r r9        ; InputBufferLength = 8 (unpatched) / 0x10 (patched)
db @r8 l10  ; unpatched: 06 00 00 00 06 00 00 00 (8 valid bytes; length declared as 8)
            ; patched:   06 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 (16 valid bytes)
```

Both builds present only initialized input up to the declared `InputBufferLength`; there is nothing uninitialized to observe.

IOCTL `0x3EC080` decomposition: device type `0x3E`, function `0x20`, method `METHOD_BUFFERED` (`0`), access `FILE_READ_DATA | FILE_WRITE_DATA` (`3`).

---

## 8. Changed Functions — Full Triage

### `CrashHvdSendMessage` (0x1C00018B0) — VMBus channel packet send
- **Similarity:** 0.9859
- **Change type:** Security-relevant (Low)
- **What changed:** A `mov [rsp+0x30], ebx` (arg7 = 0) is inserted at 0x1C0001906, and the `ebp` (arg5) store is rescheduled after the `lea edx,[r8+1]`. Loop-epilogue labels shift by 4 bytes as a consequence. The unpatched build set up six outgoing arguments and left `[rsp+0x30]` unwritten; the patched build sets up seven, initializing the added slot to 0. Whether the callee consumes that slot — and therefore whether any kernel data was previously disclosed — is not determinable from this module.

### `HvdDdiStartDevice` (0x1C00074B0) — Display adapter start
- **Similarity:** 0.9919
- **Change type:** Not security-relevant (functional / protocol)
- **What changed:** The SynthVid IOCTL `0x3EC080` input grew from an 8-byte buffer `{6, 6}` (`InputBufferLength = 8`) to a 16-byte buffer `{6, 6, 0, 0}` (`InputBufferLength = 0x10`). The stack frame grows `0x310 → 0x320`, the buffer moves to `[rbp+0x1b0]`, and its two qwords are zero-initialized at 0x1C00074EC / 0x1C0007500. Both builds fully initialize the bytes they declare as input, so no uninitialized memory is transmitted in either direction. Neighboring call targets shift only because the frame grew; those are relocations, not behavioral changes.

---

## 9. Unmatched Functions

No functions were added or removed. Both builds contain 71 functions. The patch consists of in-place modifications to two existing functions; no security-check routine or sanitizer is introduced or removed. An independent content-normalized diff of the two disassemblies confirmed that all instruction-level differences fall inside these two functions only.

---

## 10. Confidence & Caveats

### Confidence

- **Finding A:** the mechanical change (added `mov [rsp+0x30], 0` before the indirect dispatch) is unambiguous and the direction is correct (the patched build is stricter). The **security significance** is Low-confidence: it depends on the parameter contract of an external VMBus-library function reached through a function-pointer table, which is not present in these binaries. The finding is therefore reported as a genuine CWE-908 initialization fix with an unconfirmed disclosure impact of at most four bytes on the bugcheck-display path.
- **Finding B:** high confidence that this is **not** a security fix. Both builds fully initialize every byte declared as IOCTL input; the change is a message-length extension from 8 to 16 bytes.

### Caveats

1. The callee behind `[channel+0x10]` in `CrashHvdSendMessage` is dispatched indirectly and defined outside this module; its true parameter count (and thus whether `[rsp+0x30]` is read) cannot be verified here.
2. `HvdDdiSystemDisplayWrite` corresponds to the bugcheck-time display-write callback, so Finding A's path is the guest crash-display flow rather than ordinary rendering.
3. For Finding B, the host reads exactly `InputBufferLength` bytes under METHOD_BUFFERED; the larger `SystemBuffer` scratch (up to `OutputBufferLength`) is the receiver's own memory and is not attacker-visible guest input.
