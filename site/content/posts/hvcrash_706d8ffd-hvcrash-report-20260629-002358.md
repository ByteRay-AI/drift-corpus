Title: hvcrash.sys — Uninitialized stack bytes in crash-dump writer descriptor (CWE-908) zeroed / fixed
Date: 2026-06-29
Slug: hvcrash_706d8ffd-hvcrash-report-20260629-002358
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Low
KBDate: 2026-03-10

## 1. Overview

- **Unpatched Binary:** `hvcrash_unpatched.sys`
- **Patched Binary:** `hvcrash_patched.sys`
- **Overall Similarity:** 0.983
- **Diff Statistics:** 50 functions matched by symbol (46 identical, 4 changed), 1 function added in the patched build (`Diagnostics::Initialize`), 0 removed.
- **Verdict:** The patch zero-initializes an 8-byte tail of a 16-byte stack structure in `HvCrashWriter::Initialize` before that structure is handed to a WDF I/O target request. In the unpatched build those 8 bytes carry stale kernel-stack contents into the input buffer of an internal device I/O control request sent down the driver stack. This is a genuine uninitialized-memory hardening fix, but it is confined to the crash-dump writer setup path and the data stays inside kernel mode; there is no demonstrable attacker-controlled trigger or cross-privilege leak. Severity is Low. The other three changed functions and the one added function are a debug-logging feature (a registry-gated `DbgPrint`), not security fixes.

## 2. Vulnerability Summary

- **Severity:** Low
- **Vulnerability Class:** Use of uninitialized stack memory (CWE-908 / CWE-200)
- **Affected Function:** `HvCrashWriter::Initialize` (unpatched `@0x1C0002E68`; patched `@0x1C0002FE0`)

**Root Cause:**
`HvCrashWriter::Initialize` builds a 16-byte structure on the kernel stack (`_DWORD v14[4]` at `rbp+0x37`). In the unpatched build it writes only the first two DWORDs (`v14[0]=6` at `rbp+0x37` and `v14[1]=0x12` at `rbp+0x3b`) and leaves the last 8 bytes (`v14[2]`/`v14[3]`, at `rbp+0x3f` through `rbp+0x46`) uninitialized, so they retain whatever was previously on the stack. The structure is wrapped in a `WDF_MEMORY_DESCRIPTOR` (type = buffer, pointer = `v14`, length = 16) and passed as the **input** buffer of a synchronous internal device I/O control request (control code `0x3EC080`) issued through the KMDF function table. Those 8 stale bytes therefore travel into the request sent to the next driver in the device stack. The patch zero-initializes the whole 16-byte structure first, then fills the two DWORD fields, so the trailing 8 bytes are defined (zero).

**Reachability:**
This runs during crash-dump writer initialization, reached through the driver's WDF device-control (`EvtIoDeviceControl`) handler. It is part of the crash/dump-preparation machinery, not a routine exposed to an ordinary untrusted caller. The recipient of the leaked bytes is a lower kernel-mode driver in the device stack (all ring 0). There is no demonstrated path by which an unprivileged user, or a party outside the guest, controls this trigger or observes the leaked bytes.

**Call chain:**
1. A device I/O control request with control code `0x2D164B` reaches the driver's WDF I/O queue.
2. `HvCrashEvtDeviceAdd` (`@0x1C00080E0`) registered `HvCrashDeviceControl` (`@0x1C00088D0`) as the `EvtIoDeviceControl` callback.
3. `HvCrashDeviceControl` switches on the control code; case `0x2D164B` (decimal `2954827`) calls `CrashdumpShim::GetDumpInfo`.
4. `CrashdumpShim::GetDumpInfo` (`@0x1C00019E8`) retrieves a `0x48`-byte request input buffer, validates its fields, allocates pool, and calls `HvCrashWriter::Initialize`.
5. `HvCrashWriter::Initialize` (`@0x1C0002E68`) builds the partially initialized 16-byte structure and passes it as the input buffer of the internal IOCTL sent down the device stack.

## 3. Pseudocode Diff

The change is in the stack-buffer initialization of `HvCrashWriter::Initialize`.

```c
// UNPATCHED HvCrashWriter::Initialize @0x1C0002E68
__int64 HvCrashWriter::Initialize(HvCrashWriter *this, WDFDEVICE__ *a2, const _GUID *a3) {
    _DWORD v14[4];            // 16-byte struct at rbp+0x37
    v14[0] = 6;               // rbp+0x37 (4 bytes)
    v14[1] = 18;              // rbp+0x3b (4 bytes)  (0x12)
    // v14[2], v14[3] (rbp+0x3f..rbp+0x46, 8 bytes) LEFT UNINITIALIZED

    v8[0] = 1;                // WDF_MEMORY_DESCRIPTOR: type = buffer
    v8[1] = v14;              // buffer pointer
    v8[2] = 16;               // length = 16 bytes (all 16 are consumed)
    ...
    // WdfFunctions_01015 + 1488 (table offset 0x5d0): synchronous internal
    // device IOCTL 0x3EC080; v8 is the INPUT memory descriptor
    v5 = (*(...)(WdfFunctions_01015 + 1488))(WdfDriverGlobals, v3, 0, 4112512, v8, v7, 0, 0);
}

// PATCHED HvCrashWriter::Initialize @0x1C0002FE0
__int64 HvCrashWriter::Initialize(HvCrashWriter *this, WDFDEVICE__ *a2, const _GUID *a3) {
    _DWORD v14[4];
    // FIX: whole 16-byte struct zeroed first
    *(_QWORD*)&v14[0] = 0;    // zeros rbp+0x37..rbp+0x3e
    *(_QWORD*)&v14[2] = 0;    // zeros rbp+0x3f..rbp+0x46  (the fix)
    v14[0] = 6;               // then fields are set
    v14[1] = 18;
    ...
    v5 = (*(...)(WdfFunctions_01015 + 1488))(WdfDriverGlobals, v3, 0, 4112512, v8, v7, 0, 0);
}
```

## 4. Assembly Analysis

Frame base: after `push rbp`, `lea rbp, [rsp-57h]`, so a variable shown as `[rbp+57h+var_XX]` is at `rbp + 0x57 - 0xXX`. The 16-byte structure is `var_20` (= `rbp+0x37`); its uninitialized tail is `var_18` (= `rbp+0x3f`).

**Unpatched initialization sequence (`HvCrashWriter::Initialize @0x1C0002E68`):**
```
00000001C0002E88  xor     eax, eax
00000001C0002E8A  mov     [rbp+57h+var_20], 6        ; dword [rbp+0x37] = 6
00000001C0002E91  mov     [rbp+57h+var_58], rax      ; [rbp-0x1] = 0
00000001C0002E95  mov     [rbp+57h+var_48], rax      ; [rbp+0xf] = 0
00000001C0002E99  mov     [rbp+57h+var_1C], 12h      ; dword [rbp+0x3b] = 0x12
00000001C0002EA0  lea     r8d, [rax+1]
00000001C0002EA4  mov     dword ptr [rbp+57h+var_48], 10h   ; length = 16
00000001C0002EAB  lea     rax, [rbp+57h+var_20]      ; &struct (rbp+0x37)
00000001C0002EB3  mov     [rbp+57h+var_50], rax      ; descriptor buffer ptr at rbp+0x7
; bytes rbp+0x3f..rbp+0x46 (var_18) are NEVER written
```

**Patched initialization sequence (`HvCrashWriter::Initialize @0x1C0002FE0`):**
```
00000001C0003000  xor     eax, eax
00000001C0003002  mov     [rbp+57h+var_20], rax          ; NEW: qword [rbp+0x37] = 0
00000001C0003006  mov     [rbp+57h+var_58], rax
00000001C000300A  mov     [rbp+57h+var_48], rax
00000001C000300E  lea     r8d, [rax+1]
00000001C0003012  mov     [rbp+57h+var_18], rax          ; FIX: qword [rbp+0x3f] = 0
00000001C0003016  lea     rax, [rbp+57h+var_20]
00000001C000301A  mov     dword ptr [rbp+57h+var_20], 6  ; then dword [rbp+0x37] = 6
00000001C0003048  mov     dword ptr [rbp+57h+var_20+4], 12h ; dword [rbp+0x3b] = 0x12
00000001C0003053  mov     dword ptr [rbp+57h+var_48], 10h   ; length = 16
```

The net effect: the patched build additionally writes `qword [rbp+0x3f] = 0` (`var_18`), defining the 8 bytes the unpatched build left stale.

**The request that carries the buffer:**
```
00000001C0002EF2  mov     rcx, cs:WdfFunctions_01015
00000001C0002EF9  mov     r9d, 3EC080h               ; internal IOCTL control code
00000001C0002F11  mov     r10, [rcx+5D0h]            ; KMDF table entry (offset 0x5d0)
00000001C0002F24  lea     rcx, [rbp+57h+var_58]      ; WDF_MEMORY_DESCRIPTOR (input) -> struct
00000001C0002F34  call    cs:__guard_dispatch_icall_fptr   ; request issued
```
The indirect target is an entry in `WdfFunctions_01015`, the KMDF (Kernel-Mode Driver Framework) function dispatch table, at table offset `0x5d0`; the preceding call at table offset `0x150` obtains the I/O target handle. These are WDF framework calls, not an inter-partition/VMBus interface.

## 5. Trigger Conditions

1. **Entry:** a WDF device I/O control request with control code `0x2D164B` reaches the driver's I/O queue, dispatched by `HvCrashDeviceControl`.
2. **Payload constraints (validated in `CrashdumpShim::GetDumpInfo`):** the retrieved request input buffer is `0x48` bytes, with:
   - DWORD at offset `0x0` equal to `0x48`;
   - DWORD at offset `0x4` equal to `0x1`;
   - DWORD at offset `0x8` non-zero and `< 0x10`, and not equal to `0xf` (`0xf` returns early without reaching the writer).
3. **Execution:** on a passing payload the driver allocates the writer object and calls `HvCrashWriter::Initialize`, which builds the descriptor and issues the internal IOCTL.
4. **Effect (unpatched):** the input buffer of that internal IOCTL contains a 16-byte structure whose last 8 bytes hold stale kernel-stack data rather than defined values.

## 6. Impact & Limitations

- **Primitive:** 8 bytes of uninitialized kernel-stack memory placed into the input buffer of an internal device I/O control request that is sent to the next driver in the device stack.
- **Boundary:** the source and the recipient are both kernel-mode (ring 0). There is no verified path making the trigger reachable from an unprivileged user process, and no verified path by which the 8 bytes are returned to, or observed by, a lower-privileged or external party. The value of the 8 bytes is whatever the prior stack frames left; no specific sensitive content is demonstrable.
- **Nature:** defense-in-depth hardening against use of uninitialized memory (CWE-908) on the crash-dump writer setup path. This is why the severity is Low rather than a directly exploitable information-disclosure primitive.

## 7. Debugger Notes

Attach a kernel debugger to a system running the unpatched `hvcrash.sys`.

**Breakpoints (RVAs; add the actual load base):**
```
; vulnerable function entry
bp hvcrash+0x2E68

; the request-issuing call, just before the buffer leaves the function
bp hvcrash+0x2F34
```

**What to inspect at `+0x2F34`:**
- The descriptor buffer pointer is stored at `[rbp+0x7]` and points to the 16-byte structure at `rbp+0x37`.
- `dq poi(rbp+7) L2` — the first QWORD is `0x0000001200000006`; the second QWORD is the trailing 8 bytes. In the unpatched build it may be non-zero (stale stack); in the patched build it is zero.

## 8. Changed Functions — Full Triage

- **`HvCrashWriter::Initialize`** (unpatched `@0x1C0002E68`, patched `@0x1C0002FE0`; Security Relevant):
  - **Change:** adds `mov qword [rbp+0x37], 0` and `mov qword [rbp+0x3f], 0` (from `xor eax,eax`) to zero the full 16-byte stack structure before setting the two DWORD fields. Defines the previously uninitialized 8-byte tail. This is the fix.
- **`CrashdumpShim::GetDumpInfo`** (unpatched `@0x1C00019E8`, patched `@0x1C0001AF8`; Behavioral, low security relevance):
  - **Change:** caller of the fixed function. The substantive change is that the patched build adds three `WdfRequestComplete` calls (KMDF table offset `0x838`): on the `0x148` pool-allocation failure, the `HvCrashWriter::Initialize` failure, and the `RtlGetVersion` failure paths. In the unpatched build these three paths return without completing the WDF request, so the request is left pending (caller hang / resource leak) when one of those failures occurs. The unpatched build already completes the request on the earlier input-validation and `0xC0`-allocation failures, and on the success path. The remaining differences are compiler register-allocation, global/string reference offsets shifted by the newly added globals, and updated debug line-number constants. The request-buffer validation logic is identical between builds. This is a robustness fix on abnormal (allocation / version-query) failure paths, not a directly attacker-controlled primitive.
- **`Diagnostics::NtStatus_ResultErrorCallback`** (`@0x1C00010BC`; Behavioral, not security):
  - **Change:** the error-reporting helper. Its `DbgPrint` call is now guarded by a new global flag `Diagnostics::g_DbgPrintOnError` (set from a `DebugFlags` registry value); in the unpatched build it was unconditional. Blocks reordered and the stack-cookie check target relocated. A debug-logging feature, not a security fix.
- **`DriverEntry`** (`@0x1C000A008`; Behavioral, not security):
  - **Change:** adds a call to the new `Diagnostics::Initialize` (which reads the `DebugFlags` registry value and populates the debug-logging globals). Stack layout and a debug line-number constant shift. A debug feature, not a security fix.

## 9. Unmatched Functions

- **Added (patched only):** `Diagnostics::Initialize` (`@0x1C00011F8`) — reads the `DebugFlags` registry value and sets the debug-logging globals used by `Diagnostics::NtStatus_ResultErrorCallback`. Not security relevant.
- **Removed:** none.

## 10. Confidence & Caveats

- **Confidence:** High that the mechanism is a real uninitialized-memory fix: both builds and both the decompilation and disassembly show the same 16-byte structure, the missing 8-byte initialization in the unpatched build, and the two added zeroing writes in the patched build.
- **Severity rationale:** Low. The routine is on the crash-dump writer setup path, the trigger is a device-control request handled by the crash-dump shim rather than an ordinary untrusted surface, and the leaked bytes move between kernel-mode components. No cross-privilege or guest-boundary disclosure is demonstrable from the binaries.
- **Not claimed:** there is no evidence in the binaries that the trigger is a VMBus message, that the data is transmitted to the Hyper-V host, or that specific sensitive values (pointers, cookies) are disclosed. Such claims are not supported and are not made here.
