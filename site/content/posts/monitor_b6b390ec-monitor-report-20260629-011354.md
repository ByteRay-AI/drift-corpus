Title: monitor.sys — No security-relevant change (brightness dim-state telemetry instrumentation and recompilation churn)
Date: 2026-06-29
Slug: monitor_b6b390ec-monitor-report-20260629-011354
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: None
KBDate: 2026-03-10

## 1. Overview

- **Unpatched binary**: `monitor_unpatched.sys`
- **Patched binary**: `monitor_patched.sys`
- **Overall similarity**: `0.9036`
- **Diff stats**: 117 functions matched, 15 changed, 102 identical, 0 unmatched in each direction.

**Verdict**: The patch adds brightness dim/bright state-change telemetry to the driver and is otherwise recompilation churn (address renumbering, register allocation, WPP/ETW trace GUID changes). No security-relevant change was found. The two areas that changed the most — the `EvtDriverDeviceAdd` PnP callback and the `EvtIoInternalDeviceControl` internal-IOCTL dispatcher — were examined in both builds and are functionally equivalent with respect to bounds checking, buffer initialization, and input validation. The functions carry real symbol names in both builds, so all matching below is by name and by content, not by reused address.

---

## 2. Change Summary

### Item 1 — `EvtDriverDeviceAdd` buffer-zeroing refactor (No security-relevant change)

- **Severity**: None (informational)
- **Nature**: Refactor of a fixed-size stack buffer's zero-initialization; recompilation churn
- **Affected function**: `EvtDriverDeviceAdd @ 0x1C0009F50` (unpatched) → `EvtDriverDeviceAdd @ 0x1C000CAC0` (patched)

`EvtDriverDeviceAdd` is the WDF `EvtDriverDeviceAdd` PnP callback. It runs when the framework adds a monitor device, not in response to any user-mode request. It takes two parameters (`WDFDRIVER`, `WDFDEVICE_INIT`), creates the `BrightnessControl` symbolic link, then builds an internal device-control request (`IoBuildDeviceIoControlRequest(0x232407, ...)`) and sends it **down** to the lower device object with `IofCallDriver`, waiting on a `KEVENT`. The 0x28-byte stack area passed as the *output* buffer of that internal request is zero-initialized in **both** builds:

- Unpatched: `memset(v83, 0, 0x28)` (asm: `lea r8d, [r15+0x28]; call memset`).
- Patched: five unrolled `mov qword [rbp+..], rax` stores writing zero to the same 0x28-byte buffer (`v93..v97`, the operand of `IoBuildDeviceIoControlRequest(0x232407, ..., &v93, 0x28u, ...)`).

The buffer is not returned to a user-mode caller; it is the driver's own output area for a request it issues to the device below it. There is no uninitialized-memory disclosure to user mode in either build. The stack frame grew from `0x360` to `0x440` (+224 bytes) because the patched function carries additional local storage for the new telemetry/tracing data, not because of any added output-sanitization requirement.

### Item 2 — `EvtIoInternalDeviceControl` dispatch refactor + new brightness telemetry (No security-relevant change)

- **Severity**: None (informational)
- **Nature**: Control-flow refactor (nested `if/else-if` + `switch` collapsed into one `switch`) plus added telemetry; functionally equivalent dispatch
- **Affected function**: `EvtIoInternalDeviceControl @ 0x1C0009C40` (unpatched) → `EvtIoInternalDeviceControl @ 0x1C000BF80` (patched)

This is the `IRP_MJ_INTERNAL_DEVICE_CONTROL` handler. Internal device control requests originate from other kernel-mode drivers in the device stack, not from user-mode `DeviceIoControl`. Both builds gate every code through the identical whitelist `SupportedInternalIoctl` (`0x1C0001240` unpatched / `0x1C0001270` patched — byte-for-byte equivalent apart from data renumbering); any code the whitelist rejects is forwarded unchanged via `ForwardRequestToPhysicalDevice`.

The unpatched dispatcher special-cases `0x23242f` and `0x2324d7`, then uses a `switch` over the remaining codes. The patched dispatcher collapses all of these into a single `switch (a5)`. The set of handled codes is **identical** in both builds: `0x23242f, 0x232433, 0x232437, 0x23243b, 0x23243f, 0x2324cb, 0x2324cf, 0x2324d7`. No code was added, none was removed, and no dispatch gap exists in either build because unrecognized codes are rejected by `SupportedInternalIoctl` before the switch is reached.

The one behavioral addition is telemetry for the brightness-mode-change code `0x2324d7`. The patched case captures the previous brightness-mode byte (`*(ctx + 0x4a4)`, i.e. offset 1188), the new user-supplied value, and a per-step status code into a small stack structure, then reports it through the new `DimStateTelemetry` function after applying the change. The actual brightness-mode read at offset `0x4a4` happens **in the dispatcher in both builds** — it is not relocated, and there is no time-of-check/time-of-use difference. `ProcessBrightness` gained an optional second parameter used only to write that status back for telemetry; its device-context reads and locking are otherwise unchanged.

---

## 3. Decompiled Behavior

### Item 1 — `EvtDriverDeviceAdd`

```c
// UNPATCHED EvtDriverDeviceAdd @ 0x1C0009F50 — 2-arg WDF PnP callback
memset(v83, 0, sizeof(v83));               // zero the 0x28-byte output area
wcscpy(v98, L"BrightnessControl");
...
InputBuffer = (*(WdfFunctions_01015 + 992))(..., v3);   // lower device object
KeInitializeEvent(&Event, NotificationEvent, 0);
v9 = IoBuildDeviceIoControlRequest(0x232407u, InputBuffer, nullptr, 0,
                                   v83, 0x28u, 1u, &Event, &IoStatusBlock);
Status = IofCallDriver(v8, v9);            // request sent DOWN the stack
```

```c
// PATCHED EvtDriverDeviceAdd @ 0x1C000CAC0 — same behavior; buffer zeroed inline
v93 = 0; v94 = 0; v95 = 0; v96 = 0; v97 = 0;   // same 0x28-byte output area, unrolled
wcscpy(v128, L"BrightnessControl");
...
v8 = (*(WdfFunctions_01015 + 992))(WPP_MAIN_CB.Reserved);   // lower device object
KeInitializeEvent(&Event, NotificationEvent, 0);
v11 = IoBuildDeviceIoControlRequest(0x232407u, v8, nullptr, 0,
                                    &v93, 0x28u, 1u, &Event, &IoStatusBlock);
```

The `memset` and the five zero-stores initialize the same fixed 0x28-byte buffer. The change is a compiler/codegen difference, not a fix.

### Item 2 — `EvtIoInternalDeviceControl` dispatch

```c
// UNPATCHED @ 0x1C0009C40
v11 = (*(WdfFunctions_01015 + 1256))(..., a1);
if ( SupportedInternalIoctl(v11, a5) == 0 )
    return ForwardRequestToPhysicalDevice(v11, a2, a3, a4, a5);
if ( a5 != 0x23242f ) {
    if ( a5 == 0x2324d7 ) { /* brightness mode change; reads *(ctx+1188) here */ }
    else switch ( a5 ) { case 0x232433: case 0x232437: case 0x23243b:
                         case 0x23243f: case 0x2324cb: case 0x2324cf: }
}
else { /* code 0x23242f handling */ }
```

```c
// PATCHED @ 0x1C000BF80 — same whitelist gate, same 8 codes, flat switch
v11 = (*(WdfFunctions_01015 + 1256))(WPP_MAIN_CB.Reserved, a1);
if ( SupportedInternalIoctl(v11, a5) == 0 )
    return ForwardRequestToPhysicalDevice(v11, a2, a3, a4, a5);
switch ( a5 ) {
    case 0x23242f: ...
    case 0x232433: ... v9 = ProcessBrightness(v11, 0);
    case 0x232437: ...
    case 0x23243b: ...
    case 0x23243f: ...
    case 0x2324cb: ...
    case 0x2324cf: ...
    case 0x2324d7:                                  // brightness mode change
        LODWORD(v43) = *(unsigned __int8 *)(v25 + 1188);   // old mode (also read in unpatched)
        ... read new value from input into HIDWORD(v43) ...
        v31 = ProcessBrightness(v11, (__int64)&v43);        // out-param carries status
        DimStateTelemetry(&v43, v26, v9);                   // NEW: report old/new/status
}
```

### Item 2 — `ProcessBrightness` signature change

```c
// UNPATCHED ProcessBrightness @ 0x1C0009B10 — 1 arg
__int64 __fastcall ProcessBrightness(__int64 a1) { ... }

// PATCHED ProcessBrightness @ 0x1C000BC80 — 2 args; second is an optional status out-param
__int64 __fastcall ProcessBrightness(__int64 a1, __int64 a2) {
    if ( a2 != 0 ) *(_QWORD *)(a2 + 8) = 0;      // NEW
    ...
    if ( a2 != 0 ) { *(_DWORD *)(a2 + 8) = 1; *(_DWORD *)(a2 + 12) = v13; }  // NEW: status
    ...
}
```

The device-context field reads (`+616`, `+481`, `+64`, `+480`, `+48`, `+60`, `+32`), the fast-mutex critical section, and the brightness application path are identical between the two `ProcessBrightness` bodies. Only the optional status write-back is new.

---

## 4. Assembly Analysis

### Item 1 — `EvtDriverDeviceAdd` prologue

```asm
; UNPATCHED @ 0x1C0009F50 — frame 0x360; buffer zeroed via memset(0x28)
00000001C0009F70  sub     rsp, 360h
00000001C0009F77  mov     rax, cs:__security_cookie
00000001C0009F81  mov     [rbp+280h+var_30], rax
00000001C0009F92  lea     rcx, [rbp+280h+var_2A8]        ; dst
00000001C0009F96  xor     edx, edx                        ; val = 0
00000001C0009FA3  lea     r8d, [r15+28h]                  ; size = 0x28
00000001C0009FA7  call    memset
00000001C0009FB5  movups  xmm0, xmmword ptr cs:aBrightnesscont      ; "BrightnessControl" string
00000001C0009FC9  movups  xmm1, xmmword ptr cs:aBrightnesscont+10h  ; "...ssControl"
```

```asm
; PATCHED @ 0x1C000CAC0 — frame 0x440; same 0x28 buffer zeroed via 5 unrolled stores
00000001C000CAE0  sub     rsp, 440h
00000001C000CAE7  mov     rax, cs:__security_cookie
00000001C000CAF8  movups  xmm0, xmmword ptr cs:aBrightnesscont      ; SAME "BrightnessControl" load
00000001C000CAFF  xor     eax, eax                        ; zero
00000001C000CB01  xor     ecx, ecx
00000001C000CB03  movups  xmm1, xmmword ptr cs:aBrightnesscont+10h  ; SAME string load
00000001C000CB0A  mov     [rbp+360h+var_3A8], rax         ; zero  (part of &v93 output buffer)
00000001C000CB11  mov     [rbp+360h+var_3A0], rax         ; zero
00000001C000CB18  mov     [rbp+360h+var_398], rax         ; zero
00000001C000CB1F  mov     [rbp+360h+var_390], rax         ; zero
00000001C000CB25  mov     [rbp+360h+var_388], rax         ; zero
```

The two `movups xmm0/xmm1` loads reference the same `BrightnessControl` string constant in both builds; they are string setup, not new data. The five zero-stores replace the unpatched `memset` of the same 0x28-byte area. The frame growth reflects additional telemetry/tracing locals in the patched function, not added output sanitization.

### Item 2 — `EvtIoInternalDeviceControl` dispatch

The unpatched dispatcher decides by direct comparison (`a5 != 0x23242f`, `a5 == 0x2324d7`) and a `switch` over the remaining codes; the patched dispatcher uses a single `switch (a5)`. Both first call `SupportedInternalIoctl(v11, a5)` and return `ForwardRequestToPhysicalDevice` on rejection. The handled code set is identical (`0x23242f, 0x232433, 0x232437, 0x23243b, 0x23243f, 0x2324cb, 0x2324cf, 0x2324d7`). The brightness-mode read `*(ctx + 0x4a4)` (offset 1188) occurs in the dispatcher body in both builds.

---

## 5. Reachability

`EvtDriverDeviceAdd` (Item 1) is a PnP device-add callback invoked by the WDF framework during device enumeration; it is not reachable from a user-mode request, and the 0x28-byte buffer it zero-initializes is an output area for a request the driver sends **down** its own stack, not a buffer returned to any caller.

`EvtIoInternalDeviceControl` (Item 2) services `IRP_MJ_INTERNAL_DEVICE_CONTROL`, which is a kernel-to-kernel interface used by drivers above/below monitor.sys in the device stack; it is not the `IRP_MJ_DEVICE_CONTROL` path that user-mode `DeviceIoControl` reaches. Every code is validated by the identical `SupportedInternalIoctl` whitelist in both builds.

No attacker-reachable primitive (information disclosure, memory corruption, race, or dispatch gap) was demonstrated in either build for these changes.

---

## 6. Impact Assessment

No exploit primitive is provided by these changes. In particular:

- There is no kernel-memory disclosure: the only buffer whose initialization changed is a fixed 0x28-byte internal-request output area that is zeroed in both builds and is never returned to user mode.
- There is no dispatch gap or improper-input-validation issue: the set of handled internal-IOCTL codes is identical and is gated by the same whitelist in both builds.
- There is no time-of-check/time-of-use difference: the brightness-mode field at offset `0x4a4` is read in the dispatcher in both builds; the patched build merely also copies the old and new values into a telemetry structure.

---

## 7. Verification Notes

The following facts were confirmed directly against both builds:

- `EvtDriverDeviceAdd` is a 2-parameter WDF `EvtDriverDeviceAdd` callback that issues an internal request (`IoBuildDeviceIoControlRequest(0x232407, ...)`) downward; the 0x28-byte output buffer is zeroed in both builds (`memset` vs. five unrolled stores).
- The patched prologue's `movups xmm0/xmm1` loads target the `BrightnessControl` string constant present in both builds — they are not new 128-bit data constants.
- `SupportedInternalIoctl` is content-identical in both builds and whitelists the same internal-IOCTL codes; unrecognized codes are forwarded via `ForwardRequestToPhysicalDevice`.
- `EvtIoInternalDeviceControl` handles the same eight codes in both builds; the patch only reshapes the control flow into a single `switch` and adds telemetry.
- `ProcessBrightness` remains `ProcessBrightness` across the patch (`0x1C0009B10` → `0x1C000BC80`); it gained one optional status out-parameter. Its device-context reads and locking are unchanged. It was **not** repurposed into a telemetry function.
- `DimStateTelemetry` (`0x1C0001A60`), `InitializeTelemetryAssertsKM` (`0x1C0001C4C`), and `MicrosoftTelemetryAssertTriggeredNoArgsKM` do not exist in the unpatched build; they are new telemetry code in the patched build.
- The brightness-mode field at offset `0x4a4` (1188) is read in the dispatcher in both builds.

---

## 8. Changed Functions — Full Triage

| Function (unpatched → patched) | Similarity | Change Type | Note |
|--------------------------------|-----------:|-------------|------|
| `EvtIoInternalDeviceControl 0x1C0009C40 → 0x1C000BF80` | 0.8644 | behavioral (telemetry) | Nested `if/else-if`+`switch` collapsed into one `switch (a5)`; same eight handled codes; same `SupportedInternalIoctl` gate. New brightness dim-state telemetry for code `0x2324d7` (`DimStateTelemetry`, status codes). Not security-relevant. |
| `EvtDriverDeviceAdd 0x1C0009F50 → 0x1C000CAC0` | 0.8041 | cosmetic/behavioral | Fixed 0x28-byte internal-request output buffer zeroed via unrolled stores instead of `memset`; frame grew for added telemetry locals. PnP callback, not user-reachable. Not security-relevant. |
| `ProcessBrightness 0x1C0009B10 → 0x1C000BC80` | — | behavioral (telemetry) | Gained one optional status out-parameter (`*(a2+8)`, `*(a2+12)`) used by the new telemetry path; core brightness logic and locking unchanged. Not a TOCTOU fix. |
| `DimStateTelemetry — → 0x1C0001A60` | — | added | New telemetry reporter for brightness dim/bright state changes. Called from the `0x2324d7` case of the dispatcher. Not security-relevant. |
| `InitializeTelemetryAssertsKM — → 0x1C0001C4C` | — | added | New telemetry-assert initialization, called from `DriverEntry`. Not security-relevant. |
| `DriverEntry 0x1C0012040 → 0x1C0014040` | 0.8933 | behavioral (telemetry) | Adds a call to `InitializeTelemetryAssertsKM(arg2)` during init; remaining differences are data-section renumbering. Not security-relevant. |
| `EvtIoDeviceControl` (user-facing `IRP_MJ_DEVICE_CONTROL`) | — | behavioral (telemetry) | Adds an inline TraceLogging brightness-state emission gated on the telemetry provider being enabled; the IOCTL handling itself is unchanged (the 208-byte `memmove(dst+5, src+169, *(src+168))` path is byte-for-byte identical between builds). Not security-relevant. |
| `EvtDriverUnload` | — | behavioral (telemetry) | Adds `UninitializeTelemetryAssertsKM()` teardown to match the new init. Not security-relevant. |
| `SetThermalThrottle 0x1C000EB90 → 0x1C0010BC0` | 0.9911 | cosmetic | Call target updated to `ProcessBrightness(arg1, 0)` to match the new 2-parameter signature; otherwise renumbering. |
| `SupportedInternalIoctl 0x1C0001240 → 0x1C0001270` | — | identical (renumbered) | IOCTL whitelist; content-identical apart from data/name renumbering. |
| `0x1C000F4D0 → 0x1C0011500` (ETW cleanup) | 0.9878 | cosmetic | Address renumbering; minor cleanup helper call. |
| `0x1C0009010 → 0x1C000B010` (WMI query handler) | 0.9755 | cosmetic | Data renumbering + register allocation. |
| `memset 0x1C0001E40 → (renumbered)` | 0.3337 | cosmetic | Matcher paired the optimized `memset` helper with an unrelated address; the routine is structurally identical, just renumbered. |
| `0x1C000B620 → 0x1C000F090` (WMI/ETW helper) | 0.1559 | cosmetic | Matcher artifact; dynamic routine resolution via `MmGetSystemRoutineAddress` for `PsGetVersion`, `WmiTraceMessage`, `WmiQueryTraceInformation`, `EtwRegisterClassicProvider`, `EtwUnregister`. Not security-relevant. |
| `0x1C00026B8 / 0x1C00026E4 / 0x1C00029E4` (ETW helpers) | 0.6333 | cosmetic | Address renumbering + minor register allocation. |

**Cosmetic cluster**: the ETW/WMI helpers and the `memset` helper are renumbering / register-allocation churn from recompilation with no behavioral change.

---

## 9. Unmatched Functions

The diff tool reported `0` unmatched in each direction because the new telemetry functions were paired with existing ones by the matcher (for example, the low-similarity `ProcessBrightness → DimStateTelemetry` pairing is a matcher artifact — `ProcessBrightness` actually maps to `ProcessBrightness`). By content, the patched build adds a Windows Implementation Library (WIL) "TelemetryAsserts" / TraceLogging subsystem that has no counterpart in the unpatched build:

- `DimStateTelemetry` (`0x1C0001A60`)
- `InitializeTelemetryAssertsKM` (`0x1C0001C4C`)
- `UninitializeTelemetryAssertsKM`
- `MicrosoftTelemetryAssertTriggeredNoArgsKM`, `MicrosoftTelemetryAssertTriggeredWorker`
- `TraceLoggingRegisterEx`, `_TlgCreateSz`, `_TlgKeywordOn`, and a new TraceLogging provider annotation stub (which replaces the old provider annotation stub removed from the unpatched build).

No sanitizer was removed and no security mitigation was added. An independent function-by-function comparison of both builds confirmed there is no new bounds/length check, no new buffer zeroing (the patched build in fact contains fewer explicit `memset` calls), no integer-overflow guard, no added input validation, and no privilege/ACL/security-descriptor change on any pre-existing code path. The variable-length `memmove(dst+5, src+169, *(src+168))` copy in the user-facing `EvtIoDeviceControl` handler is byte-for-byte identical between builds.

---

## 10. Confidence & Caveats

**Confidence**: High that there is no security-relevant change. Both of the substantially changed functions were read in full in both builds. The `EvtDriverDeviceAdd` buffer is zeroed in both builds and is an internal-request output area, not a user-visible buffer. The `EvtIoInternalDeviceControl` dispatcher handles the same code set through the same whitelist in both builds; the only behavioral additions are telemetry (`DimStateTelemetry`, status-code tracking) and the corresponding optional out-parameter on `ProcessBrightness`.

**Nature of the patch**: brightness dim/bright state-change telemetry instrumentation (`DimStateTelemetry`, `InitializeTelemetryAssertsKM`, `MicrosoftTelemetryAssertTriggeredNoArgsKM`) plus recompilation churn (address/data renumbering, register allocation, WPP/ETW trace GUID changes).

**Notes**

- The affected IOCTL codes (`0x23242f`–`0x2324d7`) are internal device-control codes serviced by `IRP_MJ_INTERNAL_DEVICE_CONTROL`, reached from adjacent kernel-mode drivers, not from user-mode `DeviceIoControl`.
- Device-context offset `0x4a4` (1188) holds the current brightness-mode byte and is read in the dispatcher in both builds.
