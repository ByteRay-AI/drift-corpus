Title: msisadrv.sys — No security-relevant change (KMDF static-stub rebuild plus defensive stack-slot zeroing in init/enumeration paths)
Date: 2026-06-29
Slug: msisadrv_0dfb0ac9-msisadrv-report-20260629-140058
Category: Corpus
Author: Argus
Summary: KB5087545

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `msisadrv_unpatched.sys` |
| Patched binary | `msisadrv_patched.sys` |
| Overall similarity | 0.7282 |
| Matched functions | 18 |
| Changed functions | 9 |
| Identical functions | 9 |
| Unmatched (unpatched) | 0 |
| Unmatched (patched) | 2 (KMDF static-stub helper `FxGetNextClassBindInfo` and an XFG dispatch thunk, both introduced by the framework-stub rebuild) |

**Verdict:** No attacker-reachable security fix is present in this diff. The patched build is a routine KMDF (Kernel-Mode Driver Framework) static-stub library rebuild layered on top of the same driver logic. The differences are: (a) the framework binding/type-init stub functions were regenerated to use a shared bounds-checking helper and to emit `DbgPrintEx` diagnostics; (b) `memset` was changed from an inlined SSE body to a tail-call into the imported `memset`; (c) the device-add and query-interface callbacks pick up bulk `xorps`/`movdqu` zero-initialization instead of scattered individual stores, which additionally zeroes one pure-output stack slot and a few otherwise-dead stack bytes. None of these change observable behaviour on any attacker-reachable path. The three items examined below are retained as findings but each is downgraded to no demonstrable security impact after verification against both builds.

---

## 2. Vulnerability Summary

### Finding 1 — Defensive zeroing of a write-only output slot in the bus query-interface callback

- **Severity:** None (informational)
- **Class:** Use of Uninitialized Variable (CWE-457) — technically present, no reachable impact
- **Affected function:** `MsIsaEvtDeviceProcessQueryInterface` (unpatched `@ 0x1C00062A0`, patched `@ 0x1C00062B0`)
- **Entry point:** kernel `IRP_MN_QUERY_INTERFACE` for `GUID_TRANSLATOR_INTERFACE_STANDARD` from the device stack (not user-mode reachable)

**What the code is.** This function is the driver's `EvtDeviceProcessQueryInterfaceRequest` callback. It is registered in `MsIsaEvtDeviceAdd` through `WdfDeviceAddQueryInterface` (WDF function table offset `0x720`) with a `WDF_QUERY_INTERFACE_CONFIG` naming `GUID_TRANSLATOR_INTERFACE_STANDARD` (`{6C154A92-AACF-11D0-8D2A-00A0C906B244}`, stored at `.rdata:0x1C0002110` and symbolized as `GUID_TRANSLATOR_INTERFACE_STANDARD` in both builds). The callback runs when the PnP/bus stack sends `IRP_MN_QUERY_INTERFACE` requesting the standard resource/interrupt translator interface. On a matching request it reads the two device-registry properties `DevicePropertyLegacyBusType` (`0xd`) and `DevicePropertyBusNumber` (`0xe`) via `WdfDeviceQueryProperty` (WDF table offset `0x288`) and calls `HalDispatchTable->HalGetInterruptTranslator` (`HalDispatchTable + 0x78`) to obtain the translator it returns to the requester. This is normal ISA-bus translator behaviour and is identical in both builds.

**The actual change.** In the unpatched build the 4-byte stack slot at `[rsp+0x44]` (`var_14`) is used as the `ResultLength` output pointer (6th argument) of the first `WdfDeviceQueryProperty` call, and it is not written before the call. The property-value buffer slot passed as the 5th argument (`var_18` at `[rsp+0x40]`) *is* zeroed. In the patched build both slots are zeroed at entry (`xor esi,esi` followed by explicit stores to `[rsp+0x40]` and `[rsp+0x44]`), and the buffer/length slot roles are swapped by codegen.

**Why there is no impact.** `ResultLength` is a pure output parameter of `WdfDeviceQueryProperty`; the framework writes the produced length there and never reads the incoming value. The driver also never reads `var_14` back after either call — only the property-value buffer (`var_18`, which is zeroed in both builds) and the fixed-size 4-byte results are consumed by the subsequent `HalGetInterruptTranslator` call. Passing the address of an uninitialized slot as a write-only output therefore has no observable effect. There is no information disclosure (nothing uninitialized is read), no size confusion (`BufferLength` is the compile-time constant `4` in `r9d`, not the residue), and the callback is not reachable from an untrusted user-mode surface. The change is defensive stack-slot initialization, not a fix for a reachable defect.

### Finding 2 — Bulk zero-initialization of WDF config structures in `MsIsaEvtDeviceAdd`

- **Severity:** None (informational)
- **Class:** Use of Uninitialized Resource (CWE-908) — no demonstrable impact
- **Affected function:** `MsIsaEvtDeviceAdd` (`@ 0x1C0006010` in both builds)

`MsIsaEvtDeviceAdd` is the `EvtDriverDeviceAdd` callback; it runs only during PnP device enumeration. Both builds construct the same two structures on the stack: a `WDF_IO_QUEUE_CONFIG` (Size `0x38`, `EvtCleanupCallback = MsIsaEvtCleanupCallback`, default-queue dispatch flags `1`/`1`) passed to WDF function `0x258`, and a `WDF_QUERY_INTERFACE_CONFIG` (Size `0x30`, `Interface` pointer, `InterfaceType = &GUID_TRANSLATOR_INTERFACE_STANDARD`, `EvtDeviceProcessQueryInterfaceRequest = MsIsaEvtDeviceProcessQueryInterface`, `ImportInterface = 1`) plus the 48-byte translator `INTERFACE` template, passed to WDF function `0x720`. The unpatched build zeroes these with individual `mov` stores from a zeroed register; the patched build uses `xorps xmm0,xmm0` with `movdqu`/`movups` bulk stores and adds a few extra byte/dword zero writes for trailing stack slots. Both builds fully populate every field the framework reads; the extra zeroed bytes in the patched build fall outside the declared config `Size` and are not consumed. This is a codegen refresh on an init-only path, not a security fix.

### Finding 3 — KMDF static-stub framework functions regenerated

The patched build regenerates the KMDF static-stub library functions that run at `DriverEntry` to bind WDF classes and initialize object type-info:

- `FxStubBindClasses` (unpatched `@ 0x1C00011F4`, patched `@ 0x1C0001224`)
- `FxStubInitTypes` (unpatched `@ 0x1C0001334`, patched `@ 0x1C000147C`)
- `FxStubUnbindClasses` (unpatched `@ 0x1C00012B0`, patched `@ 0x1C0001384`)

The patched versions delegate iteration to a new shared helper `FxGetNextClassBindInfo` (`@ 0x1C000143C`) that skips null entries and checks that a full entry fits before dereferencing, use variable-size stepping (`ptr += *ptr`) instead of a fixed stride, add `DbgPrintEx` diagnostics, and return `STATUS_INVALID_IMAGE_FORMAT` instead of `STATUS_INFO_LENGTH_MISMATCH` on malformed input. These functions iterate the driver's own linker-generated sections (`__KMDF_CLASS_BIND_START/END`, `__KMDF_TYPE_INIT_START/END`), which are fixed at build time and are not attacker-controlled. In `msisadrv.sys` these regions hold no entries, so neither the old nor the new code performs any iteration at runtime. This is a static-stub library rebuild inherited from the framework, not a fix for a defect reachable in this driver.

---

## 3. Pseudocode Diff

### Finding 1 — `MsIsaEvtDeviceProcessQueryInterface`

The decompiled bodies are equivalent in both builds; the local that receives the property value is initialized to `0` in both. The only difference is at the assembly level: the unpatched build leaves the `ResultLength` output slot unwritten, the patched build zeroes it.

```c
// Both builds (identical decompilation)
__int64 MsIsaEvtDeviceProcessQueryInterface(__int64 a1, _QWORD *a2,
                                            unsigned __int16 *a3, int a4)
{
    if ( a4 != 2 || *a3 < 0x30u )                 // action must be 2, buffer >= 0x30
        return 0xC00000BB;                          // STATUS_NOT_SUPPORTED
    // GUID match against GUID_TRANSLATOR_INTERFACE_STANDARD
    if ( *a2 != 0x11D0AACF6C154A92 || a2[1] != 0x44B206C9A0002A8D )
        return 0xC00000BB;
    // WdfDeviceQueryProperty(globals, dev, DevicePropertyLegacyBusType=0xd, 4, &buf, &len)
    if ( WdfDeviceQueryProperty(... 0xd, 4, &buf, &len) < 0 )
        return 0xC0000001;                          // STATUS_UNSUCCESSFUL
    // WdfDeviceQueryProperty(globals, dev, DevicePropertyBusNumber=0xe, 4, &busno, &len)
    if ( WdfDeviceQueryProperty(... 0xe, 4, &busno, &len) < 0 )
        return 0xC0000001;
    return HalDispatchTable->HalGetInterruptTranslator(0, buf, 1, *a3, ..., a3, &busno);
}
```

The `&len` slot (`[rsp+0x44]` in the unpatched build) is written by the framework and never read by the driver. Unpatched does not pre-zero it; patched does.

### Finding 2 — `MsIsaEvtDeviceAdd`

```asm
; UNPATCHED: scattered zero stores from a zeroed register (rax=0)
mov [rbp+57h+var_60], rax          ; queue-config fields zeroed individually
mov [rbp+57h+var_50], rax
mov [rbp+57h+var_40], rax
mov [rbp+57h+var_38], rax
mov dword [rbp+57h+var_60], 38h    ; Size = 0x38
mov dword [rbp+57h+var_48], 1      ; dispatch flags
mov dword [rbp+57h+var_48+4], 1

; PATCHED: bulk zero + selective writes (same resulting config)
xorps  xmm0, xmm0
movdqu [rbp+57h+var_40], xmm0       ; 16-byte bulk zero
mov    [rbp+57h+var_60], 38h        ; Size = 0x38
mov    [rbp+57h+var_48], 1
mov    [rbp+57h+var_44], 1
```

---

## 4. Assembly Analysis

### Finding 1 — `MsIsaEvtDeviceProcessQueryInterface` (UNPATCHED `@ 0x1C00062A0`)

Real disassembly of the relevant block. `var_18 = [rsp+0x40]` (property-value buffer, zeroed), `var_14 = [rsp+0x44]` (`ResultLength` output slot, not written before the call).

```asm
00000001C00062A0  mov     [rsp+arg_0], rbx
00000001C00062A5  push    rdi
00000001C00062A6  sub     rsp, 50h
00000001C00062B0  cmp     r9d, 2                    ; action == 2 ?
00000001C00062B4  jz      short loc_1C00062C6
00000001C00062C6  cmp     word ptr [r8], 30h        ; *a3 >= 0x30 ?
00000001C00062CB  jb      short loc_1C00062B6
00000001C00062CD  mov     rax, [rdx]                ; GUID_TRANSLATOR_INTERFACE_STANDARD match
00000001C00062D0  sub     rax, qword ptr cs:GUID_TRANSLATOR_INTERFACE_STANDARD.Data1
00000001C00062D9  mov     rax, [rdx+8]
00000001C00062DD  sub     rax, qword ptr cs:GUID_TRANSLATOR_INTERFACE_STANDARD.Data4
00000001C00062E7  jnz     short loc_1C00062B6
00000001C00062E9  mov     [rsp+58h+var_18], eax     ; buffer var_18 = 0 (eax = 0 here)
00000001C00062ED  lea     rcx, [rsp+58h+var_14]     ; &var_14 (ResultLength out; NOT pre-zeroed)
00000001C00062FF  mov     [rsp+58h+var_30], rcx     ; arg6 = &var_14
00000001C0006307  lea     rcx, [rsp+58h+var_18]     ; &var_18
00000001C000630C  mov     [rsp+58h+var_38], rcx     ; arg5 = &var_18 (buffer)
00000001C0006311  mov     rax, [rax+288h]           ; WdfDeviceQueryProperty
00000001C0006318  lea     r8d, [r9+9]               ; DevicePropertyLegacyBusType = 0xd
00000001C0006323  call    cs:__guard_dispatch_icall_fptr
00000001C0006331  ...                               ; second query: property 0xe (BusNumber)
00000001C000637D  mov     rax, cs:__imp_HalDispatchTable
00000001C00063A0  mov     rax, [rax+78h]            ; HalGetInterruptTranslator
00000001C00063B2  call    cs:__guard_dispatch_icall_fptr
00000001C00063C2  retn
```

### Same function — PATCHED (`@ 0x1C00062B0`)

```asm
00000001C00062BF  xor     esi, esi
00000001C00062C4  mov     [rsp+58h+var_18], esi     ; var_18 = 0
00000001C0006311  lea     rcx, [rsp+58h+var_18]
00000001C0006316  mov     [rsp+58h+var_30], rcx     ; arg6 (ResultLength) = &var_18
00000001C0006321  lea     rcx, [rsp+58h+var_14]
00000001C0006326  mov     [rsp+58h+var_14], esi     ; var_14 = 0  (newly zeroed)
00000001C000632A  mov     [rsp+58h+var_38], rcx     ; arg5 (buffer) = &var_14
00000001C0006344  call    cs:__guard_dispatch_icall_fptr
```

The patched build zeroes both stack slots and swaps which one is the buffer versus the `ResultLength` output. Because the `ResultLength` slot is write-only and never read back, the two builds are behaviourally equivalent; the change is defensive initialization.

---

## 5. Reachability

`MsIsaEvtDeviceProcessQueryInterface` is invoked only when the device receives a kernel-mode `IRP_MN_QUERY_INTERFACE` whose requested interface GUID equals `GUID_TRANSLATOR_INTERFACE_STANDARD`. Such requests originate from the PnP manager or an adjacent bus/child driver during device enumeration and resource translation. There is no user-mode path to this callback: the driver exposes no WMI provider (the config registered at WDF offset `0x720` is a `WDF_QUERY_INTERFACE_CONFIG`, not a WMI provider), and the GUID above is a bus translator interface identifier, not a WMI data-block GUID. The guard conditions in the callback (`action == 2`, `*a3 >= 0x30`, GUID match) operate on the kernel-supplied query-interface request, not on attacker-controlled input.

`MsIsaEvtDeviceAdd` and the `FxStub*` functions run only during driver load / device add and iterate build-time data. None of the three findings is reachable from an untrusted IOCTL, WMI, or other user-mode surface.

---

## 6. Impact Assessment

There is no exploit primitive in this diff.

- **Finding 1:** the only changed data flow is an output-only `ResultLength` slot that the framework writes and the driver never reads. No value derived from uninitialized memory reaches any sink. The subsequent `HalGetInterruptTranslator` call receives the two fixed-size property values (whose buffers are zeroed in both builds) and fields from the kernel-supplied query-interface request; nothing there is attacker-controlled or affected by the zeroing change.
- **Finding 2:** init-only config construction; both builds produce identical, fully-populated `WDF_IO_QUEUE_CONFIG` and `WDF_QUERY_INTERFACE_CONFIG` structures. The extra zeroed bytes lie outside the declared config sizes.
- **Finding 3:** static-stub library code iterating empty, build-time linker sections; no runtime iteration occurs in this driver.

Control Flow Guard is enabled in both builds (indirect calls dispatch through `__guard_dispatch_icall_fptr`), unchanged by this patch. No information leak, memory corruption, or privilege-escalation primitive is demonstrable.

---

## 7. Verification Notes

The following observations were confirmed against both disassembled builds:

- The changed 4-byte slot in `MsIsaEvtDeviceProcessQueryInterface` (`[rsp+0x44]`, `var_14`) is the `ResultLength` argument of `WdfDeviceQueryProperty`. Setting a breakpoint at the first property call (unpatched `0x1C0006323`) and inspecting `dd rsp+0x44 L1` shows uninitialized residue in the unpatched build and `0x00000000` in the patched build. Because the driver never reads this slot after the call, the difference is not observable in the callback's output or return value.
- The property-value buffer slot passed to `WdfDeviceQueryProperty` is zeroed in both builds, so no uninitialized property value is ever forwarded to `HalGetInterruptTranslator`.
- `MsIsaEvtDeviceAdd` builds the same `WDF_IO_QUEUE_CONFIG` (Size `0x38`) and `WDF_QUERY_INTERFACE_CONFIG` (Size `0x30`) in both builds; dumping the config ranges before the WDF `0x258` and `0x720` calls shows all framework-read fields populated identically.
- The `FxStub*` iteration ranges (`__KMDF_CLASS_BIND_START/END`, `__KMDF_TYPE_INIT_START/END`) contain no entries in this driver, so the new bounds-checking helper and the old inline checks alike perform zero iterations.

---

## 8. Changed Functions — Full Triage

| Function | Sim | Type | Note |
|---|---|---|---|
| `MsIsaEvtDeviceProcessQueryInterface` (unpatched `0x1C00062A0` / patched `0x1C00062B0`) | 0.976 | Defensive init | Zeroes the write-only `ResultLength` output slot before the first `WdfDeviceQueryProperty` call and swaps buffer/length slot roles. No behavioural change; the slot is never read back. Kernel query-interface callback, not user-mode reachable. |
| `FxStubInitTypes` (unpatched `0x1C0001334` / patched `0x1C000147C`) | 0.642 | Static-stub rebuild | Uses the new `FxGetNextClassBindInfo` helper with variable-size stepping and a null-skip loop; adds `DbgPrintEx`; returns `STATUS_INVALID_IMAGE_FORMAT` instead of `STATUS_INFO_LENGTH_MISMATCH`. Iterates an empty build-time type-info section. Not attacker-reachable. |
| `FxStubBindClasses` (unpatched `0x1C00011F4` / patched `0x1C0001224`) | 0.443 | Static-stub rebuild | Same regeneration pattern via `FxGetNextClassBindInfo`; adds `DbgPrintEx` on bind failures. Iterates an empty build-time class-bind section. Not attacker-reachable. |
| `FxStubUnbindClasses` (unpatched `0x1C00012B0` / patched `0x1C0001384`) | 0.779 | Static-stub rebuild | Same helper-based iteration and diagnostic logging. |
| `MsIsaPnPIrpPreProcessingCallback` (unpatched `0x1C00063D0` / patched `0x1C00063F0`) | 0.986 | Cosmetic | Pool-init reordered; status variable hoisted; the ISA-PnP bus-info structure (`GUID_BUS_TYPE_ISAPNP`, flag `1`, bus number) is written with the same final values. Semantically equivalent. |
| `FxDriverEntryWorker` (`0x1C00010C4`) | 0.920 | Diagnostic | Adds `DbgPrintEx(0x4d, 0, "DriverEntry failed 0x%x for driver %wZ\n", ...)` on the device-add error path; saves/restores an extra callee-saved register (frame `0x20`→`0x30`). No security impact. |
| `MsIsaEvtDeviceAdd` (`0x1C0006010`) | 0.908 | Codegen refresh | Bulk `xorps`/`movdqu` zero-init of `WDF_IO_QUEUE_CONFIG` / `WDF_QUERY_INTERFACE_CONFIG` plus a few extra zeroed trailing bytes. Init-only; both builds produce identical configs. |
| `DriverEntry` (`0x1C0007040`) | 0.649 | Cosmetic | `xorps`/`movdqu` zero-init pattern; data references shifted due to added format strings. Same driver-config setup and `WdfDriverCreate` call. |
| `memset` (unpatched `0x1C0001400` / patched `0x1C00015A0`) | 0.140 | Cosmetic | Inline SSE `memset` replaced with a tail-call to the imported `memset`. Functionally identical. |

**Newly present in the patched build (framework-stub rebuild):** the shared helper `FxGetNextClassBindInfo` (`0x1C000143C`) and an XFG dispatch thunk (`_guard_xfg_dispatch_icall_nop`, `0x1C00015A0`). Both are library-internal artifacts of the KMDF static-stub regeneration; neither is a security change.

**Grouped cosmetic/codegen changes:** the `memset` rewrite, the PnP device-usage handler reorder, the `DriverEntry` addressing/zero-init pattern, and the added `DbgPrintEx` diagnostics are toolchain/version-refresh differences. None alter observable behaviour.

---

## 9. Unmatched Functions

The diff reports zero removed functions. Two functions are present only in the patched build — the KMDF static-stub helper `FxGetNextClassBindInfo` and an XFG dispatch thunk — both introduced by the framework-stub rebuild rather than representing a delivered driver-level change. All other differences are body-level edits within matched function pairs.

---

## 10. Confidence & Caveats

**Confidence:** High that this diff contains no attacker-reachable security fix. Every changed function was matched by content across relocations and examined in both builds. The one data-flow change with a security flavour (Finding 1) resolves to defensive zeroing of a write-only output-parameter slot that the driver never reads, on a callback that is not reachable from user mode.

**Basis for the downgrade:**

- The `{6C154A92-AACF-11D0-8D2A-00A0C906B244}` GUID is `GUID_TRANSLATOR_INTERFACE_STANDARD` (a bus translator interface), symbolized as such in both builds; the callback is `EvtDeviceProcessQueryInterfaceRequest` registered via `WdfDeviceAddQueryInterface` (WDF offset `0x720`). There is no WMI provider in this driver.
- `WdfDeviceQueryProperty`'s `ResultLength` (WDF offset `0x288`, 6th argument) is a pure output parameter; the uninitialized slot is written by the framework and never read by the driver.
- `MsIsaEvtDeviceAdd`, `FxStubBindClasses`, `FxStubInitTypes`, and `FxStubUnbindClasses` are init-only and iterate build-time data (empty in this driver); they are not reachable from any untrusted input surface.
