Title: msisadrv.sys — KMDF static-stub rebuild and compiler stack-init churn
Date: 2026-07-03
Slug: msisadrv_a4481dbc-msisadrv-report-20260703-155135
Category: Corpus
Author: Argus
Summary: KB5082142
Severity: Unknown
KBDate: 2026-04-14

## 1. Overview

- **Unpatched Binary:** `msisadrv_unpatched.sys`
- **Patched Binary:** `msisadrv_patched.sys`
- **Overall Similarity Score:** `0.7282`
- **Diff Statistics:** 18 matched functions, 9 changed functions, 9 identical functions, 0 unmatched functions in either direction.
- **Verdict:** No security-relevant change. The differences between the two builds are a KMDF static-stub rebuild (dynamic-size class/type iteration with added `DbgPrintEx` diagnostics, a new `FxGetNextClassBindInfo` helper, an added XFG dispatch thunk) plus compiler stack-initialization churn (zero-init of address-taken locals, stack-slot reassignment). The device-facing callbacks (`MsIsaEvtDeviceProcessQueryInterface`, `MsIsaPnPIrpPreProcessingCallback`) are functionally identical across builds; no attacker-reachable behavior changed.

## 2. Assessment Summary

- **Severity:** None (no security-relevant change).
- **Nature of change:** Framework rebuild + compiler code-generation differences.
- **Primary function examined:** `MsIsaEvtDeviceProcessQueryInterface` (`0x1C00062A0` unpatched, `0x1C00062B0` patched).

**Why there is no vulnerability here:**

`MsIsaEvtDeviceProcessQueryInterface` is the driver's `EvtDeviceProcessQueryInterface` callback, registered in `MsIsaEvtDeviceAdd` through the WDF function at table offset `1824` (against `GUID_TRANSLATOR_INTERFACE_STANDARD`). It runs when another kernel component issues a PnP `IRP_MN_QUERY_INTERFACE` for the translator interface. It is **not** an `EvtIoDeviceControl` handler and is **not** reachable from a user-mode `DeviceIoControl` call.

The decompiled body of this function is byte-for-byte identical between the unpatched and patched builds. At the instruction level the only differences are:

1. The patched build saves/restores `rsi` and uses `esi` (zeroed) as a source of the constant `0`.
2. The compiler assigns the first WDF-retrieval output to a different stack slot (`[rsp+0x44]` in the patched build vs `[rsp+0x40]` in the unpatched build) and zero-initializes the address-taken 4-byte local `[rsp+0x44]` before the call.

In **both** builds the value passed as the first argument to `HalDispatchTable+0x78` is the output written by the first WDF-retrieval call into its 5th-parameter buffer, and that slot is pre-initialized to `0` before the call in both builds (`mov [rsp+0x40], eax` with `eax = 0` in unpatched at `0x1C00062E9`; `mov [rsp+0x44], esi` with `esi = 0` in patched at `0x1C0006326`). The second output slot is written by WDF but its value is never read in either build. There is no swapped-semantics bug, no uninitialized value flows into the HAL call, and nothing is leaked to a caller-visible buffer.

## 3. Pseudocode

The decompiled body is identical in both builds (only the entry address and internal stack-slot assignment differ).

```c
// MsIsaEvtDeviceProcessQueryInterface
// unpatched @ 0x1C00062A0, patched @ 0x1C00062B0 (identical decompilation)
__int64 __fastcall MsIsaEvtDeviceProcessQueryInterface(__int64 a1, _QWORD *a2,
                                                        unsigned __int16 *a3, int a4)
{
    if ( a4 != 2 || *a3 < 0x30u )
        return 3221225659LL;                       // 0xC00000BB STATUS_NOT_SUPPORTED
    __int64 v7 = *a2 - 0x11D0AACF6C154A92LL;
    if ( *a2 == 0x11D0AACF6C154A92LL )
        v7 = a2[1] - 0x44B206C9A0002A8DLL;
    if ( v7 != 0 )
        return 3221225659LL;
    if ( (*(int (__fastcall **)(PWDF_DRIVER_GLOBALS, __int64, __int64))
          (WdfFunctions_01015 + 648))(WdfDriverGlobals, a1, 13) < 0 )
        return 3221225473LL;                       // 0xC0000001 STATUS_UNSUCCESSFUL
    unsigned int v9 = 0;
    unsigned int *v8 = &v9;
    if ( (*(int (__fastcall **)(PWDF_DRIVER_GLOBALS, __int64, __int64))
          (WdfFunctions_01015 + 648))(WdfDriverGlobals, a1, 14) < 0 )
        return 3221225473LL;
    LOWORD(v8) = a3[1];
    return ((__int64 (__fastcall *)(_QWORD, _QWORD, __int64, _QWORD,
             unsigned int *, unsigned __int16 *, unsigned int *))
            HalDispatchTable->HalGetInterruptTranslator)(0, v9, 1, *a3, v8, a3, &v9);
}
```

## 4. Assembly Analysis

The two builds differ only in stack-slot allocation and the added zero-init; the control flow, the WDF table offset (`0x288`), the type indices (`0xd`, `0xe`), and the `HalDispatchTable+0x78` target are identical.

### UNPATCHED (`MsIsaEvtDeviceProcessQueryInterface` @ 0x1C00062A0)
```assembly
00000001C00062E9  mov     [rsp+58h+var_18], eax     ; var_18 ([rsp+0x40]) = 0 (GUID match result)
00000001C00062ED  lea     rcx, [rsp+58h+var_14]     ; &var_14 ([rsp+0x44]), address-taken only
00000001C00062FF  mov     [rsp+58h+var_30], rcx     ; 6th param slot = &var_14
00000001C0006307  lea     rcx, [rsp+58h+var_18]
00000001C000630C  mov     [rsp+58h+var_38], rcx     ; 5th param slot = &var_18
00000001C0006311  mov     rax, [rax+288h]           ; WDF function ptr at offset 0x288
00000001C0006318  lea     r8d, [r9+9]               ; type index = 0xd
00000001C0006323  call    cs:__guard_dispatch_icall_fptr
...
00000001C00063AE  mov     ecx, [rsp+58h+var_18]     ; HAL arg1 = var_18 (5th-param output, pre-set to 0)
00000001C00063B2  call    cs:__guard_dispatch_icall_fptr   ; HalDispatchTable+0x78
```

### PATCHED (`MsIsaEvtDeviceProcessQueryInterface` @ 0x1C00062B0)
```assembly
00000001C00062BF  xor     esi, esi                  ; esi = 0
00000001C00062C4  mov     [rsp+58h+var_18], esi      ; var_18 ([rsp+0x40]) = 0
...
00000001C0006311  lea     rcx, [rsp+58h+var_18]
00000001C0006316  mov     [rsp+58h+var_30], rcx      ; 6th param slot = &var_18
00000001C0006321  lea     rcx, [rsp+58h+var_14]
00000001C0006326  mov     [rsp+58h+var_14], esi      ; var_14 ([rsp+0x44]) = 0 (zero-init)
00000001C000632A  mov     [rsp+58h+var_38], rcx      ; 5th param slot = &var_14
00000001C0006339  mov     rax, [rax+288h]
00000001C0006340  lea     r8d, [r9+9]                ; type index = 0xd
00000001C0006344  call    cs:__guard_dispatch_icall_fptr
...
00000001C00063CB  mov     ecx, [rsp+58h+var_14]      ; HAL arg1 = var_14 (5th-param output, pre-set to 0)
00000001C00063CF  call    cs:__guard_dispatch_icall_fptr   ; HalDispatchTable+0x78
```

In both listings the value handed to `HalDispatchTable+0x78` is the 5th-parameter output of the first WDF call, and that slot is written to `0` before the call. The compiler simply picked `[rsp+0x40]` for it in the unpatched build and `[rsp+0x44]` in the patched build. The remaining slot is a WDF output whose value is never read.

## 5. Reachability

`MsIsaEvtDeviceProcessQueryInterface` is invoked by the PnP manager / another kernel driver when it queries `GUID_TRANSLATOR_INTERFACE_STANDARD` on the ISA bus device, not by a user-mode process. The parameters (`a2` = queried GUID, `a3` = interface buffer, `a4` = interface size/version) are supplied by kernel PnP plumbing, not by an untrusted IOCTL buffer. There is no user-mode `DeviceIoControl` path into this routine.

## 6. Notes on the Other Device-Facing Callback

`MsIsaPnPIrpPreProcessingCallback` (`0x1C00063D0` unpatched, `0x1C00063F0` patched) handles the PnP `IRP_MN_QUERY_BUS_INFORMATION` minor function (value `0x18`), allocating a `0x18`-byte pool buffer (tag `MIsa`) that holds `GUID_BUS_TYPE_ISAPNP`, a reference count, and the assigned bus number. In **both** builds all `0x18` bytes are fully written before the buffer is published via `IoStatus.Information`; the unpatched build writes `[rax+0x10] = 0` then `[rax+0x10] = 1` then `[rax+0x14] = busnum`, and the patched build writes `[rax+0x10] = 1` (as a qword, also zeroing `[rax+0x14]`) then `[rax+0x14] = busnum`. The net buffer contents are identical and there is no window of uninitialized pool residue in either build. The only change is instruction ordering and the point at which the `IoStatus.Status` constant is materialized. This is a code-generation refactor, not a security fix.

## 7. Independent Diff — Full Triage

Every function that differs between the two builds, matched by content across relocations:

- **`MsIsaEvtDeviceProcessQueryInterface` (0x1C00062A0 → 0x1C00062B0):**
  - Identical decompilation. Only differences are stack-slot reassignment of the first WDF output and zero-init of an address-taken local; the value flowing into `HalDispatchTable+0x78` is unchanged and pre-initialized in both builds. No security-relevant change.
- **`MsIsaPnPIrpPreProcessingCallback` (0x1C00063D0 → 0x1C00063F0):**
  - Instruction reordering of pool-buffer initialization; both builds fully initialize the buffer before publishing it. No security-relevant change.
- **`FxStubBindClasses` (0x1C00011F4 → 0x1C0001224):**
  - KMDF static-stub rebuild: fixed `0x50` stride replaced with dynamic size iteration via the new `FxGetNextClassBindInfo` helper; added `DbgPrintEx` diagnostics. Runs only at driver load. Not attacker-reachable.
- **`FxStubInitTypes` (0x1C0001334 → 0x1C000147C):**
  - KMDF static-stub rebuild: fixed `0x28` stride replaced with dynamic size iteration; added `DbgPrintEx` diagnostics. Runs only at driver load. Not attacker-reachable.
- **`FxStubUnbindClasses` (0x1C00012B0 → 0x1C0001384):**
  - KMDF static-stub rebuild cleanup path using dynamic size iteration and the new helper; added `DbgPrintEx`. Runs only at unload. Not attacker-reachable.
- **`FxGetNextClassBindInfo` (new, 0x1C000143C in patched):**
  - New KMDF static-stub helper used by the bind/unbind rebuild above. Init/unload only. Not attacker-reachable.
- **`FxDriverEntryWorker` (0x1C00010C4):**
  - Added `DbgPrintEx("DriverEntry failed ...")` diagnostic and updated WDF data references (`unk_1C0003150 → unk_1C00031D0`, `qword_1C0003120 → qword_1C00031A0`). No behavioral security change.
- **`MsIsaEvtDeviceAdd` (0x1C0006010):**
  - Additional compiler stack zero-initialization of address-taken locals and updated data/callback references. Init-only device-add routine. No behavioral security change.
- **`DriverEntry` (0x1C0007040):**
  - Compiler stack-initialization churn (zeroing of the WDF config structure). Init-only. No behavioral security change.
- **`memset` / XFG thunk (0x1C0001400 → import/thunk; new `_guard_xfg_dispatch_icall_nop` @ 0x1C00015A0):**
  - Compiler/linker artifact: inlined `memset` and CFG/XFG dispatch thunk changes from the rebuild. Not a security fix.

No changed function contains an attacker-reachable security fix that was omitted from this triage.

## 8. Unmatched Functions

There are no unmatched functions in this diff. All differences are relocations, framework-stub rebuild churn, or compiler code-generation changes.

## 9. Confidence & Caveats

- **Confidence Level:** High.
- **Rationale:** The device-facing callbacks decompile identically across builds; the only instruction-level differences are stack-slot allocation and zero-init of address-taken locals, verified directly against both disassemblies. The value reaching `HalDispatchTable+0x78` is pre-initialized in both builds, and the pool buffer in the PnP callback is fully initialized in both builds. The remaining changed functions are KMDF static-stub rebuild and init/unload-only routines.
- **Caveats:** `MsIsaEvtDeviceProcessQueryInterface` is a kernel PnP `EvtDeviceProcessQueryInterface` callback, not a user-mode-reachable IOCTL handler; its inputs are supplied by PnP plumbing rather than an untrusted buffer.
