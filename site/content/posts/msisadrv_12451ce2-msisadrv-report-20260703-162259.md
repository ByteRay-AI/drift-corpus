Title: msisadrv.sys — KMDF static-stub rebuild: init-time bounds-check hardening plus stack-init/codegen refactors
Date: 2026-06-09
Slug: msisadrv_12451ce2-msisadrv-report-20260703-162259
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Informational
KBDate: 2026-06-09

## 1. Overview
- **Unpatched Binary**: `msisadrv_unpatched.sys`
- **Patched Binary**: `msisadrv_patched.sys`
- **Overall Similarity Score**: 0.7282
- **Diff Statistics**:
  - Matched Functions: 18 (9 identical, 9 changed)
  - Unmatched Functions: 0 added, 0 removed (one helper, `FxGetNextClassBindInfo`, was split out of existing stub code)
- **Verdict**: The delta is a Kernel-Mode Driver Framework (KMDF) static-stub library rebuild. The linked-in WDF loader stub functions (`FxStubBindClasses`, `FxStubUnbindClasses`, `FxStubInitTypes`, and a new shared helper `FxGetNextClassBindInfo`) gained tighter bounds checking and `DbgPrintEx` telemetry. These stubs run only during driver load, iterating a compile-time, linker-bracketed metadata table inside the driver's own image; they are not reachable from any untrusted (user-mode IOCTL or remote) surface. The remaining changed functions are stack-initialization and code-generation refactors. No attacker-reachable vulnerability is fixed or introduced.

## 2. Vulnerability Summary

### Finding 1: Init-time out-of-bounds read hardening in `FxStubInitTypes` (statically-linked KMDF stub)
- **Severity**: Informational (not attacker-reachable)
- **Vulnerability Class**: Out-of-bounds read of a callback pointer / missing full-entry bounds check (CWE-125)
- **Affected Function**: `FxStubInitTypes` (unpatched `0x1C0001334`, patched `0x1C000147C`)
- **Root Cause**: The unpatched loop iterates a table of 0x28-byte object-type-init records bracketed by the linker markers `__KMDF_TYPE_INIT_START`/`__KMDF_TYPE_INIT_END`. The loop's continuation test compares only the *start* of the current entry against the end marker (`cmp rbx, rdi`), then reads a function pointer from `entry+0x20`, calls it through the Control Flow Guard dispatch, and stores the result at `entry+0x18`. It does not verify that the full 0x28-byte record fits below the end marker before those accesses. The patched build adds an explicit full-entry check (`lea rax,[rcx+0x28]; cmp rax,rdi; ja fail`), a zero-entry skip loop, and a NULL check, then emits `DbgPrintEx` on failure.
- **Reachability**: This code executes during driver load only. The table it walks is generated at compile time by the KMDF headers and delimited by linker-placed markers inside the driver image; there is no attacker-controlled input on this path. The added check is defensive hardening in the WDF static stub that ships linked into KMDF drivers of this build, not a fix for an attacker-reachable condition in msisadrv. Note that the sibling stub `FxStubBindClasses` already performed a full-entry check in the unpatched build; the patch generalizes the pattern across the stub family.

### Finding 2: Stack-slot zero-initialization / codegen refactor in `MsIsaEvtDeviceProcessQueryInterface`
- **Severity**: Informational (no reachable impact)
- **Vulnerability Class**: Uninitialized stack variable (CWE-908), defense-in-depth only
- **Affected Function**: `MsIsaEvtDeviceProcessQueryInterface` (unpatched `0x1C00062A0`, patched `0x1C00062B0`)
- **Root Cause**: This is the driver's WDF query-interface callback for `GUID_TRANSLATOR_INTERFACE_STANDARD` (registered via the interface-descriptor set up in `MsIsaEvtDeviceAdd`). It queries two device properties (property IDs 0xd and 0xe) through the WDF function table (`WdfFunctions_01015+0x288`) and then calls `HalGetInterruptTranslator` (`HalDispatchTable+0x78`). In the unpatched build the stack slot `[rsp+0x44]` used as the query's output `ResultLength` parameter is not zeroed before the first call. The patched build zeroes it (`mov [rsp+0x44], esi` with `esi=0`) and reorders which slot serves as buffer vs. `ResultLength`.
- **Reachability / impact**: `ResultLength` is an output-only parameter; the property-query function writes to it. The uninitialized value is never read back by this function (only the property *buffer* slot, which is zero-initialized in both builds, is forwarded to the HAL call). There is therefore no information disclosure. This is a defense-in-depth stack-hygiene change bundled with register-allocation/codegen differences.

## 3. Pseudocode Diff

### `FxStubInitTypes` (Finding 1)

```c
// UNPATCHED FxStubInitTypes @ 0x1C0001334
if ( &__KMDF_TYPE_INIT_START > (_UNKNOWN *)__KMDF_TYPE_INIT_END )
    return 3221225595LL;                       // 0xC000007B
for ( i = __KMDF_TYPE_INIT_END; ; i += 40 )
{
    if ( i >= __KMDF_TYPE_INIT_END )           // only checks START of entry vs end marker
        return 0;
    if ( *(_DWORD *)i != 40 )
        break;
    v2 = *((__int64 (**)(void))i + 4);         // read fn ptr at i+0x20 (no full-entry check)
    if ( v2 != nullptr )
        *((_QWORD *)i + 3) = v2();              // call via CFG, store result at i+0x18
}
return 3221225476LL;                            // 0xC0000004

// PATCHED FxStubInitTypes @ 0x1C000147C
for ( i = __KMDF_TYPE_INIT_END; ; i = (_QWORD *)((char *)v3 + *v3) )
{
    for ( j = i + 1; j <= __KMDF_TYPE_INIT_END && *i == 0; ++j )   // NEW: skip empty 8-byte slots
        i = j;
    if ( i >= __KMDF_TYPE_INIT_END )
        break;
    if ( i + 5 > __KMDF_TYPE_INIT_END           // NEW: full 0x28-byte entry must fit
      || *(_DWORD *)i != 40
      || (v3 = (unsigned int *)i, i == nullptr) ) // NEW: NULL check
    {
        DbgPrintEx(0x4Du, 0, "FxGetNextObjectContextTypeInfo failed\n");
        return 3221225595LL;
    }
    v4 = (__int64 (*)(void))i[4];
    if ( v4 != nullptr )
        i[3] = v4();
}
return 0;
```

### `MsIsaEvtDeviceProcessQueryInterface` (Finding 2)

The decompiled bodies are equivalent; the difference is stack-slot initialization and which slot is the property buffer vs. the `ResultLength` output. Both builds zero the property *buffer*; the patched build also zeroes the `ResultLength` slot.

```c
// Both builds (identical decompiled logic):
if ( a4 != 2 || *a3 < 0x30u )                    return 3221225659LL;   // 0xC00000BB
v7 = *a2 - 0x11D0AACF6C154A92LL;                 // GUID_TRANSLATOR_INTERFACE_STANDARD.Data1..
if ( *a2 == 0x11D0AACF6C154A92LL ) v7 = a2[1] - 0x44B206C9A0002A8DLL;
if ( v7 != 0 )                                   return 3221225659LL;
// query device property 0xd (buffer + ResultLength), then property 0xe ...
// then HalGetInterruptTranslator(HalDispatchTable+0x78)(...)
```

## 4. Assembly Analysis

### `FxStubInitTypes` (Finding 1)

Unpatched: the loop enters the body when only the entry *start* is below the end marker, then reads `[rbx+0x20]` and writes `[rbx+0x18]`.

```assembly
; UNPATCHED FxStubInitTypes @ 0x1C0001334
0x1C000133E  lea     rax, __KMDF_TYPE_INIT_START
0x1C0001345  lea     rdi, __KMDF_TYPE_INIT_END      ; end marker
0x1C000134C  cmp     rax, rdi
0x1C000134F  jbe     0x1C0001358
0x1C0001358  lea     rbx, __KMDF_TYPE_INIT_END
0x1C000135F  jmp     0x1C000137D
0x1C0001361  cmp     dword [rbx], 0x28              ; entry size field
0x1C0001364  jnz     0x1C000138F
0x1C0001366  mov     rax, [rbx+0x20]                ; read callback pointer (no full-entry check)
0x1C000136A  test    rax, rax
0x1C000136D  jz      0x1C0001379
0x1C000136F  call    cs:__guard_dispatch_icall_fptr ; CFG-guarded indirect call
0x1C0001375  mov     [rbx+0x18], rax                ; store result
0x1C0001379  add     rbx, 0x28                       ; advance by fixed stride
0x1C000137D  cmp     rbx, rdi                        ; only checks entry START vs end
0x1C0001380  jb      0x1C0001361
0x1C0001382  xor     eax, eax                        ; return 0
```

Patched: the new checks precede any field access.

```assembly
; PATCHED FxStubInitTypes @ 0x1C000147C
0x1C00014D2  cmp     qword [rcx], 0                 ; zero-entry skip loop
0x1C00014DF  cmp     rax, rdi
0x1C00014E2  jbe     0x1C00014D2
0x1C00014E4  cmp     rcx, rdi
0x1C00014E7  jnb     0x1C0001533                    ; reached end -> return 0
0x1C00014E9  lea     rax, [rcx+0x28]                ; NEW: full-entry extent
0x1C00014ED  cmp     rax, rdi
0x1C00014F0  ja      0x1C0001519                    ; NEW: entry must fully fit -> fail
0x1C00014F2  cmp     dword [rcx], 0x28
0x1C00014F5  jnz     0x1C0001519
0x1C00014F7  mov     rbx, rcx
0x1C00014FA  test    rcx, rcx
0x1C00014FD  jz      0x1C0001519                    ; NEW: NULL check
0x1C00014FF  mov     rax, [rcx+0x20]
0x1C0001508  call    cs:__guard_dispatch_icall_fptr
0x1C000150E  mov     [rbx+0x18], rax
```

### `MsIsaEvtDeviceProcessQueryInterface` (Finding 2)

The patched build introduces a zero register (`esi`) and initializes both the property buffer slot and the `ResultLength` slot; it also swaps which named slot is buffer vs. `ResultLength`.

```assembly
; UNPATCHED @ 0x1C00062A0 (first property query, ID 0xd)
0x1C00062E9  mov     [rsp+0x40], eax                ; buffer slot = GUID-compare residual (0)
0x1C00062ED  lea     rcx, [rsp+0x44]                ; &ResultLength slot (not initialized)
0x1C00062FF  mov     [rsp+0x28], rcx                ; arg6 = ResultLength = &[rsp+0x44]
0x1C0006307  lea     rcx, [rsp+0x40]                ; &buffer slot
0x1C000630C  mov     [rsp+0x20], rcx                ; arg5 = Buffer = &[rsp+0x40]
0x1C0006311  mov     rax, [rax+0x288]               ; WdfFunctions_01015+0x288 (device-property query)
0x1C0006318  lea     r8d, [r9+9]                    ; PropertyId = 0xd
0x1C0006323  call    cs:__guard_dispatch_icall_fptr
...
0x1C00063AE  mov     ecx, [rsp+0x40]                ; forward property buffer to HAL call
0x1C00063A0  mov     rax, [rax+0x78]                ; HalDispatchTable+0x78 = HalGetInterruptTranslator
0x1C00063B2  call    cs:__guard_dispatch_icall_fptr

; PATCHED @ 0x1C00062B0
0x1C00062BF  xor     esi, esi
0x1C00062C4  mov     [rsp+0x40], esi                ; slot zeroed
0x1C0006311  lea     rcx, [rsp+0x40]
0x1C0006316  mov     [rsp+0x28], rcx                ; arg6 = ResultLength = &[rsp+0x40]
0x1C0006321  lea     rcx, [rsp+0x44]
0x1C0006326  mov     [rsp+0x44], esi                ; NEW: ResultLength/buffer slot zeroed
0x1C000632A  mov     [rsp+0x20], rcx                ; arg5 = Buffer = &[rsp+0x44]
0x1C0006344  call    cs:__guard_dispatch_icall_fptr
...
0x1C00063CB  mov     ecx, [rsp+0x44]                ; forward property buffer to HAL call
```

## 5. Trigger Conditions

### Finding 1 (`FxStubInitTypes`)
1. Executes automatically during driver load (`DriverEntry` -> `FxDriverEntryWorker` -> `FxStubInitTypes`).
2. The iterated table is compile-time KMDF object-type-init metadata delimited by the linker markers `__KMDF_TYPE_INIT_START`/`__KMDF_TYPE_INIT_END` inside the driver image.
3. There is no attacker-controlled input on this path. The unpatched missing full-entry check could only misbehave on a malformed driver image, which the toolchain that produced the binary does not emit. Not reachable from an untrusted surface.

### Finding 2 (`MsIsaEvtDeviceProcessQueryInterface`)
1. This is a WDF query-interface callback, not an IOCTL dispatch routine. It is invoked when another kernel component queries the device for `GUID_TRANSLATOR_INTERFACE_STANDARD` during PnP interface negotiation.
2. The callback validates the interface size (`*a3 >= 0x30`), the interface-type parameter (`a4 == 2`), and the requested GUID against `GUID_TRANSLATOR_INTERFACE_STANDARD`.
3. The only difference between builds is stack-slot zero-initialization plus codegen; there is no user-mode-reachable behavioral change.

## 6. Exploit Primitive & Development Notes

- **Finding 1**: No reachable primitive. The added bounds check hardens init-time stub code that walks the driver's own compile-time metadata; there is no attacker input and no observed control-flow or memory-corruption primitive reachable at runtime.
- **Finding 2**: No reachable primitive. The `ResultLength` slot is output-only and its value is never consumed; the forwarded property buffer is zero-initialized in both builds. `HalDispatchTable+0x78` resolves to `HalGetInterruptTranslator` and is invoked identically in both builds.
- **Mitigations present**: Indirect calls in both functions go through the Control Flow Guard dispatch (`__guard_dispatch_icall_fptr`).

## 7. Debugger PoC Playbook

There is no attacker-reachable trigger for either change; the notes below are for observing the code paths in a kernel debugger (WinDbg/KD), not a user-mode exploit.

### Finding 1 (`FxStubInitTypes`)
- **Breakpoint**: `bp msisadrv!FxStubInitTypes` (unpatched entry `0x1C0001334`).
- **What to inspect**: `rax`/`rdi` hold the `__KMDF_TYPE_INIT_START`/`__KMDF_TYPE_INIT_END` markers; watch `rbx` advance by 0x28. The unpatched check at `0x1C000137D` (`cmp rbx, rdi`) validates only the entry start.
- **Key offsets**: `0x1C0001366` (read `[rbx+0x20]`), `0x1C000136F` (CFG-guarded call), `0x1C0001375` (write `[rbx+0x18]`).
- **Setup**: Runs automatically at driver load; the table is fixed compile-time metadata, so under a normally built image the loop terminates cleanly at the end marker.

### Finding 2 (`MsIsaEvtDeviceProcessQueryInterface`)
- **Breakpoint**: `bp msisadrv!MsIsaEvtDeviceProcessQueryInterface` (unpatched entry `0x1C00062A0`).
- **What to inspect**: `r9d` must be 2 and `word [r8]` must be `>= 0x30` to pass the guards; `[rdx]`/`[rdx+8]` must equal `GUID_TRANSLATOR_INTERFACE_STANDARD`. Observe `[rsp+0x44]` before the first property query (uninitialized in unpatched, zeroed in patched).
- **Key offsets**: `0x1C00062ED` (`&ResultLength` slot loaded, unpatched, not initialized), `0x1C0006323` (property query), `0x1C00063B2` (call `HalGetInterruptTranslator`).
- **Setup**: Reached only via an in-kernel PnP query for the translator interface, not from user mode.

## 8. Changed Functions — Full Triage

- **`FxStubInitTypes`** (`0x1C0001334` -> `0x1C000147C`): Added full-entry bounds check, zero-entry skip, NULL check, and `DbgPrintEx` telemetry. Init-time KMDF stub, not attacker-reachable. See Finding 1.
- **`FxStubBindClasses`** (`0x1C00011F4` -> `0x1C0001224`): Refactored to call the new `FxGetNextClassBindInfo` helper and added `DbgPrintEx` telemetry. The unpatched build already performed both a start (`entry+4`) and full-entry (`entry+0x50`) bounds check, so this is a structural refactor plus zero-entry skipping, not a newly added bounds check. Init-time stub, not attacker-reachable.
- **`FxStubUnbindClasses`** (`0x1C00012B0` -> `0x1C0001384`): Same refactor into `FxGetNextClassBindInfo` plus telemetry. Teardown-time stub, not attacker-reachable.
- **`FxGetNextClassBindInfo`** (new, `0x1C000143C`): Shared helper split out of the stub functions; skips empty slots and validates that an entry fully fits within the table.
- **`FxDriverEntryWorker`** (`0x1C00010C4`): Added `DbgPrintEx` on the `DriverEntry` failure path; condition restructured to accommodate it. Telemetry only.
- **`memset`** (`0x1C0001400`): Code-generation difference. Cosmetic.
- **`MsIsaEvtDeviceAdd`** (`0x1C0006010`): More thorough stack initialization of the WDF I/O queue / interface descriptor structures using a zero register. Defense-in-depth stack hygiene, no behavioral security change.
- **`MsIsaEvtDeviceProcessQueryInterface`** (`0x1C00062A0` -> `0x1C00062B0`): Zero-initializes the `ResultLength` stack slot and reorders buffer/`ResultLength` slots; register-allocation/codegen churn. See Finding 2.
- **`MsIsaPnPIrpPreProcessingCallback`** (`0x1C00063D0` -> `0x1C00063F0`): Reordered the bus-info structure field writes and the `IoStatus.Status` assignment; net field values are equivalent. Cosmetic.

## 9. Unmatched Functions
No functions were added or removed as independent units. The new `FxGetNextClassBindInfo` helper was factored out of the existing stub functions during the KMDF static-stub rebuild.

## 10. Confidence & Caveats
- **Confidence Level**: High. Every statement above is anchored to the disassembly of the named functions at the stated addresses in both builds.
- **Nature of the patch**: A KMDF static-stub library rebuild (bounds-check generalization and `DbgPrintEx` telemetry in `FxStub*` loader code) plus stack-initialization and code-generation refactors. The `FxStub*` code is linked into KMDF drivers of this build and runs only at load/teardown over compile-time, linker-bracketed metadata.
- **Reachability**: None of the changed code is reachable from a user-mode IOCTL or other untrusted surface. `MsIsaEvtDeviceProcessQueryInterface` is a PnP interface-query callback, not an IOCTL handler, and its changed slot is an output-only value that is never read back. No exploitable primitive is present in either build.
