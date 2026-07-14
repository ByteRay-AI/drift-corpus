Title: fsdepends.sys — recompilation; WCOS support flag enabled
Date: 2026-05-12
Slug: fsdepends_89ca1ca9-fsdepends-report-20260628-231341
Category: Corpus
Author: Argus
Summary: KB5087545
Severity: Unknown
KBDate: 2026-05-12

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `fsdepends_unpatched.sys` |
| Patched binary | `fsdepends_patched.sys` |
| Overall similarity | 0.9577 |
| Matched functions | 87 |
| Changed functions | 19 |
| Identical functions | 68 |
| Unmatched (each direction) | 0 / 0 |

**Verdict:** The delta between the two builds of the Dependent File System minifilter (`fsdepends.sys`) is a recompilation. The changed functions differ only by register allocation, instruction scheduling, short-vs-near branch encoding, WPP/ETW trace-block placement, and a couple of equivalent idiom swaps (`cmovb`→conditional branch, `test`-with-mask→`bt`). The one intentional behavioral change is a filter-registration flag: `DepFSRegisterFilters` sets `FLT_REGISTRATION.Flags` from `0` to `8` (`FLTFL_REGISTRATION_SUPPORT_WCOS`). No pointer-validation, null-guard, bounds-check, or reference-counting logic is added or removed. There is no security-relevant fix in this patch.

---

## 2. Function-Level Findings

### Finding A — `DependentFSCheckFileHandle` (VA `0x1C0008070`, both builds)

**No security-relevant change.** This routine enumerates a pool-allocated dependency array produced by `DepFSGenerateDependencyList (sub_1C000DDD0)` and, for each entry, reads the per-entry flags at `*(P + idx*0x10 + 8)` and processes the pointer at `+0x10`. The dependency-processing loop is byte-for-byte identical in both builds:

- The first branch (`test r15b, dl`) loads `*(P + idx*0x10 + 0x10)`, compares it against the saved `Context` at `[rsp+130h+Context]`, and only on a match falls through to `DereferenceVolumeContext (sub_1C000DB9C)`.
- The second branch (`test dl, 2`) loads `*(P + idx*0x10 + 0x10)` and calls `DereferenceDependencyContext (sub_1C000DBF0)` with it.

Both branches, including the `cmp rdx, [rsp+130h+Context]` context comparison in the first branch, are present and unchanged in **both** the unpatched and patched binaries. No comparison, status assignment, or bail-out is added to the second branch by the patch.

The only differences in this function are compiler codegen:
- An earlier buffer-size status assignment is emitted as `cmp ... ; mov eax, 0xC00000C3 ; cmovb ebx, eax` in one build and as `jnb ... ; mov ebx, 0xC00000C3` (a conditional branch) in the other. Same value (`STATUS_FILE_SYSTEM_LIMITATION`), same condition.
- A flag test emitted as `mov edx, 0x800 ; test edx, r12d ; test edx, eax` in one build and as `bt r12d, 0Bh ; bt eax, 0Bh` in the other. Bit 11 (`0x800`), same test.
- Reordering of `mov edx, 0x15/0x16`, `mov r9d, ebx`, the `FsInformation & 0x10000000` test, and relocation of a WPP trace block.

These are semantically equivalent, which is consistent with the 0.9844 similarity.

### Finding B — `DepFSHandleQueryDependentVolume (sub_1C000BA18)` (unpatched VA `0x1C000BA18`, patched VA `0x1C000B9F8`)

**No security-relevant change.** This function builds a dependent-volume name string and compares it against context state. The two builds contain the identical set of `test`/`cmp`/`jz` guards (31 `test` instructions in each, an identical sorted set). No null-pointer guard, no `test reg,reg / je` pair, and no dereference is added or removed. Every difference is register reallocation (`r8`↔`rdx`, `edx`↔`ecx`, `r11`↔`r8`) and instruction reordering around the two `RtlInitUnicodeString`-style string setups. This matches the 0.9834 similarity.

---

## 3. Actual Code Behavior (Diff Detail)

### `DependentFSCheckFileHandle` — dependency loop (identical in both builds)

```asm
; ----- first branch: validated release via DereferenceVolumeContext -----
        test    r15b, dl
        jz      .second_branch
        mov     rdx, [rcx+rax*8+0x10]
        cmp     rdx, [rsp+0x130+Context]     ; present in BOTH builds
        jnz     .skip_release
        movzx   esi, word ptr [rcx+rax*8+0xa]
        mov     rcx, rdx
        call    DereferenceVolumeContext     ; sub_1C000DB9C

; ----- second branch: DereferenceDependencyContext -----
.second_branch:
        test    dl, 2
        jz      .next
        mov     rcx, [rcx+rax*8+0x10]
        xor     r8d, r8d
        mov     dl, r15b
        call    DereferenceDependencyContext ; sub_1C000DBF0
```

The unpatched loop occupies `0x1C0008803`–`0x1C0008838`; the patched loop occupies `0x1C0008822`–`0x1C0008857` (relocated ~0x1F later by upstream codegen changes). Opcode-for-opcode the loop bodies match.

### `DependentFSCheckFileHandle` — codegen-only deltas

```asm
; unpatched                          ; patched
mov  eax, 0C00000C3h                 jnb  short <skip>
cmovb ebx, eax                       mov  ebx, 0C00000C3h
...                                  ...
mov  edx, 800h                       bt   r12d, 0Bh
test edx, r12d                       jb   <t>
test edx, eax                        bt   eax, 0Bh
```

### `DepFSHandleQueryDependentVolume` — register-only deltas

```asm
; unpatched            ; patched
mov  edx, 20h          mov  ecx, 20h
mov  ecx, r15d         mov  r8d, r15d
mov  r8,  [rax]        mov  rdx, [rax]
cmp  r8,  rax          cmp  rdx, rax
imul rcx, rdx          imul rcx, r8
```

No control-flow or guard instruction is added on either side.

---

## 4. Changed Functions — Full Triage

### Behavioral (non-security)

| Function | Similarity | Note |
|---|---|---|
| `DepFSRegisterFilters (sub_1C000D1A8)` | 0.9911 | `FLT_REGISTRATION.Flags` set from `0` to `8` (`FLTFL_REGISTRATION_SUPPORT_WCOS`). The struct header write splits from one 8-byte store (`mov qword [Registration], 0x2030070`, Flags=0) into a 4-byte store plus `mov dword [Registration+4], 8`. Feature-enablement flag, not a security fix. |
| `DepFSForEachDependency (sub_1C000B7D0)` | 0.8744 | Retry/enumeration loop recompiled: register renames, relocation of the WPP trace-enabled check (`test al,1 ; cmp byte [rcx+29h],2 ; call WPP_SF_D`) and the `DepFSSendIoctl` call target address (`sub_1C000E9F4`→`sub_1C000E918`, same routine relocated). Logic preserved. |

### Cosmetic / register-allocation / codegen only

| Function | Similarity | Note |
|---|---|---|
| `DependentFSCheckFileHandle` (VA 0x1C0008070) | 0.9844 | `cmovb`→branch and `test`-mask→`bt` idiom swaps, instruction reordering, WPP block relocation. Dependency loop identical. |
| `DepFSHandleQueryDependentVolume (sub_1C000BA18)` | 0.9834 | Register reallocation and instruction reordering only. Guard set identical. |
| `DepFSGenerateDependencyList (sub_1C000DDD0)` | 0.8897 | Register renames and WPP/`DereferenceVolumeContext` block reordering; `arg_28 & 0x8000` test present in both. |
| `DepFSCheckDependencies (sub_1C000E7C8)` | 0.9339 | Register renames, WPP trace-check relocation; the `cmp [rbx], magic` / `cmp dword [rbx+60h], 0` checks present in both. |
| `DependentFSRegister (sub_1C000C510)` | 0.8998 | Frame base `rsp`→`rbp` relocation, register renames; `ZwQueryInformationFile`/`ObQueryNameString` and the 0x10000 pool cap preserved. |
| `memset (sub_1C0002180)` | 0.599 | Reoptimized SSE2/AVX memset. |
| `WPP_SF_qddZ (sub_1C00015CC)` | 0.807 | ETW/WPP message helper; register reassignment for the null-string path. |
| `DepFSInstanceSetup (sub_1C000ED80)` | 0.9485 | Compiler restructuring. |
| `DepFSInstanceQueryTeardown (sub_1C000FE20)` | 0.9493 | Compiler restructuring of lock/teardown. |
| `DepFSPreVolumeMount (sub_1C000B330)` | 0.9514 | Error-path restructuring. |
| `DriverEntry (sub_1C0012008)` | 0.968 | Compiler restructuring. |
| `DepFSBugCheckNotEnoughSpace (sub_1C0001188)` | 0.9864 | `OBJECT_ATTRIBUTES` field-ordering. |
| `DepFSPreCreate (sub_1C0007010)` | 0.9885 | Register rename, `KeGetCurrentIrql()` replaces direct `CR8` read; `SeAccessCheck` logic preserved. |
| `DepFSCheckSmbLoopback (sub_1C0008E18)` | 0.9917 | Volume-query restructuring. |
| `DepFSDismountDependencyList (sub_1C000A5B0)` | 0.9917 | Register renames, lock address shifts. |
| `DepFSPreShutdown (sub_1C000AC10)` | 0.9919 | Register renames, lock address shifts. |
| `DepFSPostVolumeMount (sub_1C0001810)` | 0.9921 | `KeGetCurrentIrql()` replaces direct control-register read, register renames. |

None of these introduce or remove a security-relevant check.

---

## 5. Unmatched Functions

No functions were added or removed (`unmatched_unpatched: 0`, `unmatched_patched: 0`). Every change is an in-place edit to an existing routine, and every edit is compiler codegen or the single `DepFSRegisterFilters` flag change.

---

## 6. Confidence & Caveats

**Confidence: High that this patch carries no security-relevant code change.**

- The `DependentFSCheckFileHandle` dependency loop, including its context comparison, is opcode-identical between the two builds; the function's 0.9844 similarity is fully accounted for by `cmovb`↔branch and `test`↔`bt` idiom swaps plus reordering.
- `DepFSHandleQueryDependentVolume` has an identical set of guard instructions in both builds (comparing the full sorted `test`/`cmp`/`jz` sets); its differences are register allocation.
- The lower-similarity enumeration routines (`DepFSForEachDependency`, `DepFSGenerateDependencyList`, `DepFSCheckDependencies`, `DependentFSRegister`) were diffed at the control-flow level; each retains its complete set of comparisons and calls, differing only by register names and WPP-block placement.
- The one deliberate behavioral change, `FLT_REGISTRATION.Flags 0 → 8`, enables Windows Container OS (`WCOS`) volume support for the filter and has no bearing on memory safety.
- All VA references assume each binary is loaded at its preferred base.
