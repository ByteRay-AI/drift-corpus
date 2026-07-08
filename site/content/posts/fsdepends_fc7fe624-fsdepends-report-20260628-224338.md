Title: fsdepends.sys — No security-relevant change (cross-branch recompilation)
Date: 2026-06-28
Slug: fsdepends_fc7fe624-fsdepends-report-20260628-224338
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Informational

## 1. Overview

- **Binary IDs:** `fsdepends_unpatched.sys` (10.0.19041.7417) vs `fsdepends_patched.sys` (10.0.20348.5256)
- **Overall Similarity:** 0.9577
- **Diff Statistics:**
  - Matched Functions: 87
  - Changed Functions: 19
  - Identical Functions: 68
  - Unmatched Functions (Unpatched/Patched): 0 / 0
- **Verdict:** No security-relevant behavioral change is present in this diff. The two binaries belong to two different Windows servicing branches (client 19041 vs server 20348) and the differences across the changed functions are recompilation and code-generation artifacts (instruction selection, register allocation, data-address relocation, and one IRQL-read helper change). In particular, `DependentFSCheckFileHandle` performs the same dependency-pointer validation and the same output-buffer-size checks in both builds.

## 2. Function-Level Summary

- **Severity:** Informational (no fix identified)
- **Primary Function Examined:** `DependentFSCheckFileHandle` (exported kernel API) at `0x1C0008070`

**What the function does (both builds):**
`fsdepends.sys` is the File System Dependency Manager minifilter. `DependentFSCheckFileHandle` takes a file handle (`rcx`) and a `FILE_OBJECT*` (`rdx`) and determines whether the underlying file/volume has file-system dependencies (for example cloud-file placeholders on virtual storage volumes). It queries the object name (`ObQueryNameString`), file information (`ZwQueryInformationFile`), the volume-name attribute, and `RtlIsCloudFilesPlaceholder`, then acquires the driver's dependency table under an `ERESOURCE`, obtains the filter instance context via `FltGetVolumeFromFileObject` / `FltGetVolumeInstanceFromName` / `FltGetInstanceContext`, and builds a dependency list through `DepFSGenerateDependencyList`. It finishes by walking that list and releasing references (`DereferenceVolumeContext` / `DereferenceDependencyContext`).

**Pointer validation is present in both builds:**
Inside the final dependency-list walk, each entry's stored context pointer is compared against the acquired instance context before the match counter is updated:

```
mov     rdx, [rcx+rax*8+10h]      ; load entry context pointer
cmp     rdx, [rsp+130h+Context]   ; compare against acquired instance Context
jnz     <skip count update>       ; only matching entries update the match count
```

This `mov`/`cmp`/`jnz` sequence is byte-for-byte equivalent in the unpatched build (at `0x1C0008808`–`0x1C0008812`) and the patched build (at `0x1C0008827`–`0x1C0008831`). There is no missing-validation gap between the two binaries.

**Buffer-size checks are equivalent in both builds:**
The two size checks against `0x28` (40 bytes) and `0x10` (16 bytes) on `IoStatusBlock.Information` bail out to the error/trace return path when the returned size is too small, in both builds. The only difference is code-generation: the client-branch build uses `cmovb ebx, eax; test ebx, ebx; js <error>`, and the server-branch build uses `jnb <continue>; mov ebx, 0C00000C3h` falling into the same error/trace path. Both set `STATUS_BUFFER_TOO_SMALL` (`0xC00000C3`) and both stop processing when the size is below the threshold; neither continues into dependency processing with an undersized buffer.

## 3. Pseudocode of the Dependency Walk (both builds)

```c
// Present identically in unpatched and patched builds.
for (i = 0; i < list->count; i++) {
    entry_flags = list->entries[i].flags;      // word at [base + i*0x10 + 0x08]
    if (want_flag & entry_flags) {
        void *ctx = list->entries[i].context;  // qword at [base + i*0x10 + 0x10]
        if (ctx == acquired_instance_context) { // cmp rdx, [Context]; jnz skip
            matched = list->entries[i].match;    // update match count only on equality
        }
        DereferenceVolumeContext(ctx);
    } else if (entry_flags & 0x2) {
        DereferenceDependencyContext(list->entries[i].context, want_flag);
    }
}
ExFreePoolWithTag(list, 'DpDl');
```

## 4. Assembly Comparison

### Dependency walk — unpatched (`0x1C00087F4`)
```assembly
cmp     [rcx+4], esi
jbe     loc_1C0008845
mov     eax, ebx
add     rax, rax
movzx   edx, word ptr [rcx+rax*8+8]
test    r15b, dl
jz      short loc_1C0008823
mov     rdx, [rcx+rax*8+10h]          ; load entry context pointer
cmp     rdx, [rsp+130h+Context]       ; validate against acquired instance context
jnz     short loc_1C0008819           ; skip count update if not the matching entry
movzx   esi, word ptr [rcx+rax*8+0Ah]
loc_1C0008819:
mov     rcx, rdx
call    DereferenceVolumeContext
```

### Dependency walk — patched (`0x1C0008813`)
```assembly
cmp     [rcx+4], esi
jbe     loc_1C0008864
mov     eax, ebx
add     rax, rax
movzx   edx, word ptr [rcx+rax*8+8]
test    r15b, dl
jz      short loc_1C0008842
mov     rdx, [rcx+rax*8+10h]          ; load entry context pointer
cmp     rdx, [rsp+130h+Context]       ; validate against acquired instance context
jnz     short loc_1C0008838           ; skip count update if not the matching entry
movzx   esi, word ptr [rcx+rax*8+0Ah]
loc_1C0008838:
mov     rcx, rdx
call    DereferenceVolumeContext
```

The two sequences are logically identical; only the relative jump targets differ because of address relocation between the two branch builds.

### Buffer-size check
```assembly
; unpatched (0x1C000838C)
cmp     [rsp+130h+IoStatusBlock.Information], 0x28
mov     eax, 0xC00000C3
cmovb   ebx, eax
test    ebx, ebx
js      loc_1C000892F                 ; -> WPP trace + STATUS_BUFFER_TOO_SMALL return

; patched (0x1C0008384)
cmp     [rsp+130h+IoStatusBlock.Information], 0x28
jnb     loc_1C00083C7                 ; continue only when size >= 0x28
mov     ebx, 0xC00000C3               ; else STATUS_BUFFER_TOO_SMALL, fall into trace/return
```

## 5. IRQL Read Helper Change (`DepFSPostVolumeMount`, `0x1C0001810`)

The one substantive instruction-level change in the diff is in `DepFSPostVolumeMount (sub_1C0001810)`. At `0x1C0001A0E` the client-branch build reads the current IRQL directly from the control register (`mov rax, cr8`), while the server-branch build calls the exported helper (`call KeGetCurrentIrql`). Both obtain the current IRQL to decide whether to run the dependency-enumeration work synchronously or queue it as a work item. This is a correctness/portability code-generation difference, not a security fix; there is no change in the validation performed or the trust boundary crossed.

## 6. Trigger Conditions

No reachable vulnerability is introduced or removed by this diff, so there is no exploitation trigger. `DependentFSCheckFileHandle` is reachable through file open/create operations on virtual storage volumes (VHD, cloud-file placeholders) that route through the filter stack, but in both builds the dependency-list walk validates each entry's context pointer against the acquired instance context and both builds enforce the output-buffer-size checks.

## 7. Exploit Primitive

None. There is no missing check, no lifetime/use-after-free regression, and no authorization-context confusion between the two builds in the examined path.

## 8. Debugger Notes

For anyone tracing the dependency-check path in either build:

- `bp fsdepends!DependentFSCheckFileHandle` (`0x1C0008070`) — entry. Arguments: `rcx` = file handle, `rdx` = `FILE_OBJECT*`, `r8d` = flags, `r9` = pointer to a mode word, `[rsp+0x28]` = optional out `int*`.
- In the dependency walk, `[rsp+130h+Context]` holds the instance context acquired via `FltGetInstanceContext`; each entry's pointer at `[rcx+rax*8+0x10]` is compared to it before the match counter (`esi`) is updated. Entry stride is `0x10` bytes; flags word at offset `+0x08`, context pointer at offset `+0x10`.
- `[rsp+130h+IoStatusBlock.Information]` holds the queried size compared against `0x28` and `0x10`.
- `0x1C0001A0E` in `DepFSPostVolumeMount (sub_1C0001810)`: `mov rax, cr8` (client branch) vs `call KeGetCurrentIrql` (server branch).

## 9. Changed Functions — Full Triage

- **`DependentFSCheckFileHandle`** (Sim: 0.9844): **[No security change]** The dependency-pointer validation (`cmp rdx, [Context]; jnz`) and the `0x28`/`0x10` output-buffer-size checks are present and equivalent in both builds. Differences are instruction selection (`cmovb`+`js` vs `jnb`+fall-through), register allocation, and relocated jump/data targets.
- **`DepFSPostVolumeMount (sub_1C0001810)`** (Sim: 0.9921): **[Behavioral]** IRQL read changed from `mov rax, cr8` to `call KeGetCurrentIrql`; lock/event data addresses relocated. Correctness/portability, not security.
- **`DepFSRegisterFilters (sub_1C000D1A8)`** (Sim: 0.9911): **[Behavioral]** `FLT_REGISTRATION.Flags` value differs; callback pointers and telemetry data addresses relocated. Feature/compat, not security.
- **`DepFSGenerateDependencyList (sub_1C000DDD0)`** (Sim: 0.8897): **[Behavioral]** Control-flow layout of the dependency-enumeration loop and error propagation differ; the underlying allocation, `FltGet*`, and refcount operations are the same. Recompilation restructuring.
- **`memset (sub_1C0002180)`** (Sim: 0.599): **[Cosmetic]** Library memset re-vectorized with a different SIMD block strategy.
- **`WPP_SF_qddZ (sub_1C00015CC)`** (Sim: 0.807): **[Cosmetic]** WPP software-trace helper; argument-marshalling order differs.
- **`DepFSForEachDependency (sub_1C000B7D0)`** (Sim: 0.8744): **[Behavioral]** Allocation-failure error path reorganized; call targets relocated.
- **`DepFSCheckDependencies`** (unpatched `0x1C000E7C8`, patched `0x1C000E6E4`) (Sim: 0.9339): **[Behavioral, cross-branch divergence]** The two builds have different implementations. The client-branch (unpatched) function is a thin `ExAllocatePoolWithTag`/`DepFSSendIoctl` retry wrapper that returns the IOCTL status. The server-branch (patched) function takes additional arguments and, after the query IOCTL succeeds and reports at least `0x38` bytes (`if ( v18 >= 0x38 )`), iterates the returned dependency entries: for each non-NULL entry whose signature word equals `0x3030` (`if ( v11 != 0 && *(_WORD *)v11 == 12336 )`) it calls `DepFSIncrementActiveMountCount`, checks the entry's in-use fields, then in a second pass calls `DepFSDecrementActiveMountCount` (only on failure) and `DependentFSDereferenceDependency` under the same NULL guard. This is active-mount-count bookkeeping present only in the server branch, not a delivered security fix: no shared code path gains or loses a validation check, and every per-entry pointer dereferenced in the loop is NULL-checked in the build that contains it.
- **`DepFSInstanceSetup (sub_1C000ED80)`** (Sim: 0.9485): **[Cosmetic]** Minor restructuring and data-address relocation.
- **`DepFSInstanceQueryTeardown (sub_1C000FE20)`** (Sim: 0.9493): **[Behavioral]** Error path reorganized; lock resource address relocated.
- **`DepFSPreVolumeMount (sub_1C000B330)`** (Sim: 0.9514): **[Behavioral]** `FltAllocateGenericWorkItem` hoisted earlier; error path reorganized.
- **`DepFSBugCheckNotEnoughSpace (sub_1C0001188)`** (Sim: 0.9864): **[Cosmetic]** Variable-initialization order and buffer handling reorganized.
- **`DepFSPreCreate (sub_1C0007010)`** (Sim: 0.9885): **[Cosmetic]** Register allocation (`r9`↔`r8`) and data/call-target relocation.
- **`DepFSCheckSmbLoopback (sub_1C0008E18)`** (Sim: 0.9917): **[Cosmetic]** Field-init order and data-address relocation.
- **`DepFSDismountDependencyList (sub_1C000A5B0)`** (Sim: 0.9917): **[Cosmetic]** Data-address and lock-variable relocation.
- **`DepFSPreShutdown (sub_1C000AC10)`** (Sim: 0.9919): **[Cosmetic]** Call-target relocation.
- **`DepFSHandleQueryDependentVolume (sub_1C000BA18)`** (Sim: 0.9834): **[Cosmetic]** Data-address relocation.

*(Note: some functions appear more than once in the raw diff metadata because they were matched across multiple compilation-unit boundaries; entries are consolidated above.)*

## 10. Unmatched Functions

No functions were added or removed between the two builds.

## 11. Confidence & Caveats

- **Confidence Level:** High that no security-relevant behavioral change exists in this diff. The dependency-pointer validation and the output-buffer-size checks in `DependentFSCheckFileHandle` are verified present in both builds, and the remaining changed functions differ only by recompilation artifacts across two Windows servicing branches.
- **Corpus note:** The unpatched sample is a client-branch build (10.0.19041.7417) and the patched sample is a server-branch build (10.0.20348.5256). Cross-branch recompilation accounts for the pervasive but non-semantic instruction, register, and address differences. `fsdepends.sys` has no CVE attribution in the associated update metadata.
