Title: fsdepends.sys — Missing authorization / access check (CWE-862) in DepFSPreCreate fixed
Date: 2026-06-25
Slug: fsdepends_308a0c48-fsdepends-report-20260625-233200
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Medium
KBDate: 2026-01-13

## 1. Overview

- **Unpatched Binary:** `fsdepends_unpatched.sys`
- **Patched Binary:** `fsdepends_patched.sys`
- **Overall Similarity Score:** 0.9817 (98.17%)
- **Diff Statistics:** 87 matched functions (84 identical, 3 changed), 0 unmatched in both directions.
- **Verdict:** The patch fixes a medium-severity missing authorization vulnerability (CWE-862) in the minifilter's pre-create callback. In the post-startup steady state the unpatched driver performs no access check of its own against the managed volume's security descriptor before letting create operations proceed; the patch adds that driver-level `SeAccessCheck` gate.

## 2. Vulnerability Summary

- **Severity:** Medium
- **Vulnerability Class:** Missing Authorization / Access Check (CWE-862)
- **Affected Function:** `DepFSPreCreate`

**Root Cause Analysis:**
The `FsDepends` minifilter driver intercepts `IRP_MJ_CREATE` (file open/create) operations on managed dependency volumes. The unpatched version only performs volume-context and autochk handling *before* system startup applications complete (`FsRtlAreVolumeStartupApplicationsComplete()` returns `FALSE`). Once startup completes (normal system steady-state), the unpatched driver falls straight through to an unconditional return of `FLT_PREOP_SUCCESS_WITH_CALLBACK` (value `1`). As a result, in steady-state operation the minifilter performs no authorization check of its own against the managed volume's security descriptor before letting the create proceed; the driver-level access gate that the patch adds is simply absent. (Note: the minifilter returning `FLT_PREOP_SUCCESS_WITH_CALLBACK` does not disable the underlying filesystem's own access check — it only means the minifilter does not impose its own additional restriction.)

The patch introduces an `else` branch for the post-startup state. It fetches the minifilter instance context, extracts the volume's security descriptor (stored at offset `0x78`), and calls `SeAccessCheck()` with `AccessMode = UserMode` (`1`). If access is denied, the driver updates the `IoStatus.Status` and returns `FLT_PREOP_COMPLETE` (`4`), successfully blocking the unauthorized access.

**Attacker-Reachable Entry Point & Data Flow:**
1. A low-privileged user initiates an `NtCreateFile` / `CreateFile` request targeting a file on a volume managed by the `FsDepends` minifilter (typically VHD or cloud files).
2. The Windows Filter Manager intercepts the IRP and dispatches it to the `DepFSPreCreate` callback.
3. `DepFSPreCreate` calls `FsRtlAreVolumeStartupApplicationsComplete()`, which returns `TRUE` in the normal steady-state.
4. The unpatched binary immediately returns `FLT_PREOP_SUCCESS_WITH_CALLBACK` (1), overriding any standard filesystem DACL denials and allowing the operation to proceed.

## 3. Pseudocode Diff

Below is a high-level comparison of the vulnerable logic path. The unpatched version completely lacks the `else` block that enforces authorization in the post-startup phase.

```c
// === UNPATCHED DepFSPreCreate ===
uint64_t DepFSPreCreate(void* arg1, void* arg2) {
    int32_t rbx = 1; // FLT_PREOP_SUCCESS_WITH_CALLBACK

    if (!FsRtlAreVolumeStartupApplicationsComplete()) {
        // Pre-startup logic: handles autochk/volume verification
        // (Not vulnerable)
    }
    
    // VULNERABILITY: No 'else' block. 
    // When FsRtlAreVolumeStartupApplicationsComplete() == TRUE, 
    // control falls straight through to the return without any access check.
    
    return rbx; // Always returns 1 (SUCCESS)
}

// === PATCHED DepFSPreCreate ===
uint64_t DepFSPreCreate(void* arg1, void* arg2) {
    int32_t rbx = 1; 

    if (!FsRtlAreVolumeStartupApplicationsComplete()) {
        // Pre-startup logic...
    } else {
        // FIX: Post-startup authorization check
        FltGetInstanceContext(..., &Context);
        if (Context && *(Context + 0x78)) { // Check if SD exists
            GENERIC_MAPPING* gm = IoGetFileObjectGenericMapping();
            BOOLEAN granted = SeAccessCheck(
                *(Context + 0x78),   // SecurityDescriptor
                ...,                  // SubjectSecurityContext
                ...,                  // DesiredAccess
                gm,                   // GenericMapping
                1,                    // AccessMode = UserMode
                &GrantedAccess,
                &AccessStatus
            );
            
            if (!granted) {
                // Access Denied
                *(arg1 + 0x18) = AccessStatus; // Set IoStatus.Status
                rbx = 4;                       // FLT_PREOP_COMPLETE (block)
            }
        }
    }
    return rbx;
}
```

## 4. Assembly Analysis

The vulnerability is a straight-line bypass. In the unpatched binary, the result of `FsRtlAreVolumeStartupApplicationsComplete()` dictates whether the function jumps straight to the return epilogue.

**Unpatched Assembly (`fsdepends_unpatched!DepFSPreCreate`)**:
```assembly
0x1c0007034: call    qword [rel 0x1c0006238]    ; FsRtlAreVolumeStartupApplicationsComplete()
0x1c000703b: nop     dword [rax+rax]
0x1c0007040: test    al, al
0x1c0007042: jne     0x1c0007185                ; if TRUE (Startup Complete), JUMP TO EPILOGUE
...
; === EPILOGUE (Reached when startup apps are complete) ===
0x1c0007185: mov     rbp, qword [rsp+0x38]
0x1c000718a: mov     eax, ebx                   ; eax = 1 (FLT_PREOP_SUCCESS_WITH_CALLBACK)
0x1c000718c: mov     rbx, qword [rsp+0x30]
0x1c0007191: mov     rsi, qword [rsp+0x40]
0x1c0007196: add     rsp, 0x20
0x1c000719a: pop     rdi
0x1c000719b: retn                               ; Returns SUCCESS unconditionally
```

**Patched Assembly Redirect:**
In the patched binary the same test is restructured: `test al, al` sits at `0x1c000704b` followed by `jz 0x1c00071c3` at `0x1c0007051`. When startup applications are complete (`al != 0`) control now falls through into the newly inserted `FltGetInstanceContext` (`0x1c000708b`) and `SeAccessCheck` (`0x1c0007111`) call sequence instead of returning immediately. The startup-not-complete autochk path is preserved unchanged at `0x1c00071c3`.

## 5. Trigger Conditions

To trigger the vulnerability, an attacker must:

1. Ensure the target Windows system has fully booted (such that `FsRtlAreVolumeStartupApplicationsComplete()` returns `TRUE`).
2. Identify a volume managed by the `FsDepends` minifilter (typically virtual disk/VHD-backed or Cloud Files placeholder volumes).
3. Identify a target file on such a managed volume whose access the volume's security descriptor would deny to the caller.
4. Execute a standard `CreateFile` or `NtCreateFile` call from an unprivileged user context against the target file.
5. **Observable Effect:** Against the unpatched binary the minifilter does not apply its own authorization gate — `DepFSPreCreate` returns `FLT_PREOP_SUCCESS_WITH_CALLBACK` and does not complete the create with `STATUS_ACCESS_DENIED`. Against the patched binary the same create is completed by the minifilter with the `SeAccessCheck` failure status (`FLT_PREOP_COMPLETE`).

## 6. Exploit Primitive & Development Notes

- **Primitive:** Missing driver-level authorization gate. In steady state the unpatched minifilter does not run its own `SeAccessCheck` against the managed volume's security descriptor before allowing a create on that volume to proceed.
- **Scope of demonstrable impact:** What is provable from the binaries is limited to the presence/absence of this minifilter-level check. The patched build can complete the create with an access-denied status (`FLT_PREOP_COMPLETE`) when the volume's security descriptor denies the caller; the unpatched build performs no such check. The broader real-world impact depends on what these managed dependency volumes contain and on how the volume's security descriptor differs from the file's own DACL — neither of which is determinable from the driver binaries alone. No memory-corruption, information-leak, or code-execution primitive is present.
- **Required Steps:** No heap spraying, race conditions, or memory manipulation are involved; this is a logical authorization-check difference.

## 7. Debugger PoC Playbook

For a researcher using WinDbg/KD on the unpatched binary to verify the flaw:

**Breakpoints:**
Set a breakpoint on the pre-create callback:
`bp fsdepends_unpatched!DepFSPreCreate`
Set a breakpoint specifically on the vulnerable conditional jump:
`bp fsdepends_unpatched!DepFSPreCreate+0x32`

**What to inspect at each breakpoint:**
- At `DepFSPreCreate` entry: `rcx` holds the `FLT_CALLBACK_DATA`. `rdx` holds `PFLT_RELATED_OBJECTS`.
- At `DepFSPreCreate+0x32` (`0x1c0007042`): Step over (`p`). The instruction is `jne 0x1c0007185`. Because startup is complete, `AL` will be `1` (ZF=0), and the jump will be taken. 
- Check the return value: The execution will land at `0x1c000718a: mov eax, ebx`. Inspect `ebx`; it will be `1` (`FLT_PREOP_SUCCESS_WITH_CALLBACK`).

**Trigger setup:**
1. Open an elevated command prompt and a normal user command prompt.
2. From the normal user prompt, attempt to read or write a restricted file located on a mounted VHD or Cloud Files volume managed by `FsDepends`.
3. Observe in the debugger that `DepFSPreCreate` intercepts the request, takes the jump at `0x1c0007042`, and returns `1` (`FLT_PREOP_SUCCESS_WITH_CALLBACK`) without calling `SeAccessCheck` (which the unpatched binary does not even import).
4. On the patched binary, observe the same create instead reach `SeAccessCheck` and, when the volume's security descriptor denies the caller, be completed with `FLT_PREOP_COMPLETE` (`ebx=4`) and an access-denied `IoStatus.Status`.

**Key Instructions / Offsets:**
- `0x1c0007034`: Call to `FsRtlAreVolumeStartupApplicationsComplete()`.
- `0x1c0007042`: The missing-check jump (`jne 0x1c0007185`).
- `0x1c0007185` to `0x1c000719b`: The vulnerable success epilogue.

## 8. Changed Functions — Full Triage

- **`DepFSPreCreate` (Similarity: 0.6365)**
  - **Change:** Security-relevant. Added the entire `SeAccessCheck` logic block for post-startup `IRP_MJ_CREATE` operations. Fixed the CWE-862 vulnerability.
- **`DepFSInstanceSetup` (Similarity: 0.9329)**
  - **Change:** Security-relevant. Added 16 bytes to the stack frame. Added calls to `FltQuerySecurityObject` and `ExAllocatePoolWithTag`. This queries the volume's security descriptor during instance setup and stores it at `Context+0x78` so `DepFSPreCreate` has the data it needs to enforce access control.
- **`DepFSCleanupVolumeContext` (Similarity: 0.9447)**
  - **Change:** Security-relevant (resource management). Added cleanup logic (`ExFreePoolWithTag` with tag `0x73447044` / `'DpDs'`, at `0x1c001042d`) to free the newly allocated security descriptor stored at `Context+0x78` when the context is destroyed, preventing a kernel memory leak.

## 9. Unmatched Functions

There are no added or removed functions between the unpatched and patched binaries. All modifications occurred within existing functions.

## 10. Confidence & Caveats

- **Confidence Level:** High. The logic gap is unambiguous in the assembly and pseudocode. The patched code introduces standard Windows Filter Manager `SeAccessCheck` semantics.
- **Assumptions:** It is assumed that the `FsDepends` driver attaches automatically to VHD-backed or Cloud Files volumes. A researcher developing a PoC should verify which specific mount operations trigger `DepFSInstanceSetup` to attach the minifilter to the target volume.
- **Verification needed:** A researcher should verify the exact flags required in the `CreateFile` call. While `GENERIC_READ`/`GENERIC_WRITE` should trigger the bypass easily, verifying the exact `DesiredAccess` masks mapped by `IoGetFileObjectGenericMapping` will help in building a clean, deterministic PoC.
