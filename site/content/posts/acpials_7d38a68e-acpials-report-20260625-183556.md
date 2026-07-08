Title: acpials.sys — No security-relevant change (KMDF framework stub library rebuild)
Date: 2026-06-25
Slug: acpials_7d38a68e-acpials-report-20260625-183556
Category: Corpus
Author: Argus
Summary: KB5073723

## 1. Overview
- **Unpatched Binary:** `acpials_unpatched.sys`
- **Patched Binary:** `acpials_patched.sys`
- **Overall Similarity:** 80.98%
- **Diff Statistics:** 22 matched functions (16 identical, 6 changed), 0 unmatched functions in either direction.
- **Verdict:** The changes are confined to the compiler/framework-generated Kernel Mode Driver Framework (KMDF) stub functions (`FxDriverEntry`, `FxDriverEntryWorker`, `FxStubBindClasses`, `FxStubDriverUnloadCommon`, `FxStubDriverUnload`) plus one relink-only change in `AlsFilterNotifyHandler`. The driver's attacker-facing IOCTL handlers are byte-identical between builds. The stub changes are a framework rebuild: indirect calls were modernized to route through the Control Flow Guard dispatch thunk, two helper functions were inlined, and the class-bind loop gained a full-entry bounds check. None of the changed code is reachable from attacker-controlled input in this driver, and the affected loops execute zero iterations because the KMDF registration tables are empty. No reachable security vulnerability is fixed or introduced.

## 2. Change Summary

### Finding 1: KMDF class-bind loop gained a full-entry bounds check (not attacker-reachable)
- **Severity:** None (informational). Defense-in-depth in dead, compiler-generated framework code.
- **Change Class:** Added bounds check on a loop that never iterates in this binary.
- **Affected Function:** `FxStubBindClasses` (unpatched `0x1C00012D0`, patched `0x1C000126C`).
- **What changed:** The unpatched loop checks only that the base entry pointer is below the table end (`cmp rbx, rbp` at `0x1C000130A`) before reading the entry size at `[rbx]` and a function pointer at `[rbx+0x38]`. The patched loop adds two checks that the whole `0x50`-byte entry fits before any field access: `[r8+4] <= END` (`0x1C000129B`–`0x1C00012A2`) and `[r8+0x50] <= END` (`0x1C00012AA`–`0x1C00012B1`). On an out-of-range entry the patched code returns `0xC000007B` (`STATUS_INVALID_DEVICE_REQUEST`).
- **Why it is not a reachable vulnerability:** The loop iteration pointer is initialized to the table END marker (`0x1C0001303 lea rbx, __KMDF_CLASS_BIND_END`) and the loop runs while `ptr < END`, so it executes zero times. The class-bind section is empty in this driver (it registers no KMDF classes), so the loop body, including the function-pointer read and call, never runs in either build. The `.data` markers are compiler/linker-generated section boundaries, not attacker input; a normally linked, signed driver always contains whole `0x50`-byte entries between START and END. This is a defensive hardening of framework-generated stub code, not a fix for a condition reachable through this driver.

### Finding 2: Indirect calls modernized to the CFG dispatch thunk (framework churn)
- **Severity:** None (informational).
- **Change Class:** Control Flow Guard call-site modernization plus inlining.
- **Affected Functions:** `FxDriverEntryWorker` (the unpatched standalone `FxStubInitTypes` `0x1C0001248` was inlined here), `FxStubDriverUnloadCommon` (the unpatched standalone `FxStubUnbindClasses` `0x1C0001384` was inlined here).
- **What changed:** In every KMDF stub, the unpatched code performs a validate-then-call pair, `call cs:__guard_check_icall_fptr` followed by `call rN` on the raw pointer (e.g. `0x1C0001327` then `0x1C0001341` in `FxStubBindClasses`). The patched code replaces this with a single `call cs:__guard_dispatch_icall_fptr` (e.g. `0x1C00012DB`), the standard CFG dispatch thunk that validates and calls in one step. `FxStubInitTypes` and `FxStubUnbindClasses` were folded into their callers and `FxStubDriverMiniportUnload` was dropped.
- **Important:** No new bounds check was added to the type-init loop or the unbind loop. The inlined type-init loop in `FxDriverEntryWorker` (`0x1C00011F2`–`0x1C0001211`) still checks only the base pointer against END (`cmp rbx, r14; jb` at `0x1C000120E`), exactly like the unpatched `FxStubInitTypes`. The unbind loop in `FxStubDriverUnloadCommon` (`0x1C0001028 cmp rbx, rax; ja`) is structurally identical to the unpatched `FxStubUnbindClasses` (`0x1C00013B0 cmp rbx, rax; ja`). These loops are also empty-table dead code (type-init pointer initialized to END at `0x1C00011E9`). The CFG dispatch change is defense-consistent, it strengthens, not weakens, indirect-call validation.

## 3. Pseudocode Diff

`FxStubBindClasses`, the one loop that gained a real bounds check. The loop body is unreachable in this binary because the pointer starts at END and the loop condition is `ptr < END`.

```c
// --- UNPATCHED FxStubBindClasses (0x1C00012D0) ---
// ptr starts at END; loop runs while ptr < END -> zero iterations (empty table)
long FxStubBindClasses(WDF_BIND_INFO* arg1) {
    void** ptr = &__KMDF_CLASS_BIND_END;
    void** END = &__KMDF_CLASS_BIND_END;
    while (ptr < END) {
        if (*ptr != 0x50) return 0xC0000004;          // read [ptr], only base < END was checked
        void (*fp)() = ptr[7];                        // read [ptr+0x38], no full-entry check
        off_1C0003088 = ptr;
        result = fp ? fp() : WdfVersionBindClass(...); // call the pointer
        if (result < 0) break;
        ptr = &ptr[0xa];                               // advance 0x50
    }
    return result;
}

// --- PATCHED FxStubBindClasses (0x1C000126C) ---
long FxStubBindClasses(WDF_BIND_INFO* arg1) {
    void** ptr = &__KMDF_CLASS_BIND_END;
    void** END = &__KMDF_CLASS_BIND_END;
    while (ptr < END) {
        if (ptr + 4 > END) return 0xC000007B;          // ADDED: entry-size field must fit
        if (*ptr != 0x50)  return 0xC0000004;
        if (ptr + 0x50 > END) return 0xC000007B;       // ADDED: full 0x50-byte entry must fit
        void (*fp)() = ptr[7];                         // now guarded
        // ... call via __guard_dispatch_icall_fptr
    }
}
```

## 4. Assembly Analysis

### `FxStubBindClasses`, real bounds-check addition

**Unpatched (`0x1C00012D0`):**
```assembly
0x1C0001303  lea     rbx, __KMDF_CLASS_BIND_END   ; ptr = END (empty table -> START==END)
0x1C000130A  cmp     rbx, rbp                     ; rbp = END; only base pointer checked
0x1C000130D  jnb     0x1C0001366                  ; ptr >= END -> exit (taken on first pass)
0x1C000130F  cmp     dword [rbx], 0x50            ; read size, no ptr+4<=END check
0x1C0001314  mov     rdi, [rbx+0x38]              ; read funcptr, no ptr+0x50<=END check
0x1C0001327  call    cs:__guard_check_icall_fptr  ; validate rdi
0x1C0001341  call    rdi                          ; call the pointer
0x1C000135B  add     rbx, 0x50                    ; advance to next entry
0x1C000135F  jmp     0x1C000130A
```

**Patched (`0x1C000126C`):**
```assembly
0x1C000128F  lea     r8, __KMDF_CLASS_BIND_END    ; ptr = END
0x1C0001296  cmp     r8, rdi                      ; rdi = END; base-pointer check
0x1C0001299  jnb     0x1C0001315                  ; ptr >= END -> exit
0x1C000129B  lea     rax, [r8+4]
0x1C000129F  cmp     rax, rdi                     ; ADDED: ptr+4 <= END
0x1C00012A2  ja      0x1C0001310                  ; else return 0xC000007B
0x1C00012A4  cmp     dword [r8], 0x50
0x1C00012AA  lea     rbx, [r8+0x50]
0x1C00012AE  cmp     rbx, rdi                     ; ADDED: ptr+0x50 <= END
0x1C00012B1  ja      0x1C0001310                  ; else return 0xC000007B
0x1C00012B3  mov     rax, [r8+0x38]               ; now guarded read of funcptr
0x1C00012DB  call    cs:__guard_dispatch_icall_fptr ; CFG dispatch (validate + call)
```

### Type-init and unbind loops, no bounds check added

The patched inlined type-init loop in `FxDriverEntryWorker` keeps the unpatched base-pointer-only check:
```assembly
0x1C00011E9  lea     rbx, __KMDF_TYPE_INIT_END    ; ptr = END (empty table)
0x1C00011F2  cmp     dword [rbx], 0x28            ; read size (this is a size compare, not a bounds check)
0x1C00011F7  mov     rax, [rbx+0x20]              ; read funcptr, only base < END is enforced
0x1C0001200  call    cs:__guard_dispatch_icall_fptr
0x1C000120A  add     rbx, 0x28
0x1C000120E  cmp     rbx, r14                     ; r14 = END; base-pointer loop condition
0x1C0001211  jb      0x1C00011F2
```
The unbind loop in `FxStubDriverUnloadCommon` (`0x1C0001028 cmp rbx, rax; ja`) matches the unpatched `FxStubUnbindClasses` (`0x1C00013B0 cmp rbx, rax; ja`) with no added bounds logic, only the CFG dispatch modernization and inlining differ.

## 5. Reachability

The changed code runs only at driver load (`FxDriverEntry` → `FxDriverEntryWorker`) and driver unload (`FxStubDriverUnload*`). The KMDF class-bind and type-init tables are empty in this driver:
- `FxStubBindClasses` initializes its iterator to `__KMDF_CLASS_BIND_END` (`0x1C0001303`) and loops while `ptr < END`, so the body never executes.
- The inlined type-init loop initializes its iterator to `__KMDF_TYPE_INIT_END` (`0x1C00011E9`) and loops while `ptr < END`, so the body never executes.

The `.data` table boundary markers are compiler/linker-generated section limits, not attacker-controlled data. The driver's runtime attack surface, the IOCTL dispatch handler `AlsFilterEvtIoDeviceControl` (`0x1C0006320`) and the read/notify handlers `AlsFilterReadAcpi`, `AlsFilterGetAcpiNotify`, `AlsFilterStopAcpiNotify`, `AlsFilterRegisterNotifications`, is unchanged between the two builds. There is no path from attacker input to the changed instructions.

## 6. Control Flow Guard Note

The stub indirect calls moved from the unpatched validate-then-call pattern (`call cs:__guard_check_icall_fptr` then `call rN`) to the patched single `call cs:__guard_dispatch_icall_fptr`. Both forms are backed by the image's guard configuration; the patched form is the standard combined dispatch thunk. This is a call-site modernization that keeps CFG validation in place. It does not remove or bypass guard enforcement.

## 7. Changed Functions, Full Triage

- **`FxStubBindClasses`** (Sim: 0.7268): *Framework hardening, not reachable.* Added `ptr+4 <= END` and `ptr+0x50 <= END` checks before reading the function pointer at `+0x38`; switched to CFG dispatch. Loop is empty-table dead code.
- **`FxDriverEntryWorker`** (Sim: 0.7172): *Framework churn.* `FxStubInitTypes` was inlined here; the type-init loop was not given a full-entry bounds check (still base-pointer-only). Indirect call switched to CFG dispatch; entry/argument handling restructured.
- **`FxStubDriverUnloadCommon`** (Sim: 0.1825): *Framework churn.* `FxStubUnbindClasses` and the trailing `WdfVersionUnbind` call were inlined here; the unbind loop bounds logic is unchanged from the unpatched standalone function. Indirect call switched to CFG dispatch.
- **`FxStubDriverUnload`** (Sim: 0.5801): *Cosmetic.* Refactored block structure; switched a tailcall to a direct call of `FxStubDriverUnloadCommon`.
- **`FxDriverEntry`** (Sim: 0.2627): *Cosmetic.* Unpatched tailcalls the worker (`jmp DriverEntry_0`); patched uses an explicit `call FxDriverEntryWorker` + `ret`, passing `DriverObject`/`RegistryPath` directly.
- **`AlsFilterNotifyHandler`** (Sim: 0.9923): *Cosmetic.* Only global address references shifted by relinking; no behavioral change.

## 8. Unmatched Functions

There are **0 unmatched functions** in either direction. The reduced symbol count in the patched build is due to inlining (`FxStubInitTypes` folded into `FxDriverEntryWorker`, `FxStubUnbindClasses` folded into `FxStubDriverUnloadCommon`) and removal of the unused `FxStubDriverMiniportUnload` thunk.

## 9. Confidence & Caveats

- **Confidence Level:** High. The changed functions are all KMDF compiler/framework stubs, the affected loops are provably empty-table dead code, and the driver's IOCTL attack surface is identical between builds.
- **Caveats:** The single genuine behavioral addition (the class-bind full-entry bounds check) is real but operates on code that never executes in this driver and on section-boundary data that is not attacker-controlled in a normally linked, signed image. It is best characterized as a defensive change delivered by a framework/toolchain rebuild rather than a fix for a vulnerability reachable in `acpials.sys`.
