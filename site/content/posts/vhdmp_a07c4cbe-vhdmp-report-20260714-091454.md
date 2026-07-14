Title: vhdmp.sys — Kernel-pointer information disclosure in the storage-dependency query handler (sub_1C0082CCC)
Date: 2026-07-14
Slug: vhdmp_a07c4cbe-vhdmp-report-20260714-091454
Category: Corpus
Author: Argus
Summary: KB5094123
Severity: Medium
KBDate: 2026-06-09

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | vhdmp_unpatched.sys |
| Patched binary | vhdmp_patched.sys |
| Overall similarity | 0.9918 |
| Matched functions | 2312 |
| Changed functions | 1 |
| Identical functions | 2311 |
| Unmatched (unpatched / patched) | 0 / 0 |

**Verdict:** A single function — the storage-dependency query handler `sub_1C0082CCC` — was patched to stop copying raw kernel-mode object pointers into a user-visible output buffer. The pre-patch code discloses live kernel heap addresses to any caller, defeating KASLR and handing an attacker precise targets for a follow-on memory-corruption chain.

Of the one changed function, all of the meaningful diff is security-relevant and concentrated in `sub_1C0082CCC`. The remainder of the delta is telemetry/ETW event-code churn (event codes `0x1d` -> `0x1f`, new `0x1b`–`0x1e` emissions, and a changed event-data pointer from `&data_1c00544a0` to `&data_1c0052c78`) which is a side effect of the added logging around the sanitized path and is not itself the vulnerability. The fix is additive: it inserts a caller-trust gate (`sub_1c0010298`) at function entry and, combined with the request flag `*(arg2+0x40)`, NULs each disclosed pointer for untrusted callers.

---

## 2. Vulnerability Summary

### 2.1 MEDIUM — Kernel-mode pointer information disclosure (CWE-200 -> CWE-497)
- **Affected function:** `sub_1C0082CCC (sub_1c0082ccc)` (unpatched), `sub_1C0082CCC (sub_1c0082ccc)` (patched) — the IRP_MJ_DEVICE_CONTROL handler that answers storage-dependency queries (`GetStorageDependencyInformation`) by walking the VHD dependency chain and filling per-dependency `STORAGE_DEPENDENCY_INFO` records into a caller-supplied output buffer.
- **Root cause:** The handler writes raw kernel-mode object pointers directly into records that are copied back to user mode. Relevant object layout:
  - `i_5` — current dependent-chain object (a nonpaged-pool vhdmp object); its kernel address is written to `record+0x28` (and `record+0x20` in chained entries).
  - `i_5[0x428]` / `i_5[0x85]` — the dependency object hung off the chain object; its kernel address is written to `record+0x28`/`record+0x30`.
  - `i_5[0x92]` — the "next" chain link used to iterate the dependency chain.

The exact flawed store:

```asm
mov     qword [r14+0x28], r13     ; *(record+0x28) = i_5  (live kernel pointer -> user memory)
```

- **Why exploitable:** The output buffer at `*(arg2+0x18)` is attacker-supplied user memory. After a successful query, the caller reads back live kernel heap addresses (`0xFFFF...` range) that resolve via `!pool` to vhdmp-tagged nonpaged-pool objects. This directly defeats KASLR and reveals the exact base of internal vhdmp objects — precisely the targets needed for a subsequent write/UAF primitive.
- **What the patch does:** Adds `call 0x1c0010298` (a caller-trust / previous-mode gate) at entry, storing its int32 result at `[rsp+0xb0]`. Combined with the request flag `*(arg2+0x40)`, each pointer store is now preceded by a `cmovne rax, rdi` that substitutes NULL for untrusted callers before the pointer is written. No unchecked fallback path remains: every store site (`+0x20`, `+0x28`, `+0x30` in both the count==2 branch and the general loop) is gated identically.
- **Attacker-reachable entry point:** `DeviceIoControl` on a VHD-backed / dependent-volume handle, driven by `VirtDisk!GetStorageDependencyInformation` (the storage-dependency query IOCTL, e.g. `IOCTL_STORAGE_GET_DEPENDENT_DISKS` / the FSCTL used by `GetStorageDependencyInformation`).
- **Call chain:**
  1. user: `OpenVirtualDisk` / `CreateFile` on a VHD-backed or dependent-volume handle
  2. user: `GetStorageDependencyInformation()` -> `DeviceIoControl(storage-dependency query IOCTL)`
  3. `vhdmp!IRP_MJ_DEVICE_CONTROL` dispatch
  4. `vhdmp!sub_1C0082CCC (sub_1c0082ccc)` — pointer stores at `~0x1c0083127`, `~0x1c008314d`, `~0x1c008319b`, `~0x1c00831c1`

---

## 3. Pseudocode Diff

### 3.1 sub_1C0082CCC (sub_1c0082ccc)

```c
// UNPATCHED — sub_1C0082CCC (sub_1c0082ccc); pointer fields hold raw kernel addresses
// ... level validation: (level-1) > 2 => STATUS_INVALID_LEVEL ...
// ... size/count computation building rbp_3 (required size) ...
// ... if (buf_size < required) => STATUS_BUFFER_OVERFLOW ...

*(r14_1 + 0x28) = i_5;                 // <-- leaks dependent-chain object pointer
if (*(uint32_t*)r15 == 3) {
    rax_25 = i_5[0x85];                // dependency object (== *(int64_t*)(r13+0x428))
    *(r14_1 + 0x30) = rax_25;          // <-- leaks dependency object pointer
}

// general chain loop over i_5 = i_5[0x92]:
*(r14_2 + 0x20) = rbx_6;               // <-- leaks next chain object pointer
rax_28 = rbx_6[0x85];
*(r14_2 + 0x28) = rax_28;              // <-- leaks dependency object pointer

// count==2 branch:
*(r15_2 + 0x20) = i_5;                 // <-- leaks
rax_14 = i_5[0x85];
*(r15_2 + 0x28) = rax_14;              // <-- leaks

*(arg2 + 0x38) = bytes_written;
```

```c
// PATCHED — sub_1C0082CCC (sub_1c0082ccc); pointers NULed for untrusted callers
int32_t rax = sub_1c0010298();         // ADDED caller-trust gate
// rdx_2 = rax  (result stored at [rsp+0xb0])

// ... identical level validation, size computation, overflow handling ...

int64_t* i_8 = i_5;
if (rdx_2 && *(arg2 + 0x40))           // untrusted caller?
    i_8 = nullptr;                     // -> NUL the pointer
*(r14_2 + 0x28) = i_8;                 // sanitized store

// every other store site (record+0x20 / +0x28 / +0x30) receives the
// same gate: cmp byte [rbp+0x40], dil; cmovne rax, rdi; mov [record], rax
```

**Key changes:**
- Unpatched stores `i_5` and `i_5[0x428]/[0x85]` (live kernel object pointers) directly into user-returned records at `+0x20`/`+0x28`/`+0x30`.
- Patched calls `sub_1c0010298()` once at entry and gates every pointer store on `(rdx_2 && *(arg2+0x40))`, substituting NULL via `cmovne rax, rdi` for untrusted callers.
- No fallback path stores the pointer unsanitized in the patched build — all count==2 and general-loop store sites are covered.

---

## 4. Assembly Analysis

### 4.1 sub_1C0082CCC (sub_1c0082ccc)

**Unpatched — direct kernel-pointer stores into the user-returned records:**
```asm
mov     qword [rsp+0x8], rbx
mov     qword [rsp+0x10], rdx
push    rbp
push    rsi
push    rdi
push    r12
push    r13
push    r14
push    r15
sub     rsp, 0x40
mov     r12, rdx                 ; r12 = arg2 (request object)
mov     rbx, rcx                 ; rbx = arg1
mov     rcx, qword [rel 0x1c005f048]
lea     rbp, [rel 0x1c005f048]
lea     r14, [rel 0x1c00544a0]   ; ETW event data (pre-patch)
cmp     rcx, rbp
je      0x1c0082d23
mov     rax, qword [r12+0xb8]    ; output buffer descriptor
mov     qword [rsp+0x90], rax
cmp     dword [rax+0x10], 0x4    ; descriptor level >= 4 gate
jae     0x1c0082d6d
mov     r15, qword [r12+0x18]    ; r15 = output buffer ptr
mov     r9d, dword [r15]         ; r9d = query level (1..3)
lea     eax, [r9-0x1]
cmp     eax, 0x2
ja      0x1c0083275              ; level>3 => STATUS_INVALID_LEVEL
; ... size/count computation building rbp_3 (required size) ...
cmp     eax, r9d
jb      0x1c0083245              ; buf size < required => STATUS_BUFFER_OVERFLOW
mov     qword [r14+0x28], r13    ; @~0x1c0083127  *(record+0x28) = i_5  (KERNEL POINTER LEAK)
cmp     dword [r15], 0x3
jne     0x1c0083156
mov     rax, qword [r13+0x428]   ; dependency object
mov     qword [r15+0x28], rax    ; @~0x1c008314d  *(record+0x28) = i_5[0x85] (KERNEL POINTER LEAK)
mov     qword [r15+0x20], r13    ; @~0x1c008319b  *(record+0x20) = dependent object (KERNEL POINTER LEAK)
mov     rax, qword [r13+0x428]
mov     qword [r15+0x28], rax    ; @~0x1c00831a5/0x1c00831c1 dependency object (KERNEL POINTER LEAK)
mov     qword [r12+0x38], rdi    ; *(arg2+0x38) = bytes written
```
Annotations:
- `~0x1c0082d80` (`lea eax,[r9-1]; cmp eax,0x2; ja 0x1c0083275`): the only input validation on the level — it bounds the level to 1..3 but does nothing about pointer disclosure.
- `~0x1c0083127` (`mov qword [r14+0x28], r13`): the vulnerable write — `r13` holds `i_5`, a live kernel pointer, copied straight into the user-facing record with no trust check.
- `~0x1c008314d` / `~0x1c00831c1` (`mov qword [r15+0x28], rax`): stores the dependency object pointer `[r13+0x428]` into the record.
- `~0x1c008319b` (`mov qword [r15+0x20], r13`): chained-record store, showing the leak scales to every dependency in the chain.

**Patched — trust gate at entry and NUL-on-untrusted before each store:**
```asm
; at function entry (replaces the direct-store setup):
call    0x1c0010298              ; caller-trust / previous-mode gate (ADDED)
mov     dword [rsp+0xb0], eax    ; save result (rdx_2)
; ...
; at each former leak store site:
cmp     byte [rbp+0x40], dil     ; consult request flag *(arg2+0x40)
cmovne  rax, rdi                 ; rdi == 0 -> NUL the pointer for untrusted caller
mov     qword [record], rax      ; sanitized store
; new ETW emissions: event codes 0x1b/0x1c/0x1d/0x1e; exit code 0x1f
; event data pointer changed &data_1c00544a0 -> &data_1c0052c78
```
Annotations:
- `call 0x1c0010298` at entry: the new gate; its int32 result is stashed at `[rsp+0xb0]` and drives the sanitization decision. It takes no arguments — likely keys on `Irp->RequestorMode` / `ExGetPreviousMode` or a global policy flag.
- `cmp byte [rbp+0x40], dil; cmovne rax, rdi`: detects the untrusted condition and replaces the pointer with NULL before it is written into the record; there is no un-gated path back to the old direct store.

---

## 5. Trigger Conditions

1. **Reach the target.** Open a handle to a VHD-backed / dependent storage object that has at least one storage dependency — e.g. attach a VHD with a parent (differencing chain) via `OpenVirtualDisk`/`CreateFile`.
2. Issue the storage-dependency query the way `VirtDisk!GetStorageDependencyInformation` does — `DeviceIoControl` with the storage-dependency query IOCTL — so the IRP reaches `vhdmp!sub_1C0082CCC`.
3. Set the query level in the first dword of the output buffer `*(arg2+0x18)` to `2` or `3` (1..3 are valid; level 1 also stores `i_5`; else `STATUS_INVALID_LEVEL`). Ensure the output-descriptor level `*(arg2+0xb8)+0x10 >= 4`.
4. Size the output buffer so `*(arg2+0xb8)+8` is `>=` the computed required size (`rbp_3`/`r13_3`), so the fill path is taken rather than the `STATUS_BUFFER_OVERFLOW` / `BUFFER_TOO_SMALL` early-out. At least one dependency must exist so a record is emitted.
5. Fire the single `DeviceIoControl` call.
6. **Observable effect.** The call returns `STATUS_SUCCESS`; the returned `STORAGE_DEPENDENCY_INFO` record(s) contain non-zero 64-bit kernel addresses (`0xFFFF...`) at record offsets `+0x20`/`+0x28`/`+0x30`. On the patched driver the same fields read as `0` for the same unprivileged caller.

**Notes:** The chain must contain at least one dependency for a record to be produced (a lone VHD with no parent/differencing relationship yields nothing to leak). The disclosure is per-query and requires no race; simply repeat with a large enough buffer.

---

## 6. Exploit Primitive & Development Notes
- **Primitive:** Kernel-heap address information disclosure. The attacker recovers the exact base addresses of internal vhdmp dependency-chain objects (`i_5`) and their sub-objects (`i_5[0x428]`) from a low-privileged / user-mode caller — an OOB-free, deterministic KASLR defeat with object-precise granularity.
- **Turning it into a full exploit:**
  1. Groom the vhdmp dependency-chain objects by attaching one or more VHDs with controlled differencing chains so that a known pool layout is produced and the leaked object addresses are predictable.
  2. Use the leaked object base to locate a corruptible field (function pointer, `LIST_ENTRY`, or reference count) inside the disclosed vhdmp object as the write target for a separate primitive.
  3. The leak *is* the info-leak stage; no additional KASLR bypass is needed once a vhdmp object address is known.
  4. Pair with an out-of-band write/UAF in vhdmp (or another driver operating on the same object) to redirect control flow or perform a data-only privilege escalation using the now-known object address.
- **Mitigations to consider:**
  - **kASLR:** Directly defeated for the disclosed objects — this is the whole point of the bug.
  - **SMEP / SMAP:** Unaffected by the leak itself; relevant only to the follow-on corruption stage.
  - **CFG / CET:** Not relevant to disclosure; a leaked function-pointer field would still need a CFG-valid or ROP-based target in the corruption stage.
  - **HVCI / VBS:** The leak survives HVCI (it is data disclosure, not code injection); a data-only privilege-escalation variant using the leaked object address remains viable under HVCI.
  - **Pool hardening:** The leak reveals object bases rather than pool headers, so pool-cookie/header protections do not stop it; corrupt object fields (not the header) in the follow-on stage.
- **Realistic outcome:** Local KASLR defeat / kernel-object address disclosure to an unprivileged process, usable as the info-leak half of a local privilege-escalation chain when combined with a separate write primitive.

---

## 7. Debugger PoC Playbook

### 7.1 sub_1C0082CCC (sub_1c0082ccc)

**Breakpoints:**
```text
bp vhdmp!sub_1C0082CCC              ; @0x1c0082ccc entry: inspect arg2 fields; patched build inserts call 0x1c0010298 here
bp vhdmp+0x83127                   ; mov [r14+0x28], r13  -> r13 = i_5 (leaked chain object ptr)
bp vhdmp+0x8314d                   ; mov [r15+0x28], rax  -> dependency object ptr (i_5[0x85])
bp vhdmp+0x8319b                   ; mov [r15+0x20], r13  -> chained-record leak (loop scales)
```
Rebase note: the analysis base is `0x1c0000000`; RVAs above are `store_VA − 0x1c0000000` (e.g. `0x1c0083127 − 0x1c0000000 = 0x83127`). If the loaded module base differs, apply the same subtraction against the analysis base before setting the breakpoints. Re-confirm exact VAs with `uf vhdmp!sub_1C0082CCC`, since the per-binary disassembly worker was unreachable during analysis and offsets are taken from the diff hunks.

**Inspect at each breakpoint:**
- **At entry (`vhdmp!sub_1C0082CCC`):** `rcx` (arg1) = internal context/device object; `rdx` (arg2) = request object. Read the request fields:

```text
dq @rdx+0x18 L1      ; output buffer ptr; first dword = query level (1..3)
dd poi(@rdx+0x18) L1 ; confirm level == 2 or 3
dq @rdx+0xb8 L1      ; output descriptor; +8 = buffer size, +0x10 = descriptor level
dq @rdx+0x38 L1      ; bytes-written out
db @rdx+0x40 L1      ; request flag the patch ANDs with the trust result
```

- **At +0x83127:** `r13` holds `i_5`, the live kernel object pointer being written into `record+0x28`. This register value is exactly what leaks to user mode.

```text
r r13                ; leaked kernel object base
dq @r14+0x28 L1      ; the record slot receiving it
!pool @r13           ; should resolve to a vhdmp-tagged nonpaged pool object
```

- **At +0x8314d:** watch `rax` / `[r13+0x428]` — the dependency object pointer copied into the record.
- **At +0x8319b:** `rbx_6` (the next chain object) is written into each subsequent record, confirming the leak covers every dependency in the chain.

**Trigger setup (from user mode):**
1. `OpenVirtualDisk` / `CreateFile` on a VHD-backed volume that has at least one storage dependency (a mounted/attached VHD with a parent or differencing chain).
2. Call `VirtDisk!GetStorageDependencyInformation` requesting `STORAGE_DEPENDENCY_INFO` version 2, with a large-enough output buffer to pass the size check:

```text
GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES (or default)
STORAGE_DEPENDENCY_INFO.Version = STORAGE_DEPENDENCY_INFO_VERSION_2
buffer size >= computed required size (over-provision, e.g. 0x1000)
```

3. No loop needed — a single successful query fills the records; break at entry to confirm `arg2` fields, then step to the leak stores.

**Expected observation:** `STATUS_SUCCESS` return; the returned record(s) contain non-zero 64-bit values at `record+0x20`/`+0x28`/`+0x30` in the kernel range (`0xFFFF...`). `!pool` on those values resolves to vhdmp-tagged nonpaged-pool objects. On the patched driver the same fields read `0` for the same unprivileged caller.

**Struct / offset notes:**
```text
arg2 (request object):
  +0x18  PVOID   output buffer ptr (first dword = query level 1..3)
  +0x38  UINT64  bytes-written out
  +0x40  BYTE    request flag consulted by the patch's trust gate
  +0xb8  PVOID   output descriptor  (+0x08 = buffer size, +0x10 = descriptor level, must be >=4)

i_5 (dependent-chain object):
  +0x428 (== [0x85] as int64 index)  dependency object pointer
  +0x490 (== [0x92] as int64 index)  next chain link

STORAGE_DEPENDENCY_INFO record fields receiving pointers:
  +0x20  dependent object (chained/count==2)
  +0x28  i_5 / dependency object
  +0x30  dependency object (level 3)

sub_1c0010298: added trust gate; no args; returns int32 stored at [rsp+0xb0].
  Confirm whether it keys on Irp->RequestorMode / ExGetPreviousMode or a policy flag.
```

---

## 8. Changed Functions — Full Triage
- **`sub_1C0082CCC (sub_1c0082ccc)` -> `sub_1C0082CCC (sub_1c0082ccc)`** (similarity 0.846, security_relevant): The storage-dependency query handler. Pre-patch it stores raw kernel object pointers (`i_5`, `i_5[0x428]`) into user-returned `STORAGE_DEPENDENCY_INFO` records at `+0x20`/`+0x28`/`+0x30`. The patch adds a caller-trust gate (`call 0x1c0010298`) at entry and NULs each pointer (`cmovne rax, rdi`) for untrusted callers, keyed on the gate result and the request flag `*(arg2+0x40)`. The similarity dip is explained by the added gate, per-store cmov sequences, and telemetry churn (event codes `0x1d`->`0x1f`, new `0x1b`–`0x1e`, event-data pointer `&data_1c00544a0`->`&data_1c0052c78`).

*Collapsed note on non-security changes:* The only changed function is `sub_1C0082CCC`; the ETW/telemetry event-code and event-data-pointer shifts inside it are a byproduct of the added logging around the sanitized path and carry no independent security significance. Everything else (2311 functions) is byte-identical.

---

## 9. Unmatched Functions
- **Removed (unpatched only):** None
- **Added (patched only):** None
- **Implication:** The fix is purely additive within the existing function `sub_1C0082CCC`. Note that `sub_1c0010298` (the trust gate the patch calls) already exists in both builds — it is not a newly added function, only newly *called* from the fixed handler — so it does not appear in the unmatched list. The absence of removed/added functions confirms the patch is a targeted, in-place sanitization of the leak rather than a structural rewrite.

---

## 10. Confidence & Caveats
- **Confidence:** high
- **Rationale:**
  - The diff is unambiguous: pre-patch stores raw registers holding kernel object pointers (`r13 = i_5`, `[r13+0x428]`) into user-facing records; post-patch inserts a trust gate and `cmovne rax, rdi` (NUL-on-untrusted) before every such store. This is a textbook info-disclosure-fix idiom.
  - Only one function changed, and every store site is covered by the same gate, leaving no unchecked fallback — the fix intent is clear.
  - The data flow from `*(arg2+0x18)` (user output buffer) through the record stores back to user mode is direct.
- **Assumptions made:**
  - `sub_1c0010298` is a caller-trust / previous-mode check (inferred from its zero-argument signature and its role gating the disclosure); its exact predicate (`Irp->RequestorMode` / `ExGetPreviousMode` vs a global policy flag) is not confirmed.
  - The leaked objects reside in nonpaged pool with vhdmp tags (implied by the handler's role); exact pool type/tag is inferred, not observed.
  - The precise IOCTL/FSCTL code behind `GetStorageDependencyInformation` and the exact `STORAGE_DEPENDENCY_INFO` record field mapping are inferred from field offsets, not from a symbol dump.
- **To verify before a PoC:**
  1. Re-run `uf vhdmp!sub_1C0082CCC` on the loaded unpatched binary to confirm the exact runtime VAs of the store sites (`~0x1c0083127`, `~0x1c008314d`, `~0x1c008319b`, `~0x1c00831c1`) — the analysis disassembly worker was unreachable, so these come from diff hunks.
  2. Disassemble `sub_1c0010298` to confirm it is the previous-mode / trust check and identify what makes a caller "trusted" vs "untrusted."
  3. Confirm the concrete storage-dependency query request shape (IOCTL code, `STORAGE_DEPENDENCY_INFO` version, and the mapping of record offsets `+0x20`/`+0x28`/`+0x30`) and reproduce a non-zero kernel value in the returned buffer on the unpatched driver vs `0` on the patched driver.
