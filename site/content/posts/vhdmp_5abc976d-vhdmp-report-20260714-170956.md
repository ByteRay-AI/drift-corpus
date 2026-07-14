Title: vhdmp.sys — Kernel-pointer information disclosure in the dependent-disk / STORAGE_DEPENDENCY_INFO query handler (sub_1C008F040)
Date: 2026-06-09
Slug: vhdmp_5abc976d-vhdmp-report-20260714-170956
Category: Corpus
Author: Argus
Summary: KB5094127
Severity: Medium
KBDate: 2026-06-09

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | vhdmp_unpatched.sys |
| Patched binary | vhdmp_patched.sys |
| Overall similarity | 0.9914 |
| Matched functions | 2401 |
| Changed functions | 1 |
| Identical functions | 2400 |
| Unmatched (unpatched / patched) | 0 / 0 |

**Verdict:** A single function, `sub_1C008F040` (the dependent-disk / STORAGE_DEPENDENCY_INFO query handler), was patched to stop leaking raw kernel-mode heap pointers into a user-supplied output buffer. This is a KASLR-defeating information disclosure reachable by any caller who can issue the query IOCTL against a vhdmp VHD device object.

Of the single changed function, the diff is entirely security-relevant. The measured similarity dip (0.7851) is caused by two overlapping things: (1) the genuine security fix — an added caller-provenance check plus a `cmovne`-to-NULL guard at every pointer-disclosure site — and (2) benign version drift (re-numbered debug/telemetry message IDs and helper thunks such as `0x1c005d6e0→0x1c005adc8` and `sub_1c00191c4→sub_1c0019204`). All 2400 other functions are byte-identical, so the fix is tightly concentrated in this one handler. The disclosure zeroing is gated behind the untrusted-requestor flag (`sub_1c0011800() != 0`) AND the request flag at `arg2+0x40`, meaning a trusted / kernel-mode requestor still receives the raw pointers by design.

---

## 2. Vulnerability Summary

### 2.1 MEDIUM — Kernel-pointer information disclosure (CWE-200 -> CWE-201)
- **Affected function:** `sub_1C008F040` (sub_1c008f040) in both builds — the dependent-disk / STORAGE_DEPENDENCY_INFO query handler that builds a dependency-chain description and copies it into the caller's output buffer.
- **Root cause:** For each entry in the VHD dependency linked list, the pre-patch handler writes **raw kernel-mode heap pointers** into the user output buffer without any trust check. The relevant object layout:
  - `r13` / `rbx` — a dependency-chain list node (non-paged pool kernel address)
  - `node+0x88` (`i_5[0x88]`) — an associated kernel object pointer, referenced via `DependentFSReferenceDependency`
  - `node+0x440` — read into `rax` before storing the object pointer
  - Output entry fields: `+0x28` = node pointer, `+0x30` = object pointer (primary entry); `+0x20`/`+0x28` in the chained-entry loop

The exact flawed writes:
```asm
mov     qword [r14+0x28], r13   ; leak: node pointer into output entry+0x28
mov     qword [r14+0x30], rax   ; leak: node[0x88] object pointer into entry+0x30
mov     qword [r12+0x20], r13   ; leak: chained entry+0x20 node pointer
mov     qword [r12+0x28], rax   ; leak: chained entry+0x28 object pointer
```
- **Why exploitable:** The attacker controls the class/version selector (`*(arg2+0x18)[0]` = 1, 2, or 3), the detail flag (`*(arg2+0x40)`), and the output buffer size. Once the fill path executes, the returned entries carry live non-paged-pool kernel addresses. These are precise heap-pointer anchors into vhdmp-owned allocations — enough to defeat kernel ASLR and to seed a follow-on write / UAF exploit. The leaked fields correspond to internal dependency-object references, not the documented name/path strings, so a benign client never needs them.
- **What the patch does:** Adds a provenance check at the prologue: `call 0x1c0011800; test eax,eax; setne cl; mov [rsp+0x98],ecx` — a boolean meaning "untrusted / user-mode requestor." At each disclosure site the raw pointer is conditionally NULLed: `cmp byte [rbp+0x40],r8b; cmovne rax,r8(=0); mov [dst],rax`. When the provenance flag AND the `arg2+0x40` request flag are both set, the kernel pointer becomes NULL. A trusted requestor still receives the raw pointer (intended fallback).
- **Attacker-reachable entry point:** `IRP_MJ_DEVICE_CONTROL` on a vhdmp VHD device object — the dependent-disk / STORAGE_DEPENDENCY_INFO query IOCTL (GetStorageDependencyInformation / IOCTL_STORAGE_QUERY_DEPENDENT_DISK path).
- **Call chain:**
  1. `NtDeviceIoControlFile` (user mode)
  2. vhdmp `IRP_MJ_DEVICE_CONTROL` dispatch
  3. dependent-disk / STORAGE_DEPENDENCY_INFO query router
  4. `sub_1C008F040` (0x1c008f040) — disclosure store at 0x1c008f496

---

## 3. Pseudocode Diff

### 3.1 sub_1C008F040 (sub_1c008f040)
```c
// UNPATCHED — sub_1C008F040 (sub_1c008f040); disclosure sites write raw kernel pointers
*(r14_1 + 0x28) = i_6;                 // FLAW: raw kernel node pointer -> output entry+0x28
if (*r12_1 != 3)
    rax_20 = 0;
else {
    rcx_32 = i_6[0x88];
    if (!rcx_32) rax_20 = 0;
    else if (DependentFSReferenceDependency(rcx_32) < 0) rax_20 = 0;
    else rax_20 = i_6[0x88];
}
*(r14_1 + 0x30) = rax_20;               // FLAW: kernel object pointer -> output entry+0x30

// chained-entry loop:
*(r14_2 + 0x20) = rbx_6;                // FLAW: raw kernel node pointer -> chained entry+0x20
*(r14_2 + 0x28) = rax_23;               // FLAW: kernel object pointer -> chained entry+0x28
```
```c
// PATCHED — sub_1C008F040 (sub_1c008f040); provenance-gated NULLing of pointer fields
int rcx = (sub_1c0011800() != 0);       // untrusted-requestor boolean, stored at [rsp+0x98]
...
int64_t* i_8 = i_5;                      // candidate kernel node pointer
if (rcx && *(arg2 + 0x40))               // untrusted AND detail flag set
    i_8 = nullptr;                       // FIX: zero the disclosed pointer
*(rsi_1 + 0x28) = i_8;                   // output entry+0x28 now NULL for untrusted callers
// same cmovne-to-NULL guard applied at +0x30, chained +0x20, chained +0x28
```

**Key changes:**
- Unpatched unconditionally stores `r13` (node pointer) and `node[0x88]` (object pointer) into the user output buffer.
- Patched computes an untrusted-requestor flag once at entry (`sub_1c0011800()`), stores it, and at each store uses `cmovne` to substitute NULL when both that flag and `*(arg2+0x40)` are set.
- A trusted / kernel-mode requestor (flag == 0) still gets the raw pointers — that fallback path is intentionally preserved and is *not* a bug.

---

## 4. Assembly Analysis

### 4.1 sub_1C008F040 (sub_1c008f040)

**Unpatched — validation and unconditional disclosure stores:**
```asm
0x1c008f040 | mov     qword [rsp+0x10], rdx
            | push    rbx
            | push    rbp
            | push    rsi
            | push    r12
            | push    r13
            | push    r14
            | push    r15
            | sub     rsp, 0x40
            | mov     r15, rdx            ; r15 = arg2 (request/context)
            | mov     rbx, rcx            ; rbx = arg1 (target object)
            | lea     rbp, [rel 0x1c0068048]
            | mov     r14d, 0x7
            | cmp     qword [rel 0x1c0068048], rbp
            | lea     r13, [rel 0x1c005d6e0]
            | je      0x1c008f0a1
            | mov     rax, qword [r15+0xb8]   ; output buffer descriptor
            | mov     qword [rsp+0x90], rax
            | cmp     dword [rax+0x10], 0x4   ; level check
0x1c008f0e9 | mov     ecx, dword [r12]        ; class/version 1..3
            | lea     eax, [rcx-0x1]
            | cmp     eax, 0x2
            | ja      0x1c008f5eb             ; invalid class -> STATUS_INVALID_LEVEL
            | ...
            | mov     eax, dword [rax+0x8]    ; caller output length
            | cmp     eax, ebp                ; vs required size
            | jb      0x1c008f583             ; too small -> BUFFER_OVERFLOW/TOO_SMALL
0x1c008f496 | mov     qword [r14+0x28], r13   ; LEAK: node ptr -> entry+0x28
            | cmp     dword [r12], 0x3
            | jne     0x1c008f4c6
            | mov     rax, qword [r13+0x440]
            | mov     qword [r14+0x30], rax   ; LEAK: object ptr -> entry+0x30
            | mov     qword [r12+0x20], r13   ; LEAK: node ptr -> chained+0x20
            | mov     rax, qword [r13+0x440]
            | mov     qword [r12+0x28], rax   ; LEAK: object ptr -> chained+0x28
            | mov     qword [r14+0x20], rbx   ; LEAK: node ptr -> chained+0x20
            | ...
            | mov     qword [r15+0x38], rcx   ; *(arg2+0x38) = bytes written
            | call    0x1c000e354
            | mov     eax, esi                ; return status
            | add     rsp, 0x40
            | pop     r15
            | pop     r14
            | pop     r13
            | pop     r12
            | pop     rsi
            | pop     rbp
            | pop     rbx
            | retn
```
Annotations:
- `0x1c008f0e9`: the only input validation on the class/version dword — `cmp eax,0x2 / ja` rejects values outside 1..3. There is **no** trust/provenance check anywhere in this function.
- `0x1c008f496`: the smoking-gun `mov qword [r14+0x28], r13` — writes a raw kernel pool node pointer straight into the user output entry.
- `~0x1c008f4bd`: `mov rax,[r13+0x440]` then `mov qword [r14+0x30], rax` — discloses the `node+0x88` object pointer.

**Patched — added provenance check and guarded stores:**
```asm
; ADDED at prologue (patched only):
call    0x1c0011800         ; untrusted-requestor / previous-mode style check
test    eax, eax
setne   cl
mov     [rsp+0x98], ecx     ; save boolean gate

; ADDED at each disclosure site (patched only), e.g. entry+0x28:
mov     rax, r13            ; candidate kernel node pointer
xor     r8d, r8d            ; r8 = 0 (NULL)
cmp     byte [rbp+0x40], r8b ; test the arg2+0x40 detail flag against the gate
cmovne  rax, r8             ; if untrusted+flag -> substitute NULL
mov     qword [rsi+0x28], rax
```
Annotations:
- `call 0x1c0011800`: the new provenance routine — returns non-zero for an untrusted / user-mode requestor. Absent entirely in the unpatched build.
- `cmovne rax, r8`: conditionally replaces the leaked pointer with NULL. The same idiom is applied at `+0x28`, `+0x30`, chained `+0x20`, and chained `+0x28`.
- The fallback where the gate is 0 (trusted requestor) still writes the raw pointer — this is by design and remains present in the patched binary.

---

## 5. Trigger Conditions
1. **Reach the target.** Attach or open a VHD/VHDX via `OpenVirtualDisk`, or open the vhdmp device object directly, to obtain a handle whose device stack routes IOCTLs to vhdmp.
2. Issue the dependent-disk / STORAGE_DEPENDENCY_INFO query IOCTL (GetStorageDependencyInformation / `IOCTL_STORAGE_QUERY_DEPENDENT_DISK` path) via `DeviceIoControl`.
3. Set the input record so the class/version dword at `*(arg2+0x18)[0]` is **1, 2, or 3** — anything else returns `STATUS_INVALID_LEVEL` at `0x1c008f0e9`.
4. Set the request so the detail flag `*(arg2+0x40)` selects the pointer-bearing record path, and provide an output buffer whose length (`*(arg2+0xb8)->+0x8`) is at least the computed required size: `>= 0x10` and `>= ((count*3)<<4)+8` for class 1/3, or `(count<<6)+8` (+per-entry `2+name_len`) for class 2. This avoids the `STATUS_BUFFER_OVERFLOW` / `STATUS_BUFFER_TOO_SMALL` early-out at `0x1c008f583`.
5. Fire the single `DeviceIoControl` call — no race or special timing required.
6. **Observable effect.** IOCTL returns `STATUS_SUCCESS`; the returned dependency-info entries contain 8-byte canonical kernel addresses (`0xffff8...`/`0xfffff...`) at entry offsets `+0x28`/`+0x30` (and `+0x20`/`+0x28` for chained entries), resolvable via `!pool`/`!address` to vhdmp-owned non-paged-pool allocations.

**Notes:** Single IOCTL, no ordering or race constraints. The class/version selector controls layout: class 1/3 use fixed-stride entries (stride 0x30/0x40); class 2 is variable-length with an embedded name copied by `sub_1c0012c40` / `sub_1c0012980`. Ensure the dependency chain actually has at least one node (i.e. the VHD is a differencing/parented disk) so entries are produced.

---

## 6. Exploit Primitive & Development Notes
- **Primitive:** Kernel-address information disclosure. The attacker obtains the address of the internal VHD dependency-chain node object and a referenced kernel object (`node+0x88`), both in non-paged pool. This is a read-only leak — not by itself a write or code execution.
- **Turning it into a full exploit:**
  1. Use the leaked node/object addresses as precise anchors to locate vhdmp-owned pool allocations and to fingerprint the pool layout around them.
  2. Pair with a separate memory-corruption primitive (OOB write / UAF elsewhere) whose target must be a known kernel address — this leak supplies that address, e.g. a function pointer or `LIST_ENTRY` field inside the disclosed object.
  3. The leak directly defeats KASLR for the vhdmp allocation region; combine with a driver-base leak or a well-known object offset to pivot to a code-execution target.
  4. Data-only path: corrupt a token or object field at a now-known address to achieve privilege escalation without hijacking control flow.
- **Mitigations to consider:**
  - **kASLR:** Directly defeated for the disclosed allocations — that is the entire impact of this bug.
  - **SMEP / SMAP:** Not relevant to a pure info leak; matters only for the follow-on corruption stage.
  - **CFG / CET:** Not engaged by disclosure; relevant when choosing a control-flow target in a chained exploit.
  - **HVCI / VBS:** Do not block the leak. A data-only privilege-escalation variant built on the leaked addresses survives HVCI.
  - **Pool hardening:** The leak exposes object body pointers, not pool headers, so pool cookie/quota checks are not an obstacle to reading; they matter only when corrupting.
- **Realistic outcome:** Local KASLR defeat / kernel-heap pointer disclosure for a low-privileged user; a building block for LPE when combined with a separate write primitive — not standalone code execution.

---

## 7. Debugger PoC Playbook

### 7.1 sub_1C008F040 (sub_1c008f040)
Assume WinDbg/KD attached to the UNPATCHED binary. Image base 0x1c0000000; symbols are stripped, so use addresses verbatim.

**Breakpoints:**
```text
bp vhdmp+0x8f040    ; entry of the vulnerable handler; rcx=arg1(target), rdx=arg2(request)
bp vhdmp+0x8f496    ; disclosure store `mov qword [r14+0x28], r13` — watch r13 and [r14+0x28]
bp vhdmp+0x11800    ; provenance routine — ABSENT on the unpatched path; use to confirm the missing check
```
Rebase note: if the loaded module base is not 0x1c0000000, subtract the analysis base (0x1c0000000) from each address above to get the RVA, then add the actual base.

**Inspect at each breakpoint:**
- **At +0x8f040 (entry):** `rdx` = arg2 request/context. Dump the selectors:
```text
dd poi(@rdx+0x18) L1        ; class/version dword (must be 1,2,3)
db @rdx+0x40 L1             ; detail flag byte
dq poi(@rdx+0xb8)+0x8 L1    ; caller output buffer length
dd poi(@rdx+0xb8)+0x10 L1   ; level field
```
- **At +0x8f496 (disclosure store):** `r14` = current output entry base, `r13` = kernel dependency-chain node pointer. The smoking gun is a canonical kernel address about to be written to user-visible memory:
```text
r r13
dq @r14+0x28 L2            ; +0x28 node ptr, +0x30 object ptr after the store
```
- **At +0x11800 (patched only):** In the patched binary, break here to observe the gating boolean in `eax`; in the unpatched binary this breakpoint is never hit, confirming no provenance check exists.

**Trigger setup (from user mode):**
1. `OpenVirtualDisk` on an attached differencing VHD/VHDX (so the dependency chain is non-empty), or open the vhdmp device object directly.
2. Call `DeviceIoControl` with the dependent-disk / STORAGE_DEPENDENCY_INFO query IOCTL. Shape the input record:
```text
input[0x00] dword = 1        ; class/version (1, 2, or 3)
request+0x40      = 1        ; detail flag selecting pointer-bearing records
output buffer      : size >= computed requirement (>=0x10, and >= ((count*3)<<4)+8 for class 1/3)
```
3. No loop needed — a single IOCTL fills the entries. Break at +0x8f040, step to +0x8f496, continue, then read back the returned buffer.

**Expected observation:** After `STATUS_SUCCESS`, entry offsets `+0x28`/`+0x30` (and chained `+0x20`/`+0x28`) hold 8-byte canonical kernel addresses in the `0xffff8...`/`0xfffff...` range. `!pool <addr>` / `!address <addr>` resolve them to vhdmp-owned non-paged-pool allocations. On the patched driver, the same fields read back as 0 for the untrusted path.

**Struct / offset notes:**
```text
arg2 (rdx / r15):
  +0x18  ->  pointer to input/output struct; [ptr+0x00] = class/version (1..3)
  +0x38      bytes-written out field
  +0x40      detail/flag byte gating the pointer-bearing path
  +0xb8  ->  output buffer descriptor; [desc+0x08] = caller length, [desc+0x10] = level

dependency node (r13 / rbx):
  +0x88      referenced kernel object pointer (also disclosed)
  +0x440     value loaded into rax before storing the object pointer

output entry:
  +0x20      chained node pointer (leak)
  +0x28      node pointer (primary leak) / chained object pointer
  +0x30      node[0x88] object pointer (primary leak)

sub_1c0011800() -> nonzero = untrusted/user-mode requestor (patched-only provenance check)
```

---

## 8. Changed Functions — Full Triage
- **sub_1C008F040 (sub_1c008f040) -> sub_1C008F040 (sub_1c008f040)** (similarity 0.7851, security_relevant): The dependent-disk / STORAGE_DEPENDENCY_INFO query handler. The fix adds a caller-provenance check at the prologue (`call 0x1c0011800; setne cl`) and guards every kernel-pointer store with a `cmovne`-to-NULL when the requestor is untrusted and the `arg2+0x40` flag is set, at output offsets `+0x28`/`+0x30` (primary) and `+0x20`/`+0x28` (chained loop). The unpatched version writes those pointers unconditionally. Part of the similarity drop is version drift: re-numbered debug/telemetry message IDs (`0x1c005d6e0→0x1c005adc8`) and helper thunks (`sub_1c00191c4→sub_1c0019204`, `sub_1c002aa60→sub_1c002aaa0`, `sub_1c001e088→sub_1c001e0c8`).

*Collapsed note on non-security changes:* The only meaningful diff is the added provenance gate and the NULLing guards; the remaining delta in this one function is cosmetic re-numbering of message IDs and helper thunk targets. Every other function in the image (2400 of them) is byte-identical.

---

## 9. Unmatched Functions
- **Removed (unpatched only):** None.
- **Added (patched only):** None.
- **Implication:** The fix is purely additive *within* the existing `sub_1C008F040`; no new standalone functions were introduced or removed. The provenance helper `sub_1c0011800` already existed in both builds (it is simply *called* from the patched handler and *not called* from the unpatched one), so the fix is a set of inline checks rather than a new sanitizer routine. There is no KIR/feature-flag gating visible beyond the runtime provenance + request-flag conditions.

---

## 10. Confidence & Caveats
- **Confidence:** high
- **Rationale:**
  - The diff is a textbook info-leak fix: raw kernel pointers stored into a user output buffer pre-patch, replaced by a provenance-gated `cmovne`-to-NULL post-patch. The added `call 0x1c0011800; test eax,eax; setne cl` prologue and the `cmp byte [rbp+0x40],r8b; cmovne rax,r8` guard at every store are unambiguous.
  - Data flow is clear: `r13`/`rbx` are kernel pool node pointers and `node+0x88` is a referenced kernel object, all written to caller-visible offsets `+0x28`/`+0x30`/`+0x20`.
  - Only one function changed out of 2401 matched, isolating the fix.
- **Assumptions made:**
  - The exact IOCTL code and the precise user-facing struct field that maps to `arg2+0x40` (the detail flag) and `arg2+0x18` (class/version) are inferred from the STORAGE_DEPENDENCY_INFO / GetStorageDependencyInformation semantics, not confirmed from the dispatch table.
  - The disclosed pointers reside in non-paged pool; the specific pool type/tag was not confirmed from the allocation sites.
  - Reachability from a low-privileged token (vs requiring a handle only obtainable with elevated rights) is assumed but not proven.
- **To verify before a PoC:**
  1. Confirm the exact IOCTL control code and the input-buffer layout that lands `class/version` at `*(arg2+0x18)[0]` and the detail flag at `arg2+0x40`, and that a low-privileged process can open a routing handle.
  2. Reproduce live: break at `vhdmp+0x8f496`, confirm `r13` is a canonical kernel address, and after return verify the output entries at `+0x28`/`+0x30` contain those addresses (and read 0 on the patched build). Confirm `sub_1c0011800` returns non-zero for the low-privileged caller so the patched path actually NULLs the fields.
