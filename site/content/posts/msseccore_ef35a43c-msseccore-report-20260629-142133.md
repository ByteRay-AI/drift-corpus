Title: msseccore.sys — Insufficient required signing level in the kernel-integrity check callback (CWE-347) fixed
Date: 2026-06-29
Slug: msseccore_ef35a43c-msseccore-report-20260629-142133
Category: Corpus
Author: Argus
Summary: KB5078885

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `msseccore_unpatched.sys` |
| Patched binary | `msseccore_patched.sys` |
| Overall similarity | 0.8982 |
| Matched functions | 43 |
| Changed functions | 10 |
| Identical functions | 33 |
| Unmatched (either direction) | 0 |

**Verdict:** The patch raises the required signing level in `SecKernelIntegrityCheck` from `0x06` (`SE_SIGNING_LEVEL_STORE`) to `0x08` (`SE_SIGNING_LEVEL_MICROSOFT`) in the descriptor passed to an OS-provided kernel-integrity callback. All other changed functions are compiler/register-allocation and code-relocation noise plus one benign pool-flag change; none is a security fix.

This is a **signing-level / trust-policy tightening**, not a memory-corruption bug. In the unpatched build the check accepts a component signed at the Store level; the patched build requires the higher Microsoft level.

---

## 2. Vulnerability Summary

### Finding 1 — Insufficient required signing level

- **Severity:** Low
- **Vulnerability class:** Improper verification of cryptographic signature / insufficient required signing level (CWE-347)
- **Affected function:** `SecKernelIntegrityCheck` @ `0x1C00081B8` (unpatched) / `0x1C0008178` (patched)

**Root cause (plain English).**
`SecKernelIntegrityCheck` builds a small descriptor on the stack and passes it to a function pointer held in `qword_1C0007008`. That pointer is an OS-supplied kernel-integrity callback: it is captured by the driver's own `SecKernelIntegrityCallback` (`0x1C0001080`), which stores the callback's `Argument1` into `qword_1C0007008` and hands back `&SecProtectedRanges`. The callback object is created and registered during driver initialization via `ExCreateCallback`/`ExRegisterCallback`. One field in the descriptor — the required signing level — is a hard-coded constant.

In the unpatched binary the constant is `0xA000006`:
- Low byte `0x06` = `SE_SIGNING_LEVEL_STORE`.
- High bits `0x0A000000` are an additional flags/mode qualifier carried in the same field.

The patched binary uses `0xA000008`:
- Low byte `0x08` = `SE_SIGNING_LEVEL_MICROSOFT`.

The documented Windows signing-level constants place `SE_SIGNING_LEVEL_STORE` at `0x06` and `SE_SIGNING_LEVEL_MICROSOFT` at `0x08`; `SE_SIGNING_LEVEL_WINDOWS` is `0x0C` and `SE_SIGNING_LEVEL_WINDOWS_TCB` is `0x0E`. This driver corroborates the numbering: `SecIsWindowsSigned` (`0x1C000855C`) uses `SeCompareSigningLevels` against level `0x0C` for its "Windows" comparison.

Because the unpatched driver requires only `SE_SIGNING_LEVEL_STORE`, the integrity check admits an object signed at the lower Store level; the patched driver requires the higher Microsoft level. The fix is a one-constant bump: `0xA000008` in place of `0xA000006`. No new branch, no sanitizer, no allocation change.

**Reachable entry point and data flow.**

1. `SecBindHost` (`0x1C00010B0`, exported) validates the caller (via `SecValidateDriverFileSignatureLevel` → `SecIsWindowsSigned`, plus range and lock checks) and, on success, populates the caller-supplied binding table. It writes `off_1C0004008[0]` into the table at offset `+0x8`.
2. `off_1C0004008` (in `.data` at `0x1C0004008`) holds the address `0x1C0001650` = `SecDispatchKernelIntegrityCheck`.
3. A bound host that invokes that table entry calls `SecDispatchKernelIntegrityCheck` (`0x1C0001650`), a thin wrapper (`sub rsp,0x28; call SecKernelIntegrityCheck; add rsp,0x28; ret`).
4. → `SecKernelIntegrityCheck` builds the descriptor with the required signing level and calls the OS callback in `qword_1C0007008` through the CFG dispatch stub `__guard_dispatch_icall_fptr`.

Note that reaching this callback already requires the caller to have passed `SecBindHost`'s own Windows-signed gate and to be the registered kernel client, so the constant is a defense-in-depth trust gate rather than a first-line boundary.

---

## 3. Pseudocode Diff

Only one function is security-relevant; the change is a single constant:

```c
// SecKernelIntegrityCheck  (unpatched 0x1C00081B8  ->  patched 0x1C0008178)

// Validation gates (identical in both)
if (!SecIsKernelIntegrityEnabled())  return 0xC00000BB;  // STATUS_NOT_SUPPORTED
if (a2 == 0 && a3 == 0)              return 0xC000000D;  // STATUS_INVALID_PARAMETER
if (a1 >= 6)                         return 0xC00000EF;  // STATUS_INVALID_PARAMETER_1
if (a1 != 0 && a2 == 0)             return 0xC00000F1;  // STATUS_INVALID_PARAMETER_3
if (a1 == 0 && a3 == 0)             return 0xC00000F0;  // STATUS_INVALID_PARAMETER_2
if (KeAreApcsDisabled())            return 0xC00000BB;  // STATUS_NOT_SUPPORTED

// Build the descriptor at v8 / [rbp-0x19]
v8[0] = 0x40;                    // Size

---- UNPATCHED -------------------------------------------------------
v8[1] = 0x0A000006;              // low byte 0x06 = SE_SIGNING_LEVEL_STORE   <<< weaker
---------------------------------------------------------------------

---- PATCHED ---------------------------------------------------------
v8[1] = 0x0A000008;              // low byte 0x08 = SE_SIGNING_LEVEL_MICROSOFT  <<< fix
---------------------------------------------------------------------

LODWORD(v8[2]) = 0x80000;        // flags
// binding type (a1) and the object pointer (a2, or a3 when a2==0) are stored later
v8[7] = a2 ? a2 : a3;

// Retry loop: repeat while the callback returns STATUS_MORE_PROCESSING_REQUIRED
do {
    result = ((fn)qword_1C0007008)(v8, v9);       // call via __guard_dispatch_icall_fptr
    if ((DWORD)result != 0xC0000016) break;        // 0xC0000016 = STATUS_MORE_PROCESSING_REQUIRED
} while (++v6 <= 5);
return result;
```

The only behavioral change is the value assigned to the required signing-level field.

---

## 4. Assembly Analysis

### Unpatched — `SecKernelIntegrityCheck` @ `0x1C00081B8` (full)

```asm
00000001C00081B8  mov     rax, rsp
00000001C00081BB  mov     [rax+8], rbx
00000001C00081BF  mov     [rax+10h], rsi
00000001C00081C3  mov     [rax+18h], rdi
00000001C00081C7  mov     [rax+20h], r14
00000001C00081CB  push    rbp
00000001C00081CC  lea     rbp, [rax-5Fh]
00000001C00081D0  sub     rsp, 90h
00000001C00081D7  mov     rax, cs:__security_cookie
00000001C00081DE  xor     rax, rsp
00000001C00081E1  mov     [rbp+57h+var_8], rax
00000001C00081E5  mov     rdi, rdx                       ; a2 = object
00000001C00081E8  mov     rsi, r8                        ; a3 = secondary object
00000001C00081EB  xor     edx, edx
00000001C00081ED  mov     r14d, ecx                      ; a1 = binding type
00000001C00081F0  lea     rcx, [rbp+57h+var_30]
00000001C00081F4  lea     r8d, [rdx+28h]
00000001C00081F8  call    memset
00000001C00081FD  xor     edx, edx
00000001C00081FF  lea     rcx, [rbp+57h+var_70]
00000001C0008203  lea     r8d, [rdx+40h]
00000001C0008207  call    memset
00000001C000820C  xor     ebx, ebx
00000001C000820E  call    SecIsKernelIntegrityEnabled
00000001C0008213  test    al, al
00000001C0008215  jnz     short loc_1C0008221
00000001C0008217  mov     eax, 0C00000BBh                ; STATUS_NOT_SUPPORTED
00000001C000821C  jmp     loc_1C00082C1
00000001C0008221  test    rdi, rdi
00000001C0008224  jnz     short loc_1C0008235
00000001C0008226  test    rsi, rsi
00000001C0008229  jnz     short loc_1C0008235
00000001C000822B  mov     eax, 0C000000Dh                ; STATUS_INVALID_PARAMETER
00000001C0008230  jmp     loc_1C00082C1
00000001C0008235  cmp     r14d, 6
00000001C0008239  jl      short loc_1C0008242
00000001C000823B  mov     eax, 0C00000EFh                ; STATUS_INVALID_PARAMETER_1
00000001C0008240  jmp     short loc_1C00082C1
00000001C0008242  test    r14d, r14d
00000001C0008245  jnz     short loc_1C0008253
00000001C0008247  test    rsi, rsi
00000001C000824A  jnz     short loc_1C000825F
00000001C000824C  mov     eax, 0C00000F0h                ; STATUS_INVALID_PARAMETER_2
00000001C0008251  jmp     short loc_1C00082C1
00000001C0008253  test    rdi, rdi
00000001C0008256  jnz     short loc_1C000825F
00000001C0008258  mov     eax, 0C00000F1h                ; STATUS_INVALID_PARAMETER_3
00000001C000825D  jmp     short loc_1C00082C1
00000001C000825F  call    cs:__imp_KeAreApcsDisabled
00000001C0008266  nop     dword ptr [rax+rax+00h]
00000001C000826B  test    al, al
00000001C000826D  jnz     short loc_1C0008217            ; APCs disabled -> STATUS_NOT_SUPPORTED
; ---- descriptor construction ----
00000001C000826F  mov     [rbp+57h+var_70], 40h          ; Size = 0x40
00000001C0008277  mov     [rbp+57h+var_68], 0A000006h    ; <<< required signing level, low byte 0x06 = STORE
00000001C000827F  mov     [rbp+57h+var_60], 80000h       ; flags
00000001C0008286  mov     [rbp+57h+var_40], r14d         ; binding type
00000001C000828A  mov     [rbp+57h+var_3C], 10h
00000001C0008291  mov     [rbp+57h+var_38], rdi          ; object = a2
00000001C0008295  test    rdi, rdi
00000001C0008298  jnz     short loc_1C000829E
00000001C000829A  mov     [rbp+57h+var_38], rsi          ; fallback object = a3
00000001C000829E  mov     rax, cs:qword_1C0007008        ; OS integrity callback fn pointer
00000001C00082A5  lea     rdx, [rbp+57h+var_30]
00000001C00082A9  lea     rcx, [rbp+57h+var_70]          ; &descriptor
00000001C00082AD  call    cs:__guard_dispatch_icall_fptr ; CFG dispatch of qword_1C0007008
00000001C00082B3  cmp     eax, 0C0000016h                ; STATUS_MORE_PROCESSING_REQUIRED ?
00000001C00082B8  jnz     short loc_1C00082C1
00000001C00082BA  inc     ebx
00000001C00082BC  cmp     ebx, 5
00000001C00082BF  jbe     short loc_1C000829E            ; retry up to 5 times
00000001C00082C1  mov     rcx, [rbp+57h+var_8]
00000001C00082C5  xor     rcx, rsp
00000001C00082C8  call    __security_check_cookie
00000001C00082CD  lea     r11, [rsp+90h+var_s0]
00000001C00082D5  mov     rbx, [r11+10h]
00000001C00082D9  mov     rsi, [r11+18h]
00000001C00082DD  mov     rdi, [r11+20h]
00000001C00082E1  mov     r14, [r11+28h]
00000001C00082E5  mov     rsp, r11
00000001C00082E8  pop     rbp
00000001C00082E9  retn
```

### Patched — the fix

The patched build reorders the memset-inlined zeroing but is otherwise the same; the required-level store lands at the relocated address `0x1C0008239`:

```asm
00000001C0008239  mov     [rbp+57h+var_68], 0A000008h    ; <<< fix: low byte 0x08 = SE_SIGNING_LEVEL_MICROSOFT
```

### Key annotations

- **Weaker instruction (unpatched):** `0x1C0008277` `mov [rbp+57h+var_68], 0A000006h` — required signing level `0x06` (Store) at descriptor offset `+0x08`.
- **Fix instruction (patched):** `0x1C0008239` `mov [rbp+57h+var_68], 0A000008h` — required signing level `0x08` (Microsoft).
- **Dispatch:** `0x1C00082AD` (unpatched) / `0x1C000826F` (patched) `call cs:__guard_dispatch_icall_fptr` — CFG-guarded call to the OS integrity callback held in `qword_1C0007008`; `rcx` = `&descriptor`.
- **No bounds/length issue:** there is no array or size problem here. The change is purely the value of the required-level constant.

---

## 5. Trigger Conditions

To reach and fire the integrity-check path:

1. **Driver loaded and integrity callback captured.** During initialization the driver creates and registers a callback (`ExCreateCallback`/`ExRegisterCallback` with `SecKernelIntegrityCallback`). When the OS notifies it, `SecKernelIntegrityCallback` stores the provided function pointer into `qword_1C0007008`. `SecIsKernelIntegrityEnabled` (`0x1C0001060`) returns true only once `qword_1C0007008 != 0` (gate 1).
2. **Bind as the kernel client.** A kernel-mode caller invokes the exported `SecBindHost` (`0x1C00010B0`). `SecBindHost` first validates the caller with `SecValidateDriverFileSignatureLevel` (which enforces Windows-signing via `SecIsWindowsSigned`) and other checks, then writes the callback table into the caller's buffer, including `off_1C0004008` (= `&SecDispatchKernelIntegrityCheck`) at offset `+0x8`.
3. **Invoke the integrity-check callback.** The bound host calls that table entry, routing `SecDispatchKernelIntegrityCheck` (`0x1C0001650`) → `SecKernelIntegrityCheck`.
4. **Argument constraints for `SecKernelIntegrityCheck`** (Microsoft x64):
   - `rcx` (`a1`) = binding type, must satisfy `a1 < 6` (`cmp r14d, 6 ; jl`).
   - `rdx` (`a2`) = object pointer, must be non-NULL when `a1 != 0`.
   - `r8` (`a3`) = secondary object, consistent with gates 2–5.
5. **APCs must be enabled.** `KeAreApcsDisabled()` at `0x1C000825F` must return false.
6. **Behavioral difference.** With the unpatched required level `0x06`, an object meeting only `SE_SIGNING_LEVEL_STORE` satisfies the callback; the patched required level `0x08` requires `SE_SIGNING_LEVEL_MICROSOFT`. The exact status returned by the callback for a sub-threshold object is determined by the OS routine in `qword_1C0007008` and is not fixed by this driver.

---

## 6. Impact & Development Notes

### Nature of the issue

This is **not** a memory-corruption primitive. It is a **trust-policy weakness**:

- *What changes:* an object presented to the kernel-integrity callback needed only `SE_SIGNING_LEVEL_STORE` (`0x06`) in the unpatched build; the patched build requires `SE_SIGNING_LEVEL_MICROSOFT` (`0x08`).
- *What it does not give:* kernel code execution, arbitrary kernel read/write, or any memory-safety primitive.

### Practical reach

The path is only reachable by a component that has already bound through the exported `SecBindHost`, which itself enforces a Windows-signing check on the caller and bug-checks on range/lock violations. The required-level constant is therefore an internal, defense-in-depth trust gate. Raising it from Store to Microsoft narrows which signed objects the integrity callback will accept.

### Mitigations context

| Mitigation | Relevance |
|---|---|
| CFG (Control Flow Guard) | The callback dispatch at `0x1C00082AD` is CFG-guarded. Not relevant to this issue — it is not a control-flow hijack. |
| kASLR / SMEP / SMAP / HVCI | Not relevant. No address leak or user-mode vector is involved. |
| Code Integrity / signing policy | Directly relevant: this constant is the signing-level threshold the driver requires from the integrity callback. |

---

## 7. Debugger Notes

Target: **`msseccore_unpatched.sys`**, kernel debugger attached.

### Breakpoints

```text
bp msseccore_unpatched!SecKernelIntegrityCheck                 "Function entry — observe arg setup"
bp msseccore_unpatched+0x8277                                  "Required signing-level store (0x06)"
bp msseccore_unpatched+0x82AD                                  "CFG-guarded integrity callback dispatch"
bp msseccore_unpatched!SecDispatchKernelIntegrityCheck          "Wrapper into SecKernelIntegrityCheck"
bp msseccore_unpatched!SecBindHost                             "Exported entry that hands out the callback table"
```

For the patched binary the required-level store lands at `msseccore_patched+0x8239`.

### What to inspect

| Stop | Register / Memory | Why |
|---|---|---|
| `SecKernelIntegrityCheck` entry | `rcx` = binding type, `rdx` = object, `r8` = secondary object | How the arguments arrive. |
| `+0x826F` (before the level store) | `[rbp-0x19]` start of the descriptor | Confirm it was zeroed. |
| `+0x8277` (level store) | `qword [rbp-0x11]` | Unpatched: `0x0A000006`. Patched (`+0x8239`): `0x0A000008`. |
| `+0x82AD` (dispatch) | `rcx` = `&descriptor`, `rdx` = output area | `dq rcx L8` shows the descriptor; `+0x08` holds the required level. |
| `+0x82B3` (return check) | `eax` | Compared against `0xC0000016` (`STATUS_MORE_PROCESSING_REQUIRED`); equal means the retry loop continues. |

### Key offsets

- `0x1C0008277` — required-level store `0x0A000006` (Store) in unpatched.
- `0x1C0008239` (patched) — required-level store `0x0A000008` (Microsoft).
- `0x1C000820E` — `call SecIsKernelIntegrityEnabled`, gate 1 (must return true).
- `0x1C000825F` — `call cs:__imp_KeAreApcsDisabled`, must return false.
- `0x1C00082AD` — `call cs:__guard_dispatch_icall_fptr`, integrity callback dispatch.
- `0x1C00082B3` — return compared against `0xC0000016` (retry loop).

### Descriptor / offset notes

```text
descriptor @ [rbp-0x19]  (0x40 bytes)
  +0x00  Size                = 0x40
  +0x08  required level      = 0x0A000006 (unpatched) / 0x0A000008 (patched)   ; low byte = SE_SIGNING_LEVEL
  +0x10  flags               = 0x80000
  +0x30  binding type        = a1
  +0x38  object              = a2 (or a3 when a2 == 0)
output  @ [rbp+0x27]  (0x28 bytes)
```

---

## 8. Changed Functions — Full Triage

Ten functions differ. Only one is security-relevant; the rest are compiler/relocation noise or a benign pool-flag change.

- **`SecKernelIntegrityCheck` (`0x1C00081B8` → `0x1C0008178`)** — **SECURITY-RELEVANT.** Required signing level in the descriptor at offset `+0x08` raised from `0xA000006` (`SE_SIGNING_LEVEL_STORE`) to `0xA000008` (`SE_SIGNING_LEVEL_MICROSOFT`). All other deltas in this function are memset-inlining/zeroing reorder.

*Cosmetic / non-security changes:*

- **`memmove` (`0x1C0001C80`)** — SIMD copy routine restructured (SSE/AVX paths reorganized). Semantically identical memory copy.
- **`SecCreateKernelClient` (`0x1C0008378`)** — variable rename and removal of an unused seed local; magic `0x28df01` init, rundown refcount, and time query unchanged.
- **`SecRegisterKernelExtension` (`0x1C00082F0` → `0x1C0008304`)** — `ExRegisterExtension` registration with identical parameters; struct-init style change only.
- **`SecValidateDriverFileSignatureLevel` (`0x1C00014C0` → `0x1C000169C`)** — variable renames, struct typing and zeroing-style change; the `SecIsWindowsSigned` gate and all status codes are unchanged.
- **`SecBindHost` (`0x1C00010B0` → `0x1C00010E0`)** — `a2` kept in a register and a `min(a2,1)` clamp rewrite; all validation, signature gating, locking, and the callback-table population are unchanged.
- **`DriverEntry` (`0x1C000A008` → `0x1C000A078`)** — added explicit zeroing of a local before `RtlGetVersion`; `OBJECT_ATTRIBUTES` reordered. Initialization sequence semantically identical.
- **`SecCreateDriverValidationKernelEcp` (`0x1C00085FC` → `0x1C0008560`)** — GUID pointer relocated (`data_1c00031c8` → `data_1c00031d8`); memset inlined. FsRtl ECP allocation/insertion logic identical.
- **`__GSHandlerCheckCommon` (`0x1C0001BCC`)** — explicit cast on an intermediate; relocation-driven address shift. Logic identical.
- **`SecAllocateKernelApcObject` (`0x1C0001878` → `0x1C0001884`)** — removed a redundant `mov byte [rbx+0x70], 0` already covered by the preceding structure memset. Allocation and refcount logic identical.

Additional textual differences observed in the independent diff (`DriverUnload`, `SecAllocatePoolWithTag`, `SecFreeKernelApcObject`, `SecDereferenceKernelApcObject`, the three `SecKernelApc*Routine` functions, `SecUninitializeKernelApcSupport`) are relocation and decompiler-artifact differences (return-type inference, lookaside-list field naming). One concrete constant change appears in `SecAllocatePoolWithTag`: the pool type passed to `ExAllocatePoolWithTag` changed from `0x200` to `0x600`. The non-executable bit (`0x200`, `POOL_NX_ALLOCATION`) is retained in both builds; the added `0x400` bit does not remove a mitigation, so this is not a security fix.

No security-relevant change was found beyond the single signing-level constant.

---

## 9. Unmatched Functions

None. `unmatched_unpatched = 0` and `unmatched_patched = 0`. No sanitizer added or mitigation removed; the security-relevant change is entirely the one signing-level constant.

---

## 10. Confidence & Caveats

**Confidence: High for the diff/fix identification; Medium for the descriptor field semantics.**

- **High-confidence items:**
  - The only security-relevant change is the required signing-level constant (`0xA000006` → `0xA000008`), visible in both the decompilation (`v8[1] = 167772166` → `167772168`) and a single-instruction assembly diff.
  - The direction is a tightening: the patched build requires the higher signing level. This is confirmed against both builds and is not reversed.
  - The signing-level numbering is corroborated inside this driver: `SecIsWindowsSigned` uses `SeCompareSigningLevels` against `0x0C` (`SE_SIGNING_LEVEL_WINDOWS`), consistent with `0x06 = STORE` and `0x08 = MICROSOFT`.
  - The reachability path (`SecBindHost` → `off_1C0004008` = `SecDispatchKernelIntegrityCheck` → `SecKernelIntegrityCheck`) is established from the exported `SecBindHost`, the `.data` pointer table at `0x1C0004008`, and the wrapper body at `0x1C0001650`.

- **Inferences / not confirmed:**
  - The specific OS routine behind `qword_1C0007008` is captured from the `ExRegisterCallback` notification and is not resolved to a named kernel export in these binaries. It is described as an OS-provided kernel-integrity callback.
  - The `0x0A000000` high bits of the required-level field are treated as flags/mode carried with the low-byte signing level; the exact bit semantics are not derivable from the diff.
  - The low byte is interpreted as an `SE_SIGNING_LEVEL` value based on the function's role and the corroborating use of `SeCompareSigningLevels` elsewhere in the driver.

- **What to verify before relying on this for exploitation scoping:**
  1. Resolve the routine in `qword_1C0007008` at runtime to confirm exactly how the required level is compared.
  2. Enumerate which bound kernel clients can legitimately reach the callback table entry, and the downstream effect of a successful integrity check.
  3. Confirm, on a live system, the status difference between an object at Store level and one at Microsoft level across the two builds.
