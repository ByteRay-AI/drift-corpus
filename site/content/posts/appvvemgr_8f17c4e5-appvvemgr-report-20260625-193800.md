Title: appvvemgr.sys — No security-relevant change (version rebuild and re-sign, 3570 to 3636)
Date: 2026-06-25
Slug: appvvemgr_8f17c4e5-appvvemgr-report-20260625-193800
Category: Corpus
Author: Argus
Summary: KB5073724
Severity: Informational

---

## 1. Overview

| Field | Value |
|-------|-------|
| **Unpatched Binary** | `appvvemgr_unpatched.sys` |
| **Patched Binary** | `appvvemgr_patched.sys` |
| **Overall Similarity** | 0.9928 |
| **Matched Functions** | 332 |
| **Changed Functions** | 0 |
| **Identical Functions** | 332 |
| **Unmatched (either direction)** | 0 |

> **One-sentence verdict:** The executable code of both builds is byte-identical — the `.text`, `PAGE`, and `INIT` sections match exactly at the byte level — so this pairing carries no code-level vulnerability fix; the binary differences are confined to build metadata (version resource `10.0.19041.3570` → `10.0.19041.3636`, debug-directory GUID, PE and export timestamps) and the Authenticode signature, and the user-kernel message handler `notify_client_message@vemgr_listener_connection_manager` (0x1c00016a0) is documented below as the driver's principal attack surface rather than as a patched defect.

### Nature of the Binary Differences

A section-by-section comparison shows the executable sections are identical: `.text` (104099 bytes of code), `PAGE`, `INIT`, `.pdata`, `.idata`, `.data`, `GFIDS`, and `.reloc` all hash the same in both files. The differing regions are entirely non-code:

- **`.rsrc`** — the version resource changed from `10.0.19041.3570` to `10.0.19041.3636`.
- **`.rdata` debug directory** — the CodeView/RSDS record's PDB signature GUID and age differ (a normal per-build value); the PDB name `AppvVemgr.pdb` is unchanged.
- **`.edata` export directory** and the PE optional-header fields — the build timestamp and checksum differ.
- **Authenticode signature** — the certificate/signature blob at the end of the file was re-generated; the unpatched file is 112 bytes larger solely because of this blob.

**Key binary-level facts:**

- All 11 PE section sizes are identical between the two binaries (`.text`: 104099 bytes, `.rdata`: 33416, `.data`: 1248, `PAGE`: 6720, `INIT`: 1242, etc.) — no code sections were added, removed, or modified. Eight sections hash identically (`.text`, `.data`, `.pdata`, `.idata`, `PAGE`, `INIT`, `GFIDS`, `.reloc`); only `.rsrc`, `.rdata`, and `.edata` differ.
- The 0.9928 overall similarity is accounted for entirely by the version resource, debug GUID, timestamps, and re-signing; none of it falls in an executable section.
- All 332 functions are instruction-identical between the two builds, including `ProcessNotifyCallbackEx`, `PiRegStateReadStackCreationSettingsFromKey`, `SepSddlSecurityDescriptorFromSDDLString`, and `IoDevObjCreateDeviceSecure`.

---

## 2. Vulnerability Summary

### Finding 1: Attack Surface — User-Kernel Message Handler (No Code Change in This Pairing)

| Attribute | Detail |
|-----------|--------|
| **Severity** | Informational (attack-surface documentation; no code change between the two builds) |
| **Vulnerability Class** | Insufficient input validation / authorization bypass surface in user-kernel message handling (CWE-20) |
| **Affected Function** | `?notify_client_message@vemgr_listener_connection_manager@@SAJPEAX0K0KPEAK@Z` at `0x1c00016a0` (1909 bytes, 501 instructions, 6 parameters) |
| **Entry Point** | `FilterConnectCommunicationPort` / `FilterSendMessage` (user-mode) → `FltSendMessage` → minifilter message dispatch |
| **Primitive** | Attack surface for privilege escalation, unauthorized process manipulation, or security descriptor tampering if a validation gap exists in this code path |

#### Root Cause (Attack-Surface Observation)

`appvvemgr.sys` is a kernel-mode minifilter driver that exposes a user-kernel communication port via `FltCreateCommunicationPort`. User-mode processes send messages through this port using `FilterSendMessage`, which the filter manager dispatches to the minifilter's `notify_client_message` handler at `0x1c00016a0`. This is the **largest function in the binary** (1909 bytes) and processes attacker-controlled message buffers, dispatching them to internal virtual environment management methods.

This function is byte-identical between the two builds, so no validation, bounds-checking, or authorization change was applied to it in this pairing. It is documented here because it is the driver's principal attacker-reachable code path. The driver imports highly sensitive kernel APIs that an attacker could reach through this handler:

- `ZwOpenProcess` — open arbitrary process handles
- `ZwTerminateProcess` — kill arbitrary processes
- `ZwOpenProcessTokenEx` / `ZwQueryInformationToken` — inspect/escalate tokens
- `ZwSetSecurityObject` — modify security descriptors
- `ObReferenceObjectByHandle` — reference kernel objects from user-supplied handles
- `SeCaptureSecurityDescriptor` (2 call sites: `0x1c0029008`, `0x1c0029350`)
- `ExAllocatePoolWithTag` (50+ call sites)

If any message handler path reaches one of these APIs without proper validation or authorization, the result ranges from information disclosure to full kernel-mode code execution.

#### Attacker-Reachable Call Chain

1. **User mode:** Attacker calls `FilterConnectCommunicationPort` with the driver's communication port name (located in `.rdata` — needs extraction).
2. **Filter Manager:** `fltMgr.sys` dispatches the connected client's messages via `FltSendMessage`.
3. **Minifilter dispatch:** `notify_client_message@vemgr_listener_connection_manager` (`0x1c00016a0`) receives the message. `FLT_MESSAGE_NOTIFY` convention at entry: `rcx = PortCookie`, `rdx = InputBuffer` (attacker-controlled), `r8 = InputBufferLength`, `r9 = OutputBuffer`, with `OutputBufferLength` and `ReturnOutputBufferLength` on the stack.
4. **Command dispatch:** The first DWORD of `InputBuffer` (offset 0x0) is read as a command code and matched against a series of comparisons (`cmp ebx, 4` / `cmp ebx, 6` / a subtract chain for the rest), selecting a sub-handler.
5. **Sub-handler execution:** Depending on the command code, one of the following is invoked (command code → handler):
   - `1` → `VirtualEnvironmentManager::AddJITVThread` (`0x1c00022bc`)
   - `2` → `VirtualEnvironmentManager::RemoveJITVThread` (`0x1c000209c`)
   - `3` → `VirtualEnvironmentManager::RemoveProcessFromVE` (via `ProcessTracker::FindProcessInVE`)
   - `4` → `VirtualEnvironmentManager::SetJITVInjectionAllowList` (`0x1c0002450`)
   - `5` → `VirtualEnvironmentManager::AddJITVProcess` (`0x1c000261c`)
   - `6` → `VirtualEnvironmentManager::ExePathStartsWithPackageRoot` (`0x1c0001e1c`)
6. **Dangerous API invocation:** The sub-handler processes attacker-supplied parameters (process IDs, thread IDs, SID data, buffer lengths) and calls into sensitive kernel APIs.

---

## 3. Pseudocode Diff

The two builds are instruction-identical in every function, so there is no before/after pseudocode difference for this pairing. The decompiled structure of the message handler at `0x1c00016a0` is shown below to document the attack surface; it is the same in both builds. The handler performs its input validation (minimum length, per-command output-buffer length, and offset/length bounds checks) directly, so there is no missing-check to reconstruct.

### `notify_client_message` (both builds, unchanged)

```c
// notify_client_message@vemgr_listener_connection_manager @ 0x1c00016a0
// Size: 1909 bytes | FLT_MESSAGE_NOTIFY signature (6 params):
//   a1 = PortCookie
//   a2 = InputBuffer             (ATTACKER-CONTROLLED message)
//   a3 = InputBufferLength       (ATTACKER-CONTROLLED)
//   a4 = OutputBuffer
//   a5 = OutputBufferLength
//   a6 = ReturnOutputBufferLength (out)

NTSTATUS notify_client_message(void *PortCookie, int *InputBuffer, ULONG InputBufferLength,
                               int *OutputBuffer, ULONG OutputBufferLength, ULONG *ReturnLength)
{
    *ReturnLength = 0;

    VirtualEnvironmentManager *vem = g_pDeviceExtn->VeManager;   // *(g_pDeviceExtn + 0x20)
    if (vem == NULL || refcount == 0)          // reject if manager not connected
        return 0xC0000016;

    // Minimum-length validation (present in both builds)
    if (InputBufferLength < 0x28 || OutputBufferLength < 4)
        return STATUS_INVALID_PARAMETER;       // 0xC000000D

    ULONG cmd = InputBuffer[0];                 // command code at offset 0x00

    if (cmd == 4) {   // SetJITVInjectionAllowList
        ULONG off = InputBuffer[8];             // +0x20
        USHORT len = *(USHORT*)((char*)InputBuffer + 0x24);
        if ((ULONG)off + len > InputBufferLength)   // bounds check
            return STATUS_INVALID_PARAMETER;
        status = VirtualEnvironmentManager::SetJITVInjectionAllowList(vem, &str);  // 0x1c0002450
        *ReturnLength = 4;
        return status;
    }

    if (cmd == 6) {   // ExePathStartsWithPackageRoot
        if (OutputBufferLength < 0xA2)
            return STATUS_INVALID_PARAMETER;
        // off at +0x20, len WORD at +0x24, flag DWORD at +0x04; bounds-checked
        VirtualEnvironmentManager::ExePathStartsWithPackageRoot(vem, ...);         // 0x1c0001e1c
        // writes a result structure into OutputBuffer; sets *ReturnLength
        return status;
    }

    // Commands 1,2,3,5 — two (offset,length) string regions
    ULONG off1 = InputBuffer[4]; USHORT len1 = *(USHORT*)((char*)InputBuffer + 0x14);  // region 1
    ULONG off2 = InputBuffer[6]; USHORT len2 = *(USHORT*)((char*)InputBuffer + 0x1C);  // region 2
    if ((ULONG)off1 + len1 > InputBufferLength || (ULONG)off2 + len2 > InputBufferLength)
        return STATUS_INVALID_PARAMETER;        // both regions bounds-checked
    ULONG ProcessId = InputBuffer[1];           // +0x04
    ULONG ThreadId  = InputBuffer[2];           // +0x08

    switch (cmd) {
    case 1: status = VirtualEnvironmentManager::AddJITVThread(vem, ProcessId, ThreadId, &sp, str2); break;   // 0x1c00022bc
    case 2: status = VirtualEnvironmentManager::RemoveJITVThread(vem, ProcessId, ThreadId, str2);   break;   // 0x1c000209c
    case 3: status = FindProcessInVE(...) then RemoveProcessFromVE(vem, ProcessId, &sp);            break;
    case 5: status = VirtualEnvironmentManager::AddJITVProcess(vem, ProcessId, &sp, str, flag);     break;   // 0x1c000261c
    default: status = STATUS_INVALID_PARAMETER; break;
    }
    return status;
}
```

Message layout used by the handler, derived from the field accesses above:

| Offset | Size | Field | Used by command |
|--------|------|-------|-----------------|
| 0x00 | DWORD | command code (1,2,3,4,5,6) | all |
| 0x04 | DWORD | ProcessId / flags | 1,2,3,5,6 |
| 0x08 | DWORD | ThreadId | 1,2 |
| 0x0C | DWORD | flags | 6 |
| 0x10 | DWORD | offset of string region 1 | 1,2,3,5 |
| 0x14 | WORD | byte length of region 1 | 1,2,3,5 |
| 0x18 | DWORD | offset of string region 2 | 1,2,3,5 |
| 0x1C | WORD | byte length of region 2 | 1,2,3,5 |
| 0x20 | DWORD | offset of string region 3 | 4,6 |
| 0x24 | WORD | byte length of region 3 | 4,6 |

The minimum accepted `InputBufferLength` is `0x28` (40) bytes, and every offset/length pair is checked against `InputBufferLength` before the referenced bytes are read (`RtlInitUnicodeString` + `managed_unicode_string::assign`). Out-of-range inputs return `STATUS_INVALID_PARAMETER` (`0xC000000D`).

---

## 4. Assembly Analysis

### `notify_client_message@vemgr_listener_connection_manager`

The full function is 1909 bytes. This function is byte-identical in both builds. The prologue, the input-length validation, and the command dispatch are shown below verbatim from the disassembly.

```asm
; ============================================================
; notify_client_message@vemgr_listener_connection_manager
; Start: 0x1c00016a0 | Size: 1909 bytes | identical in both builds
; ============================================================
; PRIMARY USER-KERNEL MESSAGE HANDLER (FLT_MESSAGE_NOTIFY)
;
; Register convention at entry (x64 calling convention):
;   rcx = PortCookie
;   rdx = InputBuffer (PVOID) — ATTACKER-CONTROLLED
;   r8d = InputBufferLength (ULONG) — ATTACKER-CONTROLLED
;   r9  = OutputBuffer
;   [rsp+0x28] = OutputBufferLength (ULONG)  (spilled to arg_20)
;   [rsp+0x30] = ReturnOutputBufferLength (PULONG) (spilled to arg_28)

0x1c00016a0  mov     rax, rsp                    ; prologue
0x1c00016a3  mov     [rax+8], rbx                ; save nonvolatile regs
0x1c00016a7  mov     [rax+10h], rsi
0x1c00016ab  mov     [rax+18h], rdi
0x1c00016af  mov     [rax+20h], r9
...
0x1c00016c8  mov     rax, [rbp+80h+arg_28]       ; ReturnOutputBufferLength
0x1c00016d5  mov     [rax], r12d                 ; *ReturnOutputBufferLength = 0
0x1c00016d8  mov     rax, cs:?g_pDeviceExtn@vemgr@@3PEAUDEVICE_EXTENSION@1@EA
0x1c00016e3  mov     r14, [rax+20h]              ; VirtualEnvironmentManager
...
; --- input-length validation (present in both builds) ---
0x1c0001718  cmp     r8d, 28h                    ; InputBufferLength >= 0x28 ?
0x1c000171c  jb      loc_1C00017EC               ; -> STATUS_INVALID_PARAMETER
0x1c0001722  cmp     [rbp+80h+arg_20], 4         ; OutputBufferLength >= 4 ?
0x1c0001729  jb      loc_1C00017EC
0x1c000172f  mov     ebx, [rdx]                  ; command code = InputBuffer[0]
0x1c0001731  cmp     ebx, 4                      ; cmd 4 -> SetJITVInjectionAllowList
0x1c0001734  jnz     loc_1C00017F6
; --- cmd 4: bounds-check region-3 (offset [rdx+20h], len [rdx+24h]) ---
0x1c000173a  movzx   ecx, word ptr [rdx+24h]     ; length
0x1c000173e  mov     r9d, [rdx+20h]              ; offset
0x1c0001742  lea     eax, [r9+rcx]
0x1c0001746  cmp     eax, r8d                    ; offset+length <= InputBufferLength ?
0x1c0001749  ja      loc_1C00017EC               ; -> STATUS_INVALID_PARAMETER
...
0x1c00017c5  call    ?SetJITVInjectionAllowList@...@Z    ; 0x1c0002450

0x1c00017ec  mov     edi, 0C000000Dh             ; STATUS_INVALID_PARAMETER
0x1c00017f1  jmp     loc_1C0001DB4               ; reject path

; --- cmd 6 branch (loc_1C00017F6): requires OutputBufferLength >= 0xA2 ---
0x1c00017f6  cmp     ebx, 6
0x1c00017ff  cmp     [rbp+80h+arg_20], 0A2h
0x1c0001809  jb      loc_1C00017EC
0x1c00018fc  call    ?ExePathStartsWithPackageRoot@...@Z ; 0x1c0001e1c

; --- cmd 1/2/3/5 branch (loc_1C0001A40): two (offset,len) regions ---
0x1c0001a40  movzx   r14d, word ptr [rdx+14h]    ; region-1 length
0x1c0001a45  mov     ecx, [rdx+10h]              ; region-1 offset
0x1c0001a4c  cmp     eax, r8d                    ; bounds check vs InputBufferLength
0x1c0001a4f  ja      loc_1C00017EC
0x1c0001a55  movzx   r15d, word ptr [rdx+1Ch]    ; region-2 length
0x1c0001a5a  mov     r9d, [rdx+18h]              ; region-2 offset
0x1c0001a62  cmp     eax, r8d
0x1c0001a65  ja      loc_1C00017EC
0x1c0001ad2  mov     r8d, 66446753h              ; ExAllocatePoolWithTag Tag
; subtract chain selects the handler:
0x1c0001bb5  sub     ebx, 1                       ; cmd 1 -> AddJITVThread (0x1c00022bc)
0x1c0001bb8  jz      loc_1C0001CBC
0x1c0001bbe  sub     ebx, 1                       ; cmd 2 -> RemoveJITVThread (0x1c000209c)
0x1c0001bc1  jz      loc_1C0001CA7
0x1c0001bc7  sub     ebx, 1                       ; cmd 3 -> FindProcessInVE/RemoveProcessFromVE
0x1c0001bca  jz      loc_1C0001C18
0x1c0001bcc  cmp     ebx, 2                       ; cmd 5 -> AddJITVProcess (0x1c000261c)
0x1c0001bcf  jz      loc_1C0001BF1
```

### Assembly Diff: None

A side-by-side assembly diff is empty for this pairing: the `.text` section is byte-identical between the two files and every function hashes the same. Confirmed via:

1. Section-level hashing of both PE files — `.text`, `PAGE`, `INIT`, `.pdata`, `.idata`, `.data`, `GFIDS`, and `.reloc` all match.
2. A raw byte comparison of the `.text` section — zero differing bytes across the byte range `0x1c00016a0` through `0x1c0001e25` (1909 bytes of `notify_client_message`) and across the 7 `VirtualEnvironmentManager` JITV methods and `VEMgrNotifications::SendNotification` (`0x1c0005204`).
3. The only differing bytes fall in the version resource, debug directory, PE/export timestamps, and the Authenticode signature.

---

## 5. Trigger Conditions

> The following steps exercise the message handler's attack surface. The command codes (1-6) and the message layout are taken from the dispatch code at `0x1c00016a0` shown in sections 3 and 4. This handler is byte-identical in both builds, so there is no behavioral difference between the two versions to trigger.

1. **Load the driver.** Ensure `appvvemgr.sys` is loaded as a minifilter (it registers via `FltRegisterFilter`). Verify with `fltmc instances` or `!fltkd.filter` in WinDbg.

2. **Identify the communication port name.** Search `.rdata` (around `0x1c0028xxx`) for the Unicode string passed to `FltCreateCommunicationPort`. This is the port name the attacker must connect to.

3. **Open the communication port from user mode.**
   ```c
   HANDLE hPort;
   HRESULT hr = FilterConnectCommunicationPort(
       L"\\<port_name>",     // from step 2
       0,                     // options
       NULL,                  // context
       0,                     // context size
       NULL,                  // security attributes
       &hPort                 // out: client port handle
   );
   ```

4. **Construct a message buffer.** The message begins with a DWORD command code at offset 0x0. The layout that the handler reads (from sections 3 and 4) is:
   ```c
   struct VEMGR_MSG {          // minimum accepted length 0x28 (40) bytes
       DWORD CommandCode;      // 0x00 — 1..6
       DWORD ProcessId;        // 0x04
       DWORD ThreadId;         // 0x08
       DWORD Flags;            // 0x0C
       DWORD Region1Offset;    // 0x10 — bounds-checked: offset+len <= InputBufferLength
       WORD  Region1Length;    // 0x14
       DWORD Region2Offset;    // 0x18 — bounds-checked
       WORD  Region2Length;    // 0x1C
       DWORD Region3Offset;    // 0x20 — bounds-checked (commands 4, 6)
       WORD  Region3Length;    // 0x24
       // string data referenced by the region offsets follows
   };
   ```

5. **Send the message via `FilterSendMessage`:**
   ```c
   BYTE buffer[256] = {0};       // >= 0x28 bytes or the handler rejects it
   *(DWORD*)(buffer + 0x00) = 1; // command 1 = AddJITVThread (2/3/4/5/6 select the others)
   *(DWORD*)(buffer + 0x04) = ProcessId;
   *(DWORD*)(buffer + 0x08) = ThreadId;
   // region offsets/lengths at 0x10/0x14, 0x18/0x1C, 0x20/0x24 must stay within the buffer
   DWORD replyLen = 0;
   HRESULT hr = FilterSendMessage(
       hPort,
       buffer,
       sizeof(buffer),
       replyBuf, sizeof(replyBuf),   // OutputBuffer (>= 4 bytes required)
       &replyLen
   );
   ```

6. **Boundary vectors and their observed handling (both builds):**
   - **Undersized buffer (`InputBufferLength < 0x28`):** rejected with `STATUS_INVALID_PARAMETER` (`0xC000000D`) at `0x1c0001718` before any field is read.
   - **`OutputBufferLength < 4` (or `< 0xA2` for command 6):** rejected with `STATUS_INVALID_PARAMETER`.
   - **Region offset+length exceeding `InputBufferLength`:** rejected with `STATUS_INVALID_PARAMETER`; each of the three (offset, length) pairs is checked before its bytes are read.
   - **Command code outside 1..6:** falls through to the default and returns `STATUS_INVALID_PARAMETER`.
   - **Command 4 with a valid allow-list string / command 1 with `ProcessId`/`ThreadId`:** reaches `SetJITVInjectionAllowList` / `AddJITVThread`; observe whether a non-privileged client can connect to the port and reach these handlers, and how `ProcessId`/`ThreadId` are consumed downstream.

7. **Ordering constraints.** The `AddJITVThread`/`RemoveJITVThread`/`AddJITVProcess`/`RemoveProcessFromVE` handlers operate on a `VirtualEnvironment` that is looked up by `ProcessId`; a corresponding virtual environment must exist (established via a prior message) or `FindProcessInVE` returns an error and the operation is a no-op.

8. **Observed handler responses:**
   - **Out-of-range input (undersized buffer, out-of-bounds region offset/length, unknown command):** returns `STATUS_INVALID_PARAMETER` (`0xC000000D`); no dispatch occurs.
   - **Well-formed command 4:** reaches `SetJITVInjectionAllowList`; `*ReturnLength` is set to 4 and the handler's status is returned.
   - **Well-formed command 1/2/3/5:** reaches the corresponding `VirtualEnvironmentManager` method after both string regions are copied via `managed_unicode_string::assign`.
   - Because the two builds are byte-identical, these responses are the same in the patched and unpatched drivers.

---

## 6. Exploit Primitive & Development Notes

### No Primitive Introduced or Removed in This Pairing

No exploit primitive is provided by this pairing: the `.text` section is byte-identical between the two builds, so no defense was added and no defect was removed. The message handler at `0x1c00016a0` performs the input validation shown in sections 3 and 4 — a minimum `InputBufferLength` of `0x28`, an `OutputBufferLength` floor (`4`, or `0xA2` for command 6), and an offset+length bounds check on each of the three string regions against `InputBufferLength` — and returns `STATUS_INVALID_PARAMETER` (`0xC000000D`) on any out-of-range input. Nothing in the two binaries demonstrates a length, bounds, or authorization defect in this handler.

### Verifiable Binary Facts Relevant to Exploitability

- **Control Flow Guard is compiled in.** The handler dispatches virtual calls through `__guard_dispatch_icall_fptr` (for example at `0x1c0001a13`, `0x1c0001c81`, `0x1c0001c9f`), so indirect calls are CFG-checked.
- **Pool allocations in the handler use tag `0x66446753`** (`mov r8d, 66446753h` at `0x1c0001ad2`, allocated via `ExAllocatePoolWithTag` at `0x1c0001ade`).
- **The security-descriptor path uses tag `0x64536553` (`'SeSd'`)** in `SepSddlSecurityDescriptorFromSDDLString`, allocated at `0x1c00285ca`.

Any future exploitation work must first identify an actual defect in this driver; none is present in the difference between these two builds.

---

## 7. Debugger PoC Playbook

> The following is oriented toward a researcher with WinDbg/KD attached to a system running the **unpatched** `appvvemgr.sys`.

### Phase 0: Binary Diff (Already Performed)

A byte-level diff of the two `.sys` files was performed and confirms the code is unchanged:

```
// In WinDbg or offline:
1. Extract .text section from both PE files
2. Hash each PE section from both files and compare
   OR: raw byte compare of the .text bytes
3. Result: .text / PAGE / INIT are byte-identical; the only
   differing bytes are in .rsrc (version), .rdata debug directory
   (PDB GUID), .edata/header timestamps, and the signature
4. No differing bytes map to any function boundary
```

### Breakpoints

```text
// Primary message handler — break on EVERY user-kernel message
bp appvvemgr_unpatched!notify_client_message@vemgr_listener_connection_manager
// = bp 0x1c00016a0
// WHY: This is the entry point for all attacker-controlled messages.
//      Inspect rcx/rdx/r8/r9 at entry to capture the message.

// Command 1 handler (JITV thread add)
bp appvvemgr_unpatched!VirtualEnvironmentManager::AddJITVThread
// = bp 0x1c00022bc
// WHY: Looks up the ProcessTracker entry (indexed_avl_tree::find) under an
//      ExAcquireResourceExclusiveLite lock and calls ProcessTrackerValue::AddJitvThread.
//      Operates on internal tracking state; it does not call ZwOpenProcess.

// Command 4 handler (injection allow-list modification)
bp appvvemgr_unpatched!VirtualEnvironmentManager::SetJITVInjectionAllowList
// = bp 0x1c0002450
// WHY: Under a mutex (scoped_lock), edits the package-config doubly_linked_list.
//      No SeAccessCheck/token call is present inside this function.

// Process notification callback (identical — reference only)
bp appvvemgr_unpatched!ProcessNotifyCallbackEx
// = bp 0x1c0015340
// WHY: Process create/exit callback; calls FltGetFileNameInformationUnsafe and
//      VirtualEnvironmentManager::AddProcess. It does not call token APIs.

// Dangerous API calls — set conditional breakpoints
bp nt!ZwOpenProcess ".if /q @$rcx == 0x1c00016a0 {} .else {gc}"
// Adjust condition to filter for calls originating from notify_client_message's
// call tree. Use return address on stack to filter.
```

### What to Inspect at Each Breakpoint

**At `notify_client_message` entry (`0x1c00016a0`):**

```text
// Registers at entry (FLT_MESSAGE_NOTIFY):
//   rcx = PortCookie
//   rdx = InputBuffer — POINTER TO ATTACKER MESSAGE
//   r8d = InputBufferLength — ATTACKER-CONTROLLED LENGTH
//   r9  = OutputBuffer
//   [rsp+0x28] = OutputBufferLength, [rsp+0x30] = ReturnOutputBufferLength

// Commands to run:
dd rdx L1                  // command code at offset 0x00 (valid: 1..6)
dd rdx+4 L1                // ProcessId (offset 0x04)
dd rdx+8 L1                // ThreadId  (offset 0x08)
?? r8d                     // InputBufferLength (must be >= 0x28 to pass validation)

// Follow the dispatch: the length checks are at 0x1c0001718 (r8d >= 0x28)
// and 0x1c0001722 (OutputBufferLength >= 4); the command compares are at
// 0x1c0001731 (==4), 0x1c00017f6 (==6), and the subtract chain at 0x1c0001bb5.
```

**At `AddJITVThread` (`0x1c00022bc`):**

```text
// rcx = this (VirtualEnvironmentManager); edx = ProcessId; r8d = ThreadId
// The handler acquires an ExAcquireResourceExclusiveLite lock, looks up the
// ProcessTracker entry via indexed_avl_tree::find (0x1c000232c), and calls
// ProcessTrackerValue::AddJitvThread (0x1c00023ba). Inspect edx/r8d and the
// AVL lookup result; no process handle is opened here.
```

**At `SetJITVInjectionAllowList` (`0x1c0002450`):**

```text
// rcx = this (VirtualEnvironmentManager); rdx = &managed_unicode_string (allow-list entry)
// The function takes a mutex (scoped_lock at 0x1c0002480), edits the package-config
// doubly_linked_list (erase/push_back), and allocates via ExAllocatePoolWithTag
// (0x1c0002531). No SeAccessCheck, privilege test, or token query is called inside
// this function; any access control is at the port-connect layer, not here.
```

### Key Instructions / Offsets

| Offset | Symbol / Meaning |
|--------|-----------------|
| `0x1c00016a0` | `notify_client_message` function start — primary attack surface, 1909 bytes |
| `0x1c000209c` | `RemoveJITVThread` (544 bytes) — JITV thread removal handler |
| `0x1c00022bc` | `AddJITVThread` (404 bytes) — JITV thread injection handler |
| `0x1c0002450` | `SetJITVInjectionAllowList` (460 bytes) — injection policy modifier |
| `0x1c0005204` | `VEMgrNotifications::SendNotification` — outbound notification (calls FltSendMessage) |
| `0x1c0005397`, `0x1c0005439` | `FltSendMessage` call sites within `SendNotification` |
| `0x1c0015340` | `ProcessNotifyCallbackEx` — identical between binaries |
| `0x1c00082d4` | `ZwOpenProcessTokenEx` call site |
| `0x1c000a013` | `ZwQueryInformationToken` call site |
| `0x1c0029008`, `0x1c0029350` | `SeCaptureSecurityDescriptor` call sites |
| `0x1c00285ca` | `ExAllocatePoolWithTag` in `SepSddlSecurityDescriptorFromSDDLString` — pool tag `'SeSd'` (0x64536553) |
| `0x1c0001ad2` / `0x1c0001ade` | pool tag `0x66446753` / `ExAllocatePoolWithTag` inside `notify_client_message` |
| `0x1c00016d8` | load of `vemgr::g_pDeviceExtn` (`DEVICE_EXTENSION`); VE manager at `+0x20` |

> **No instruction was patched or removed in this pairing.** The byte-diff maps entirely to the version resource, debug directory, timestamps, and signature; none of the code addresses above changed.

### Trigger Setup

1. **Ensure the driver is loaded:**
   ```
   !fltkd.filters    // in WinDbg — confirm appvvemgr is registered
   fltmc instances   // from admin cmd — confirm filter is attached
   ```

2. **Find the communication port name:** Search `.rdata` in the unpatched binary for the Unicode string passed to `FltCreateCommunicationPort`:
   ```
   // In WinDbg:
   !for_each_module
   // Then search .rdata for L"\\..." port name patterns
   s -u <module_base>+<.rdata_rva> l<.rdata_size> \\\\
   ```

3. **Compile and run a user-mode client:**
   ```c
   #include <fltuser.h>
   #pragma comment(lib, "fltlib.lib")
   
   int main() {
       HANDLE hPort;
       HRESULT hr = FilterConnectCommunicationPort(
           L"\\AppVveMgrPort",  // replace with actual port name
           0, NULL, 0, NULL, &hPort);
       if (FAILED(hr)) return -1;
       
       // Fuzz: iterate command codes 0x0 through 0xFF
       for (DWORD cmd = 0; cmd < 256; cmd++) {
           BYTE buf[512] = {0};
           *(DWORD*)buf = cmd;
           DWORD reply = 0;
           FilterSendMessage(hPort, buf, sizeof(buf),
                             NULL, 0, &reply);
       }
       CloseHandle(hPort);
       return 0;
   }
   ```

4. **Monitor in debugger:** With breakpoints set on `notify_client_message` and the JITV handlers, observe which command codes reach which sub-handlers. Compare the code path taken in the unpatched binary against the patched binary.

### Expected Observation

Both builds contain identical handler code, so the observed behavior is the same in each:

| Input | Observed Behavior |
|-------|-------------------|
| `InputBufferLength < 0x28`, out-of-bounds region offset/length, or command code outside 1..6 | Handler returns `STATUS_INVALID_PARAMETER` (`0xC000000D`); no sub-handler runs |
| Well-formed command 4 | Reaches `SetJITVInjectionAllowList`; `*ReturnOutputBufferLength` set to 4 |
| Well-formed command 1/2/3/5 | Reaches the matching `VirtualEnvironmentManager` method after both string regions are copied |
| Same message to patched vs. unpatched | Identical code path and result (`.text` is byte-identical) |

### Struct / Offset Notes

The message layout the handler reads, taken directly from the field accesses in the dispatch code at `0x1c00016a0`:

```
// Message layout (minimum accepted InputBufferLength = 0x28):
offset 0x00: DWORD  CommandCode       // 1..6
offset 0x04: DWORD  ProcessId / flags
offset 0x08: DWORD  ThreadId
offset 0x0C: DWORD  flags             // command 6
offset 0x10: DWORD  Region1Offset     // bounds-checked against InputBufferLength
offset 0x14: WORD   Region1Length
offset 0x18: DWORD  Region2Offset     // bounds-checked
offset 0x1C: WORD   Region2Length
offset 0x20: DWORD  Region3Offset     // bounds-checked (commands 4, 6)
offset 0x24: WORD   Region3Length
// string data referenced by the region offsets follows
```

---

## 8. Changed Functions — Full Triage

> **No functions changed.** All 332 functions are instruction-identical between the two builds, confirmed by section-level and byte-level comparison of `.text`. The 0.9928 overall similarity is driven by non-code bytes (version resource, debug GUID, timestamps, signature).

### Spot-Checked Identical Functions

These functions were spot-checked and confirmed instruction-identical; the whole `.text` section is identical:

| Function | Address | Size | Notes |
|----------|---------|------|-------|
| `ProcessNotifyCallbackEx` | `0x1c0015340` | — | Process create/exit callback; uses `ZwOpenProcessTokenEx` + `ZwQueryInformationToken`. Identical between binaries. |
| `PiRegStateReadStackCreationSettingsFromKey` | `0x1c0028f60` | — | Registry settings reader. Identical. |
| `SepSddlSecurityDescriptorFromSDDLString` | `0x1c00284cc` | — | SDDL string → SD conversion; uses `ExAllocatePoolWithTag` with tag `'SeSd'`. Identical. |
| `IoDevObjCreateDeviceSecure` | `0x1c0028190` | — | Secure device creation wrapper. Identical. |

### Attack-Surface Functions (Unchanged)

The following functions carry the driver's attack surface. They are byte-identical between the two builds; they are listed for future reference, ranked by attack-surface relevance:

| Priority | Function | Address | Size | Why |
|----------|----------|---------|------|-----|
| **1** | `notify_client_message@vemgr_listener_connection_manager` | `0x1c00016a0` | 1909 bytes | Largest function; primary user-kernel message handler; processes attacker-controlled buffers |
| **2** | `VirtualEnvironmentManager::AddJITVThread` | `0x1c00022bc` | 404 bytes | Handles process/thread injection from user messages |
| **3** | `VirtualEnvironmentManager::SetJITVInjectionAllowList` | `0x1c0002450` | 460 bytes | Modifies injection policy — authorization bypass candidate |
| **4** | `VEMgrNotifications::SendNotification` | `0x1c0005204` | — | Calls `FltSendMessage` at `0x1c0005397`, `0x1c0005439` |
| **5** | `create_connection@flt_connection<vemgr_listener_connection_manager>` | `0x1c00027a4`, `0x1c00029a4` | — | Connection setup — validates client identity |
| **6** | `VirtualEnvironmentManager::RemoveJITVThread` | `0x1c000209c` | 544 bytes | JITV thread removal; state transitions |

### Register Allocation / Cosmetic Changes

There are no instruction-level differences at all between the two builds, so there is nothing to attribute to register-allocation reordering or instruction scheduling. The version resource changed from `10.0.19041.3570` to `10.0.19041.3636`, which is the meaningful difference and reflects a rebuild rather than a code fix.

---

## 9. Unmatched Functions

| Direction | Count | Details |
|-----------|-------|---------|
| **Removed (unpatched only)** | 0 | None |
| **Added (patched only)** | 0 | None |

No functions were added or removed. Combined with identical section sizes and a byte-identical `.text`, this confirms no code changed between the two builds. No added sanitizer function or removed vulnerable function exists in this pairing.

---

## 10. Confidence & Caveats

### Confidence Level: **HIGH (no code change in this pairing)**

| Aspect | Confidence | Rationale |
|--------|------------|-----------|
| **A vulnerability was patched** | **NONE** | `.text`, `PAGE`, and `INIT` are byte-identical; every function hashes the same; no code changed |
| **This pairing is a version rebuild** | **HIGH** | Only differences are the version resource (3570 → 3636), debug GUID, timestamps, and Authenticode signature |
| **`notify_client_message` is the primary attack surface** | **HIGH** | It is the largest function and the reachable user-kernel message handler; confirmed present at `0x1c00016a0` |
| **Command codes and message layout** | **HIGH** | Taken directly from the dispatch code at `0x1c00016a0` (commands 1..6; layout in sections 3, 4, 7) |

### Notes

1. **Port name:** The communication port name was not extracted for this report; it is the string argument to `FltCreateCommunicationPort` and can be recovered from `.rdata`.

2. **Message layout confirmed:** The message layout (command DWORD at offset 0, `ProcessId`/`ThreadId` at 0x04/0x08, three bounds-checked (offset,length) string regions) is read directly from the field accesses in the dispatch code, not inferred.

3. **Dispatch confirmed:** `notify_client_message` dispatches with a command-code compare chain (`cmp ebx, 4` at `0x1c0001731`, `cmp ebx, 6` at `0x1c00017f6`, and a subtract chain at `0x1c0001bb5`), not a jump table.

4. **Call chain:** `FilterConnectCommunicationPort → FltSendMessage → notify_client_message` follows from the driver being a registered minifilter with a communication port.

5. **No patch to model:** Because the code is identical, there is no before/after behavior to reconstruct. The decompilation and disassembly above document the current (and unchanged) handler.

### What a Researcher Must Verify Manually

For future auditing of this attack surface (independent of this unchanged pairing):

1. **Byte-level diff already done:** section hashing and a raw `.text` comparison show no code differences; the differing bytes are the version resource, debug directory, timestamps, and signature.

2. **Identify the communication port name** by locating the string argument to `FltCreateCommunicationPort` in `.rdata`.

3. **Dispatch enumerated (done):** the valid command codes are 1..6, mapped to their handlers in sections 3 and 4.

4. **Message layout mapped (done):** the field offsets used by the handler are listed in sections 3 and 7.

5. **Confirm the metadata delta:** the only observable change is the version resource (`10.0.19041.3570` → `10.0.19041.3636`); no code string was added or removed.

6. **Authorization model:** `notify_client_message` itself performs no `SeAccessCheck`, `FltGetClientPort`, or token inspection before dispatching; any client-side gating is at the port-connect stage (`create_connection` at `0x1c00027a4`). Confirm what, if anything, `create_connection` enforces on connecting clients.

7. **Trace each dangerous API call** (`ZwOpenProcess`, `ZwTerminateProcess`, `ZwSetSecurityObject`, `ObReferenceObjectByHandle`) backward from the call site to determine if its arguments derive from attacker-controlled message fields without validation.
