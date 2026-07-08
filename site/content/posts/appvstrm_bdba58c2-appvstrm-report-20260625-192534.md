Title: appvstrm.sys — No security-relevant change (code-identical rebuild; version bump 10.0.17763.3469 → 10.0.17763.4010)
Date: 2026-06-25
Slug: appvstrm_bdba58c2-appvstrm-report-20260625-192534
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Informational

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `appvstrm_unpatched.sys` |
| Patched binary | `appvstrm_patched.sys` |
| Overall similarity | 0.993 |
| Matched functions | 274 |
| Changed functions | 0 |
| Identical functions | 274 |
| Unmatched (unpatched) | 0 |
| Unmatched (patched) | 0 |
| Byte-level delta | Build metadata only: COFF link timestamp, debug-directory PDB GUID (`.rdata`), version resource (`.rsrc`, `10.0.17763.3469` → `10.0.17763.4010`), and the Authenticode certificate block. Executable code is unchanged. |
| ASCII string delta | +3 strings (1711 → 1714), in the certificate/timestamp block |

**Verdict:** Every function body is byte-for-byte identical between the two binaries — 274/274 functions match exactly, in both the disassembly and the decompilation. The executable code section (`.text`, file offsets `0x400`–`0x14400`) is byte-identical, as are `.data`, `.pdata`, `.idata`, and `.reloc`. This is a fresh rebuild that produced identical code: the differing bytes are confined to build metadata — the COFF link timestamp (file offset `0xE8`), the debug directory's CodeView/PDB GUID inside `.rdata` (the PDB name `Appvstrm.pdb` is unchanged), the version resource in `.rsrc` (`FileVersion`/`ProductVersion` advance from `10.0.17763.3469` to `10.0.17763.4010`), and the PE Authenticode certificate block (re-signed; the countersignature timestamps advance from 2022 to 2023 and the timestamp-service certificate organization changes from `Microsoft Operations Puerto Rico` to `Microsoft Ireland Operations Limited`). `appvstrm.sys` carries no CVE attribution in this update. No code-level security change is present. The note below documents an unchanged architectural characteristic of the message-dispatch path for completeness; it is present identically in both builds and, as shown, does not constitute a reachable authorization gap.

---

## 2. Architectural Note

### Finding 1 — Message dispatch relies solely on the port security descriptor (informational; present identically in both builds)

- **Severity:** Informational
- **Class:** Design note (per-message authorization is not re-checked inside the dispatcher). This is not a missing-authorization vulnerability for unprivileged callers: the communication port is built with `FltBuildDefaultSecurityDescriptor`, which restricts access to Administrators and SYSTEM. No code or port-descriptor change exists between the two builds.
- **Affected surface:** `Streaming::Messaging::UserCommunication::ProcessMessage` (`0x1C0012B80`) dispatch, reached through the port created in `Streaming::Messaging::UserCommunication::Initialize` (`0x1C0012A80`) via `FltCreateCommunicationPort`.

#### Description

`appvstrm.sys` is a Windows kernel minifilter that exposes a set of staging operations to a connected client through a filter communication port (`FltSendMessage` / user-mode `FilterSendMessage`). `ProcessMessage` selects an operation from the leading DWORD of the input buffer:

| Type | Handler | Address |
|---|---|---|
| 1 | `create_file` | `0x1C000FCB4` |
| 2 | `write_file` | `0x1C000FE44` |
| 3 | `request_mdl` (allocates + maps MDLs) | `0x1C0010404` |
| 6 | `query_sparse_file` | `0x1C001059C` |
| 7 | `create_hard_link` | `0x1C00106AC` |
| 8 | `config` (writes a global flag at `gStrmFltData+0x30`) | dispatch block `0x1C0012CB6` |
| 9 | `set_directory_DACL` | `0x1C0010300` |

That is seven handled message types (1, 2, 3, 6, 7, 8, 9). `ProcessMessage` performs no per-message re-check of the caller — it dispatches on the leading DWORD after a minimum-size gate. Authorization is enforced once, at the port: `Initialize` (`0x1C0012A80`) requests `DesiredAccess = FLT_PORT_ALL_ACCESS` (`0x1F0001`, set at `0x1C0012AA0`) and calls `FltBuildDefaultSecurityDescriptor` (`0x1C0012AAC`) to build the descriptor passed to `FltCreateCommunicationPort` (`0x1C0012B37`). `FltBuildDefaultSecurityDescriptor` grants the requested access to Administrators and SYSTEM only; other callers are denied at `FilterConnectCommunicationPort`. This is the standard minifilter authorization model. Both the dispatch code and this port-init path are byte-identical in the two builds.

#### Entry point & data flow

1. **User mode:** `FilterConnectCommunicationPort` opens a handle to the minifilter's communication port. The port names in the driver are `\StrmFltCommunicationClientServerPort` and `\StrmFltCommunicationServerClientPort`.
2. **Filter Manager:** `FltSendMessage` forwards the buffer to the minifilter.
3. **Kernel:** `NotifyPortMessage` (`0x1C0012960`) receives the message and calls `ProcessMessage` (call at `0x1C0012976`).
4. **Kernel:** `ProcessMessage` (`0x1C0012B80`) reads `*(uint32_t*)InputBuffer` and dispatches.
5. **Kernel:** For type 7 → `create_hard_link` (`0x1C00106AC`); type 9 → `set_directory_DACL` (`0x1C0010300`); type 1 → `create_file` (`0x1C000FCB4`). These handlers do not re-validate caller identity, because access is already constrained to Administrators/SYSTEM at the port.

---

## 3. Pseudocode

There is **no code diff**. The two binaries' `ProcessMessage` functions are identical. The pseudocode below is the common dispatch logic.

```c
// Streaming::Messaging::UserCommunication::ProcessMessage  @ 0x1C0012B80
// (identical in BOTH binaries)

NTSTATUS ProcessMessage(
    void        *this,
    void        *InputBuffer,     // rdx
    uint32_t     InputSize,       // r8d
    void        *OutputBuffer,    // r9
    uint32_t     OutputSize,      // arg_20
    uint32_t    *BytesReturned)   // arg_28
{
    if (InputSize < 8)                          // cmp r8d,8 @ 0x1C0012BB4
        return STATUS_INVALID_PARAMETER;

    uint32_t type = *(uint32_t *)InputBuffer;   // mov ecx,[rdx] @ 0x1C0012BE5

    // decrement chain (sub ecx,1 / jz ...), not a cmp table
    switch (type)
    {
        case 1: /* create_file        */ break; // 0x1C000FCB4, call @ 0x1C0012F1D
        case 2: /* write_file         */ break; // 0x1C000FE44, call @ 0x1C0012E0A
        case 3: /* request_mdl        */ break; // 0x1C0010404, call @ 0x1C0012D6E
        case 6: /* query_sparse_file  */ break; // 0x1C001059C, call @ 0x1C0012D3C
        case 7: /* create_hard_link   */ break; // 0x1C00106AC, call @ 0x1C0012D09
        case 8: /* config             */ break; // block @ 0x1C0012CB6
        case 9: /* set_directory_DACL */ break; // 0x1C0010300, call @ 0x1C0012CAC
        default: return STATUS_INVALID_PARAMETER;
    }
    // Authorization is enforced at the port, not here: the port descriptor
    // built by FltBuildDefaultSecurityDescriptor restricts access to
    // Administrators and SYSTEM.
}
```

**What the image difference actually is:** build metadata only (COFF timestamp, debug-directory PDB GUID, version resource `10.0.17763.3469` → `10.0.17763.4010`, and the Authenticode certificate). The port-init path in `Initialize` (`0x1C0012A80`), including the `FltBuildDefaultSecurityDescriptor` / `FltCreateCommunicationPort` calls, is byte-identical in both images.

---

## 4. Assembly Analysis

No instruction-level diff exists. The following is the dispatch sequence in the **unpatched** binary (byte-identical in patched). The `jz` targets are local blocks that then call the named handlers; the handler addresses and call sites are given in the comments.

```asm
; === ProcessMessage @ 0x1C0012B80 (unpatched; identical in patched) ===
; rcx = this, rdx = InputBuffer, r8d = InputSize

0x1C0012BB4  cmp     r8d, 8
0x1C0012BB8  jnb     loc_1C0012BE5      ; size < 8 -> STATUS_INVALID_PARAMETER
0x1C0012BE5  mov     ecx, [rdx]         ; message type from input buffer
0x1C0012BE7  sub     ecx, 1
0x1C0012BEA  jz      loc_1C0012E8D      ; type 1 -> create_file        (0x1C000FCB4, call @ 0x1C0012F1D)
0x1C0012BF0  sub     ecx, 1
0x1C0012BF3  jz      loc_1C0012D7A      ; type 2 -> write_file         (0x1C000FE44, call @ 0x1C0012E0A)
0x1C0012BF9  sub     ecx, 1
0x1C0012BFC  jz      loc_1C0012D5C      ; type 3 -> request_mdl        (0x1C0010404, call @ 0x1C0012D6E)
0x1C0012C02  sub     ecx, 3
0x1C0012C05  jz      loc_1C0012D10      ; type 6 -> query_sparse_file  (0x1C001059C, call @ 0x1C0012D3C)
0x1C0012C0B  sub     ecx, 1
0x1C0012C0E  jz      loc_1C0012CF7      ; type 7 -> create_hard_link   (0x1C00106AC, call @ 0x1C0012D09)
0x1C0012C14  sub     ecx, 1
0x1C0012C17  jz      loc_1C0012CB6      ; type 8 -> config (writes gStrmFltData+0x30)
0x1C0012C1D  cmp     ecx, 1
0x1C0012C20  jz      loc_1C0012C9A      ; type 9 -> set_directory_DACL (0x1C0010300, call @ 0x1C0012CAC)

; Sub-handler size gates (informational):
;   request_mdl: cmp edx, 0Ch    @ 0x1C0010432  (minimum 12 bytes)
;   GetFreeMdl:  cmp edx, 1000h  @ 0x1C000FABB  (4 KB MDL cache boundary)
```

**Key observation:** the assembly is identical on both sides. There is no instruction- or data-section change. The bytes that differ between the two images are the COFF link timestamp, the `.rdata` debug directory (PDB GUID), the `.rsrc` version resource, and the Authenticode certificate directory appended after the loadable sections.

---

## 5. Trigger Conditions

1. **Obtain port name.** The driver's port names are `\StrmFltCommunicationClientServerPort` and `\StrmFltCommunicationServerClientPort`, referenced from `.rdata` and used by `Initialize` (`0x1C0012A80`) at the `FltCreateCommunicationPort` call.
2. **Connect.** Access is governed by the port security descriptor, which `Initialize` builds via `FltBuildDefaultSecurityDescriptor` with `FLT_PORT_ALL_ACCESS` (`0x1F0001`). That descriptor grants access to Administrators and SYSTEM only; a non-admin caller is denied at `FilterConnectCommunicationPort`. This descriptor is byte-identical in both builds.
   ```c
   HANDLE hPort;
   FilterConnectCommunicationPort(
       L"\\StrmFltCommunicationClientServerPort",
       0, NULL, 0, NULL, &hPort);
   ```
3. **Build the staging message.** Layout:
   ```
   offset 0:  uint32_t MessageType   (1, 2, 3, 6, 7, 8, or 9)
   offset 4:  uint32_t reserved/payload header
   offset 8:  operation-specific body
   ```
   Total length must be `>= 8` to pass the size gate at `0x1C0012BB4`.
4. **Send the message.**
   ```c
   FilterSendMessage(hPort, buf, bufLen, out, outLen, &returned);
   ```
5. **Effect (message 7 example).** `create_hard_link` constructs source/target `UNICODE_STRING` paths from the buffer and calls `Streaming::Messaging::PackageLoader::CreateHardLink` (call at `0x1C0010790`). Because only Administrators/SYSTEM can reach this path, no privilege boundary is crossed.
6. **Ordering.** Synchronous dispatch; no race required.

---

## 6. Reachable Impact

- The staging operations reachable through `ProcessMessage` (`create_file`, `write_file`, `request_mdl`, `query_sparse_file`, `create_hard_link`, `config`, `set_directory_DACL`) are only reachable by callers the port admits.
- The port descriptor built by `FltBuildDefaultSecurityDescriptor` (`0x1C0012AAC`) restricts connection and message send to Administrators and SYSTEM. A caller already holding Administrators/SYSTEM invoking privileged filesystem operations does not cross a privilege boundary, so this dispatch design does not, on its own, provide a local privilege-escalation primitive.
- No memory-corruption primitive is present: the code is byte-identical to the prior build and this update makes no code change.
- This characteristic is identical in both builds; the update neither introduces nor removes it.

---

## 7. Debugger Notes

For a kernel-debugger session against `appvstrm_unpatched.sys`.

### Breakpoints

```text
bp appvstrm_unpatched!Streaming::Messaging::UserCommunication::ProcessMessage
bp appvstrm_unpatched!NotifyPortMessage
bp appvstrm_unpatched!Streaming::staging_operations::create_hard_link
bp appvstrm_unpatched!Streaming::staging_operations::set_directory_DACL
```
RVA form (rebase to the loaded image base with `lm` / `!fltkd`):
```text
bp appvstrm_unpatched+0x12B80    ; ProcessMessage
bp appvstrm_unpatched+0x12960    ; NotifyPortMessage
bp appvstrm_unpatched+0x106AC    ; create_hard_link
bp appvstrm_unpatched+0x10300    ; set_directory_DACL
```

### What to inspect

| Breakpoint | Registers / fields |
|---|---|
| `ProcessMessage` (`0x1C0012B80`) | `rdx` = `InputBuffer`; `dps rdx L1` shows the message type DWORD. `r8d` = `InputSize` (must be `>= 8`). `!process -1 0` to see the caller. |
| `NotifyPortMessage` (`0x1C0012960`) | `kn` to confirm `FltMgr!FltSendMessage` → `NotifyPortMessage` → `ProcessMessage`. |
| `create_hard_link` (`0x1C00106AC`) | Source/target `UNICODE_STRING` construction, then the `Streaming::Messaging::PackageLoader::CreateHardLink` call at `0x1C0010790`. |
| `set_directory_DACL` (`0x1C0010300`) | The `Streaming::DACLSetter::SetDirectoryDACL` call at `0x1C00103CA`. |

### Key instruction offsets

| Offset | Meaning |
|---|---|
| `0x1C0012BB4` | `cmp r8d, 8` — minimum message size gate. |
| `0x1C0012BE5` | `mov ecx, [rdx]` — reads message type. |
| `0x1C0012BEA` | `jz loc_1C0012E8D` — type 1 (`create_file`) dispatch branch. |
| `0x1C0012C0E` | `jz loc_1C0012CF7` — type 7 (`create_hard_link`) dispatch branch. |
| `0x1C0012CAC` | `call set_directory_DACL` (type 9). |
| `0x1C0010432` | `request_mdl` min-size check `cmp edx, 0Ch`. |
| `0x1C000FABB` | `GetFreeMdl` 4 KB MDL-cache boundary `cmp edx, 1000h`. |
| `0x1C0012AAC` | `call FltBuildDefaultSecurityDescriptor` (port descriptor: Administrators/SYSTEM). |
| `0x1C0012B37` | `call FltCreateCommunicationPort`. |

### Port-init observation

`Initialize` (`0x1C0012A80`) sets `DesiredAccess = 0x1F0001` (`FLT_PORT_ALL_ACCESS`) at `0x1C0012AA0`, calls `FltBuildDefaultSecurityDescriptor` at `0x1C0012AAC`, and passes the result to `FltCreateCommunicationPort` at `0x1C0012B37`. Both builds execute this identical path, so port access is the same on both: Administrators and SYSTEM only.

---

## 8. Changed Functions — Full Triage

There are **no changed functions**. All 274 matched functions are identical (similarity 1.0). Register allocation, instruction selection, and basic-block layout are byte-identical on both sides.

**Implication for triage:** there is no code change to triage. The bytes that differ between the two images are:

1. The COFF link timestamp (file offset `0xE8`).
2. The `.rdata` debug directory: a new CodeView/PDB GUID and updated debug entry timestamps (PDB name `Appvstrm.pdb` unchanged).
3. The `.rsrc` version resource: `FileVersion`/`ProductVersion` advance from `10.0.17763.3469` to `10.0.17763.4010`.
4. The PE Authenticode certificate directory: the image is re-signed; countersignature timestamps advance from 2022 to 2023, and the timestamp-service certificate organization changes from `Microsoft Operations Puerto Rico` to `Microsoft Ireland Operations Limited`.

The executable code (`.text`) and the `.data`, `.pdata`, `.idata`, and `.reloc` sections are byte-identical.

---

## 9. Unmatched Functions

- **Removed:** none.
- **Added:** none.

No new sanitizers or mitigation helpers were introduced — consistent with a rebuild that produced identical code. Had the update added an authorization check, one would expect a new helper function or a changed `ProcessMessage`; neither is present.

---

## 10. Confidence & Caveats

**Confidence: High.**

- *High confidence* that the two binaries are code-identical: the function-level match is unambiguous (274/274 identical, 0 changed) and the disassembly and decompilation are byte-identical. The `.text` section compares byte-for-byte equal.
- *High confidence* that the only byte-level differences are build metadata: the COFF link timestamp, the debug-directory PDB GUID, the version resource (`10.0.17763.3469` → `10.0.17763.4010`), and the Authenticode certificate. `appvstrm.sys` has no CVE attribution in this update.
- *High confidence* that this update contains no code-level or port-descriptor security change.
- *High confidence* that message dispatch is authorized at the port: `Initialize` (`0x1C0012A80`) builds the port descriptor with `FltBuildDefaultSecurityDescriptor` (`FLT_PORT_ALL_ACCESS`), which restricts access to Administrators and SYSTEM. The absence of a per-message re-check inside `ProcessMessage` is the standard minifilter model and does not expose the staging operations to unprivileged callers.

**Bottom line:** This build pair is a code-identical rebuild with a version bump and re-sign. There is no security-relevant code change. The dispatch design note above is informational and unchanged between the two builds.
