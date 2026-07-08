Title: appvstrm.sys — No security-relevant change (code byte-identical; re-sign and version bump only)
Date: 2026-06-25
Slug: appvstrm_1e621cba-appvstrm-report-20260625-191516
Category: Corpus
Author: Argus
Summary: KB5073724
Severity: Informational
KBDate: 2026-01-13

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `appvstrm_unpatched.sys` (FileVersion 10.0.19041.3570) |
| **Patched binary** | `appvstrm_patched.sys` (FileVersion 10.0.19041.3636) |
| **Overall similarity** | 0.993 |
| **Matched functions** | 275 |
| **Changed functions** | 0 |
| **Identical functions** | 275 |
| **Unmatched (unpatched)** | 0 |
| **Unmatched (patched)** | 0 |

**Verdict:** The two revisions of `appvstrm.sys` (the Windows App-V Streaming kernel minifilter driver) carry **byte-identical code**. The `.text` (raw file offsets `0x400`–`0x14800`), `.data`, `.pdata`, `.idata`, `PAGE`, `INIT`, `GFIDS`, and `.reloc` sections are byte-identical between the two files, and `.rdata` is byte-identical apart from its debug directory and CodeView/PDB record (the string and constant data in `.rdata` are unchanged). All 275 functions match at similarity 1.0 because the executable code did not change. The 0.7% overall byte delta is confined entirely to non-code build metadata: the version resource (build number `3570` → `3636`), the debug directory and its CodeView/PDB signature record (residing in `.rdata` at file offsets `0x1a050`–`0x1a3a7`), the PE header checksum (`0x2a18e` → `0x2a538`), and the appended Authenticode certificate (9688 → 9584 bytes). There is no instruction-level security fix in this driver between these two revisions.

> **Scope note:** The function-level diff correctly reported **zero changed functions**. Because the code sections are identical, no before/after instruction delta exists to attribute to any function. The overall similarity is below 1.0 solely due to the signature overlay, the rebuilt PDB debug record, the version-resource build-number bump, and the recomputed checksum — none of which affect runtime behavior.

---

## 2. Vulnerability Summary

The three code patterns below were examined during triage as candidate memory-safety surfaces. Each is present **identically** in both revisions (the code did not change), and on inspection none is an exploitable integer overflow: the size arithmetic in each case is driven by 16-bit source operands that cannot wrap a 32-bit computation. They are recorded here as informational surface notes.

### Finding 1 — Reparse Data Buffer Size Arithmetic (Informational)

| Attribute | Value |
|---|---|
| **Severity** | Informational |
| **Class** | Integer overflow candidate (CWE-190) — not reachable; bounded by 16-bit field |
| **Function** | `Streaming::FileOperations::GetReparseData` (`0x1c00029b0`) |

**Analysis:** `GetReparseData` queries reparse point data via `FltFsControlFile` with `FSCTL_GET_REPARSE_POINT` (`0x900a8`). It allocates an initial `0x1c`-byte buffer. On `STATUS_BUFFER_OVERFLOW`, it reallocates using the size field at offset `+4` of the returned reparse data, computing the new allocation as `OutputBufferLength = v7[2] + 0x1c`. The field `v7[2]` is the `ReparseDataLength` member of `REPARSE_DATA_BUFFER`, which is a `USHORT` (16-bit). Its maximum value is `0xFFFF`, so `0xFFFF + 0x1C = 0x1001B` and the 32-bit addition cannot wrap. The same `OutputBufferLength` value is then passed as the output-buffer length to the second `FltFsControlFile` call, so the allocation size and the copy length are the same variable. This arithmetic is unchanged between the two revisions.

**Reachability sketch:**

1. App-V client installed; a package is published to the user/machine.
2. A file under the App-V mount point (`C:\ProgramData\App-V\<PackageGUID>\...`) is opened or accessed.
3. The minifilter's pre/post callbacks (`StrmPreCreate`, `StrmPostCreate`) fire via FltMgr.
4. `GetReparseData` reads the App-V reparse point on the file.
5. `FltFsControlFile(..., FSCTL_GET_REPARSE_POINT, ...)` returns a reparse data buffer whose `ReparseDataLength` (16-bit) is bounded, so `length + 0x1c` stays small and matched to the copy length.

---

### Finding 2 — `stream_fault_request::pack` Size Arithmetic (Informational)

| Attribute | Value |
|---|---|
| **Severity** | Informational |
| **Class** | Integer overflow candidate (CWE-190) — not reachable; bounded by 16-bit operands |
| **Function** | `messages::stream_fault_request::pack<...>` (`0x1c0010e08`) |

**Analysis:** The `pack` function computes the message allocation as `v13 = v11 + v10 + 0x30`, where `v10` and `v11` are `unsigned __int16` (16-bit) byte-lengths of two `wchar_t` strings (each computed as `2 * <char count>` and truncated to 16 bits). Because both operands are 16-bit, the worst case is `0xFFFF + 0xFFFF + 0x30 = 0x2002E`, which does not overflow the 32-bit `v13`. The `v13` value is stored back and used consistently as the allocation size (`ExAllocatePoolWithTag(PagedPool, v13, 0x6D736673)`), and the prior contents are copied with the previously recorded length `v15` before the writes. This arithmetic is unchanged between the two revisions.

**Call chain:**

1. User-mode read against an App-V-managed file → `StrmPreRead` minifilter callback.
2. `Streaming::Reader::ReadFile` (`0x1c0009ac0`) handles the read.
3. On a cache miss, a stream fault is created.
4. `Streaming::StreamFault::Execute` (`0x1c000c3c4`) orchestrates the fault.
5. `stream_fault_request::pack` serializes the request into a kernel buffer for the user-mode streaming service, using the 16-bit-bounded size arithmetic above.

---

### Finding 3 — Bounds Check in `StreamFault::Execute` (Informational)

| Attribute | Value |
|---|---|
| **Severity** | Informational |
| **Class** | Read-length clamp (CWE-190 adjacent) — examined; unchanged |
| **Function** | `Streaming::StreamFault::Execute` (`0x1c000c3c4`) |

**Analysis:** `Execute` clamps the requested read length against the file size stored via `*(*this + 0x50)` and processes reads in chunks capped at `0x100000`. The offset-plus-length comparison and the chunk loop at `0x1c000c4a2` were reviewed for signed/unsigned or off-by-one issues. The logic is present identically in both revisions; no change was made here.

**Call chain:** Same as Finding 2, steps 1–4.

---

## 3. Pseudocode

> No before/after diff exists because the code sections are byte-identical. The pseudocode below is the shared code of the three candidate functions (identical in both revisions), annotated with the size arithmetic that was reviewed.

### `Streaming::FileOperations::GetReparseData` (`0x1c00029b0`)

```c
__int64 GetReparseData(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, void **a3) {
    // Initial small allocation (0x1c bytes)
    OutputBuffer = ExAllocatePoolWithTag(PagedPool, 0x1Cu, 'sfrd');
    v7 = OutputBuffer;

    v11 = FltFsControlFile(Instance, FileObject, 0x900A8u, nullptr, 0,
                           OutputBuffer, 0x1Cu, nullptr);
    if ( v11 == STATUS_BUFFER_OVERFLOW ) {
        // v7[2] is REPARSE_DATA_BUFFER::ReparseDataLength (USHORT, 16-bit, max 0xFFFF)
        OutputBufferLength = v7[2] + 28;               // <= 0x1001B, no 32-bit wrap
        PoolWithTag = ExAllocatePoolWithTag(PagedPool, OutputBufferLength, 'sfrd');
        ExFreePoolWithTag(v7, 0);
        // Second control call uses the SAME length as the allocation:
        v12 = FltFsControlFile(Instance, FileObject, 0x900A8u, nullptr, 0,
                               PoolWithTag, OutputBufferLength, nullptr);
        ...
    }
    ...
}
```

### `messages::stream_fault_request::pack<...>` (`0x1c0010e08`)

```c
char pack(...) {
    // v10, v11 are unsigned __int16 (16-bit) string byte-lengths
    v10 = 2 * v9;                     // first string length, truncated to 16 bits
    v11 = (a4 != 0) ? 2 * v8 : 0;     // second string length, truncated to 16 bits

    v13 = v11 + v10 + 48;             // max 0x2002E, no 32-bit wrap
    if ( v13 > a7[1] ) {
        v15 = *a7;                    // prior length recorded for the copy
        v16 = *((void **)a7 + 1);
        *a7 = v13;
        PoolWithTag = ExAllocatePoolWithTag(PagedPool, v13, 'sfsm');
        if ( PoolWithTag && v16 )
            memmove(PoolWithTag, v16, v15);   // copies v15 bytes into v13-byte buffer
        ...
    }
    ...
}
```

### `Streaming::StreamFault::Execute` (`0x1c000c3c4`)

```c
NTSTATUS Execute(...) {
    // read offset/length clamped against file size at *(*this + 0x50);
    // reads processed in chunks capped at 0x100000 (loop at 0x1c000c4a2).
    // Identical in both revisions.
}
```

---

## 4. Assembly Analysis

> The code sections are byte-identical between the two binaries, so there is no assembly diff for any function. The excerpts below are the shared assembly at each candidate location.

### `GetReparseData` — Reallocation Size (~`0x1c0002a7c`)

```asm
; rbp = pointer to reparse data header from the first FSCTL output
00000001C0002A72  movzx   edi, word ptr [rbp+4]   ; edi = ReparseDataLength (USHORT, max 0xFFFF)
00000001C0002A7C  add     edi, 1Ch                ; edi = length + 0x1c   (<= 0x1001B, no wrap)
00000001C0002A82  mov     edx, edi                ; NumberOfBytes
00000001C0002A84  call    ExAllocatePoolWithTag   ; allocation size == later FSCTL output length
```

**Annotation:**
- The loaded field is a 16-bit `ReparseDataLength`, so `add edi, 1Ch` cannot carry out of 32 bits.
- The same `edi` value is written back as the `OutputBufferLength` argument to the second `FltFsControlFile` (at `0x1c0002b1c`), so the allocation and the copy length match.

### `pack<stream_fault_request>` — Size Computation (~`0x1c0010e93`)

```asm
; si (v10) and bx (v11) are wchar_t string byte-lengths (16-bit)
00000001C0010E8A  movzx   ebp, si       ; ebp = v10 (16-bit)
00000001C0010E8D  add     ebp, 30h      ; + 0x30
00000001C0010E90  movzx   ecx, bx       ; ecx = v11 (16-bit)
00000001C0010E93  add     ebp, ecx      ; v13 = v10 + 0x30 + v11 (max 0x2002E, no wrap)
00000001C0010EB4  mov     edx, ebp      ; NumberOfBytes
00000001C0010EBB  call    ExAllocatePoolWithTag   ; PagedPool (ecx=1), v13 bytes
```

**Annotation:**
- Both addends are zero-extended from 16-bit registers; the 32-bit sum plus `0x30` cannot overflow.
- The prior buffer content is copied with the previously recorded length, then the writes fill the new buffer.

### `StreamFault::Execute` — Bounds Check (~`0x1c000c40c`)

```asm
; rbx = read offset, rsi = read length, r8 = file size (*(*this + 0x50))
lea  rax, [rbx + rsi]     ; offset + length
cmp  rax, r8
...                       ; clamp to file size; chunk loop at 0x1c000c4a2 (cap 0x100000)
```

**Annotation:**
- The comparison and clamp are identical in both revisions; reviewed for sign/off-by-one, no change present.

---

## 5. Trigger Conditions

The paths below reach the examined code. Because the code did not change and the size arithmetic is bounded by 16-bit operands, these do not produce a memory-safety fault; they are documented for completeness of the reachable surface.

### Reparse Data Path (Finding 1)

1. Install the App-V client and publish a package to the target.
2. Access a file under `C:\ProgramData\App-V\<PackageGUID>\` that carries an App-V reparse point.
3. `FSCTL_GET_REPARSE_POINT` is triggered by opening the file or listing the directory (invoking `StrmPostCreate` / `StrmPreCreate` → `GetReparseData`).
4. The 16-bit `ReparseDataLength` bounds `length + 0x1c`, and the same length drives the copy — no undersized allocation.

### Pack Path (Finding 2)

1. Publish an App-V package whose internal metadata contains `wchar_t` path/name strings.
2. Open a file in the package that is not yet streamed (cold/uncached block).
3. Issue a read (`NtReadFile`) → `StrmPreRead` → `Reader::ReadFile` → stream fault → `StreamFault::Execute` → `stream_fault_request::pack`.
4. The 16-bit string lengths keep `strlen1 + 0x30 + strlen2` within 32 bits — no wrap.

### Bounds Check Path (Finding 3)

1. Open an App-V-managed file whose streamed extent is smaller than the requested read.
2. Issue `NtReadFile` with a large `Length` and an offset near the end of the file.
3. `Execute` clamps the read length to the file size; the chunk loop caps at `0x100000`.

### Ordering / Race Constraints

- App-V package must be in a published state; the App-V user-mode service (`AppVClient.exe`) must be running for stream-fault requests to be serviced.
- The pack path requires the streaming subsystem to be active (cold read of an uncached block).

---

## 6. Exploit Primitive & Development Notes

| Candidate | Assessment |
|---|---|
| `GetReparseData` arithmetic | Not an overflow: `ReparseDataLength` is a 16-bit field (`USHORT`), so `field + 0x1c` is bounded to `0x1001B`; the same value is used for both the allocation and the FSCTL output length. |
| `pack` arithmetic | Not an overflow: both string lengths are 16-bit, so `strlen1 + 0x30 + strlen2` is bounded to `0x2002E` and cannot wrap a 32-bit sum. |
| `Execute` bounds | Read length is clamped to file size; chunk loop capped at `0x100000`. No boundary defect identified. |

Because the code is identical between the two revisions and the size arithmetic is bounded by 16-bit inputs, no kernel pool overflow primitive is available from these paths in either binary. The following mitigations are listed for reference on this driver class.

| Mitigation | Impact |
|---|---|
| **kASLR** | Kernel addresses randomized per boot. |
| **SMEP / SMAP** | Blocks user-mode shellcode/data execution and stray user-pointer access from kernel. |
| **CFG (kernel CFG, kCFG)** | Restricts indirect call targets. |
| **HVCI / VBS** | Code-integrity enforcement prevents kernel code patching. |
| **Pool quota / segmented pool** | Modern pool layout on Win10+ constrains grooming. |

---

## 7. Debugger Playbook

> Target: `appvstrm.sys` with WinDbg/KD attached. Symbols: load the matching PDB. Module base varies by boot; substitute `appvstrm!` for absolute addresses. The addresses below reference the shared code present in both revisions.

### Finding 1 — `GetReparseData` Reparse Size

**Breakpoints:**

```text
bp appvstrm!Streaming::FileOperations::GetReparseData   ; or: bp <module_base> + 0x29b0
bp <module_base> + 0x2a7c                                ; the 'add edi, 1Ch' arithmetic
```

**What to inspect:**

- At function entry: `rcx` / `rdx` — `PFLT_INSTANCE` / `PFILE_OBJECT`.
- At `0x1c0002a7c`:
  - `edi` **before** the `add` = `ReparseDataLength` (16-bit, max `0xFFFF`).
  - `edi` **after** the `add` = `length + 0x1c` (`<= 0x1001B`).
  - The same value is the length argument to the second `FltFsControlFile`.

**Key offsets:**

- `0x1c0002a7c` — `add edi, 1Ch` (16-bit source, no wrap).

**Trigger setup:**

1. `fltmc instances` — confirm `appvstrm` is attached.
2. `CreateFileW("\\\\?\\C:\\ProgramData\\App-V\\<PKG_GUID>\\<file>", ...)`.
3. Any open/create that causes the minifilter to invoke `GetReparseData` will hit the bp.

**Struct/offset notes:**

- `REPARSE_DATA_BUFFER::ReparseDataLength` at offset `+0x4` is a `USHORT` (this is the field loaded into `edi`).

---

### Finding 2 — `pack<stream_fault_request>` Size

**Breakpoints:**

```text
bp appvstrm!messages::pack<stream_fault_request>   ; or: bp <module_base> + 0x10e08
bp <module_base> + 0x10e93                          ; the size 'lea'
bp ExAllocatePoolWithTag                            ; confirm requested size
```

**What to inspect:**

- At `0x1c0010e93`:
  - The two string-length operands are 16-bit (`v10`, `v11`).
  - The computed total `v13 = v11 + v10 + 0x30` (`<= 0x2002E`).
- At `ExAllocatePoolWithTag`: size argument equals `v13`.

**Trigger setup:**

1. Publish an App-V package with `wchar_t` file/path names in its manifest.
2. Open a file in the package that has not been streamed yet.
3. Issue a `ReadFile` — the read faults → `StreamFault::Execute` → `pack`.

---

### Finding 3 — `StreamFault::Execute` Bounds

**Breakpoints:**

```text
bp appvstrm!Streaming::StreamFault::Execute   ; or: bp <module_base> + 0xc3c4
bp <module_base> + 0xc40c                      ; offset+length compare
bp <module_base> + 0xc4ac                      ; remaining-bytes subtraction
```

**What to inspect:**

- At `0x1c000c40c`:
  - `rbx` = read offset (from IRP `ByteOffset`).
  - `rsi` = read length (from IRP `Length`).
  - `r8` = file size (`*(*this + 0x50)`).
- At `0x1c000c4ac`: remaining bytes after the current chunk.

**Key offsets:**

- `0x1c000c40c` — boundary comparison.
- `0x1c000c4a2` — chunk loop entry, cap `0x100000`.
- `0x1c000c4ac` — remaining-bytes subtraction.

**Struct/offset notes:**

- `StreamFault` object: file size reached via `*(*this + 0x50)`.
- IRP read params: `IrpSp->Parameters.Read.ByteOffset` (8 bytes), `IrpSp->Parameters.Read.Length` (4 bytes).

---

## 8. Changed Functions — Full Triage

The function-level diff reported **zero changed functions**, and byte-level inspection confirms this: the `.text` section is identical between the two binaries. No function's instructions differ.

**Cosmetic / register-allocation changes:** None (code sections are byte-identical).

**Behavioral changes:** None. All 275 functions are identical.

The functions below were examined during triage against the App-V driver's attacker-reachable surface (reparse parsing, message packing, read-length clamping). All are identical across the two revisions:

- `Streaming::FileOperations::GetReparseData` (`0x1c00029b0`)
- `messages::stream_fault_request::pack<...>` (`0x1c0010e08`)
- `Streaming::StreamFault::Execute` (`0x1c000c3c4`)
- `Streaming::Reader::ReadFile` (`0x1c0009ac0`)
- `Streaming::StagingManager::StageDirectoryInternal` (`0x1c000a0b4`)
- `Streaming::Context::StreamingBitmapBuilder::ReadStreamingInformation` (`0x1c000a998`)
- `Streaming::Messaging::PackageLoader::CreateStreamableFile` (`0x1c0007ef4`)

The string tables in `.rdata` are byte-identical between the two files; there is no added or removed string. The `.rdata` byte differences are confined to the debug directory and its CodeView/PDB signature record (a rebuild artifact), not to string constants.

---

## 9. Unmatched Functions

| Direction | Functions |
|---|---|
| **Removed (unpatched only)** | None |
| **Added (patched only)** | None |

No functions were added or removed. Consistent with two builds of identical source: same function set, same instructions. No sanitizer function was added and no validator was removed.

---

## 10. Confidence & Caveats

**Confidence: High.**

Byte-level comparison of the two PE files establishes that the executable code did not change. The `.text` (raw file offsets `0x400`–`0x14800`), `.data`, `.pdata`, `.idata`, `PAGE`, `INIT`, `GFIDS`, and `.reloc` sections are byte-identical, and `.rdata` is byte-identical apart from its debug directory and CodeView/PDB record (the string and constant data in `.rdata` are unchanged). The 0.7% overall difference is fully accounted for by non-code metadata:

1. **Version resource** — `FileVersion` / `ProductVersion` build number `10.0.19041.3570` → `10.0.19041.3636`, and the matching binary fields in `VS_FIXEDFILEINFO`.
2. **Debug directory + CodeView/PDB record** — a new PDB GUID/age from the rebuild.
3. **PE header checksum** — recomputed for the new file.
4. **Authenticode certificate** — the appended signature overlay (9688 → 9584 bytes).

**Consequences:**

1. The function-level diff's report of **zero changed functions** is accurate.
2. There is no instruction-level security fix in `appvstrm.sys` between these two revisions. Any security change shipped in the corresponding update was not applied to this driver's code.
3. The three candidate size-arithmetic patterns (`GetReparseData`, `pack`, `StreamFault::Execute`) are present identically in both revisions. On inspection none is an exploitable integer overflow: the reparse length field is a 16-bit `USHORT` and the pack string lengths are 16-bit, so neither computation can wrap a 32-bit sum, and each allocation size matches the corresponding copy/output length.

**What a researcher would confirm to close this out:**

1. Cross-check the update's file manifest to identify which binary in the package actually received the code fix for this revision.
2. Confirm, in any binary that did change, that the changed function is the one carrying the security fix.
