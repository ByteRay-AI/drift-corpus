Title: kbdhid.sys — No security-relevant change (IRP_MJ_CREATE device-name string correction, no authorization change)
Date: 2026-06-29
Slug: kbdhid_1d27d4f3-kbdhid-report-20260629-004010
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview
- **Unpatched Binary:** `kbdhid_unpatched.sys`
- **Patched Binary:** `kbdhid_patched.sys`
- **Overall Similarity Score:** 0.9917
- **Diff Statistics:** 81 matched functions, 1 changed function, 80 identical functions, 0 unmatched functions in either direction.
- **Verdict:** The only function whose body changed is `KbdHid_Create` (the `IRP_MJ_CREATE` dispatch handler). The change corrects a hardcoded relative-open name that `RtlEqualUnicodeString` compares against — from `"KBD"` (case-sensitive) to `"\KBD"` (case-insensitive) — and adds a `DesiredAccess` test so that a `"\KBD"` open that does **not** request `FILE_READ_DATA` is allowed to proceed. In the unpatched build every non-empty relative name was rejected; the patched build newly permits attribute-only `"\KBD"` opens. Read-data opens on this named path remain denied in both builds, and the direct (empty-name) device-open path that actually connects the keyboard for reading is ungated and identical in both builds. The net effect on the authorization posture is nil (if anything the patched build is marginally more permissive). No CWE is assignable.

## 2. Change Summary
- **Severity:** None (no demonstrable security impact).
- **Change Class:** Functional correctness of a device-name string constant, plus a benign relaxation for metadata opens.
- **Affected Function:** `KbdHid_Create` @ `0x1C0004CB0` (registered as `DriverObject->MajorFunction[IRP_MJ_CREATE]`).

**What the code actually does:**
`KbdHid_Create` runs when a process opens the kbdhid device. It reads the `IO_STACK_LOCATION`, the `IO_SECURITY_CONTEXT` (at `+0x8`, `DesiredAccess` at `+0x10`), and `FileObject` (at `+0x30`). If `FileObject` is non-NULL and `FileObject->FileName.Length != 0` (a relative open with a name component), the handler compares the name against a hardcoded constant and returns an error; otherwise (empty name) it falls through to normal processing, which acquires the remove lock, forwards the create IRP to the lower device, and — only when `DesiredAccess & FILE_READ_DATA` is set and no keyboard is already connected — calls `KbdHid_StartRead` to connect the keyboard input stream.

**Unpatched behavior (non-empty FileName):**
- `FileName` equals `"KBD"` (exact, case-sensitive, 3 UTF-16 chars) → `STATUS_SHARING_VIOLATION` (`0xC0000043`).
- `FileName` anything else → `STATUS_ACCESS_DENIED` (`0xC0000022`).
- Every non-empty relative name is therefore rejected. Because the real relative name is `"\KBD"` (with a leading backslash), the case-sensitive `"KBD"` comparison never matches it, and such opens fall into the `STATUS_ACCESS_DENIED` branch.

**Patched behavior (non-empty FileName):**
- `FileName` does not equal `"\KBD"` (case-insensitive) → `STATUS_ACCESS_DENIED` (`0xC0000022`).
- `FileName` equals `"\KBD"` and `DesiredAccess & FILE_READ_DATA` (bit 0) set → `STATUS_SHARING_VIOLATION` (`0xC0000043`).
- `FileName` equals `"\KBD"` and `FILE_READ_DATA` clear → allowed through to normal processing.

**Direction of the change:** The patch does not add an authorization check that was previously bypassable. The unpatched build is the stricter one for named opens — it denies all of them. The patched build introduces a new *allowed* path for `"\KBD"` opens that do not request read data. Read-data opens of `"\KBD"` are denied in both builds (`STATUS_ACCESS_DENIED` unpatched via name mismatch, `STATUS_SHARING_VIOLATION` patched). The security-sensitive operation — connecting the keyboard for keystroke reading via `KbdHid_StartRead` — is reached only from the empty-name path gated by `test cl, 1` (`FILE_READ_DATA`), which is byte-identical in both builds. Consequently no keystroke-read authorization is added, removed, or changed by this patch.

## 3. Decompiled Diff

```c
// UNPATCHED KbdHid_Create (name-check region)
v9 = CurrentStackLocation->FileObject;
if ( v9 != nullptr )
{
    p_FileName = &v9->FileName;
    if ( p_FileName->Length != 0 )
    {
        *(_DWORD *)&String2.Length = 524294;      // Length=6, MaximumLength=8
        v37 = 0x440042004BLL;                     // "KBD" (UTF-16LE, no backslash)
        String2.Buffer = (PWSTR)&v37;
        if ( RtlEqualUnicodeString(p_FileName, &String2, 0) != 0 )  // CaseInSensitive = FALSE
        {
            Status = -1073741757;                 // 0xC0000043 STATUS_SHARING_VIOLATION
        }
        else
        {
            Status = -1073741790;                 // 0xC0000022 STATUS_ACCESS_DENIED
        }
        goto LABEL_11;                            // complete IRP with error (always denied)
    }
}
// empty name -> IoAcquireRemoveLockEx -> forward IRP -> (if FILE_READ_DATA) KbdHid_StartRead

// ------------------------------------------------------------------

// PATCHED KbdHid_Create (name-check region)
v8 = *(_DWORD *)(CurrentStackLocation->Parameters.WMI.ProviderId + 16);  // DesiredAccess (SecurityContext+0x10)
v9 = CurrentStackLocation->FileObject;
if ( v9 != nullptr && v9->FileName.Length != 0 )
{
    String2.Buffer = (PWSTR)v37;
    wcscpy((wchar_t *)v37, L"\\KBD");             // "\KBD" (with backslash)
    *(_DWORD *)&String2.Length = 655368;          // Length=8, MaximumLength=0xA
    if ( RtlEqualUnicodeString(&v9->FileName, &String2, 1u) == 0 )  // CaseInSensitive = TRUE
    {
        Status = -1073741790;                     // 0xC0000022 STATUS_ACCESS_DENIED
        goto LABEL_7;
    }
    if ( (v8 & 1) != 0 )                          // FILE_READ_DATA requested?
    {
        Status = -1073741757;                     // 0xC0000043 STATUS_SHARING_VIOLATION
        goto LABEL_7;
    }
    // "\KBD" without FILE_READ_DATA falls through -> allowed
}
// IoAcquireRemoveLockEx -> forward IRP -> (if FILE_READ_DATA) KbdHid_StartRead
```

## 4. Assembly Analysis

### Unpatched (name check and denial paths)
```assembly
0x1C0004D5F  mov     rcx, [r14+30h]           ; FileObject
0x1C0004D63  test    rcx, rcx
0x1C0004D66  jz      loc_1C0004E01            ; NULL -> normal processing
0x1C0004D6C  add     rcx, 58h                 ; &FileObject->FileName
0x1C0004D70  cmp     [rcx], r15w              ; FileName.Length == 0 ?
0x1C0004D74  jz      loc_1C0004E01            ; empty -> normal processing
0x1C0004D7A  mov     rax, 440042004Bh         ; "KBD" (UTF-16LE, no backslash)
0x1C0004D84  mov     dword ptr [rsp+...], 80006h  ; Length=6, MaxLength=8
0x1C0004D8C  mov     [rsp+...var_48], rax
0x1C0004D94  lea     rdx, [rsp+...String2]
0x1C0004DA1  xor     r8d, r8d                 ; CaseInSensitive = FALSE
0x1C0004DA9  call    cs:__imp_RtlEqualUnicodeString
0x1C0004DB9  test    al, al
0x1C0004DBB  jnz     short loc_1C0004DF4      ; match ("KBD") -> SHARING_VIOLATION
0x1C0004DBD  mov     esi, 0C0000022h          ; STATUS_ACCESS_DENIED (no match)
0x1C0004DC2  mov     r9d, 0Ch
0x1C0004DC8  ...                              ; log + complete IRP with error
0x1C0004DF4  mov     esi, 0C0000043h          ; STATUS_SHARING_VIOLATION (match)
0x1C0004DF9  mov     r9d, 0Dh
0x1C0004DFF  jmp     short loc_1C0004DC8
0x1C0004E01  lea     rcx, [rdi+98h]           ; normal processing: IoAcquireRemoveLockEx follows
```

### Patched (name check, added DesiredAccess gate)
```assembly
0x1C0004D62  mov     rax, [r14+30h]           ; FileObject
0x1C0004D66  test    rax, rax
0x1C0004D69  jz      loc_1C0004E17            ; NULL -> normal processing
0x1C0004D6F  lea     rcx, [rax+58h]           ; &FileObject->FileName
0x1C0004D73  cmp     [rcx], r15w              ; FileName.Length == 0 ?
0x1C0004D77  jz      loc_1C0004E17            ; empty -> normal processing
0x1C0004D7D  movzx   eax, word ptr cs:aKbd+8
0x1C0004D89  movsd   xmm0, qword ptr cs:aKbd  ; "\KBD" (with backslash)
0x1C0004D91  mov     r8b, r13b                ; CaseInSensitive = TRUE (r13 = 1)
0x1C0004DB2  mov     dword ptr [rsp+...], 0A0008h ; Length=8, MaxLength=0xA
0x1C0004DBA  call    cs:__imp_RtlEqualUnicodeString
0x1C0004DC6  test    al, al
0x1C0004DC8  jnz     short loc_1C0004E05      ; match ("\KBD") -> DesiredAccess gate
0x1C0004DCA  mov     esi, 0C0000022h          ; STATUS_ACCESS_DENIED (no match)
0x1C0004E05  test    r13b, r12b               ; r13 = 1, r12 = DesiredAccess -> FILE_READ_DATA bit
0x1C0004E08  jz      short loc_1C0004E17      ; no read data -> ALLOWED (normal processing)
0x1C0004E0A  mov     esi, 0C0000043h          ; STATUS_SHARING_VIOLATION (read data requested)
0x1C0004E0F  mov     r9d, 0Dh
0x1C0004E15  jmp     short loc_1C0004DD5      ; log + complete IRP with error
0x1C0004E17  lea     rcx, [rdi+98h]           ; normal processing: IoAcquireRemoveLockEx follows
```

## 5. Behavioral Difference

Reachability: `KbdHid_Create` runs for any `IRP_MJ_CREATE` on the kbdhid device. The name-check branch is entered only when the create carries a non-empty relative `FileName`. The compared constant is the exact string `"\KBD"` (4 UTF-16 characters); `RtlEqualUnicodeString` performs full-length equality, not prefix matching.

- Unpatched, `FileName = "\KBD"`, any `DesiredAccess`: `STATUS_ACCESS_DENIED` (the case-sensitive `"KBD"` constant does not match `"\KBD"`).
- Unpatched, `FileName = "KBD"` (no backslash): `STATUS_SHARING_VIOLATION`.
- Patched, `FileName = "\KBD"`, `DesiredAccess` without `FILE_READ_DATA`: create proceeds to normal processing.
- Patched, `FileName = "\KBD"`, `DesiredAccess` with `FILE_READ_DATA`: `STATUS_SHARING_VIOLATION`.
- Patched, any other non-empty `FileName`: `STATUS_ACCESS_DENIED`.

In every case where read data is requested, the outcome is a denial in both builds. The only observable change is that attribute-only `"\KBD"` opens, previously denied, now succeed.

## 6. Security Assessment

- **Exploit primitive:** None. The change grants no additional access to the keyboard input stream. Opening the device for reading keystrokes goes through `KbdHid_StartRead`, which is reached only from the empty-name path guarded by `test cl, 1` (`FILE_READ_DATA`); that guard is byte-identical in both builds. Named `"\KBD"` opens that request `FILE_READ_DATA` are rejected in both builds.
- **Direction:** The patched build is not stricter than the unpatched build on this path; it is marginally more permissive (it introduces a new allowed path for `"\KBD"` attribute-only opens).
- **Authorization / access control:** No authorization gate is added or removed. Device DACLs and exclusivity are established elsewhere (I/O-manager device creation) and are not determinable from this function or this diff.
- **Mitigations:** Not relevant; no memory-safety, information-disclosure, or control-flow issue is present in the diff.

## 7. Observation Notes

The behavioral difference can be observed under a kernel debugger by breaking inside `KbdHid_Create` and issuing a relative-name open. These are observation points only; they do not demonstrate a security bypass.

- `0x1C0004D7A` (unpatched) / `0x1C0004D7D`–`0x1C0004D89` (patched): the compared name constant (`"KBD"` vs `"\KBD"`) and the `CaseInSensitive` argument (`r8 = 0` unpatched, `r8 = r13 = 1` patched).
- `0x1C0004DB9` (unpatched) / `0x1C0004DC6` (patched): `al` = result of `RtlEqualUnicodeString`.
- `0x1C0004E05` (patched only): `test r13b, r12b` — the new `FILE_READ_DATA` gate; `jz 0x1C0004E17` sends read-less opens to normal processing.

Registers / memory of interest:
- `r14` = `IO_STACK_LOCATION` (from `IRP+0xB8`).
- `[r14+0x08]` = `IO_SECURITY_CONTEXT`; `[[r14+0x08]+0x10]` = `DesiredAccess` (bit 0 = `FILE_READ_DATA`).
- `[r14+0x30]` = `FileObject`; `[FileObject+0x58]` = `FileName.Length`; `[FileObject+0x60]` = `FileName.Buffer`.

## 8. Changed Functions — Full Triage
- **`KbdHid_Create`** @ `0x1C0004CB0` (Similarity: 0.9628, not security-relevant)
  - Corrected the compared relative-open name from `"KBD"` (Length=6, case-sensitive, `0x440042004B`) to `"\KBD"` (Length=8, case-insensitive, includes the leading backslash).
  - Flipped the `RtlEqualUnicodeString` `CaseInSensitive` argument from `FALSE` to `TRUE`.
  - Added a `DesiredAccess` test (`test r13b, r12b; jz 0x1C0004E17` at `0x1C0004E05`) so that a matching `"\KBD"` open without `FILE_READ_DATA` proceeds to normal processing; with `FILE_READ_DATA` it still returns `STATUS_SHARING_VIOLATION`.
  - Compiler/layout churn: stack frame grew from `0xA0` to `0xB0` to hold the larger `"\KBD"` string; register allocation shifted (`r12`/`r13` roles swapped, `r12` now carrying `DesiredAccess`). Adding the `"\KBD"` constant to `.rdata` also relocated later data (one TraceLogging metadata offset) and shifted every function after `KbdHid_Create` by `0x20`; none of those bodies changed.

An independent content diff of both builds' decompilation and disassembly confirms `KbdHid_Create` is the only function whose body changed; all other differences are pure relocations.

## 9. Unmatched Functions
- **Added:** None.
- **Removed:** None.

## 10. Confidence & Caveats
- **Confidence Level:** High. Both builds' decompilation and disassembly were compared directly; the name-constant correction, the case-insensitivity flip, and the added `DesiredAccess` test are the entire delta in `KbdHid_Create`, and no other function body changed.
- **Assessment:** This is a functional correction to an internal relative-open name gate, not a security fix. It does not tighten access control on the keyboard; read-data opens remain denied on this path in both builds, and the keystroke-read connect path is unchanged.
- **Not determinable from the binary:** the exact user-mode caller (if any) that issues a `"\KBD"` relative open, and the device object's DACL/exclusivity, are not recoverable from this function or diff.
