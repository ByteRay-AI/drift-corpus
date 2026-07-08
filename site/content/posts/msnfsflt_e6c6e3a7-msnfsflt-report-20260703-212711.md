Title: msnfsflt.sys — Uninitialized kernel stack memory leaked through NFS server-call record (CWE-908) fixed
Date: 2026-07-03
Slug: msnfsflt_e6c6e3a7-msnfsflt-report-20260703-212711
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Medium

## 1. Overview

- **Unpatched binary:** `msnfsflt_unpatched.sys`
- **Patched binary:** `msnfsflt_patched.sys`
- **Overall similarity:** `0.8262`
- **Function diff statistics:**
  - Matched functions: `76`
  - Changed functions: `45`
  - Identical functions: `31`
  - Unmatched removed: `0`
  - Unmatched added: `0`

**Verdict:** The patch fixes an uninitialized kernel stack information leak in the NFS minifilter. Two functions build a 0x4c-byte "server call information" record on the kernel stack and populate it through `MsNfsFltServerCallInformationInitialization`, which writes every named field but leaves 8 bytes of inter-field padding (offsets `+0x04` and `+0x14`) unwritten. The record is then handed to the registered NFS server notification callback. The unpatched builds do not zero the record first, so the padding carries stale kernel stack bytes. The patch inserts `memset(record, 0, 0x4c)` before population in both affected functions: `MsNfsFltNotifyServerOfBlockingFileOpen` (the `STATUS_SHARING_VIOLATION` handler) and `MsNfsFltPostOpCreate` (the post-create callback).

---

## 2. Vulnerability Summary

### Finding 1: Uninitialized kernel stack memory passed to the NFS server-call callback

- **Severity:** Medium
- **Vulnerability class:**
  - CWE-908: Use of Uninitialized Resource
  - CWE-200: Information Exposure
- **Affected functions (unpatched):**
  - `MsNfsFltNotifyServerOfBlockingFileOpen` @ `0x1C0009C50` (record at `[rbp-0x30]`)
  - `MsNfsFltPostOpCreate` @ `0x1C0008BB0` (record at `[rbp-0x30]`, local `var_70`)
- **Patched functions:**
  - `MsNfsFltNotifyServerOfBlockingFileOpen` @ `0x1C0009DA8`
  - `MsNfsFltPostOpCreate` @ `0x1C000A080`
- **Entry point:** `IRP_MJ_CREATE` post-operation callback (`MsNfsFltPostOpCreate`). The `MsNfsFltNotifyServerOfBlockingFileOpen` path is reached when a create returns `STATUS_SHARING_VIOLATION` / `0xC0000043`; the `MsNfsFltPostOpCreate` record is built on the normal (non-error) activity-notification path.

#### Root cause

Both functions declare a 0x4c-byte record on the kernel stack and fill it through the shared builder `MsNfsFltServerCallInformationInitialization` (`0x1C0003578` unpatched, relocated to `0x1C0002E18` patched — byte-for-byte identical). The builder writes:

- `+0x00` (4), `+0x08` (8), `+0x10` (4), `+0x18` (8), `+0x20` (8), `+0x28` (8), `+0x30` (8), `+0x38` (8), `+0x40` (4), `+0x44` (4), `+0x48` (4), `+0x4C` (4)

It never writes `+0x04..0x07` or `+0x14..0x17`. In the unpatched builds the record is not zeroed before this call, so those 8 bytes keep whatever was previously on the stack frame.

The partially populated record is then passed to the registered server notification callback (installed via `MsNfsFltRegisterServer`), stored at `arg1[8]` (`[rdi+0x40]`), and invoked through the Control Flow Guard dispatch stub with the record address in `rdx`:

```c
if ( arg1[8] && arg2 != 1 )
    arg1[8](arg1[7], &record);   // dispatched via __guard_dispatch_icall_fptr
```

The patched version inserts, before the record is populated:

```c
memset(&record, 0, 0x4c);
```

This zeroes the padding bytes before any field assignment.

#### Attacker-reachable call chain

1. A user-mode application opens a file on a volume monitored by `msnfsflt.sys`.
2. The post-create minifilter callback `MsNfsFltPostOpCreate` runs.
3. On the normal activity path, `MsNfsFltPostOpCreate` builds its own stack record (`var_70`) via `MsNfsFltServerCallInformationInitialization` and forwards it to `MsNfsFltNotifyServerOfFileActivity` / `MsNfsFltNotifyServerOfVolumeActivity`, which relay it to the registered server callback.
4. If the create returned `STATUS_SHARING_VIOLATION` (`0xC0000043`), `MsNfsFltPostOpCreate` instead calls `MsNfsFltNotifyServerOfBlockingFileOpen` (`cmp eax, 0C0000043h` at `0x1C0008DA9`, call at `0x1C0008DBA`).
5. `MsNfsFltNotifyServerOfBlockingFileOpen` builds its record (`[rbp-0x30]`) via the same builder.
6. The builder leaves padding at `+0x04` and `+0x14` uninitialized.
7. The record is passed to the server callback:

```c
arg1[8](arg1[7], &record)
```

8. Whatever the callback does with the record, the 8 stale stack bytes leave the local frame in kernel context.

---

## 3. Pseudocode Diff

### Unpatched `MsNfsFltNotifyServerOfBlockingFileOpen` (`0x1C0009C50`)

```c
void MsNfsFltNotifyServerOfBlockingFileOpen(
    struct _FLT_INSTANCE **a1,
    __int64 a2,
    struct _FLT_CALLBACK_DATA *a3)
{
    _BYTE record[0x4c];   // [rbp-0x30], NOT zero-initialized

    // ... FltGetFileNameInformation / FltCreateFile / ObReferenceObjectByHandle /
    //     FltQueryInformationFile (FileInternalInformation, FileStandardInformation) ...

    // Builder writes named fields only; padding at +0x04 and +0x14 stays stale.
    MsNfsFltServerCallInformationInitialization(record, a2, a3, 1, 1, FileInformation);

    // flags field at record+0x10 is updated from partially populated data
    *(int *)(record + 0x10) =
        (*(int *)(record + 0x10) & 0xFFFFFF6F)
        | (16 * ((BYTE5(v21) & 1) | (8 * ((a3->Iopb->Parameters.Create.Options & 0x1000) != 0))))
        | 8;

    if ( MsNfsFltOperationBegin(a1) >= 0 )
    {
        if ( a1[8] != NULL && a2 != 1 )
            a1[8](a1[7], record);   // record padding still stale
    }
    // ...
}
```

### Patched `MsNfsFltNotifyServerOfBlockingFileOpen` (`0x1C0009DA8`)

```c
void MsNfsFltNotifyServerOfBlockingFileOpen(
    struct _FLT_INSTANCE **a1,
    __int64 a2,
    struct _FLT_CALLBACK_DATA *a3)
{
    _BYTE record[0x4c];   // [rbp-0x30]

    memset(&record, 0, 0x4c);   // FIX: zero the full record before use

    // ... same acquisition sequence ...

    MsNfsFltServerCallInformationInitialization(record, a2, a3, 1, 1, FileInformation);
    // padding at +0x04 and +0x14 is now guaranteed zero
    // ...
}
```

### Second fixed site: `MsNfsFltPostOpCreate`

The same record is built on the post-create activity path. Unpatched (`0x1C0008BB0`) calls the builder at `0x1C0008D25` with no prior zeroing of `var_70`. Patched (`0x1C000A080`) prepends `memset(&var_70, 0, 0x4c)` at `0x1C000A0B6`, before any other work in the function.

### Activity record write map (both builds, `MsNfsFltServerCallInformationInitialization`)

| Offset | Size | Written by builder |
|---|---:|---|
| `0x00` | 4 | Yes: flags (constant `1`) |
| `0x04` | 4 | **No — uninitialized padding** |
| `0x08` | 8 | Yes: `a2` (file id / type indicator) |
| `0x10` | 4 | Yes: operation flags |
| `0x14` | 4 | **No — uninitialized padding** |
| `0x18` | 8 | Yes: file information (file internal id) |
| `0x20` | 8 | Yes: `0` |
| `0x28` | 8 | Yes: `0` |
| `0x30` | 8 | Yes: `0` |
| `0x38` | 8 | Yes: `0` |
| `0x40` | 4 | Yes: `0xFFFFFFFF` |
| `0x44` | 4 | Yes: `0xFFFFFFFF` |
| `0x48` | 4 | Yes: `0xFFFFFFFF` |
| `0x4C` | 4 | Yes: `0xFFFFFFFF` |

The record spans `0x00`–`0x4F`; the added `memset` covers `0x00`–`0x4B`, which includes both padding gaps. The `0x4C` field is written by the builder in both builds.

---

## 4. Assembly Analysis

### Unpatched `MsNfsFltNotifyServerOfBlockingFileOpen` (`0x1C0009C50`)

The record lives at `[rbp-0x30]` and is never zeroed before the builder runs. The relevant tail of the function:

```asm
00000001C0009E1A  mov     rax, [rbp+60h+FileInformation]
00000001C0009E1E  lea     r9d, [r15+1]
00000001C0009E22  mov     [rsp+160h+IoStatusBlock], rax
00000001C0009E27  lea     rcx, [rbp+60h+var_90]           ; rcx = &record ([rbp-0x30]), UNINITIALIZED
00000001C0009E2B  mov     r8, rsi                         ; r8 = a3
00000001C0009E2E  mov     byte ptr [rsp+160h+ObjectAttributes], 1
00000001C0009E33  mov     rdx, r14                        ; rdx = a2
00000001C0009E36  call    MsNfsFltServerCallInformationInitialization
00000001C0009E3B  mov     r8, [rsi+10h]                   ; a3->Iopb
00000001C0009E3F  movzx   eax, byte ptr [rbp+60h+var_30+5]
00000001C0009E43  and     eax, 1
00000001C0009E46  mov     ecx, [r8+20h]
00000001C0009E4A  shr     ecx, 0Ch
00000001C0009E4D  and     ecx, 1
00000001C0009E50  shl     ecx, 3
00000001C0009E53  or      ecx, eax
00000001C0009E55  mov     eax, [rbp+60h+var_80]           ; record+0x10 flags field
00000001C0009E58  shl     ecx, 4
00000001C0009E5B  and     eax, 0FFFFFF6Fh
00000001C0009E60  or      ecx, eax
00000001C0009E62  or      ecx, 8
00000001C0009E65  mov     [rbp+60h+var_80], ecx
00000001C0009E68  mov     rcx, rdi                        ; rcx = a1
00000001C0009E6B  call    MsNfsFltOperationBegin
00000001C0009E70  test    eax, eax
00000001C0009E72  js      short loc_1C0009EA6
00000001C0009E74  mov     rax, [rdi+40h]                  ; a1[8] = server callback pointer
00000001C0009E78  test    rax, rax
00000001C0009E7B  jz      short loc_1C0009E91             ; no callback -> skip
00000001C0009E7D  cmp     r14, 1                          ; a2 != 1 ?
00000001C0009E81  jz      short loc_1C0009E91
00000001C0009E83  mov     rcx, [rdi+38h]                  ; a1[7] = callback context
00000001C0009E87  lea     rdx, [rbp+60h+var_90]           ; rdx = &record (padding still stale)
00000001C0009E8B  call    cs:__guard_dispatch_icall_fptr  ; CFG-dispatched call of a1[8](a1[7], &record)
00000001C0009E91  mov     rcx, rdi
00000001C0009E94  call    MsNfsFltOperationComplete
00000001C0009E99  jmp     short loc_1C0009EA6
```

The indirect call at `0x1C0009E8B` goes through the Control Flow Guard dispatch stub (`__guard_dispatch_icall_fptr`); the actual target is the pointer loaded from `[rdi+0x40]` at `0x1C0009E74`.

### Patched `MsNfsFltNotifyServerOfBlockingFileOpen` (`0x1C0009DA8`)

The patched prologue adds the `memset`:

```asm
00000001C0009DCE  xor     r15d, r15d
00000001C0009DD1  mov     r14, r8                         ; r14 = a3
00000001C0009DD4  mov     rsi, rdx                        ; rsi = a2
00000001C0009DD7  mov     [rsp+160h+Object], r15
00000001C0009DDC  mov     rdi, rcx                        ; rdi = a1
00000001C0009DDF  mov     [rbp+60h+FileInformation], r15
00000001C0009DE3  xorps   xmm0, xmm0
00000001C0009DE6  mov     [rbp+60h+FileNameInformation], r15
00000001C0009DEA  xor     eax, eax
00000001C0009DEC  lea     r8d, [r15+4Ch]                  ; r8 = 0x4c  (memset size)
00000001C0009DF0  xor     edx, edx                        ; edx = 0    (fill byte)
00000001C0009DF2  mov     [rbp+60h+var_30], rax
00000001C0009DF6  lea     rcx, [rbp+60h+var_90]           ; rcx = &record ([rbp-0x30])
00000001C0009DFA  movups  [rbp+60h+var_40], xmm0
00000001C0009DFE  call    memset                          ; memset(&record, 0, 0x4c)
```

After this call, offsets `+0x04` and `+0x14` are zero before the record builder runs at `0x1C0009FB9`.

### Patched `MsNfsFltPostOpCreate` (`0x1C000A080`)

The same fix at the second site, at the very top of the function:

```asm
00000001C000A0A9  xor     edx, edx                        ; Val = 0
00000001C000A0AB  mov     rdi, rcx
00000001C000A0AE  lea     rcx, [rbp+57h+var_70]           ; &record
00000001C000A0B2  lea     r8d, [rdx+4Ch]                  ; Size = 0x4c
00000001C000A0B6  call    memset                          ; memset(&var_70, 0, 0x4c)
```

The unpatched `MsNfsFltPostOpCreate` (`0x1C0008BB0`) has no equivalent zeroing before its builder call at `0x1C0008D25`.

---

## 5. Trigger Conditions

1. Ensure Services for NFS is installed and `msnfsflt.sys` is loaded and attached.
   - From a shell, `fltmc` should list the NFS filter.
2. A registered NFS server callback is required for the callback-delivery path. Registration is performed by the NFS redirector service via `MsNfsFltRegisterServer`. The callback path requires:

```c
arg1[8] != NULL
arg2 != 1
```

3. Create or identify a target file on a filtered volume.

4. For the `STATUS_SHARING_VIOLATION` path, open the file once with exclusive sharing:

```c
HANDLE hA = CreateFileW(
    L"\\\\?\\C:\\NfsFltTarget\\file.bin",
    GENERIC_READ | GENERIC_WRITE,
    0,                          // exclusive: no sharing
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);
```

5. While `hA` remains open, open the same file again with incompatible access:

```c
HANDLE hB = CreateFileW(
    L"\\\\?\\C:\\NfsFltTarget\\file.bin",
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    0,
    NULL
);
```

6. The second create returns `ERROR_SHARING_VIOLATION` (Win32 error 32), NT status:

```c
STATUS_SHARING_VIOLATION = 0xC0000043
```

7. `MsNfsFltPostOpCreate` compares the status at `0x1C0008DA9` and calls `MsNfsFltNotifyServerOfBlockingFileOpen` at `0x1C0008DBA`.

8. Inside `MsNfsFltNotifyServerOfBlockingFileOpen`, these calls must succeed:
   - `FltGetFileNameInformation`
   - `FltCreateFile`
   - `ObReferenceObjectByHandle`
   - `FltQueryInformationFile` (twice: `FileInternalInformation`, `FileStandardInformation`)
   - `MsNfsFltServerCallInformationInitialization`

9. If the server callback is registered and `arg2 != 1`, the record is passed to `arg1[8](arg1[7], &record)`.

10. Observable confirmation:
    - In a kernel debugger, the bytes at `[rbp-0x30]+0x04` and `[rbp-0x30]+0x14` are non-zero before the callback in the unpatched build.
    - In the patched build, those bytes are zero.
    - There is no crash; this is an information-initialization issue, not memory corruption.

Note: the ordinary (non-error) post-create activity path builds the `MsNfsFltPostOpCreate` `var_70` record on every monitored create, so the second fixed site is reached without needing a sharing violation.

---

## 6. Exploit Primitive and Development Notes

### Primitive

The vulnerability is a **kernel stack information-initialization flaw**.

- Uninitialized bytes: 8 per record (4 at `+0x04`, 4 at `+0x14`).
- The bytes are structure padding filled with stale kernel stack contents from earlier execution in the same thread frame. Their content is not controlled or predictable from the binaries.

### What is established from the binaries

- Both unpatched functions build the record without zeroing it, and the shared builder leaves the two padding gaps unwritten.
- The record is passed to the registered server notification callback (directly in `MsNfsFltNotifyServerOfBlockingFileOpen`, or via `MsNfsFltNotifyServerOfFileActivity` / `MsNfsFltNotifyServerOfVolumeActivity` in `MsNfsFltPostOpCreate`).
- The patch zeroes the record in both functions.

### What is NOT established from the binaries

- Whether the registered callback (in the NFS server subsystem) copies, stores, or transmits the padding bytes, and whether they reach any lower-privilege or remote sink. The callback target is not present in these two binaries.
- The semantic value of the leaked bytes. No claim about kernel pointers, return addresses, tokens, or KASLR-relevant content can be justified from this diff.

Because downstream observability is not demonstrable here, the severity is capped at Medium and the leak should be treated as an uninitialized-padding disclosure of undetermined exploit value rather than a proven information-disclosure primitive.

### Mitigations notes

- **KASLR / SMEP / SMAP / CFG / XFG / HVCI:** none of these prevent an uninitialized-padding disclosure, and none are bypassed by it on their own. This bug produces no control-flow or write primitive.
- **Stack zeroing:** fresh kernel stack pages may be zeroed, but frame reuse means stale data can remain in reused slots; the patch removes the dependency on that.

---

## 7. Debugger Notes

This section assumes a kernel debugger is attached to the **unpatched** target with `msnfsflt.sys` loaded. Runtime addresses differ from the static `0x1c000000`-based addresses because of relocation; use module-relative offsets.

```text
0: kd> lm m msnfsflt*
```

### Key breakpoints (unpatched offsets)

#### 1. Post-create status check

```text
bp msnfsflt_unpatched+0x8da9
```

`MsNfsFltPostOpCreate` compares the create status against `0xC0000043` here; the `jnz` at `+0x8dae` and the call to `MsNfsFltNotifyServerOfBlockingFileOpen` at `+0x8dba` follow.

#### 2. Vulnerable handler entry

```text
bp msnfsflt_unpatched+0x9c50
```

Entry registers: `rcx = a1` (instance/server context), `rdx = a2`, `r8 = a3` (`FLT_CALLBACK_DATA*`). After the prologue, `rdi = a1`, `r14 = a2`, `rsi = a3`.

#### 3. Before the record builder call

```text
bp msnfsflt_unpatched+0x9e36
```

`rcx = [rbp-0x30]` points to the uninitialized record. Inspect the padding gaps:

```text
dd @rcx+4 l1
dd @rcx+0x14 l1
```

#### 4. After the builder returns

```text
bp msnfsflt_unpatched+0x9e3b
dd @rbp-0x30 l0x13
dd @rbp-0x30+4 l1
dd @rbp-0x30+0x14 l1
```

The two DWORDs at `+0x04` and `+0x14` retain pre-call stack contents (the builder does not write them).

#### 5. Server callback invocation

```text
bp msnfsflt_unpatched+0x9e8b
```

This is the CFG-dispatched call `arg1[8](arg1[7], &record)`. `rdx = [rbp-0x30]` is the record. The callback pointer is `[rdi+0x40]` (loaded into `rax` at `+0x9e74`), and the gate requires:

```text
[rdi+0x40] != 0     ; a1[8] callback pointer non-NULL
r14 != 1            ; a2 != 1
```

Dump the record passed to the callback:

```text
dd @rdx l0x13
dd @rdx+4 l1
dd @rdx+0x14 l1
```

### Key instruction offsets

| Build / Offset | Instruction | Significance |
|---|---|---|
| unpatched `+0x9e27` | `lea rcx, [rbp+60h+var_90]` | Loads address of the uninitialized record |
| unpatched `+0x9e36` | `call MsNfsFltServerCallInformationInitialization` | Partially fills the record, leaves `+0x04`/`+0x14` stale |
| unpatched `+0x9e74` | `mov rax, [rdi+40h]` | Loads server callback pointer `a1[8]` |
| unpatched `+0x9e87` | `lea rdx, [rbp+60h+var_90]` | Loads `&record` for the callback |
| unpatched `+0x9e8b` | `call cs:__guard_dispatch_icall_fptr` | CFG-dispatched call of `a1[8](a1[7], &record)` |
| patched `+0x9dfe` | `call memset` | Added `memset(&record, 0, 0x4c)` in `MsNfsFltNotifyServerOfBlockingFileOpen` |
| patched `+0xa0b6` | `call memset` | Added `memset(&var_70, 0, 0x4c)` in `MsNfsFltPostOpCreate` |

### Structure layout notes

| Offset | Size | Meaning |
|---|---:|---|
| `0x00` | 4 | Flags (constant `1`) |
| `0x04` | 4 | Padding: uninitialized in unpatched build |
| `0x08` | 8 | `a2` (file id / type indicator) |
| `0x10` | 4 | Operation flags |
| `0x14` | 4 | Padding: uninitialized in unpatched build |
| `0x18` | 8 | File information (file internal id) |
| `0x20`–`0x3F` | 32 | Written zero |
| `0x40`, `0x44`, `0x48`, `0x4C` | 4 each | `0xFFFFFFFF` |

### Trigger setup from user mode

Two creates against the same file: the first takes exclusive access, the second triggers the sharing violation.

```c
#include <windows.h>

int main()
{
    HANDLE hA = CreateFileW(
        L"\\\\?\\C:\\NfsFltTarget\\leak_trigger.bin",
        GENERIC_READ | GENERIC_WRITE,
        0,                          // exclusive sharing
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hA == INVALID_HANDLE_VALUE) {
        return 1;
    }

    HANDLE hB = CreateFileW(
        L"\\\\?\\C:\\NfsFltTarget\\leak_trigger.bin",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    DWORD err = GetLastError();

    if (hB != INVALID_HANDLE_VALUE) {
        CloseHandle(hB);
    }

    CloseHandle(hA);

    return err == ERROR_SHARING_VIOLATION ? 0 : 2;
}
```

Expected debugger observation:

- At `+0x9e3b`, the DWORDs at `[rbp-0x30]+0x04` and `[rbp-0x30]+0x14` are non-zero.
- At `+0x9e8b`, the same non-zero bytes are present in `@rdx+0x04` and `@rdx+0x14`.
- In the patched build, those locations are zero after the added `memset`.

---

## 8. Changed Functions — Full Triage

| Function | Similarity | Change type | Note |
|---|---:|---|---|
| `MsNfsFltNotifyServerOfBlockingFileOpen` | 0.9793 | Security-relevant | Adds `memset(&record, 0, 0x4c)` before the record builder; fixes uninitialized stack padding leak on the `STATUS_SHARING_VIOLATION` path. |
| `MsNfsFltPostOpCreate` | 0.9835 | Security-relevant | Adds `memset(&var_70, 0, 0x4c)` at function entry, before its record builder call; fixes the same uninitialized padding leak on the normal activity path. Also contains unrelated pool-API refactoring. |
| `MsNfsFltCheckFileForActivity` | 0.8756 | Cosmetic | Loop traversal and flag-bit encoding restructured; functionally equivalent. |
| `MsNfsFltPreOpGetFileContext` | 0.7208 | Cosmetic | Large pre-operation callback; also calls the record builder, but into a pool-allocated (zeroed) object at `[rdi+0x30]`, so it needs no memset. Control-flow and register-allocation differences only. |
| `MsNfsFltInstanceSetup` | 0.7633 | Cosmetic | Volume attachment callback; `ExAllocatePoolWithTag` to `ExAllocatePool2`. |
| `MsNFsFltContextCallbackCleanupAndDelete` | 0.8188 | Cosmetic | Pool-management changes; custom SLIST pool replaced with lookaside-list free. |
| `MsNfsFltNotifyServerOfNewlyMountedVolumeByWorkItem` | 0.8314 | Cosmetic | Work-item queueing; `ExAllocatePool2` and error-path restructuring. |
| `MsNfsFltContextCreateStreamHandle` | 0.8323 | Cosmetic | Stream handle context creation; control-flow restructuring, same `FltAllocateContext`/`FltSetStreamHandleContext` behavior. |
| `MsNfsFltGetSourceDirectoryFileId` | 0.9576 | Cosmetic | `FileHardLinkInformation` query; pool API modernization. |
| `MsNfsFltGetTargetDirectoryFileId` | 0.9800 | Cosmetic | Rename/destination query handler; explicit local initialization and struct zeroing. |
| `MsNfsFltContextFileUpdateFileId` | 0.9911 | Cosmetic | File activity update; register reallocation only. |
| `WppLoadTracingSupport` | 0.9842 | Cosmetic | Tracing initialization; explicit `UNICODE_STRING` zeroing. |

Most non-security changes fall into three categories:

- Compiler-generated control-flow restructuring
- Register allocation differences
- Pool API modernization from `ExAllocatePoolWithTag` to `ExAllocatePool2`

No removed bounds check, removed size validation, or deleted security gate was observed in the other changed functions. The only security-relevant delta is the pair of added `memset` calls at the two stack-based record sites.

---

## 9. Unmatched Functions

There are no unmatched functions in either direction.

- Removed functions: none
- Added functions: none

The patch does not introduce a new mitigation function and does not remove an existing validation routine. The meaningful change is the insertion of `memset` in the two functions that build the server-call record on the stack.

---

## 10. Confidence and Caveats

### Confidence

High confidence that the unpatched builds contain uninitialized stack padding in this record:

- The unpatched assembly shows no zero-initialization of the record before the builder runs.
- The shared builder writes every field except `+0x04` and `+0x14`.
- The patched assembly explicitly inserts `memset(record, 0, 0x4c)` in both affected functions.
- The record is passed to a registered callback.

Medium confidence on real-world impact:

- The uninitialized padding is confirmed, and the direction is unambiguous (the patched build is strictly the one that zeroes).
- Whether the leaked bytes become an attacker-observable kernel disclosure depends on what the registered server callback does with the record, which is not determinable from these two binaries.

### Verified facts

- The call chain `MsNfsFltPostOpCreate` → (`0xC0000043` check at `0x1C0008DA9`) → `MsNfsFltNotifyServerOfBlockingFileOpen` is present in the unpatched build.
- `MsNfsFltServerCallInformationInitialization` writes only the documented fields; `+0x04` and `+0x14` are left unwritten in both builds.
- The record is passed to `arg1[8]` via the CFG dispatch stub.
- The builder is byte-for-byte identical in both builds (relocated `0x1C0003578` → `0x1C0002E18`), so the added `memset` is the fix, not a change in the builder.
- The third builder caller, `MsNfsFltPreOpGetFileContext`, populates a pool-backed record and receives no memset in the patch.

The core change is straightforward: the patch adds the missing `memset` in both stack-record sites, and the unpatched code leaks uninitialized kernel stack padding through the NFS server-call record.
