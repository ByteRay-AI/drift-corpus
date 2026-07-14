Title: nfsrdr.sys — redundant XDR error-state early-out removed from XdrDecodeString
Date: 2026-01-13
Slug: nfsrdr_2cb8d71f-nfsrdr-report-20260626-064352
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Unknown
KBDate: 2026-01-13

### 1. Overview

* **Unpatched Binary:** `nfsrdr_unpatched.sys`
* **Patched Binary:** `nfsrdr_patched.sys`
* **Overall Similarity Score:** 0.993
* **Diff Statistics:** 376 matched functions, 375 identical, 1 changed, 0 unmatched in either direction.
* **Verdict:** The patch changes exactly one function, `XdrDecodeString`. It removes a redundant early-out that branched to the slow decode path when the XDR stream error-status field was negative. The trailing single-byte null-terminator write is byte-for-byte identical in both builds and is bounded by the callers, so there is no out-of-bounds write and no reachable security impact. This is a code-cleanup / correctness refactor, not a security fix.

### 2. Change Summary

* **Severity:** None (no security-relevant change)
* **Change Class:** Redundant check removal / control-flow simplification
* **Affected Function:** `XdrDecodeString` (`0x1C0012C38`, same address in both builds)

**What actually changed:**
`XdrDecodeString` decodes an XDR (External Data Representation) opaque string from an NFS/RPC reply into a caller-provided buffer.

In the unpatched build the function begins with an error-state gate:

```
0x1C0012C47  cmp     dword ptr [rcx+108h], 0    ; XDR stream error-status field
0x1C0012C56  jl      loc_1C0012CDD               ; if negative, jump straight to slow path
```

When `[rcx+0x108]` is negative (an error left by a prior decode) the function skips computing the available-byte count and branches directly to `XdrDecodeOpaqueSlow`.

In the patched build that `cmp`/`jl` pair is gone. The function instead loads the current buffer segment unconditionally (`mov r9, [rcx+48h]` at `0x1C0012C47`), always computes the available byte count, and decides between the fast (`memmove`) path and `XdrDecodeOpaqueSlow` solely on `available < requested`. The remaining differences are register reallocations (arg1 moves from `rbx` to `rdi`; the length argument moves from `edi` to `ebx`).

**Why this is not a security fix:**

1. `XdrDecodeOpaqueSlow` (`0x1C0037C7C` unpatched, relocated to `0x1C0037C6C` patched) performs the same error-state check at its own entry (`cmp [rcx+108h], edi` / `jl` at `0x1C0037CA4`–`0x1C0037CAA`) and returns immediately without copying when the field is negative. So when the stream is in error, both builds converge to the same no-copy outcome.
2. The only reachable behavioral difference is the narrow case where the error field is negative **and** the current segment already holds enough bytes: the patched build then performs the bounded `memmove` fast path instead of the no-op slow path. That copy is bounded by `available >= requested` and the callers ignore the output whenever the error field is negative, so it has no security effect in either direction.
3. The trailing null-terminator write is identical in both builds and is in bounds (see Section 4).

### 3. Pseudocode Diff

Decompiled source, the only body that differs between the two builds:

```c
// Unpatched XdrDecodeString @ 0x1C0012C38
__int64 __fastcall XdrDecodeString(__int64 a1, unsigned int a2, void *a3)
{
    size_t v4 = a2;
    if ( *(int *)(a1 + 264) < 0 )     // 264 = 0x108, REMOVED IN PATCH
        goto LABEL_17;                // -> XdrDecodeOpaqueSlow
    v6 = *(_DWORD **)(a1 + 72);       // buffer segment (0x48)
    // ... compute available bytes v7 ...
    if ( v7 < (unsigned int)v4 )
    {
LABEL_17:
        result = XdrDecodeOpaqueSlow(a1, (unsigned int)v4, a3);
    }
    else
    {
        memmove(a3, v11, v4);         // bounded: available >= v4
        // ... advance buffer + XDR 4-byte alignment ...
    }
    *((_BYTE *)a3 + v4) = 0;          // null terminator; in bounds (v4 <= 0x40, buffer >= 256)
    return result;
}

// Patched XdrDecodeString @ 0x1C0012C38
__int64 __fastcall XdrDecodeString(__int64 a1, unsigned int a2, void *a3)
{
    v3 = *(_DWORD **)(a1 + 72);       // buffer segment loaded unconditionally
    size_t v5 = a2;
    // ... compute available bytes v7 (no 0x108 gate) ...
    if ( v7 < (unsigned int)v5 )
        result = XdrDecodeOpaqueSlow(a1, (unsigned int)v5, a3);
    else
    {
        memmove(a3, v11, v5);
        // ... advance buffer + XDR 4-byte alignment ...
    }
    *((_BYTE *)a3 + v5) = 0;          // identical to unpatched
    return result;
}
```

### 4. Assembly Analysis

Full unpatched `XdrDecodeString`. The only instructions absent from the patched build are the two annotated as removed; the null-terminator write is present unchanged in both.

```assembly
; ---- XdrDecodeString @ 0x1C0012C38 (unpatched) ----
0x1C0012C38  mov     [rsp+arg_0], rbx
0x1C0012C3D  mov     [rsp+arg_8], rsi
0x1C0012C42  push    rdi
0x1C0012C43  sub     rsp, 20h
0x1C0012C47  cmp     dword ptr [rcx+108h], 0    ; REMOVED IN PATCH: XDR stream error-status gate
0x1C0012C4E  mov     rsi, r8                     ; arg3 (output buffer)
0x1C0012C51  mov     edi, edx                    ; arg2 (string length)
0x1C0012C53  mov     rbx, rcx                    ; arg1 (XDR context)
0x1C0012C56  jl      loc_1C0012CDD               ; REMOVED IN PATCH: if error, go to slow path
0x1C0012C5C  mov     r9, [rcx+48h]               ; current buffer segment ptr
0x1C0012C60  test    r9, r9
0x1C0012C63  jnz     short loc_1C0012C69
0x1C0012C65  xor     eax, eax                    ; available = 0
0x1C0012C67  jmp     short loc_1C0012C8C
0x1C0012C69  mov     edx, [r9+40h]               ; read_pos
0x1C0012C6D  sub     edx, [r9+38h]               ; consumed = read_pos - start
0x1C0012C71  mov     r8d, [r9+4Ch]               ; buffer_size
0x1C0012C75  cmp     r8d, edx
0x1C0012C78  jb      short loc_1C0012C81
0x1C0012C7A  mov     ecx, r8d
0x1C0012C7D  sub     ecx, edx                    ; available = buffer_size - consumed
0x1C0012C7F  jmp     short loc_1C0012C84
0x1C0012C81  or      ecx, 0FFFFFFFFh
0x1C0012C84  xor     eax, eax
0x1C0012C86  cmp     r8d, edx
0x1C0012C89  cmovnb  eax, ecx                    ; eax = available bytes
0x1C0012C8C  cmp     eax, edi                    ; available >= requested?
0x1C0012C8E  jb      short loc_1C0012CDD          ; if available < length -> slow path
0x1C0012C90  test    r9, r9
0x1C0012C93  jnz     short loc_1C0012C99
0x1C0012C95  xor     edx, edx
0x1C0012C97  jmp     short loc_1C0012C9D
0x1C0012C99  mov     rdx, [r9+40h]               ; Src = read_pos
0x1C0012C9D  mov     r8, rdi                     ; Size = length
0x1C0012CA0  mov     rcx, rsi                    ; dest = output
0x1C0012CA3  call    memmove                     ; bounded copy (available >= length)
0x1C0012CA8  mov     rax, [rbx+48h]
0x1C0012CAC  add     [rax+40h], rdi
0x1C0012CB0  mov     rcx, [rbx+48h]
0x1C0012CB4  test    rcx, rcx
0x1C0012CB7  jnz     short loc_1C0012CC3
0x1C0012CB9  mov     r8, [rcx+40h]
0x1C0012CBD  xor     eax, eax
0x1C0012CBF  xor     edx, edx
0x1C0012CC1  jmp     short loc_1C0012CCE
0x1C0012CC3  mov     rdx, [rcx+40h]
0x1C0012CC7  mov     rax, [rcx+38h]
0x1C0012CCB  mov     r8, rdx
0x1C0012CCE  sub     rax, rdx
0x1C0012CD1  and     eax, 3                      ; XDR 4-byte alignment padding
0x1C0012CD4  add     rax, r8
0x1C0012CD7  mov     [rcx+40h], rax
0x1C0012CDB  jmp     short loc_1C0012CEA
0x1C0012CDD  mov     r8, rsi                     ; arg3 = output buffer
0x1C0012CE0  mov     edx, edi                    ; arg2 = length
0x1C0012CE2  mov     rcx, rbx                    ; arg1 = XDR context
0x1C0012CE5  call    XdrDecodeOpaqueSlow         ; also no-op when [rcx+108h] < 0
0x1C0012CEA  mov     byte ptr [rdi+rsi], 0       ; output[length] = 0 (in bounds; identical in patched)
0x1C0012CEE  mov     rbx, [rsp+28h+arg_0]
0x1C0012CF3  mov     rsi, [rsp+28h+arg_8]
0x1C0012CF8  add     rsp, 20h
0x1C0012CFC  pop     rdi
0x1C0012CFD  retn
```

Patched equivalent of the sink (same operation, reallocated register — length is in `rbx` rather than `rdi`):

```assembly
0x1C0012CDD  mov     byte ptr [rbx+rsi], 0       ; output[length] = 0 (patched)
```

### 5. Bounds Analysis (why the null write is safe)

The null-terminator write `output[length] = 0` writes at offset `length` into the caller-supplied buffer. Both callers cap `length` at `0x40` (64) and supply buffers of at least 256 bytes, so the maximum write index is `output[64]`, well inside the allocation.

* `MapGetUnixCredsFromSid` (`0x1C0011514`): output buffer is `char v78[256]`; the guard `if ( v28 <= 0x40 )` precedes the call, so `length <= 0x40`. After the call the caller itself writes `v78[v28] = 0` guarded by an explicit range check against `0x100`.
* `MapGetUnixCredsFromNTUserName` (`0x1C0011DA0`): output buffer is `ExAllocatePoolWithTag(PagedPool, 0x100u, ...)` (256 bytes); the guard `if ( v54 > 0x40 )` skips the call for larger lengths, so `length <= 0x40`.

Both callers additionally test the XDR stream error field (`context+0x108`) around the call and discard the output when it is negative, so no stale buffer content is consumed.

### 6. Call Chain (context only)

The function is reached through NFS credential mapping, but no attacker-reachable memory-safety primitive is present in either build:

1. NFS/RPC reply received during credential mapping.
2. `MapGetUnixCredsFromSid` (`0x1C0011514`) or `MapGetUnixCredsFromNTUserName` (`0x1C0011DA0`) decodes a length, validates it `<= 0x40`, and calls `XdrDecodeString` with a >= 256-byte buffer.
3. `XdrDecodeString` (`0x1C0012C38`) copies at most `length` bytes and writes an in-bounds null terminator.

### 7. Independent Diff Verification

An independent content-level diff of the two decompiled builds (with function-header addresses normalized to account for the ~16-byte relocation of everything after `XdrDecodeString`) confirms that every differing line falls inside the `XdrDecodeString` body; no other function body changed. This matches the reported count of exactly one changed function. Functions following `XdrDecodeString` are relocated by a fixed offset (e.g. `XdrDecodeOpaqueSlow` `0x1C0037C7C` -> `0x1C0037C6C`, `XdrDecodeStringAndLength` `0x1C003179C` -> `0x1C003178C`) but their content is byte-equivalent.

### 8. Changed Functions — Full Triage

* **`XdrDecodeString`** (Similarity: 0.9401)
  * **Change Type:** Not security relevant
  * **Notes:** Removed the redundant error-state early-out (`cmp dword ptr [rcx+108h], 0` at `0x1C0012C47` and `jl loc_1C0012CDD` at `0x1C0012C56`). The patched build always computes the available byte count and branches to `XdrDecodeOpaqueSlow` only on `available < requested`. `XdrDecodeOpaqueSlow` re-checks the same error field and returns no-op when it is negative, so the reachable outcome is unchanged. Register reallocation accompanies the change (arg1 `rbx` -> `rdi`; length `edi` -> `ebx`). The trailing null-terminator write is identical in both builds and is in bounds given the callers' `<= 0x40` length cap and >= 256-byte buffers.

### 9. Unmatched Functions

There were no unmatched functions added or removed in this patch. The modification is isolated to the entry control flow of `XdrDecodeString`.

### 10. Confidence & Caveats

* **Confidence:** High. Both builds' `XdrDecodeString` were read in full in assembly and decompiled form; the sink instruction and both callers' buffer sizes and length caps were confirmed directly.
* **Basis:** Buffer sizes and length caps are read from the caller decompilation (`char v78[256]`; `ExAllocatePoolWithTag(PagedPool, 0x100u, ...)`; guards `v28 <= 0x40` and `v54 > 0x40`). The XDR context field at offset `0x108` is the stream error-status field checked identically by `XdrDecodeOpaqueSlow`.
* **Conclusion:** No security-relevant change. The patch removes a redundant check; it does not add or remove any bounds check and does not alter the in-bounds null-terminator write. No CWE applies.
