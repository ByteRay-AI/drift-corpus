Title: datascrn.sys — overflow-guard consolidation and allocation-API modernization
Date: 2026-01-13
Slug: datascrn_ee658b81-datascrn-report-20260625-221333
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Informational
KBDate: 2026-01-13

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `datascrn_unpatched.sys` |
| **Patched binary** | `datascrn_patched.sys` |
| **Overall similarity** | 0.9019 |
| **Matched functions** | 232 |
| **Changed functions** | 197 |
| **Identical functions** | 35 |
| **Unmatched (unpatched → patched)** | 0 / 0 |

**Verdict:** No security-relevant change was found between the two builds. The most conspicuous change, in `SrmAppendPath`, is a **refactor**: the caller-side overflow guard (`a1->Length + a2->Length > 0xFFFE`) is moved from every call site into the callee, and the allocation call is modernized from `ExAllocatePoolWithTag(PagedPool, …)` to `ExAllocatePool2(POOL_FLAG_PAGED, …)`. The copy logic and the resulting buffer size are byte-for-byte equivalent, and the unpatched code was already guarded at every reachable call site, so no exploitable pool overflow exists in either build. `SrmCanInsertPrefixTreePath` shows no behavioral change (both builds pass the already-processed path prefix to transaction-status validation; the low similarity is control-flow restructuring only). A broad refactoring migrates ~10 functions from a custom SLIST-based object cache to standard kernel LookasideList APIs with no observable behavior change.

---

## 2. Change Summary

### Finding 1 — `SrmAppendPath` (guard relocation + allocation-API modernization, no security change)

| Attribute | Detail |
|---|---|
| **Severity** | Informational |
| **Class** | Refactor / defense-in-depth (no reachable vulnerability) |
| **Affected function** | `SrmAppendPath` (unpatched @ `0x1C001DE10`, patched @ `0x14001E88C`) |
| **Primitive** | None |

**What actually changed:**

`SrmAppendPath` concatenates a source `UNICODE_STRING` (`a2`) onto a destination `UNICODE_STRING` (`a1`). When `RtlAppendUnicodeStringToString` reports `STATUS_BUFFER_TOO_SMALL` (`0xC0000023`), the function allocates a new pool buffer, copies the existing string, then copies the appended string, and updates `a1`. The two `memmove` calls write exactly `a1->Length + a2->Length` bytes, and the buffer is sized as `(size + 0x1FF) & 0xFFFFFE00` (round up to 512) capped at `0xFFFE`.

- **Unpatched (`0x1C001DE10`)** takes a third argument `a3` (in `r8d`) that supplies the size to round up. Every caller passes `a3 = a1->Length + a2->Length` and rejects the operation if that sum exceeds `0xFFFE` **before** calling (see Section 4 for the four call sites). So `a3` equals the real combined length at every reachable call, the sum is computed with a 32-bit `add` (no 16-bit wrap is possible), and the allocation `(a3 + 0x1FF) & 0xFFFFFE00` is always ≥ the number of bytes copied. The two `memmove`s never exceed the allocation.

- **Patched (`0x14001E88C`)** drops `a3` (signature goes from 3 args to 2), and instead computes `v3 = a1->Length + a2->Length` inside the function, returning `STATUS_NAME_TOO_LONG` (`0xC0000106`) if `v3 > 0xFFFE`. It then sizes the allocation from `v3`. It also replaces `ExAllocatePoolWithTag(PagedPool, …)` with `ExAllocatePool2(POOL_FLAG_PAGED, …)`.

The net effect is that the identical `combined > 0xFFFE` guard is **relocated from the callers into the callee**. This is a maintainability/robustness improvement (the function is now safe by construction even for a future caller that forgets the check) and an allocation-API modernization. It does not fix a reachable bug: in the unpatched build the guard was already present at every call site, the combined length was already computed in 32 bits, and the buffer was always large enough for the two copies. There is no direction of "vulnerable → fixed" here, only "guard in caller → guard in callee".

The pool tag `0x706D7253` (bytes `53 72 6D 70` in memory) is ASCII `"Srmp"`; it is unchanged between builds.

### Finding 2 — `SrmCanInsertPrefixTreePath` (no security change)

| Attribute | Detail |
|---|---|
| **Severity** | Informational |
| **Class** | No behavioral change (control-flow restructuring) |
| **Affected function** | `SrmCanInsertPrefixTreePath` (unpatched @ `0x1C001D4E8`, patched @ `0x14001E974`) |
| **Primitive** | None |

**What actually changed:**

There is no security-relevant difference between the two builds. While walking a multi-component path through the prefix tree, both builds dissect the path and, before calling `DataScreenCheckPrefixTreeNodeTxStatusCallback`, set `Source.Length = a2->Length - remaining.Length` and pass `&Source`. That `Source` value is the **already-processed path prefix** in both builds:

- Unpatched (`0x1C001D4E8`): `Source = *a2;` then in the loop `Source.Length = a2->Length - v15.Length;` and `DataScreenCheckPrefixTreeNodeTxStatusCallback(&Source, a5, &v17);`
- Patched (`0x14001E974`): `Source = v5;` (`v5 = *a2`) then `Source.Length = a2->Length - v12.Length;` and `DataScreenCheckPrefixTreeNodeTxStatusCallback(&Source, v16, va);`

The only differences are control-flow restructuring (the patched build folds the node-type test `v10 == 2 || v10 == 3 || (v10 == 1 && *(entry+0x40) != 0)` into one condition where the unpatched build uses separate branches with goto-based flow) and register/stack reallocation — codegen artifacts, not a fix.

**Data flow:**

1. File I/O occurs on a volume monitored by `datascrn.sys` (create, rename, set-info).
2. `DataScreenPreCreate` or `DataScreenPostSetInfo` intercepts the operation.
3. → `DataScreenGetDirectoryEntry` resolves the directory entry.
4. → `SrmCanInsertPrefixTreePath` walks the prefix tree and calls `DataScreenCheckPrefixTreeNodeTxStatusCallback` with the processed prefix (`&Source`) — identical in both builds.

---

## 3. Decompilation Diff

### `SrmAppendPath` — Before vs. After

```c
// ──────────────────────────────────────────────────────
// UNPATCHED @ 0x1C001DE10 — 3 args; size supplied by caller (a3)
// ──────────────────────────────────────────────────────
__int64 __fastcall SrmAppendPath(struct _UNICODE_STRING *a1, const UNICODE_STRING *a2, int a3)
{
    if ( RtlAppendUnicodeStringToString(a1, a2) == 0xC0000023 )  // STATUS_BUFFER_TOO_SMALL
    {
        unsigned int v6 = (a3 + 0x1FF) & 0xFFFFFE00;   // round up to 512
        if ( v6 > 0xFFFE ) v6 = 0xFFFE;

        WCHAR *p = ExAllocatePoolWithTag(PagedPool, v6, 0x706D7253);   // tag 'Srmp'
        if ( !p ) return 0xC000009A;                   // STATUS_INSUFFICIENT_RESOURCES

        memmove(p, a1->Buffer, a1->Length);            // existing data
        memmove((char*)p + a1->Length, a2->Buffer, a2->Length);  // appended data
        ExFreePoolWithTag(a1->Buffer, 0x706D7253);
        a1->Length += a2->Length;
        a1->MaximumLength = v6;
        a1->Buffer = p;
    }
    return 0;
}
// Note: every caller passes a3 = a1->Length + a2->Length and rejects
//       a3 > 0xFFFE before calling, so v6 is always >= the copied bytes.

// ──────────────────────────────────────────────────────
// PATCHED @ 0x14001E88C — 2 args; combined length computed & checked inside
// ──────────────────────────────────────────────────────
__int64 __fastcall SrmAppendPath(struct _UNICODE_STRING *a1, const UNICODE_STRING *a2)
{
    unsigned int v3 = a2->Length + a1->Length;         // 32-bit sum, computed in callee
    if ( v3 > 0xFFFE )
        return 0xC0000106;                             // STATUS_NAME_TOO_LONG

    if ( RtlAppendUnicodeStringToString(a1, a2) == 0xC0000023 )
    {
        unsigned int v6 = (v3 + 0x1FF) & 0xFFFFFE00;
        if ( v6 > 0xFFFE ) v6 = 0xFFFE;

        WCHAR *p = ExAllocatePool2(POOL_FLAG_PAGED, v6, 0x706D7253);
        if ( !p ) return 0xC000009A;

        memmove(p, a1->Buffer, a1->Length);
        memmove((char*)p + a1->Length, a2->Buffer, a2->Length);
        ExFreePoolWithTag(a1->Buffer, 0x706D7253);
        a1->Length += a2->Length;
        a1->MaximumLength = v6;
        a1->Buffer = p;
    }
    return 0;
}
```

**Key takeaways from the diff:**
- The `a3` parameter is removed and the `a1->Length + a2->Length` computation plus `> 0xFFFE` guard are moved from the callers into the callee. Functionally identical: both reject the operation with `STATUS_NAME_TOO_LONG` when the combined length exceeds `0xFFFE`.
- The two `memmove` calls and the resulting buffer size are byte-for-byte the same in both builds.
- `ExAllocatePoolWithTag(PagedPool, …)` is replaced by `ExAllocatePool2(POOL_FLAG_PAGED, …)` — the modern flag-based API. Same PagedPool, same tag `'Srmp'`.

### `SrmCanInsertPrefixTreePath` — Before vs. After (identical behavior)

```c
// UNPATCHED @ 0x1C001D4E8 and PATCHED @ 0x14001E974 — both pass the PROCESSED prefix
do {
    // ...
    Source.Length = a2->Length - remaining.Length;   // processed-prefix length
    // ...
    DataScreenCheckPrefixTreeNodeTxStatusCallback(&Source, ctx, out);
    // ...
} while (/* more path components */);
```

Both builds pass `&Source` (the processed prefix). The only decompiler-visible differences are control-flow flattening and register/stack naming.

---

## 4. Assembly Analysis

### `SrmAppendPath`

**Unpatched @ `0x1C001DE10`** (allocation and copy):

```asm
00000001C001DE24  mov     edi, r8d                    ; edi = a3 (caller-supplied size)
00000001C001DE2D  call    __imp_RtlAppendUnicodeStringToString
00000001C001DE39  cmp     eax, 0C0000023h             ; STATUS_BUFFER_TOO_SMALL?
00000001C001DE3E  jnz     loc_1C001DEC8               ; no -> done
00000001C001DE44  add     edi, 1FFh
00000001C001DE4A  mov     eax, 0FFFEh
00000001C001DE4F  and     edi, 0FFFFFE00h             ; v6 = (a3 + 0x1FF) & ~0x1FF
00000001C001DE55  mov     ecx, 1                      ; PoolType = PagedPool
00000001C001DE5A  cmp     edi, eax
00000001C001DE5C  mov     r8d, 706D7253h              ; Tag 'Srmp'
00000001C001DE62  cmova   edi, eax                    ; cap at 0xFFFE
00000001C001DE65  mov     edx, edi                    ; NumberOfBytes = v6
00000001C001DE67  call    __imp_ExAllocatePoolWithTag
00000001C001DE82  movzx   r8d, word ptr [rbx]         ; a1->Length
00000001C001DE89  mov     rdx, [rbx+8]                ; a1->Buffer
00000001C001DE8D  call    memmove                     ; copy existing string
00000001C001DE92  movzx   ecx, word ptr [rbx]         ; a1->Length (dest offset)
00000001C001DE95  movzx   r8d, word ptr [rsi]         ; a2->Length
00000001C001DE99  add     rcx, rbp                    ; dest = base + a1->Length
00000001C001DE9C  mov     rdx, [rsi+8]                ; a2->Buffer
00000001C001DEA0  call    memmove                     ; append a2 (bytes copied = a2->Length)
```

There is **no** combined-length check inside the unpatched function because the callers perform it (below). The bytes written by the two `memmove`s equal `a1->Length + a2->Length = a3`, and the allocation is `(a3 + 0x1FF) & ~0x1FF` (≥ `a3`), so the copy never exceeds the buffer.

**The four unpatched call sites all compute `a3` as the true combined length and bounds-check it before calling.** The first call site (the other three are identical in shape) is:

```asm
; caller @ 0x1C001CF6A
00000001C001CF6A  movzx   r8d, word ptr [rsp+...var_F8] ; a1->Length
00000001C001CF70  movzx   eax, word ptr [rsp+...var_E8] ; a2->Length
00000001C001CF75  add     r8d, eax                      ; r8d = a1->Length + a2->Length (32-bit)
00000001C001CF78  cmp     r8d, 0FFFEh
00000001C001CF7F  ja      loc_1C001D201                 ; reject (STATUS_NAME_TOO_LONG) BEFORE call
00000001C001CF8F  call    SrmAppendPath                 ; a3 (r8d) = combined length
```

The other three sites are at `0x1C001CFD9`, `0x1C001E06F`, and `0x1C001E0B5`; each performs the same `movzx … / movzx … / add / cmp …,0FFFEh / ja` before the call. Because the two operands are zero-extended to 32 bits and summed with a 32-bit `add`, the "16-bit `USHORT` wrap" scenario cannot occur, and any sum above `0xFFFE` is rejected before `SrmAppendPath` runs.

**Patched @ `0x14001E88C`** — the same guard, now inside the function:

```asm
000000014001E8A0  movzx   esi, word ptr [rcx]          ; a1->Length
000000014001E8A3  mov     ebp, 0FFFEh
000000014001E8A8  movzx   eax, word ptr [rdx]          ; a2->Length
000000014001E8AE  add     esi, eax                     ; esi = combined (32-bit)
000000014001E8B3  cmp     esi, ebp
000000014001E8B5  jbe     short loc_14001E8C1
000000014001E8B7  mov     eax, 0C0000106h              ; STATUS_NAME_TOO_LONG
000000014001E8BC  jmp     loc_14001E955                ; reject
000000014001E8C1  call    __imp_RtlAppendUnicodeStringToString
000000014001E8CD  cmp     eax, 0C0000023h
000000014001E8D4  add     esi, 1FFh
000000014001E8DA  mov     ecx, 100h                    ; POOL_FLAG_PAGED
000000014001E8DF  and     esi, 0FFFFFE00h              ; size from combined length
000000014001E8E5  mov     r8d, 706D7253h               ; Tag 'Srmp'
000000014001E8ED  cmova   esi, ebp                     ; cap at 0xFFFE
000000014001E8F2  call    __imp_ExAllocatePool2
; ... two memmoves identical to the unpatched body ...
```

The patched call sites (`0x14001EB4A`, `0x14001EB7B`, …) pass only `rcx`/`rdx` and no `r8`, confirming the guard is now the callee's responsibility.

### `DataScreenValidatePatternsInFileGroupInformation` — forbidden-char check (not security-relevant)

The forbidden-character validation is functionally equivalent between builds; only the codegen differs.

```asm
; UNPATCHED — bitmask (bt) approach for forbidden-char check
            movzx   ebx, word [r10]        ; current char
            lea     eax, [rbx-0x2f]        ; char - '/'
            cmp     ax, 0x2d               ; range check 0x2f..0x5c
            ja      .ok
            mov     r12, 0x200000000801    ; bitmask: bits 0(/),11(:),45(\)
            movzx   eax, ax
            bt      r12, rax               ; is this bit set?
            jb      .forbidden
            cmp     bx, 0x7c               ; also check '|' separately
            je      .forbidden

; PATCHED — explicit cmp for each forbidden char (functionally identical)
            cmp     word [r10], 0x2f       ; '/'
            je      .forbidden
            cmp     word [r10], 0x3a       ; ':'
            je      .forbidden
            cmp     word [r10], 0x5c       ; '\'
            je      .forbidden
            cmp     word [r10], 0x7c       ; '|'
            je      .forbidden
```

---

## 5. Trigger Conditions

### For `SrmAppendPath`:

Not applicable — there is no reachable pool overflow to trigger in either build. The concatenation is guarded by `a1->Length + a2->Length > 0xFFFE` at every reachable point (in the callers for the unpatched build, in the callee for the patched build), and the two copies never exceed the allocation. The path that reaches `SrmAppendPath` is FSRM prefix-tree path construction (e.g., `SrmInvokeCallbackOnTree` / `SrmCommitPrefixTreeTransaction`), reachable from file-group / file-screen configuration and from file I/O on a monitored volume, but that path cannot cause an out-of-bounds write in either build.

### For `SrmCanInsertPrefixTreePath`:

Not applicable — there is no behavioral change to trigger. In both builds the path is dissected component-by-component during `DataScreenGetDirectoryEntry` → `SrmCanInsertPrefixTreePath`, and `DataScreenCheckPrefixTreeNodeTxStatusCallback` is invoked with the **processed prefix** (`&Source`, `Source.Length = a2->Length - remaining.Length`).

---

## 6. Exploit Primitive

No exploit primitive exists. The change in `SrmAppendPath` is a refactor (guard relocated from callers into the callee) plus an allocation-API modernization (`ExAllocatePoolWithTag` → `ExAllocatePool2`); the copy logic and allocation size are equivalent in both builds. Because the combined-length guard is present on every reachable path in the unpatched build and the sum is computed in 32-bit arithmetic, there is no attacker-controlled out-of-bounds write, no pool corruption primitive, and nothing to escalate. `SrmCanInsertPrefixTreePath` is behavior-identical across builds and likewise provides no primitive.

---

## 7. Verification Playbook

The following is for a researcher who wants to confirm, on a live target, that the two builds are behavior-equivalent for these functions.

### `SrmAppendPath` — confirm the guard and copy sizes

#### Breakpoints

```text
bp datascrn!SrmAppendPath                 ; entry
```

Raw addresses if symbols are unavailable:

```text
bp 0x1c001de10        ; unpatched entry
bp 0x14001e88c        ; patched entry
```

#### What to inspect

| Breakpoint | Register / Memory | What to check |
|---|---|---|
| Unpatched entry | `rcx` = a1 (`UNICODE_STRING*`), `rdx` = a2, `r8d` = a3 | Confirm `r8d == [rcx].Length + [rdx].Length` (the caller already computed and range-checked it). |
| Patched entry | `rcx` = a1, `rdx` = a2 | Confirm the callee computes `combined = [rcx].Length + [rdx].Length` and returns `0xC0000106` when `combined > 0xFFFE`. |
| After allocation | `rax` = pool base, size in `edx`/`esi` | Confirm size = `(combined + 0x1FF) & ~0x1FF` (capped at `0xFFFE`) ≥ `a1->Length + a2->Length`. |

Both builds copy exactly `a1->Length` then `a2->Length` bytes into a buffer of at least that size; the two `memmove`s never write past the allocation.

#### Pool tag

The allocation tag is `0x706D7253` = ASCII `"Srmp"` (bytes `53 72 6D 70` in memory). Use `!poolfind 0x706D7253` to locate these allocations; the tag is identical in both builds.

#### Struct / offset notes

```text
UNICODE_STRING (Win64):
  +0x00  USHORT  Length          (bytes, not chars)
  +0x02  USHORT  MaximumLength
  +0x08  PWSTR   Buffer          (pointer to wide-char data)
```

### `SrmCanInsertPrefixTreePath` — confirm identical prefix passed to the callback

#### Breakpoints

```text
bp datascrn!SrmCanInsertPrefixTreePath
bp datascrn!DataScreenCheckPrefixTreeNodeTxStatusCallback
```

Raw:
```text
bp 0x1c001d4e8        ; unpatched entry
bp 0x14001e974        ; patched entry
```

#### What to inspect

At the callback, `rcx` points to `&Source` where `Source.Length = a2->Length - remaining.Length` (the processed prefix). `du poi(@rcx+8)` shows the same processed-prefix string in both the unpatched and patched builds.

---

## 8. Changed Functions — Full Triage

### Notable changes (no security impact)

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `SrmAppendPath` | 0.7673 | Refactor / no security change | Combined-length guard (`a1->Length + a2->Length > 0xFFFE`) moved from the four callers into the callee; `a3` parameter removed (3 args → 2). Allocation modernized from `ExAllocatePoolWithTag(PagedPool,…)` to `ExAllocatePool2(POOL_FLAG_PAGED,…)`. Copy logic and buffer size identical; no reachable overflow in either build. |
| `SrmCanInsertPrefixTreePath` | 0.6931 | None | No security change. Both builds pass the processed prefix (`&Source`, `Source.Length = a2->Length - remaining.Length`) to `DataScreenCheckPrefixTreeNodeTxStatusCallback`. Low similarity is control-flow flattening + register reallocation only. |

### Behavioral changes (SLIST → LookasideList migration)

The following functions were refactored from a **custom SLIST-based object cache** (`ExpInterlockedPopEntrySList` / `ExpInterlockedPushEntrySList` with runtime-resolved function pointers and `ExQueryDepthSList` depth checks) to **standard kernel LookasideList APIs** (`ExAllocateFromPagedLookasideList` / `ExFreeToPagedLookasideList` / `ExAllocateFromNPagedLookasideList` / `ExFreeToNPagedLookasideList`). No security-relevant behavior change was identified; this is an allocation-strategy modernization.

| Function | Similarity | Note |
|---|---|---|
| `DataScreenCreateStreamContext` | 0.4821 | SLIST cache for `ERESOURCE` → `FltAllocateContext` + `ExAllocateFromNPagedLookasideList`. |
| `DataScreenAllocateUnicodeString` | 0.7085 | SLIST + dynamic function pointer → `ExAllocateFromPagedLookasideList`; large allocs use `ExAllocatePool2`. |
| `DataScreenFreeUnicodeString` | 0.641 | SLIST push-with-depth-check → `ExFreeToPagedLookasideList`. |
| `DataScreenFreeDirectoryEntry` | 0.8009 | SLIST push for `ERESOURCE` free → `ExFreeToNPagedLookasideList`. |
| `DataScreenQueryDecisionGlobal` | 0.8129 | SLIST-based list-entry alloc → standard lookaside list; prefix-tree walk logic unchanged. |
| `DataScreenValidatePatternsInFileGroupInformation` | 0.654 | Bitmask `bt`-based char check → explicit `cmp` chain for `/`, `:`, `\`, `\|`. Functionally equivalent — codegen difference only. |

### Cosmetic changes

| Function | Similarity | Note |
|---|---|---|
| `DataScreenValidateFileRecord` | 0.947 | Stack layout / register reallocation; added `OBJECT_ATTRIBUTES` struct init on stack. Core validation (volume GUID, file creation, EA buffer) unchanged. |
| `DataScreenAsyncMetadataValidation` | 0.9437 | Register swap (`r12`↔`r13`), WPP trace-flag style change. Core `CcMapData` record scanning unchanged. |

---

## 9. Unmatched Functions

No functions were added or removed between the two binaries (`unmatched_unpatched: 0`, `unmatched_patched: 0`). All changes are in-place modifications to existing functions. The patch introduces no new sanitizer routines and removes no existing validation logic at the function level.

---

## 10. Confidence & Caveats

### Confidence: **High** that `SrmAppendPath` has no security-relevant change

**Rationale:**
- The unpatched body (`0x1C001DE10`) copies exactly `a1->Length + a2->Length` bytes into a buffer sized `(a3 + 0x1FF) & ~0x1FF` (capped `0xFFFE`).
- All four unpatched call sites (`0x1C001CF8F`, `0x1C001CFD9`, `0x1C001E06F`, `0x1C001E0B5`) compute `a3 = a1->Length + a2->Length` via a 32-bit `add` of two zero-extended `USHORT`s and reject `a3 > 0xFFFE` (`cmp r8d, 0FFFEh; ja …`) before the call. So `a3` equals the real combined length, no 16-bit wrap can occur, and the allocation is always ≥ the bytes copied.
- The patched body (`0x14001E88C`) performs the same computation and `> 0xFFFE` rejection inside the function and drops the `a3` parameter. The copies and buffer sizing are otherwise identical; `ExAllocatePoolWithTag` becomes `ExAllocatePool2`.
- The change is therefore guard relocation plus API modernization, not a vulnerability fix.

### Confidence: **High** that `SrmCanInsertPrefixTreePath` has no security change

**Rationale:**
- Both builds set `Source.Length = a2->Length - remaining.Length` and pass `&Source` (the processed prefix) to `DataScreenCheckPrefixTreeNodeTxStatusCallback` (unpatched `0x1C001D4E8`, patched `0x14001E974`).
- The low similarity is control-flow flattening and register/stack reallocation only. No fix, no vulnerability.

### Notes for a researcher

- The pool tag for `SrmAppendPath` allocations is `0x706D7253` = ASCII `"Srmp"`, identical in both builds.
- To confirm no overflow is reachable, break on `SrmAppendPath` and verify the size argument (`(combined + 0x1FF) & ~0x1FF`, capped `0xFFFE`) is always ≥ `a1->Length + a2->Length` before the two `memmove`s. In the unpatched build the `combined > 0xFFFE` bound is enforced by the callers; in the patched build it is enforced inside the callee.
- The SLIST → LookasideList migration across ~10 functions is an allocation-strategy modernization with no observed behavior change.
