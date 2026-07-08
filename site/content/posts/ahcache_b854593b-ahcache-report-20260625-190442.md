Title: ahcache.sys — Out-of-bounds read of a version-resource block (CWE-125) in AslpFileMakeStringVersionAttributes fixed
Date: 2026-06-25
Slug: ahcache_b854593b-ahcache-report-20260625-190442
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Low
KBDate: 2026-01-13

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `ahcache_unpatched.sys` |
| Patched binary | `ahcache_patched.sys` |
| Overall similarity | 0.993 |
| Matched functions | 522 |
| Changed functions | 1 |
| Identical functions | 521 |
| Unmatched (either direction) | 0 |

**Verdict:** The patch adds a single missing bounds check (`if (size > offset)`) in the version-resource parser `AslpFileMakeStringVersionAttributes`, closing a small kernel-mode out-of-bounds read that can occur while parsing the `\VarFileInfo\Translation` block of a file's `VS_VERSION_INFO` resource. The over-read is bounded to a few bytes past the queried block, so the practical impact is limited (see §6). Severity: **Low**.

---

## 2. Vulnerability Summary

### Finding 1 — Low Severity

| Field | Value |
|---|---|
| **Severity** | Low |
| **Class** | Out-of-bounds read (CWE-125) |
| **Function** | `AslpFileMakeStringVersionAttributes` (unpatched @ `0x1C00274D4`, patched @ `0x1C00274D4`) |
| **Entry point** | `IRP_MJ_DEVICE_CONTROL` → `AhcDispatch` cases 0 (`AhcApiLookup`) and 11 (`AhcApiLookupAndWriteToProcess`), through the shim-database exe-matching engine |

**Root cause.** `AslpFileMakeStringVersionAttributes` parses the `\VarFileInfo\Translation` block from a file's `VS_VERSION_INFO` resource. It obtains a version-block buffer pointer and the block's byte size from `AslpFileVerQueryBlock`, then calls `AslpFileVerBlockGetValueOffset` to compute a byte offset within that block that skips past the block's value-name string to the translation data. The unpatched code then forms a pointer and a remaining-length without verifying that the computed offset is not past the end of the block:

```
rsi = buffer + offset     ; pointer into the block
edi = size - offset       ; remaining length (32-bit)
```

`AslpFileVerBlockGetValueOffset` returns `offset = align4(L + 8)`, where `L` is the byte length of the value-name string measured by `RtlStringCbLengthW`. That measurement is bounded by `cbMax = size - 6`, so `L <= size - 8` and therefore `offset = align4(L + 8) <= align4(size)`. When `size` is not a multiple of 4 (specifically `size mod 4 == 2` or `3`) and the value-name string fills the block, the 4-byte-alignment round-up pushes `offset` **1 or 2 bytes past `size`**. In that case:

1. **Slightly-OOB pointer** — `rsi = buffer + offset` points 1-2 bytes past the end of the reported block.
2. **Length underflow** — `edi = size - offset` wraps to `0xFFFFFFFF` or `0xFFFFFFFE` in the 32-bit register.

Downstream, `AslpFileQueryVersionString` dereferences the pointer, reading a 4-byte language/codepage pair from just past the end of the block. The wrapped length is **not** used as a read length; it is consumed only as a non-zero flag (see §4). The over-read is therefore a fixed ~4-byte read a few bytes past the block, not a large scan.

**What the patch does.** Inserts `cmp r14, rax / jbe skip` (i.e., `if (size > offset)`). When the check fails, `rsi` is left `0` and `edi` is left `0`, so no out-of-bounds pointer is formed and `AslpFileQueryVersionString` receives safe values.

**Attacker-reachable call chain (numbered):**

1. `AhcDriverDispatchDeviceControl` (`0x1C00217C0`) — `IRP_MJ_DEVICE_CONTROL` handler.
2. `AhcDispatch` (`0x1C0021830`) — dispatches by function index. Cases 0 (`AhcApiLookup`, `0x1C00220D0`) and 11 (`AhcApiLookupAndWriteToProcess`, `0x1C0021ED0`) are the two that reach the matcher.
3. `AhcCacheLookup` (`0x1C0022360`) → `AhcpCacheBuildSdbInfo` (`0x1C0020E10`) → `AhcSdbQueryLookup` (`0x1C001F570`) → `AhcpSdbQueryLookupExe` (`0x1C002B4CC`) → `SdbGetMatchingExeEx` (`0x1C002ACA0`) → `SdbpSearchDB` (`0x1C0025630`) → `SdbpCheckExe` (`0x1C00258D4`) → `SdbpCheckForMatch` (`0x1C002599C`) → `SdbpMatchList` (`0x1C0025F40`).
4. `SdbpMatchList` invokes the file matcher through a guarded indirect call (`__guard_dispatch_icall_fptr` at `0x1C003A5D6`, target selected from the matcher table by `SdbpFindMatcher` @ `0x1C00435B4`): `SdbpCheckMatchingFiles` (`0x1C0024F20`) or `SdbpCheckMatchingWildcardFiles` (`0x1C0042D70`).
5. `SdbpCheckAllAttributes` (`0x1C00263C0`) → `AslFileAllocAndGetAttributes` (`0x1C00270A8`) → `AslpFileGetVersionAttributes` (`0x1C0027460`) → `AslpFileMakeStringVersionAttributes` (`0x1C00274D4`) — the version-string parser; the read sink is the call to `AslpFileQueryVersionString`.

---

## 3. Pseudocode Diff

```c
// ===== UNPATCHED (0x1C00274D4) =====
if (AslpFileVerQueryBlock(..., L"\\VarFileInfo\\Translation",
                          &block_buffer, &block_size) >= 0)
{
    int64_t offset;
    if (AslpFileVerBlockGetValueOffset(&offset, block_buffer, block_size) >= 0)
    {
        // offset = align4(L + 8), where L = RtlStringCbLengthW(value_name)
        // and L is bounded by cbMax = block_size - 6, so offset <= align4(block_size).

        rsi = block_buffer + offset;     // *** 1-2 bytes past end if size%4 in {2,3} ***
        edi = block_size - offset;       // *** wraps to 0xFFFFFFFE/0xFFFFFFFF ***
    }
}
    AslpFileQueryVersionString(..., rsi, edi>>2, ...);  // reads 4 bytes at rsi


// ===== PATCHED =====
if (AslpFileVerQueryBlock(..., &block_buffer, &block_size) >= 0)
{
    int64_t offset;
    if (AslpFileVerBlockGetValueOffset(&offset, block_buffer, block_size) >= 0)
    {
        if (block_size > offset)         // <<< ADDED: bounds check
        {
            rsi = offset + block_buffer;
            edi = block_size - offset;
        }
        // else: rsi stays 0, edi stays 0 — safe
    }
}
    AslpFileQueryVersionString(..., rsi, edi>>2, ...);
```

Key point: `offset` is not independently controllable up to the string-length cap. Because `RtlStringCbLengthW` is called with `cbMax = block_size - 6`, the measured length satisfies `L <= block_size - 8`, so `offset = align4(L + 8) <= align4(block_size)`. The only way `offset` exceeds `block_size` is the 4-byte-alignment round-up when `block_size` is not a multiple of 4, which overshoots by at most 2 bytes. There is no path to a large `offset >= block_size` gap.

---

## 4. Assembly Analysis

### Unpatched — `AslpFileMakeStringVersionAttributes` (`0x1C00274D4`), relevant slice

```asm
; ---- call AslpFileVerQueryBlock("\VarFileInfo\Translation", &buf, &size) ----
00000001C0027511  lea     r9, [rbp+arg_8]              ; &block_size
00000001C0027515  mov     rcx, r12
00000001C0027518  lea     r8, [rbp+arg_10]             ; &block_buffer
00000001C002751C  lea     rdx, aVarfileinfoTra        ; "\VarFileInfo\Translation"
00000001C0027523  call    AslpFileVerQueryBlock
00000001C0027528  mov     edi, eax
00000001C002752A  cmp     eax, 0C0000225h
00000001C002752F  jz      loc_1C003BA93
00000001C0027535  test    eax, eax
00000001C0027537  js      loc_1C003BA84

; ---- success: load block size and buffer, compute offset ----
00000001C002753D  mov     rdi, [rbp+arg_8]             ; rdi = block_size
00000001C0027541  lea     rcx, [rbp+arg_18]            ; &offset
00000001C0027545  mov     rsi, [rbp+arg_10]            ; rsi = block_buffer
00000001C0027549  mov     r8, rdi                      ; r8 = size
00000001C002754C  mov     rdx, rsi                     ; rdx = buffer
00000001C002754F  call    AslpFileVerBlockGetValueOffset
00000001C0027554  test    eax, eax
00000001C0027556  js      loc_1C003BA93

; ======== NO BOUNDS CHECK — offset used unchecked ========
00000001C002755C  mov     rax, [rbp+arg_18]            ; rax = offset
00000001C0027560  add     rsi, rax                     ; rsi = buffer + offset
00000001C0027563  sub     edi, eax                     ; edi = size - offset  (wraps if offset > size)
00000001C0027565  mov     r15d, edi                    ; r15 = size - offset
00000001C0027568  shr     r15, 2                       ; r15 = (size - offset) >> 2
; =========================================================

00000001C002756C  lea     rax, unk_1C00062A0
00000001C0027573  mov     r9, rsi                      ; r9 = buffer + offset (read pointer)
00000001C0027576  movsxd  r13, dword ptr [r14+rax]
00000001C002757A  lea     rdx, [rbp+var_8]
00000001C002757E  mov     rax, [r14+rax+8]
00000001C0027583  lea     rcx, [rbp+var_10]
00000001C0027587  mov     [rsp+40h+var_18], rax
00000001C002758C  mov     r8, r12
00000001C002758F  mov     [rsp+40h+var_20], r15        ; 5th arg = (size-offset)>>2
00000001C0027594  mov     dword ptr [rbp+arg_8], r13d
00000001C0027598  call    AslpFileQueryVersionString   ; read sink
```

On the failure branch at `loc_1C003BA93` the code does `mov rsi, r14 / mov edi, r14d` (`r14 == 0`) and rejoins at `0x1C0027565`, so on offset-computation failure the pointer and length are both zero.

### Where the read actually happens — `AslpFileQueryVersionString` (`0x1C00276A0`)

The pointer `r9 = buffer + offset` is stored (`0x1C00276DC  mov [rsp+1B0h+var_170], r9`) and later dereferenced:

```asm
00000001C0027822  mov     rcx, [rsp+1B0h+var_170]      ; rcx = buffer + offset
00000001C0027827  test    rcx, rcx
00000001C002782A  jz      short loc_1C00278AB
00000001C002782C  mov     rdi, [rbp+0B0h+arg_20]       ; the (size-offset)>>2 value
00000001C0027833  test    rdi, rdi                     ; used ONLY as a non-zero gate
00000001C0027836  jz      short loc_1C00278AB
00000001C0027838  movzx   eax, word ptr [rcx+2]        ; *** OOB read: 2nd word at buffer+offset ***
00000001C002783C  lea     r8, aStringfileinfo_0        ; "\StringFileInfo\%04X%04X\%s"
00000001C0027843  movzx   r9d, word ptr [rcx]          ; *** OOB read: 1st word at buffer+offset ***
00000001C0027847  mov     edx, 80h
00000001C002784C  lea     rcx, [rsp+1B0h+pszDest]
00000001C0027851  mov     [rsp+1B0h+var_188], r13
00000001C0027856  mov     dword ptr [rsp+1B0h+var_190], eax
00000001C002785A  call    RtlStringCchPrintfW
```

The read is exactly two 16-bit words (4 bytes) at `buffer + offset`. In the OOB case `offset` is 1-2 bytes past the block, so this reads a few bytes beyond the block end. The `(size-offset)>>2` value at `0x1C002782C` is tested only for non-zero; it is not used as an iteration count or read length. The two words become the `%04X%04X` language/codepage in a `\StringFileInfo\...` path that is then looked up by a further `AslpFileVerQueryBlock`; the raw over-read bytes are not returned to the caller.

### Patched — the added check (`0x1C00274D4`)

```asm
00000001C0027589  call    AslpFileVerBlockGetValueOffset
00000001C002758E  test    eax, eax
00000001C0027590  js      short loc_1C00275A4          ; on failure -> skip (rsi=0, edi=0)
00000001C0027592  mov     rax, [rbp+arg_18]            ; offset
00000001C0027596  cmp     r14, rax                     ; compare block_size vs offset
00000001C0027599  jbe     short loc_1C00275A4          ; if size <= offset, SKIP the arithmetic
00000001C002759B  mov     edi, r14d                    ; edi = block_size
00000001C002759E  lea     rsi, [rax+r15]               ; rsi = offset + buffer
00000001C00275A2  sub     edi, eax                     ; edi = size - offset
00000001C00275A4  mov     r15d, edi
```

In the patched build `r14 = block_size`, `r15 = block_buffer`, and `rsi` is pre-set to `0` (`0x1C0027583  mov rsi, r13`; `r13 == 0`). The `cmp r14, rax / jbe` is the entire fix: if `offset >= size`, the pointer/length arithmetic is skipped and the zeroed values flow to `AslpFileQueryVersionString`.

### Companion routine — `AslpFileVerBlockGetValueOffset` (`0x1C00019D4`)

```asm
00000001C00019D4  sub     rsp, 28h
00000001C00019D8  and     qword ptr [rcx], 0           ; *offset = 0
00000001C00019DC  lea     rax, [r8-8]                  ; size - 8
00000001C00019E6  cmp     rax, 7FF7h
00000001C00019EC  ja      short loc_1C0001A35          ; reject unless 8 <= size <= 0x7FFF
00000001C00019EE  lea     rdx, [r8-6]                  ; cbMax = size - 6
00000001C00019F2  lea     r8, [rsp+28h+pcbLength]
00000001C00019F7  lea     rcx, [r9+6]                  ; string starts at buffer + 6
00000001C00019FB  call    RtlStringCbLengthW           ; L bounded by cbMax = size - 6
00000001C0001A00  test    eax, eax
00000001C0001A02  js      short loc_1C0001A27
00000001C0001A04  mov     rax, [rsp+28h+pcbLength]     ; rax = L
00000001C0001A09  or      rdx, 0FFFFFFFFFFFFFFFFh
00000001C0001A0D  lea     rcx, [rax+8]                 ; L + 8
00000001C0001A11  cmp     rcx, rax
00000001C0001A14  cmovnb  rdx, rcx
00000001C0001A18  jb      short loc_1C0001A2C          ; overflow guard on L + 8
00000001C0001A1A  lea     rax, [rdx+3]
00000001C0001A1E  and     rax, 0FFFFFFFFFFFFFFFCh       ; align4(L + 8)
00000001C0001A22  mov     [r11], rax                   ; *offset = align4(L + 8)
00000001C0001A25  xor     eax, eax                     ; STATUS_SUCCESS
```

Because `cbMax = size - 6` is passed to `RtlStringCbLengthW`, the returned byte length satisfies `L <= size - 8`. Hence `offset = align4(L + 8) <= align4(size)`. The offset can exceed the block size only via 4-byte-alignment round-up, and only by 1 or 2 bytes, when `size mod 4` is 2 or 3.

---

## 5. Trigger Conditions

1. **Reach the parser.** Cause the app-compat exe-matching engine to evaluate a file's version resource. From user mode this is reached via `IRP_MJ_DEVICE_CONTROL` to the ahcache device through `AhcDispatch` cases 0 (`AhcApiLookup`) or 11 (`AhcApiLookupAndWriteToProcess`), which drive `SdbGetMatchingExeEx` → the SDB matcher → `SdbpCheckAllAttributes` → the version parser. Access to the device object may be privilege-restricted; confirm the device ACL before assuming an unprivileged trigger.

2. **Craft the version resource.** Create an `.exe`/`.dll` whose `VS_VERSION_INFO` resource contains a `\VarFileInfo\Translation` block where:
   - The block byte size reported by `AslpFileVerQueryBlock` satisfies `size mod 4 == 2` or `size mod 4 == 3` (and `8 <= size <= 0x7FFF`).
   - The value-name string (starting at offset +6 in the block) is null-terminated exactly at the end of the block so that `L = size - 8`, making `offset = align4(size)` overshoot `size` by 1-2 bytes.

3. **Effect.** With `offset = size + 1` or `size + 2`, `AslpFileQueryVersionString` reads a 4-byte language/codepage pair at `buffer + offset`, i.e. a few bytes past the reported block. The 32-bit `size - offset` wraps, but that value is only used as a non-zero gate, so it does not enlarge the read.

4. **No race condition.** The bug is single-threaded within the parse path.

5. **Observation.** The over-read is small and typically lands within the same pool page as the version resource, so a fault is unlikely; the practical observable is that the two over-read bytes are used as the language/codepage selector for the subsequent `\StringFileInfo\%04X%04X\%s` lookup. See §6 for impact limits and §7 for a debugger walkthrough.

---

## 6. Impact Assessment

**Primitive:** Kernel out-of-bounds read of 4 bytes (two 16-bit words) located 1-2 bytes past the end of the queried `\VarFileInfo\Translation` version block.

- **Bounded position.** The read offset is `align4(L + 8)` with `L <= size - 8`, so the pointer lands at most 2 bytes past the reported block end, and the 4-byte read reaches at most a few bytes beyond. The attacker cannot position the read further out; the "offset" is coupled to the block size, not independently chosen.
- **Length is not a read length.** The wrapped `size - offset` value is only tested for non-zero at `0x1C002782C`; no loop or copy uses it as a count, so there is no large scan or 4 GB walk.
- **Data flow of the leaked bytes.** The two over-read words are formatted into a `\StringFileInfo\%04X%04X\%s` string and used to query another version sub-block. The raw bytes are not returned to the caller; at most they influence which language/codepage sub-block (if any) is subsequently found.
- **Fault likelihood.** Because the over-read is only a few bytes past a pool sub-block, it will usually stay within the same mapped page, so a bugcheck is unlikely and not reliable.

This is a genuine memory-safety defect (CWE-125) but a low-impact one: a tiny, non-positionable kernel over-read whose bytes are not directly disclosed to the caller. It is best characterized as a hardening fix against an out-of-bounds read rather than a practical information-disclosure or denial-of-service primitive.

---

## 7. Debugger PoC Playbook

Assumptions: kernel debugger attached to the **unpatched** target; `ahcache.sys` loaded. The addresses below use the analysis base `0x1C0000000`; rebase with `lm ahcache` on the live system.

### Breakpoints

```text
bp ahcache_unpatched!AslpFileMakeStringVersionAttributes   ; 0x1C00274D4
bp ahcache_unpatched!AslpFileVerBlockGetValueOffset        ; 0x1C00019D4
bp ahcache_unpatched!AslpFileQueryVersionString            ; 0x1C00276A0
```

Raw offsets for the exact instructions of interest:

```text
bp 0x1C002755C    ; load unchecked offset
bp 0x1C0027560    ; add rsi, rax  -> buffer + offset
bp 0x1C0027563    ; sub edi, eax  -> size - offset (wraps if offset > size)
bp 0x1C0027598    ; call AslpFileQueryVersionString
bp 0x1C0027838    ; movzx eax, [rcx+2]  -> the actual OOB read
```

### What to inspect

| Address | Register / memory | Meaning |
|---|---|---|
| `0x1C002753D` | `rdi = [rbp+arg_8]` | Block size. |
| `0x1C0027545` | `rsi = [rbp+arg_10]` | Block buffer pointer. |
| `0x1C002755C` | `rax = [rbp+arg_18]` | Computed offset — compare to `rdi`; OOB when `rax > rdi` (by 1-2). |
| `0x1C0027560` | `rsi` (after `add`) | `buffer + offset` — the read pointer. |
| `0x1C0027563` | `edi` (after `sub`) | `size - offset` — wraps to `0xFFFFFFFE`/`0xFFFFFFFF`. |
| `0x1C0027838` | `[rcx]`, `[rcx+2]` | The two 16-bit words read from `buffer + offset`. |

Useful command at `0x1C0027838`:

```text
dw @rcx L2         ; the two over-read words (buffer + offset)
```

### Expected observation

- At `0x1C002755C`: `rax` (offset) is 1 or 2 greater than `edi` (block size), i.e. `align4(size)` overshot a non-multiple-of-4 `size`.
- After `0x1C0027563`: `edi` wrapped to `0xFFFFFFFE`/`0xFFFFFFFF`; this value is only used as a non-zero flag downstream.
- At `0x1C0027838`: `rcx` points 1-2 bytes past the version block; the two words read there are consumed as the `%04X%04X` language/codepage selector. The over-read normally stays within the same pool page, so no bugcheck is expected.

### Key instructions / offsets

- **Missing bounds check:** the `cmp r14, rax / jbe` present in the patched build at `0x1C0027596`/`0x1C0027599` is absent in the unpatched build between `0x1C0027556` and `0x1C002755C`.
- **Pointer formation:** `0x1C0027560` (`add rsi, rax`).
- **Length underflow (flag only):** `0x1C0027563` (`sub edi, eax`).
- **Read sink:** `0x1C0027598` (`call AslpFileQueryVersionString`); the dereference is at `0x1C0027838` inside that function.
- **Offset formula:** `0x1C0001A22` (`mov [r11], rax`), where `rax = align4(L + 8)` and `L <= size - 8`.

---

## 8. Changed Functions — Full Triage

Only **one** function changed between builds:

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `AslpFileMakeStringVersionAttributes` | 0.9335 | security_relevant | Added `if (size > offset)` bounds check before computing `buffer + offset` and `size - offset`. Without it, a `\VarFileInfo\Translation` block whose reported size is not a multiple of 4 can make the 4-byte-aligned value offset overshoot the block by 1-2 bytes, producing a small out-of-bounds read in `AslpFileQueryVersionString`. |

No other functions exhibit register-allocation or cosmetic-only differences; the remaining 521 functions are byte-identical.

---

## 9. Unmatched Functions

None. Both `unmatched_unpatched` and `unmatched_patched` are empty — no functions were added or removed. The entire patch is contained within `AslpFileMakeStringVersionAttributes`.

---

## 10. Confidence & Caveats

**Confidence: High** on the mechanism and direction; **Low** on any impact beyond a small over-read.

- The diff is a single, well-localized change: the unpatched build performs `buffer + offset` and `size - offset` with no comparison, and the patched build adds `cmp r14, rax / jbe` before that arithmetic. Both builds were read at the same address (`0x1C00274D4`).
- The offset is coupled to the block size through `RtlStringCbLengthW(cbMax = size - 6)`, so the over-read is bounded to a few bytes past the block and is not attacker-positionable.
- The reachability from the IOCTL dispatch through the SDB exe-matching engine to the version parser is confirmed by direct-call edges up to `SdbpMatchList`; the final hop into the file matcher is a guarded indirect call selected from a matcher table.

**Items to verify on a live system:**

1. **Driver base address.** Addresses assume base `0x1C0000000`; recompute via `lm ahcache`.
2. **Device ACL.** Confirm whether the ahcache device object is reachable by an unprivileged caller or restricted to system components; this determines whether the trigger is remotely/locally exploitable at all.
3. **Pool layout at the over-read.** Whether `buffer + offset` crosses a physical allocation boundary (versus staying inside the larger version-resource allocation) depends on how `AslpFileVerQueryBlock` sub-allocates; this bounds the already-small disclosure surface.
