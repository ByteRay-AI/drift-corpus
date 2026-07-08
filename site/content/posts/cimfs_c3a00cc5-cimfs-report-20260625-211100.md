Title: cimfs.sys — signed integer-underflow hardening in CIM image metadata parser (CWE-190) fixed
Date: 2026-06-25
Slug: cimfs_c3a00cc5-cimfs-report-20260625-211100
Category: Corpus
Author: Argus
Summary: KB5073724
Severity: Low
KBDate: 2026-01-13

---

## 1. Overview

| Item | Value |
|------|-------|
| Unpatched binary | `cimfs_unpatched.sys` |
| Patched binary   | `cimfs_patched.sys` |
| Overall similarity | 0.3743 (low — large recompile) |
| Matched functions | 176 |
| Changed functions | 141 |
| Identical functions | 35 |
| Unmatched (unpatched → patched) | 0 / 0 |

**Verdict:** The patch is a defense-in-depth hardening pass over the Composite Image File System (`cimfs.sys`) on-disk metadata parser. Across the `Cim::ImageReader` read/resolve helpers and the `Cim::LinkTable::Parse` family, unsigned-only comparisons on values derived from on-disk metadata are replaced with signed negative/underflow guards (`js` / `jl` / `jg`, and signed division via `cqo; sar`). The same recompile also removes the `CimFs::StackEventTracer` reference parameter from these functions and routes error reporting through inline ETW instead of `ProcessTraceStatusOrigin`.

These are real, security-relevant hardening changes in an attacker-facing parsing surface (a crafted CIM image is mounted, then file operations are performed). However, the audit against both binaries did **not** find a demonstrably reachable out-of-bounds primitive in the unpatched build: the offsets fed to the checks are masked to 48 bits and cross-validated before use, the copy operations are bounds-checked in both builds, and the link-table counts derive from a non-negative 32-bit field. There is **no out-of-bounds write** on any of these paths. The added guards remove a latent class of signed/unsigned confusion; the realistic worst-case direction, were any of the guarded values reachable with the sign bit set, is an out-of-bounds **read** (CWE-125). Severity is therefore assessed as low (defense-in-depth), not high. Exploitation of the parsing surface at all requires the privilege to mount a CIM volume.

---

## 2. Change Summary

The diff shows one consistent pattern applied in three related areas, all reachable from the volume-mount + file-operation surface.

### Finding A — Signed underflow guards added to `Cim::ImageReader::GetData` (LOW / defense-in-depth)

- **Class:** CWE-190 integer underflow handling in a bounds check (read-side, CWE-125 impact direction).
- **Affected functions:** `Cim::ImageReader::GetData` (unpatched 0x140018B08 → patched 0x1C000A1AC), `GetDataTruncate` (0x140018D68 → 0x1C0009F90), `GetOffsetTruncate` (0x140019AA4 → 0x1C0009CB8), and the `GetArray<>` templates.

**What actually changed.** In the unpatched build the in-region offset (`rcx`, resolved by `GetOffsetTruncate`) is validated against the region-table size (`rax`) with an unsigned compare *before* the subtraction: `cmp rax, rcx; jb terminate`. That branch guarantees `size >= offset`, so the following `sub rax, rcx` **cannot** underflow, and the second unsigned compare `cmp rax, rdi; jb terminate` rejects a request larger than the remaining bytes. The patched build removes the pre-subtraction unsigned guard and instead adds signed sanity checks: `test rcx, rcx; js terminate` on the offset, `sub rax, rcx; js terminate` on the subtraction result, `test rdi, rdi; js terminate` on the requested size, and a signed `cmp rax, rdi; jl terminate`. The net effect is that no intermediate value can be treated as negative (sign bit set).

**Reachability note.** The offset is not fully attacker-controlled at this point. `GetOffsetTruncate` masks the in-region offset to 48 bits (`and r10, 0xFFFFFFFFFFFF`) in both builds, so it is always non-negative, and it bound-checks the offset against the region entry before returning. The region index is the top 16 bits of the packed `RegionOffset`, also non-negative by construction. The added signed checks therefore guard values that, on the paths observed, are already masked and pre-validated. No input that passes the unpatched unsigned checks but produces an out-of-bounds span was demonstrated.

### Finding B — Fixed-size `File` copy in `Cim::ImageReader::GetFile` (LOW)

- **Class:** refactor of a bounded copy; removal of a feature-gated zero-initialization.
- **Affected function:** `Cim::ImageReader::GetFile` (unpatched 0x140018FB4 → patched 0x1C000A3DC).

**What actually changed.** `GetFile` reads a 16-bit `entry_size` field from a `FileTableDirectoryEntry` (loaded `movzx` at 0x14001938B) and compares it against `0x68` (`cmp dx, r8w; jbe` at 0x1400193A6). When `entry_size` exceeds `0x68` the entry is not rejected: the code emits an "Invalid entry size" trace and continues to the `GetData` call at 0x1400194E4 with `entry_size` as the read length and `entry_size * slot` as the offset. This is **not** an out-of-bounds access: `GetData` bounds-checks the requested read against the region (Finding A), and the subsequent `gsl::copy` is itself bounds-checked — the copy length is `min(entry_size, data_len)` (`cmovb` at 0x140019673) and the destination span is `{0x68, File*}`; if the length exceeds the destination, `gsl::copy` calls `gsl::details::terminate()` rather than overflowing. So an oversized `entry_size` yields at most a controlled termination, in both builds.

The patched build replaces the variable copy length with a fixed `0x58` clamped to the returned data length using signed comparisons (`mov edx, 0x58`; `cmovg`; `test rcx,rcx; js`; `cmp rcx,rax; jg`). It also drops the `Feature_CimfsV1CompatGetFileFix__private`-gated `memset(File, 0, 0x68)` that, in the unpatched build, zero-initialized the output `File` struct only when the feature was enabled. Removing that gate is a hardening of the uninitialized-tail behavior, but the `File` struct is an internal structure consumed by later `QueryInformation` handling, so any residual-data exposure is not shown to reach an unprivileged caller.

### Finding C — Signed count arithmetic in `Cim::LinkTable::Parse` (LOW / defense-in-depth)

- **Class:** CWE-190 integer handling in metadata parsing.
- **Affected functions:** `Cim::LinkTable<Stream>::Parse` (0x140029E8C → 0x1C000F324) and `Cim::LinkTable<FileId>::Parse` (0x14002A038 → 0x1C000EE4C).

**What actually changed.** Both builds reject a span smaller than 8 bytes (`cmp r9, 8; jb error`) and require an 8-byte-aligned data pointer (`test bl, 7; jnz error`); there is no size-7 shortcut. The unpatched build computes the entry count from `(size - 8)` with unsigned shifts and compares (`shr r11, 4`; `ja`/`jb`). The patched build replaces these with signed division (`cqo; and edx, mask; add; sar`) and signed comparisons (`test r9,r9; js`; `cmp r8,rax; jg`; `sub r9,rax; js`). The `disk_count` field compared against the computed count is read as a zero-extended 32-bit value (`mov r8d, [rax+4]`), so it is always non-negative; the on-disk span size would have to reach roughly `2^63` for `(size - 8)` to appear negative. No reachable input that trips the new signed checks in the unpatched build was demonstrated. This is the standard compiler-emitted signed-division pattern applied as hardening.

**Entry point:** the link tables are parsed during `MountVolumeFromFileSystem` via `Cim::ImageReader::GetStruct<Filesystem>`, so this path executes at mount time, before any file operation.

---

## 3. Pseudocode Diff

### Finding A — `GetData` (offset/size validation)

```c
// === UNPATCHED Cim::ImageReader::GetData @ 0x140018B08 ===
rcx = resolved_offset;                 // from GetOffsetTruncate; 48-bit masked, pre-validated
rax = region_table[idx].size;          // region-table entry
if (rax < rcx) goto terminate;         // UNSIGNED guard: ensures size >= offset
rax = rax - rcx;                       // available; cannot underflow (guarded above)
if (rdi != -1 && rax < rdi) goto terminate;  // UNSIGNED: reject request > available
return span(region.data_ptr + offset, rdi);

// === PATCHED Cim::ImageReader::GetData @ 0x1C000A1AC ===
rcx = resolved_offset;
if ((int64_t)rcx < 0) goto terminate;  // ADDED signed check on offset
rax = region_table[idx].size;
rax = rax - rcx;                       // subtraction, no prior unsigned guard
if ((int64_t)rax < 0) goto terminate;  // ADDED signed underflow check
if (rdi != -1) {
    if ((int64_t)rdi < 0) goto terminate;          // ADDED signed check on requested size
    if ((int64_t)rax < (int64_t)rdi) goto terminate; // SIGNED comparison (jl)
}
return span(region.data_ptr + offset, rdi);
```

### Finding B — `GetFile` (File copy)

```c
// === UNPATCHED Cim::ImageReader::GetFile @ 0x140018FB4 ===
uint16_t entry_size = entry->entry_size;             // movzx (0x14001938B)
if (entry_size > 0x68) trace("Invalid entry size");  // UNSIGNED cmp; traces, does NOT reject
GetData(&data, region_off, entry_size * slot, entry_size);  // read is bounds-checked in GetData
if (Feature_CimfsV1CompatGetFileFix__private_IsEnabled())
    memset(&File, 0, 0x68);                          // gated zero-init of output struct
copy_len = min(entry_size, data_len);                // UNSIGNED min (cmovb, 0x140019673)
gsl::copy(span(src, copy_len), span(File, 0x68));    // bounds-checked; terminates if copy_len > 0x68

// === PATCHED Cim::ImageReader::GetFile @ 0x1C000A3DC ===
GetData(&data, region_off, entry_size * slot, entry_size);
copy_len = min((int64_t)data_len, 0x58);             // fixed 0x58, SIGNED min (cmovg)
if ((int64_t)copy_len < 0 || copy_len > data_len) goto terminate;  // js / jg
gsl::copy(span(src, copy_len), span(File, 0x58));
```

### Finding C — `LinkTable<Stream>::Parse` (count arithmetic)

```c
// === UNPATCHED Cim::LinkTable<Stream>::Parse @ 0x140029E8C ===
if (span.size() < 8) goto error;                 // cmp r9,8; jb
if (span.data() & 7) goto error;                 // test bl,7; jnz (alignment)
r8 = span.size() - 8;
count = r8 >> 4;                                 // UNSIGNED (shr r11,4)
disk_count = *(uint32_t*)(entries + 4);          // zero-extended, always >= 0
if (disk_count u> r8 / 0x14) goto error;         // UNSIGNED (ja)
if (disk_count u> count)     goto terminate;     // UNSIGNED (ja)

// === PATCHED Cim::LinkTable<Stream>::Parse @ 0x1C000F324 ===
if (span.size() < 8) goto error;                 // same size floor
if (span.data() & 7) goto error;                 // same alignment check
r9 = span.size() - 8;
if ((int64_t)r9 < 0) goto terminate;             // SIGNED (test r9,r9; js)
count = (r9 + ((r9>>63)&0xF)) >> 4;              // SIGNED div-by-16 (cqo; and; add; sar)
if ((int64_t)count < 0)          goto terminate; // SIGNED (js)
if ((int64_t)disk_count > (int64_t)count) goto terminate;  // SIGNED (jg)
```

---

## 4. Assembly Analysis

### Finding A — `Cim::ImageReader::GetData` bounds block

**UNPATCHED (0x140018B08):**

```asm
0000000140018B91  mov     rcx, [rbp+var_78]   ; rcx = resolved in-region offset (from GetOffsetTruncate)
0000000140018B95  shl     rbx, 4
0000000140018B99  add     rbx, [r14+8]        ; rbx = &region_table[idx]  {size, data_ptr}
0000000140018B9D  mov     rax, [rbx]          ; rax = region size
0000000140018BA0  cmp     rax, rcx            ; UNSIGNED: size vs offset
0000000140018BA3  jb      loc_140018D5C       ; size < offset -> terminate (ensures size >= offset)
0000000140018BA9  sub     rax, rcx            ; available = size - offset (cannot underflow: guarded)
0000000140018BAC  cmp     rdi, 0FFFFFFFFFFFFFFFFh
0000000140018BB0  jnz     short loc_140018BC1
0000000140018BC1  cmp     rax, rdi            ; UNSIGNED: available vs requested
0000000140018BC4  jb      loc_140018D5C       ; available < requested -> terminate
0000000140018BCE  add     rcx, [rbx+8]        ; rcx = data_ptr + offset
0000000140018BDA  movdqu  xmmword ptr [rsi], xmm0   ; return span (len, ptr) to caller
0000000140018D5C  call    ?terminate@details@gsl@@YAXXZ
```

**PATCHED (0x1C000A1AC):**

```asm
00000001C000A227  mov     rcx, [rbp+var_68]   ; rcx = resolved in-region offset
00000001C000A22B  shl     rbx, 4
00000001C000A22F  add     rbx, [r14+8]        ; rbx = &region_table[idx]
00000001C000A233  test    rcx, rcx            ; *** ADDED signed check on offset ***
00000001C000A236  js      loc_1C000A3D0       ; offset < 0 -> terminate
00000001C000A23C  mov     rax, [rbx]          ; region size
00000001C000A23F  sub     rax, rcx            ; available = size - offset (no prior unsigned guard)
00000001C000A242  js      loc_1C000A3D0       ; *** ADDED signed underflow -> terminate ***
00000001C000A248  cmp     rdi, 0FFFFFFFFFFFFFFFFh
00000001C000A24C  jnz     short loc_1C000A254
00000001C000A254  test    rdi, rdi            ; *** ADDED signed check on requested size ***
00000001C000A257  js      loc_1C000A3D0
00000001C000A25D  cmp     rax, rdi
00000001C000A260  jl      loc_1C000A3D0       ; *** SIGNED less-than replaces unsigned jb ***
00000001C000A3D0  call    ?terminate@details@gsl@@YAXXZ
```

### Finding A (cont.) — `Cim::ImageReader::GetOffsetTruncate`

The offset resolution and its 48-bit mask are identical in both builds; the patch adds a signed index check.

**UNPATCHED (0x140019AA4):**

```asm
0000000140019AC2  mov     rax, 0FFFFFFFFFFFFh  ; 48-bit mask
0000000140019ACC  shr     rdx, 30h            ; region index = RegionOffset >> 48
0000000140019AD9  and     r10, rax            ; in-region offset & 0xFFFFFFFFFFFF (always >= 0)
0000000140019ADC  jz      loc_140019C4D       ; offset == 0 -> error
0000000140019AE2  cmp     rdx, [rcx]          ; index vs region count
0000000140019AE5  jnb     loc_140019C4D       ; UNSIGNED: index >= count -> error
0000000140019AF5  mov     r9, [rax+rcx*8]     ; region bound (after check)
0000000140019AFC  jb      short loc_140019B21
0000000140019B04  cmp     rcx, r8             ; (bound - offset) vs requested len
0000000140019B07  jb      short loc_140019B21
```

**PATCHED (0x1C0009CB8):**

```asm
00000001C0009CD2  mov     rax, 0FFFFFFFFFFFFh  ; 48-bit mask (same)
00000001C0009CDC  shr     rdx, 30h            ; index
00000001C0009CE9  and     r10, rax            ; offset masked (same)
00000001C0009CEC  jz      loc_1C0009E4E
00000001C0009CF2  cmp     rdx, [rcx]          ; index vs region count
00000001C0009CF5  jge     loc_1C0009E4E       ; *** ADDED signed check on index ***
00000001C0009CFB  jnb     loc_1C0009F82       ; unsigned out-of-range -> terminate
00000001C0009D01  mov     rax, [rbx+8]        ; region table base (after both checks)
```

The region index is the top 16 bits of the packed `RegionOffset`, so it is non-negative by construction; the added `jge` is defensive.

### Finding B — `Cim::ImageReader::GetFile` (entry size / copy)

```asm
; UNPATCHED @ 0x140018FB4
000000014001938B  movzx   edx, word ptr [rbp+var_B0+0Ah]  ; entry_size (16-bit, zero-extended)
00000001400193A6  cmp     dx, r8w                          ; compare vs 0x68
00000001400193AA  jbe     loc_1400194AE                    ; <=0x68 continue; else trace, then continue (no reject)
00000001400194AE  movzx   ecx, word ptr [rbp+var_B0+0Ah]   ; entry_size as read length
00000001400194E4  call    Cim::ImageReader::GetData         ; read is bounds-checked inside GetData
0000000140019603  call    Feature_CimfsV1CompatGetFileFix__private_IsEnabledDeviceUsageNoInline
000000014001960A  jz      short loc_140019654               ; feature off -> skip zero-init
0000000140019616  call    memset                            ; feature on: zero the 0x68 output struct
0000000140019669  movzx   edx, word ptr [rbp+var_B0+0Ah]    ; entry_size for copy bound
0000000140019673  cmovb   rcx, rdx                          ; copy_len = min(entry_size, data_len) UNSIGNED
000000014001967A  ja      loc_1400196BE                     ; copy_len > data_len -> terminate
00000001400196B2  call    gsl::copy                         ; dst span = {0x68, File*}; terminates if len > 0x68
```

```asm
; PATCHED @ 0x1C000A3DC (success path)
00000001C000A717  mov     [rbp+var_50+8], rbx               ; rbx = output File*
00000001C000A71B  mov     edx, 58h                          ; *** fixed copy size 0x58 ***
00000001C000A729  mov     rax, [rbp+var_30]                 ; data_len from GetData
00000001C000A72D  cmp     rax, rdx
00000001C000A733  cmovg   rcx, rdx                          ; copy_len = min(data_len, 0x58) SIGNED
00000001C000A73A  js      short loc_1C000A77A               ; copy_len < 0 -> terminate
00000001C000A73F  jg      short loc_1C000A77A               ; copy_len > data_len -> terminate
00000001C000A771  call    gsl::copy                         ; dst span = {0x58, File*}
```

The unpatched `entry_size > 0x68` case traces and continues, but the read (`GetData`) and the copy (`gsl::copy`) are each bounds-checked and terminate rather than overflow, in both builds.

### Finding C — `Cim::LinkTable<Stream>::Parse` (count arithmetic)

```asm
; UNPATCHED @ 0x140029E8C
0000000140029EC2  cmp     r9, 8                ; span >= 8?
0000000140029EC6  jb      loc_140029FE5        ; size < 8 -> error
0000000140029ED0  test    bl, 7                ; data pointer 8-byte aligned?
0000000140029ED3  jnz     loc_140029FE5        ; misaligned -> error
0000000140029EF0  lea     r8, [r9-8]           ; size - 8
0000000140029F0A  shr     r11, 4               ; UNSIGNED count = (size-8) / 16
0000000140029F0E  mov     r9d, [rax+4]         ; disk_count (zero-extended uint32, >= 0)
0000000140029F1F  shr     rdx, 4               ; UNSIGNED (size-8)/0x14
0000000140029F23  cmp     r9, rdx
0000000140029F26  ja      loc_140029FC4        ; UNSIGNED disk_count > (size-8)/0x14 -> error
0000000140029F3A  cmp     r9, r11
0000000140029F3D  ja      loc_14002A02B        ; UNSIGNED disk_count > count -> terminate
```

```asm
; PATCHED @ 0x1C000F324
00000001C000F35F  cmp     r8, 8                ; same size floor
00000001C000F363  jb      loc_1C000F538
00000001C000F36D  test    r11b, 7              ; same alignment check
00000001C000F371  jnz     loc_1C000F538
00000001C000F38D  lea     r9, [r8-8]
00000001C000F391  test    r9, r9
00000001C000F394  js      loc_1C000F61D        ; *** SIGNED: (size-8) < 0 -> terminate ***
00000001C000F3C3  cqo                          ; *** SIGNED div-by-16 ***
00000001C000F3C8  and     edx, 0Fh
00000001C000F3CB  add     rax, rdx
00000001C000F3CE  sar     rax, 4
00000001C000F3D2  js      loc_1C000F61D        ; SIGNED negative count -> terminate
00000001C000F3E9  cmp     r8, rax
00000001C000F3EC  jg      loc_1C000F61D        ; *** SIGNED (jg replaces ja) ***
```

`FileId`-variant `Parse` (0x14002A038 → 0x1C000EE4C) carries the same change.

---

## 5. Trigger Conditions

> **Privilege precondition:** reaching any of these paths requires mounting a CIM volume. A standard user cannot directly mount a CIM image; assume a local-admin or container-host threat model.

### Finding A — `GetData` / `GetOffsetTruncate`

1. Create a CIM image and mount it via the cimfs mount path.
2. Perform a file operation that triggers metadata parsing — `IRP_MJ_CREATE`, `IRP_MJ_READ` (via `NonCachedRead`), `IRP_MJ_DIRECTORY_CONTROL`, or `IRP_MJ_QUERY_EA`.
3. **Observable difference between builds:** if a region-table size / offset combination could be crafted so an intermediate value has the sign bit set, the patched build reaches `gsl::details::terminate()` at the added `js`/`jl` checks, whereas the unpatched build continues. On the observed paths the in-region offset is 48-bit masked and bound-checked by `GetOffsetTruncate` in both builds, so no such input was demonstrated to reach an out-of-bounds span.

### Finding B — `GetFile`

1. Craft a `FileTableDirectoryEntry` with `entry_size > 0x68`.
2. Mount the image and enumerate/open the file.
3. **Observable difference:** the unpatched build emits an "Invalid entry size" trace and proceeds; the read and copy remain bounds-checked and terminate if they would exceed their targets. The patched build uses a fixed `0x58` copy and no longer feature-gates the output-struct zero-init.

### Finding C — `LinkTable::Parse`

1. Forge the link-table descriptor in the filesystem metadata block.
2. Mount the image — parsing occurs inside `MountVolumeFromFileSystem`.
3. **Observable difference:** the patched build applies signed count arithmetic and rejects a computed size with the sign bit set at `js`/`jg`; the unpatched build uses unsigned arithmetic. Because `disk_count` is a non-negative 32-bit field and the span size would need to approach `2^63`, no reachable trigger was demonstrated.

---

## 6. Impact Assessment

**Nature of the change.** The patch adds signed integer sanity guards to metadata-derived arithmetic and reduces one copy to a fixed size. It does not remove any existing sanitizer and does not introduce a new sink.

- There is **no out-of-bounds write** on any path examined. Every `gsl::copy` is bounds-checked and terminates on violation in both builds.
- The read-path helpers (`GetData` family) construct a `gsl::span` describing a read window. The theoretical worst case of a missing signed guard here is an out-of-bounds **read** (CWE-125), not a write.
- On the observed paths the guarded values are masked (48-bit offset), derived from non-negative fields (32-bit `disk_count`, 16-bit region index), or already bound-checked before the guard, so a reachable out-of-bounds primitive in the unpatched build was not demonstrated.

**Realistic outcome.** This is defense-in-depth hardening of an image-parsing attack surface. It closes a latent signed/unsigned-confusion class rather than a proven exploitable primitive. No kernel information-disclosure or code-execution primitive is established by this diff.

---

## 7. Debugger Notes

Assume WinDbg/KD attached to a target running `cimfs_unpatched.sys`. Resolve the actual base first (`lm m cimfs`); the static offsets below assume a base of `0x140000000` and must be rebased (`<base> + (0x140018B08 - 0x140000000)`, etc.).

### Finding A — `GetData` / `GetOffsetTruncate`

**Breakpoints:**

```
bp cimfs!Cim::ImageReader::GetData
bp cimfs!Cim::ImageReader::GetOffsetTruncate
bp cimfs!Cim::ImageReader::GetFile
```

**What to inspect:**

- `r8` at `GetData` entry = the packed `RegionOffset`. The high 16 bits are the region index (`shr r8, 0x30`); the low 48 bits are the in-region offset.
- `rcx` at `0x140018BA0` = the in-region offset returned by `GetOffsetTruncate` (already 48-bit masked and bound-checked).
- `rax` at `0x140018B9D` = the region-table entry size; `rbx` at `0x140018B99` = `&region_table[idx]`, layout `[+0x00 uint64 size][+0x08 char* data_ptr]`.
- `rax` after `0x140018BA9` (`sub rax, rcx`) = available bytes; the patched build's added `js` at `0x1C000A242` would terminate here if this were negative.
- `rdi` = requested size; `0xFFFFFFFFFFFFFFFF` means "all available".

**Key instruction offsets:**

| Address | Instruction | Role |
|---------|-------------|------|
| `0x140018BA0` | `cmp rax, rcx; jb` | Unsigned pre-subtraction guard (Finding A, unpatched) |
| `0x140018BA9` | `sub rax, rcx` | Available = size − offset (guarded, no underflow) |
| `0x140018BC1` | `cmp rax, rdi; jb` | Unsigned request check |
| `0x1C000A233` | `test rcx, rcx; js` | Patched: signed offset check |
| `0x1C000A242` | `sub rax, rcx; js` | Patched: signed underflow check |
| `0x1C000A257` | `test rdi, rdi; js` | Patched: signed size check |
| `0x1C000A260` | `jl` | Patched: signed available-vs-request check |
| `0x140019AD9` | `and r10, 0xFFFFFFFFFFFF` | 48-bit offset mask (both builds) |
| `0x1400193A6` | `cmp dx, 0x68` | Finding B entry-size check (traces, no reject) |
| `0x14001960A` | `Feature_CimfsV1CompatGetFileFix` gate | Finding B feature-gated zero-init |

### Finding C — `LinkTable::Parse`

```
bp cimfs!Cim::LinkTable<struct Cim::Format::Stream>::Parse
bp cimfs!Cim::LinkTable<enum Cim::Format::FileId>::Parse
```

- `[rdx]` at entry = span size; `[rdx+8]` = data pointer (checked 8-byte aligned by `test bl, 7`).
- Watch the unsigned count arithmetic (`shr r11, 4` at `0x140029F0A`, `cmp r9, rdx; ja` at `0x140029F23`); the patched code uses signed `sar`/`js`/`jg` instead. `disk_count` is the zero-extended uint32 read at `[rax+4]`.

---

## 8. Changed Functions — Full Triage

| Function | Sim. | Change type | Note |
|----------|------|-------------|------|
| `Cim::ImageReader::GetData` | 0.9154 | hardening | Replaces the unsigned pre-subtraction guard with signed offset/underflow/size checks (`js`, `jl`). Read-side span construction. |
| `Cim::ImageReader::GetDataTruncate` | 0.8595 | hardening | Same signed-guard pattern; adds `test rdx,rdx; js` and `sub rcx,rdx; js`. Also drops the `StackEventTracer` parameter. |
| `Cim::ImageReader::GetOffsetTruncate` | 0.6174 | hardening | Offset 48-bit mask and region bound-check present in both; patch adds a signed `cmp rdx, count; jge` alongside the existing `jnb`. Error path moved from `ProcessTraceStatusOrigin` to inline ETW. |
| `Cim::ImageReader::GetFile` | 0.6273 | refactor | Variable copy length (≤0x68, unsigned min) replaced with fixed `0x58` (signed min); removes the `Feature_CimfsV1CompatGetFileFix__private`-gated output zero-init. Copy is bounds-checked in both builds. |
| `Cim::ImageReader::GetArray<gsl::byte>` | 0.9313 | hardening | Adds signed negative/upper-bound checks on the size returned by `GetDataTruncate`. |
| `Cim::ImageReader::GetArray<Cim::Format::PeImageMapping>` | 0.9345 | hardening | Same signed-check pattern for the PE image-mapping array. |
| `Cim::LinkTable<FileId>::Parse` | 0.7215 | hardening | Unsigned count arithmetic (`shr`/`ja`) replaced with signed division and checks (`cqo; sar`, `js`, `jg`). `disk_count` is a non-negative uint32. |
| `Cim::LinkTable<Stream>::Parse` | 0.7324 | hardening | Same as above for stream link tables. |
| `Cim::FileSystem::GetStreamSegment` | 0.4912 | behavioral | Heavily recompiled; `StackEventTracer` parameter removed and stream-handling control flow reorganized. No specific security-relevant mechanism verified against both builds here. |
| `Cim::FileSystem::GetReparseData` | 0.5701 | behavioral | Heavily recompiled; signature and error reporting changed. No specific security-relevant mechanism verified against both builds here. |
| `Cim::FileSystem::GetDataSegment` | 0.5089 | behavioral | Drops `StackEventTracer` parameter and `ProcessTraceStatusPushLocation` calls; struct field offsets shift. Not security-relevant. |
| `wil_InitializeFeatureStaging` | 0.696 | cosmetic | Feature-staging configuration updates, including `Feature_CimfsV1CompatGetFileFix__private` registration. |
| `DriverEntry` | 0.4708 | behavioral | Updated driver/device-name creation. Not security-relevant. |

The recurring `StackEventTracer`-removal / `ProcessTraceStatusOrigin`→ETW change and the `cqo; and edx, mask; add; sar` signed-division sequences are the dominant deltas; they are servicing/compiler-shape churn on top of the signed-guard hardening.

---

## 9. Unmatched Functions

None. `unmatched_unpatched = 0`, `unmatched_patched = 0`. The patch is an in-place rewrite — no sanitizers were removed and none of the existing bounds checks were deleted.

---

## 10. Confidence & Caveats

**Confidence: high for the nature of the change; the claimed exploitability was not substantiated.**

- The signed/unsigned hardening is unambiguous in the diff: unsigned `jb`/`ja`/`shr` replaced with signed `js`/`jl`/`jg`/`sar` across the `ImageReader` read/resolve helpers and `LinkTable::Parse`. Direction is correct (the patched build is stricter).
- The in-region offset is masked to 48 bits and bound-checked by `GetOffsetTruncate` in both builds; the region index is a top-16-bit value; the link-table `disk_count` is a zero-extended uint32. On the paths observed, the values the new signed guards protect are already non-negative or pre-validated, so a reachable out-of-bounds primitive in the unpatched build was not demonstrated.
- There is no out-of-bounds write on any examined path; every `gsl::copy` is bounds-checked and terminates on violation in both builds. The realistic impact direction, if any, is an out-of-bounds read.
- The exact CIM on-disk layout (`RegionOffset` packing, region-table entry format, `FileTableDirectoryEntry` fields, link-table descriptor) is inferred from instruction operands. The region index occupies bits 48–63 and the in-region offset bits 0–47, as shown by the `shr ..., 0x30` / `and ..., 0xFFFFFFFFFFFF` pair.
- `GetStreamSegment` and `GetReparseData` are heavily recompiled; their specific behavioral changes were not resolved against both builds and are reported as behavioral churn rather than security fixes.
- Mounting a CIM image requires elevated privilege; this limits the parsing surface to a privileged local attacker unless the cimfs mount path is exposed through a less-privileged broker.

DONE
