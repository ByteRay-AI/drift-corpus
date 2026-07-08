Title: fastfat.sys — No security-relevant change (integer-overflow-check refactor and ExAllocatePool2 migration in the EFS PFile-header builder)
Date: 2026-06-28
Slug: fastfat_0e9db596-fastfat-report-20260628-230826
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: None

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `fastfat_unpatched.sys` (base `0x1c0000000`) |
| Patched binary | `fastfat_patched.sys` (base `0x140000000`) |
| Overall similarity | 0.8428 |
| Matched functions | 800 |
| Changed functions | 484 |
| Identical functions | 316 |
| Unmatched (unpatched → patched) | 0 / 0 |

**Verdict:** The patch hardens the size arithmetic in the EFS (Encrypting File System) PFile-header builder `EfspConstructNewPfileHeader (sub_1c0009be8)` of the FAT filesystem driver. Hand-rolled sign-bit overflow checks are replaced with a checked-addition helper `sub_14000a810` (returns `STATUS_INTEGER_OVERFLOW` on wrap), and the pool allocation is migrated from `ExAllocatePoolWithTag` to `ExAllocatePool2`. In this build the inputs to the arithmetic are all 32-bit-derived and the inline checks already bound the allocation correctly, so the change is defense-in-depth rather than a fix for a reachable memory-corruption bug.

---

## 2. Change Summary

### Finding 1 — Integer-Overflow Hardening in EFS PFile-Header Builder

- **Severity:** None (defense-in-depth; no security-relevant change)
- **Class:** CWE-190 (Integer Overflow) hardening of a pool-size computation
- **Function (unpatched):** `EfspConstructNewPfileHeader (sub_1c0009be8)`
- **Function (patched):** `sub_14000a3a4`

#### What the function does

`EfspConstructNewPfileHeader` builds an EFS PFile header for a file on a FAT/FAT32 volume. It gathers EFS stream metadata (`EfsGetEfsStreamInfo`, `EfspCreateFileLicenseHeaderAndKey`, `EfspAquirePFileStream`), reads two 32-bit descriptor fields, computes a pool allocation size, allocates an `'Efsm'`-tagged PagedPool block for the header, and copies the descriptor and stream data into the appropriate buffers.

The size computation is:

```
DataOffset = *(r12 + r13 + 0x32)          // 32-bit field
DataLength = *(r12 + r13 + 0x36)          // 32-bit field
rdx_3      = DataOffset + DataLength       // 32-bit add, carry checked
rcx_4      = s - a                         // s, a are 32-bit locals
rax_10     = rdx_3 + rcx_4
alloc_size = rax_10 + 0x20
```

`s` is the EFS stream size written by `EfspCreateFileLicenseHeaderAndKey`; `a` (`var_90+8`) is a base offset written by `EfsGetEfsStreamInfo`. All three inputs (`rdx_3`, `s`, `a`) are read as 32-bit values, so `rax_10` cannot reach anywhere near a 64-bit wrap.

#### What changed

The unpatched build validates the additions with a sequence of sign-bit comparisons and a final `alloc_size > 0xFFFFFFFF` range check. The patched build performs the same additions through the checked-add helper `sub_14000a810`, keeps the `> 0xFFFFFFFF` range check, and allocates with `ExAllocatePool2(POOL_FLAG_PAGED)` instead of `ExAllocatePoolWithTag(PagedPool)`. Both builds reject anything above the 32-bit range and require `alloc_size >= 0x20` before allocating, and in both builds only 0x20 bytes plus a 16-byte UUID are written into the `'Efsm'` block. The large `memmove` operations in this function write into a separate PFile-stream buffer returned by `EfspAquirePFileStream`, not into the `'Efsm'` allocation.

Because the inputs are 32-bit-bounded and the inline checks already constrain `alloc_size` to `[0x20, 0xFFFFFFFF]`, the two builds produce the same allocation size for every input. The patch standardizes the overflow detection on a single checked-add helper and moves to the modern pool API; it does not close a reachable under-allocation.

#### Reachability

`EfspConstructNewPfileHeader (sub_1c0009be8)` is called from `EfspPostCreateImpersonateAndGetData (0x1C0056738)` at `0x1C0056888`, part of the EFS post-create data-gathering path that runs after a file on an EFS-enabled FAT volume is opened. It is not reached through `FatCommonWrite (sub_1c004f438)` and is not an `IRP_MJ_SET_EA` handler.

---

## 3. Pseudocode Diff

### `sub_1c0009be8` (unpatched) vs `sub_14000a3a4` (patched)

```c
// ============================================================
// UNPATCHED  EfspConstructNewPfileHeader (sub_1c0009be8)
// ============================================================
uint64_t rcx_4  = s - a;                    // s, a: 32-bit locals
uint64_t rax_10 = rdx_3 + rcx_4;            // rdx_3: 32-bit DataOffset+DataLength

if (!(rcx_4 >> 0x3f) && (rax_10 >> 0x3f))   // sign-bit consistency check #1
    rbx = STATUS_INTEGER_OVERFLOW;
else {
    uint64_t r14 = rax_10 + 0x20;
    if (rax_10 >= 0 &&                       // sign-bit consistency check #2
        (rax_10 >> 0x3f) != (r14 >> 0x3f))
        rbx = STATUS_INTEGER_OVERFLOW;
    else if (r14 > 0xffffffff)               // 32-bit range check
        rbx = STATUS_INTEGER_OVERFLOW;
    else if (r14 >= 0x20) {
        void *P = ExAllocatePoolWithTag(PagedPool, r14, 'Efsm');
        // 0x20 bytes + a 16-byte UUID written into P; header fields set.
        // Stream data is copied into a separate EfspAquirePFileStream buffer.
    }
}

// ============================================================
// PATCHED  sub_14000a3a4
// ============================================================
NTSTATUS s1 = sub_14000a810(rdx_3, rcx_4, &acc);      // checked add
if (s1 >= 0) {
    NTSTATUS s2 = sub_14000a810(acc, 0x20, &acc);      // checked add + 0x20
    if (s2 >= 0) {
        if (acc > 0xffffffff)                          // 32-bit range check
            rbx = STATUS_INTEGER_OVERFLOW;
        else if (acc >= 0x20) {
            void *P = ExAllocatePool2(POOL_FLAG_PAGED, acc, 'Efsm');
        }
    }
}
```

`sub_14000a810` computes `a + b`, verifies sign consistency against `0x7FFFFFFFFFFFFFFF`, and returns `STATUS_INTEGER_OVERFLOW` (`0xC0000095`) on wrap, storing the sum through its out-pointer. A third checked add of the same form (`DataOffset + rcx_4`) later in the patched function replaces the inline sign-bit check the unpatched build uses at `0x1C0009E1B`–`0x1C0009E3C`.

---

## 4. Assembly Analysis

### Unpatched `EfspConstructNewPfileHeader (sub_1c0009be8)` — size validation

```asm
0x1C0009CCF  mov   ecx, [r12+r13+32h]     ; DataOffset (32-bit)
0x1C0009CD4  mov   edx, [r12+r13+36h]     ; DataLength (32-bit)
0x1C0009CD9  add   edx, ecx               ; rdx_3 = DataOffset + DataLength
0x1C0009CDB  cmp   edx, ecx
0x1C0009CDD  jb    loc_1C0009EFB          ; 32-bit add carry -> STATUS_INTEGER_OVERFLOW
0x1C0009CE3  cmp   edx, r14d
0x1C0009CE6  jbe   short loc_1C0009D06    ; rdx_3 must be <= caller-supplied size

0x1C0009D06  mov   eax, [rbp+var_90+8]    ; a
0x1C0009D09  mov   ecx, [rbp+Size]        ; s
0x1C0009D0C  sub   rcx, rax               ; rcx_4 = s - a
0x1C0009D0F  mov   eax, edx               ; rdx_3
0x1C0009D11  add   rax, rcx               ; rax_10 = rdx_3 + rcx_4
0x1C0009D1E  shr   rdx, 3Fh               ; sign(rcx_4)
0x1C0009D22  shr   rcx, 3Fh               ; sign(rax_10)
0x1C0009D2A  test  edx, edx
0x1C0009D2C  jnz   short loc_1C0009D36
0x1C0009D2E  test  ecx, ecx
0x1C0009D30  jnz   loc_1C0009EFB          ; +/+ -> negative sum = overflow
0x1C0009D36  lea   r14, [rax+20h]         ; r14 = rax_10 + 0x20
0x1C0009D3A  test  rax, rax
0x1C0009D3D  js    short loc_1C0009D4E
0x1C0009D42  shr   rax, 3Fh
0x1C0009D46  cmp   ecx, eax
0x1C0009D48  jnz   loc_1C0009EFB          ; sign flip on +0x20 = overflow
0x1C0009D4E  mov   eax, 0FFFFFFFFh
0x1C0009D53  cmp   r14, rax
0x1C0009D56  ja    loc_1C0009EFB          ; alloc_size > 0xFFFFFFFF = reject
0x1C0009D5C  cmp   r14d, 20h
0x1C0009D60  jnb   short loc_1C0009D6A    ; require alloc_size >= 0x20
0x1C0009D6A  mov   edx, r14d              ; NumberOfBytes = alloc_size
0x1C0009D6D  mov   ecx, 1                 ; PoolType = PagedPool
0x1C0009D72  mov   r8d, 6D736645h         ; Tag = 'Efsm'
0x1C0009D78  call  cs:__imp_ExAllocatePoolWithTag
```

Writes into the `'Efsm'` block `rdi`: two 16-byte `movups` at `+0x00`/`+0x10` and a UUID `movdqu` at `+0x10` (max offset `0x20`), plus `mov [rdi], r14d`. The subsequent `call memmove (sub_1c000e600)` at `0x1C0009DD0`, `0x1C0009E59`, and `0x1C0009EBC` copy into `rsi`, the PFile-stream buffer from `EfspAquirePFileStream`, not into the `'Efsm'` block.

### Patched `sub_14000a3a4` — checked-add equivalent

```asm
0x14000A4E4  call  sub_14000a810          ; checked add: rdx_3 + rcx_4 -> var_B8
0x14000A4EB  test  eax, eax
0x14000A4ED  js    loc_14000A6CD          ; STATUS_INTEGER_OVERFLOW
0x14000A500  call  sub_14000a810          ; checked add: result + 0x20 -> var_B8
0x14000A507  test  eax, eax
0x14000A509  js    loc_14000A6CD
0x14000A513  mov   eax, 0FFFFFFFFh
0x14000A518  cmp   r15, rax
0x14000A51B  ja    loc_14000A6C8          ; alloc_size > 0xFFFFFFFF = reject
0x14000A521  cmp   r15d, 20h
0x14000A525  jnb   short loc_14000A52F    ; require alloc_size >= 0x20
0x14000A532  mov   ecx, 100h              ; POOL_FLAG_PAGED
0x14000A537  mov   r8d, 6D736645h         ; 'Efsm'
0x14000A53D  call  cs:ExAllocatePool2
```

`sub_14000a810`:

```asm
0x14000A810  lea     r10, [rcx+rdx]       ; sum
0x14000A817  shr     rcx, 3Fh
0x14000A81B  shr     rdx, 3Fh
0x14000A81F  cmp     ecx, edx
0x14000A821  jnz     short loc_14000A844
0x14000A826  mov     rdx, 7FFFFFFFFFFFFFFFh
0x14000A830  cmp     r10, rdx
0x14000A833  setnbe  al
0x14000A836  cmp     ecx, eax
0x14000A838  jz      short loc_14000A844
0x14000A83A  mov     r9d, 0C0000095h      ; STATUS_INTEGER_OVERFLOW
0x14000A840  or      r10, 0FFFFFFFFFFFFFFFFh
0x14000A844  mov     [r8], r10            ; store sum
0x14000A847  mov     eax, r9d
```

---

## 5. Behavioral Notes

The size arithmetic operates on values read as 32-bit fields, so `rax_10 = rdx_3 + (s - a)` stays within roughly `+/- 2^33` and cannot wrap the 64-bit register. In every input case the unpatched sign-bit checks plus the `> 0xFFFFFFFF` range check constrain `alloc_size` to `[0x20, 0xFFFFFFFF]`, matching the amount actually written into the `'Efsm'` block (0x20 bytes plus a UUID). The patched build reaches the same allocation size through the checked-add helper. There is no input that yields a smaller allocation than the data written into that block in either build.

**Trigger surface for the arithmetic path (both builds):**

1. EFS on FAT enabled (`HKLM\SYSTEM\CurrentControlSet\Services\Fastfat\FatEnableEfs = 1`).
2. A FAT/FAT32 volume with an EFS-tagged file.
3. Opening the file drives the EFS post-create path (`EfspPostCreateImpersonateAndGetData`), which calls `EfspConstructNewPfileHeader` and runs the size computation.

Both builds validate the descriptor fields (`DataOffset + DataLength` carry check, `rdx_3 <= caller size`, `alloc_size <= 0xFFFFFFFF`, `alloc_size >= 0x20`) before allocating.

---

## 6. Observation Points for a Researcher

Target: `fastfat_unpatched.sys`, image base `0x1c0000000`.

### Breakpoints

```text
bp fastfat_unpatched!EfspConstructNewPfileHeader     ; 0x1C0009BE8 entry
bp 0x1C0009D78                                       ; ExAllocatePoolWithTag site
bp 0x1C0009DD0                                       ; first memmove (PFile-stream buffer)
```

### What to inspect

| Address | Register / Memory | Meaning |
|---|---|---|
| `0x1C0009CCF` | `[r12+r13+0x32]`, `[r12+r13+0x36]` | On-disk `DataOffset`, `DataLength` (32-bit) |
| `0x1C0009D11` | `rax` | Computed `rax_10 = rdx_3 + (s - a)` |
| `0x1C0009D53` | `r14` | `alloc_size = rax_10 + 0x20`; rejected if `> 0xFFFFFFFF` |
| `0x1C0009D78` | `edx` | `ExAllocatePoolWithTag` size (`r8d = 'Efsm'`, `ecx = 1` PagedPool) |
| `0x1C0009DD0` | `r8` | `memmove` length into the PFile-stream buffer `rsi` |
| after alloc | `rax`/`rdi` | Pointer to the `'Efsm'` block (receives 0x20 bytes + UUID) |

On the patched build the corresponding checked adds are at `0x14000A4E4` / `0x14000A500` / `0x14000A5EC` and the allocation via `ExAllocatePool2` at `0x14000A53D`.

### Struct / offset notes

- EFS context object: `r12` (`Src`), `+0x0e` → `r13`, offset to EFS metadata inside the object.
- `+r13 + 0x32` → `DataOffset` (32-bit); `+r13 + 0x36` → `DataLength` (32-bit).
- `s` = EFS stream size (`Size` local, written by `EfspCreateFileLicenseHeaderAndKey`).
- `a` = `var_90+8`, base offset written by `EfsGetEfsStreamInfo`.
- Pool tag `0x6d736645` = `'Efsm'`.
- Copy helper `sub_1c000e600` is `memmove`.

---

## 7. Changed Functions — Triage

### Size-arithmetic hardening

| Function | Similarity | Change | Note |
|---|---|---|---|
| `EfspConstructNewPfileHeader (sub_1c0009be8)` → `sub_14000a3a4` | 0.9086 | hardening | Inline sign-bit overflow checks replaced with checked-add helper `sub_14000a810` (three call sites); `ExAllocatePoolWithTag(PagedPool)` migrated to `ExAllocatePool2(POOL_FLAG_PAGED)`; key-buffer zeroing changed to a manual loop. Allocation size is bounded identically in both builds. |

### Version/toolchain deltas (non-security)

| Function | Similarity | Change | Note |
|---|---|---|---|
| `DplWrapProtect (sub_1c0008008)` (DPL wrap encryption, AES-CBC/HMAC-SHA256) | 0.7343 | behavioral | `ExAllocatePoolWithTag(NonPagedPoolNx)` migrated to `ExAllocatePool2(0x40)`; inline `0xffff` field clamps replaced with helpers `sub_140009954` / `sub_14000992c`; `memset` key zeroing changed to a manual loop. Overflow checks already present inline (`sbb` patterns) in the unpatched build. No logic change. |
| `FatSetupAllocationSupport (sub_1c0025258)` | 0.6186 | behavioral | VCB struct offsets shifted `+0x10`; bounds/overflow checks reorganized but logically equivalent — the patched build folds a `rcx < rdx_2` bound into the initial overflow check; the unpatched build checks it at a later label. Same outcomes. |
| `FatDefragDirectory (sub_1c0038518)` | 0.9347 | behavioral | Struct offset shifts (`+0x10`); resource-list traversal changed from `do-while` to `for` (compiler). Logic identical; `ExAllocatePoolWithTag` in both builds. |
| `FatCommonWrite (sub_1c004f438)` | 0.8075 | behavioral | Struct offset shifts; call-target addresses updated. No security-relevant logic change. |

**Cosmetic / register-allocation deltas** across the changed functions follow from the different toolchain and base (`0x140000000` vs `0x1c0000000`, `+0x10` VCB offset drift) and account for the bulk of the 484 changed-function count.

---

## 8. Unmatched Functions

```text
removed: (none)
added:   (none)
```

No functions were added or removed. The checked-add helper `sub_14000a810` and the clamp helpers `sub_140009954` / `sub_14000992c` referenced by the patched build are pre-existing utility routines within the matched set, not new functions introduced by this patch.

---

## 9. Confidence & Caveats

**Confidence:** High for the structural change (inline checks → checked-add helper + `ExAllocatePool2`) and its direction; High that the allocation size is bounded identically in both builds.

**Rationale:**
- The before/after assembly for `sub_1c0009be8` / `sub_14000a3a4` and the helper `sub_14000a810` are unambiguous and match a standard integer-overflow-hardening pattern.
- The size inputs (`DataOffset`, `DataLength`, `s`, `a`) are all read as 32-bit fields, so the sum cannot approach a 64-bit wrap, and the inline `> 0xFFFFFFFF` / `>= 0x20` gates already bound the allocation.
- Only 0x20 bytes plus a UUID reach the `'Efsm'` block; the descriptor/stream `memmove`s target the separate `EfspAquirePFileStream` buffer.

**Notes:**
1. Reachability confirmed from `EfspPostCreateImpersonateAndGetData (0x1C0056738)` via the call at `0x1C0056888` (EFS post-create data path). The function is not an `IRP_MJ_SET_EA` handler.
2. Field offsets `+0x32` (`DataOffset`), `+0x36` (`DataLength`), and the `+0x0e` metadata offset are taken from the decompiled code and cross-checkable against the EFS on-disk layout.
3. Copy helper `sub_1c000e600` resolves to `memmove`; allocation `PoolType` in the unpatched build is `1` (PagedPool), size in `edx`, tag in `r8d`.
