Title: fastfat.sys — No security-relevant change (CWE-190 guards emitted in both)
Date: 2026-06-28
Slug: fastfat_b86c186d-fastfat-report-20260628-232510
Category: Corpus
Author: Argus
Summary: KB5082142

### 1. Overview
- **Unpatched Binary:** `fastfat_unpatched.sys` (version 10.0.20348.5020)
- **Patched Binary:** `fastfat_patched.sys` (version 10.0.28000.1896)
- **Overall Similarity Score:** 0.8428
- **Diff Statistics:** 800 matched functions (316 identical, 484 changed), 0 unmatched in either direction.
- **Verdict:** The two binaries are different-branch builds of the same driver. The FAT volume parameter computation function `FatSetupAllocationSupport (sub_1C0025258)` performs the same integer-overflow validation on boot-sector arithmetic in both builds. The differences between the two versions are recompilation artifacts: a +0x10 field insertion in the volume control block (VCB) that shifts struct offsets, and one bit-scan loop factored out into a helper. No security-relevant change is present in this function.

### 2. Function Summary

- **Severity:** Informational (no security-relevant change identified).
- **Function Class:** On-disk FAT metadata (BIOS Parameter Block) parsing and volume layout computation.
- **Analyzed Function:** `FatSetupAllocationSupport (sub_1C0025258)` in the unpatched build, paired with `sub_140023300` in the patched build.

**What the function does:**
`FatSetupAllocationSupport` reads FAT boot-sector fields that were parsed into the VCB (bytes-per-sector, reserved sectors, number of FATs, sectors-per-FAT for FAT16 and FAT32, root-directory entry count, sectors-per-cluster) and computes the volume layout: FAT start/size, root-directory location, cluster count, the cache file size passed to `CcSetFileSizes`, and the size of the FAT-window pool allocation made with `ExAllocatePoolWithTag` (tag `FtaW`, `0x57746146`). Because these fields come from an attacker-controllable on-disk boot sector, the function guards its arithmetic with unsigned-overflow and bounds checks and rejects malformed volumes via `ExRaiseStatus(STATUS_FILE_CORRUPT_ERROR)` (`0xC0000102`).

**Validation present in BOTH builds:**
1. Entry arithmetic `reserved + numFATs * sectorsPerFAT`: unsigned wrap check (`if (sum < reserved) reject`) plus an upper-bound check against the sectors-per-FAT field.
2. `32 * rootEntries / bytesPerSector + previous`: wrap check plus bound check.
3. FAT file-size computation `bytesPerSector * (sectorsPerFAT * numFATs) + bytesPerSector * reserved`: unsigned wrap check before it is stored into `FileSizes.FileSize` and handed to `CcSetFileSizes`.
4. Allocation-count computation `(rootDirBytes + 0xFFFF) >> 16`: explicit wrap check before use as the `ExAllocatePoolWithTag(size = count * 0xC)` multiplier.

Each of these guards is emitted in both `fastfat_unpatched.sys` and `fastfat_patched.sys` with equivalent semantics, so a crafted boot sector that overflows any of these chains is rejected with `STATUS_FILE_CORRUPT_ERROR` in both builds.

### 3. Pseudocode

Both builds implement the same validated arithmetic. Field offsets differ by +0x10 because a field was inserted earlier in the VCB.

**Unpatched (`FatSetupAllocationSupport` / `sub_1C0025258`):**
```c
// FAT32 path (sectors-per-FAT16 field == 0 selects the 32-bit field)
v14 = reserved + numFATs * sectorsPerFAT16;      // reserved = *(a2+276)
if ( v14 < reserved ) ExRaiseStatus(0xC0000102); // unsigned wrap -> reject
v12 = 32 * rootEntries / bytesPerSector + v14;
if ( v12 < v14 ) ExRaiseStatus(0xC0000102);      // unsigned wrap -> reject
if ( sectorsPerFAT < v12 ) ExRaiseStatus(0xC0000102); // bound -> reject
...
v39 = bytesPerSector * sectorsPerFATtotal + bytesPerSector * reserved;
if ( v39 < bytesPerSector * reserved ) ExRaiseStatus(0xC0000102); // wrap -> reject
FileSizes.FileSize.QuadPart = v39;
if ( FileObject->PrivateCacheMap ) CcSetFileSizes(FileObject, &FileSizes);
...
if ( entryFmt == 32 && rootDirBytes > 0x10000 ) {
    if ( rootDirBytes + 0xFFFF < rootDirBytes ) ExRaiseStatus(0xC0000102); // wrap -> reject
    count = (rootDirBytes + 0xFFFF) >> 16;
} else count = 1;
*(a2+208) = ExAllocatePoolWithTag(0x411, 12 * count, 'FtaW');
```

**Patched (`sub_140023300`):**
```c
v15 = reserved + numFATs * sectorsPerFAT16;      // reserved = *(a2+292)  (+0x10 shift)
if ( v15 < reserved ) ExRaiseStatus(0xC0000102);
v16 = 32 * rootEntries / bytesPerSector + v15;
if ( v16 < v15 || bound < v16 ) ExRaiseStatus(0xC0000102); // wrap + bound combined
...
v36 = bytesPerSector * sectorsPerFATtotal + bytesPerSector * reserved;
if ( v36 < bytesPerSector * reserved ) ExRaiseStatus(0xC0000102);
FileSizes.FileSize.QuadPart = v36;
if ( FileObject->PrivateCacheMap ) CcSetFileSizes(FileObject, &FileSizes);
...
if ( entryFmt == 32 && rootDirBytes > 0x10000 ) {
    if ( rootDirBytes + 0xFFFF < rootDirBytes ) ExRaiseStatus(0xC0000102);
    count = (rootDirBytes + 0xFFFF) >> 16;
} else count = 1;
*(a2+224) = ExAllocatePoolWithTag(0x411, 12 * count, 'FtaW');
```

The only structural change is that the patched build combines the entry wrap check and the bound check into a single `if (v16 < v15 || bound < v16)` expression, whereas the unpatched build performs the bound check a few instructions later at a shared label. The set of rejected inputs is the same.

### 4. Assembly Analysis

In `fastfat_unpatched.sys`, `FatSetupAllocationSupport` starts at `0x1C0025258`.

**Key instruction offsets in unpatched `FatSetupAllocationSupport (sub_1C0025258)`:**
```assembly
0x1C0025315: call __imp_ExRaiseStatus      ; STATUS_FILE_CORRUPT_ERROR on entry-check failure
0x1C0025332: imul r11d, r9d                 ; numFATs * sectorsPerFAT (32-bit), followed by wrap check
0x1C00256A0: call __imp_CcSetFileSizes      ; FileSize computed from validated arithmetic
0x1C00256E2: call __imp_ExRaiseStatus       ; STATUS_FILE_CORRUPT_ERROR on allocation-count wrap
0x1C0025709: call __imp_ExAllocatePoolWithTag ; size = 12 * count, tag 'FtaW' (0x57746146)
0x1C002580C: call __imp_ExRaiseStatus       ; STATUS_FILE_CORRUPT_ERROR
```

The patched build (`sub_140023300`) emits the same call sequence — the entry overflow/bound checks, `CcSetFileSizes`, the allocation-count wrap check, and `ExAllocatePoolWithTag(..., 'FtaW')` — with register allocation and struct offsets adjusted for the recompile. The bit-scan loops the unpatched build inlines (computing log2 of sector/cluster sizes, guarded by `KeBugCheckEx(0x23, 0x21309, ...)`) are factored into the helper `sub_140021EE0` in the patched build (same loop, guard code `0x2131B`). This is a code-organization change with no behavioral effect.

### 5. Trigger Conditions

`FatSetupAllocationSupport` runs while a FAT volume is being brought online and its boot-sector fields have been parsed into the VCB. Supplying boot-sector fields whose products overflow 32-bit arithmetic (for example a `numFATs * sectorsPerFAT` chain that wraps, or a root-directory computation that wraps) causes the function to take one of its `ExRaiseStatus(STATUS_FILE_CORRUPT_ERROR)` paths and reject the volume. This rejection behavior is identical in both builds; there is no build in which the overflow reaches an undersized allocation.

### 6. Notes on the FtaW Allocation Path

- The `FtaW` (`0x57746146`) allocation holds the FAT-window array; its element size is 12 bytes (`0xC`) and its count is `(rootDirBytes + 0xFFFF) >> 16`, clamped to 1 for small volumes.
- The multiplier feeding this allocation is guarded by an explicit wrap check (`if (rootDirBytes + 0xFFFF < rootDirBytes) reject`) in both builds, so the count cannot wrap to a small value ahead of the `count * 0xC` size computation.
- The FAT file size handed to `CcSetFileSizes` is guarded by its own wrap check (`if (v39 < bytesPerSector * reserved) reject`) in both builds.

### 7. Inspection Playbook

To observe the validation on a target build:

**Breakpoints:**
- `bp fastfat_unpatched!sub_1C0025258` — entry to the parameter computation. `rcx` = context (IRP context / IrpContext), `rdx` = VCB. The parsed BPB fields sit at fixed offsets from the VCB base (unpatched: `+0x110` bytes-per-sector, `+0x112` sectors-per-cluster, `+0x114` reserved sectors, `+0x116` numFATs, `+0x118` root-directory entries, `+0x11A` total sectors (16-bit), `+0x11E` sectors-per-FAT (16-bit), `+0x12C` sectors-per-FAT (32-bit)).
- `bp 0x1C00256A0` — `CcSetFileSizes` call; inspect `FileSizes.FileSize` on the stack.
- `bp 0x1C0025709` — `ExAllocatePoolWithTag` call; `r8` (size) = `12 * count`, `r9` (tag) = `0x57746146`.
- `bp 0x1C0025315`, `bp 0x1C00256E2`, `bp 0x1C002580C` — the `STATUS_FILE_CORRUPT_ERROR` rejection sites; a malformed BPB that overflows any guarded chain lands on one of these.

**What to inspect:**
- At entry, dump `dd rdx+0x110 L8` to read the parsed BPB fields.
- Step to the `imul r11d, r9d` at `0x1C0025332` and confirm the wrap check that follows routes overflowing products to `ExRaiseStatus`.
- Confirm the `ExAllocatePoolWithTag` size at `0x1C0025709` tracks the validated count and is not reachable with a wrapped count.

**Expected observation:** A boot sector engineered to overflow the guarded arithmetic causes the mount to fail with `STATUS_FILE_CORRUPT_ERROR` (`0xC0000102`) rather than producing an undersized allocation. The same outcome occurs on both builds.

### 8. Changed Functions — Full Triage

The two binaries are different-branch builds, so almost every function differs by a +0x10 struct-offset shift and register reallocation. The functions below were examined in detail.

- **FatSetupAllocationSupport (sub_1C0025258) / sub_140023300 (BPB parameter computation)**
  - *Change Type:* Recompilation (no security change)
  - *Note:* Identical integer-overflow and bounds validation on boot-sector arithmetic in both builds. Differences: +0x10 VCB offset shift; the inlined log2 bit-scan loops are factored into helper `sub_140021EE0`; the entry wrap and bound checks are merged into one expression in the patched build. Same set of rejected inputs; `CcSetFileSizes` and `ExAllocatePoolWithTag('FtaW')` are reached with the same guarded values.
- **FatVerifyVolume (sub_1C0044490) / sub_140042848 (volume verification)**
  - *Change Type:* Recompilation
  - *Note:* Volume-verification routine. Changes are predominantly +0x10 offset shifts and register renumbering from the recompile; no new security logic.
- **EfspHasPrivilege (sub_1C0007620) / sub_140007EF0 (privilege check)**
  - *Change Type:* Cosmetic
  - *Note:* Walks the token privilege array via `SeQueryInformationToken(TokenPrivileges)` looking for LUID 0x12 (SeManageVolumePrivilege) with the enabled attribute set. Loop restructured by the compiler; logic identical.
- **EdpEnforcementLog_AutomaticEncryption (sub_1C005D144) / sub_140058A58 (EDP enforcement logging)**
  - *Change Type:* Cosmetic
  - *Note:* Enterprise Data Protection enforcement logging for automatic encryption. Trace/event formatting differs slightly across the recompile; no security impact.
- **IsExcludedExtension (sub_1C0009F5C) / sub_14000A774 (extension exclusion check)**
  - *Change Type:* Cosmetic
  - *Note:* Checks whether a file extension is on an exclusion list. Search loop restructured by the compiler; comparison logic identical.
- **FatQueryFsAttributeInfo (sub_1C004EFD0) / sub_14004A3F8 (FS attribute query)**
  - *Change Type:* Recompilation
  - *Note:* Reports filesystem attribute/name information (FAT12/FAT16/FAT32). Offset shifts and minor flag-computation refactor; no security logic change.

*(The remaining changed functions are offset-shift and register-allocation differences from the +0x10 VCB field insertion and the cross-branch recompile.)*

### 9. Unmatched Functions

- **Removed:** None.
- **Added:** None.

### 10. Confidence & Caveats

- **Confidence Level:** High that `FatSetupAllocationSupport` contains no security-relevant change: the overflow and bounds guards feeding `ExAllocatePoolWithTag('FtaW')` and `CcSetFileSizes` are present and semantically equivalent in both builds, verified against the decompilation and the disassembly.
- **Build context:** The unpatched image is 10.0.20348.5020 and the patched image is 10.0.28000.1896 — different servicing branches, which accounts for the +0x10 VCB layout change and the large count of "changed" functions. The KB metadata records no CVE attributed to this component.
- **Manual verification notes:** BPB field offsets cited above are for the unpatched VCB layout; add 0x10 for the patched layout. To confirm the rejection behavior, break on `FatSetupAllocationSupport` entry and drive a boot sector whose guarded arithmetic overflows; execution reaches `ExRaiseStatus(STATUS_FILE_CORRUPT_ERROR)` on both builds.
