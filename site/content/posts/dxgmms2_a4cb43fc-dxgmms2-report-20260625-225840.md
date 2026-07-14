Title: dxgmms2.sys — feature-staged reference-count balancing gated behind disabled-by-default servicing flags
Date: 2026-02-10
Slug: dxgmms2_a4cb43fc-dxgmms2-report-20260625-225840
Category: Corpus
Author: Argus
Summary: KB5075912
Severity: Unknown
KBDate: 2026-02-10

## 1. Overview

- **Unpatched Binary:** `dxgmms2_unpatched.sys`
- **Patched Binary:** `dxgmms2_patched.sys`
- **Overall Similarity:** 0.9922 (99.22%)
- **Diff Statistics:** 2030 matched functions (2027 identical, 3 changed), 0 unmatched functions in either direction.
- **Verdict:** The patch adds a reference-count increment in the uncommit branch of `VidMmMapGpuVirtualAddressInternal` and a matching release in `UncommitVirtualAddressRangeSystemCommand`. Both additions are wrapped in runtime feature-flag checks (`Feature_3895685435` and `Feature_Servicing_VARangeHoldReference`, queried via `__private_IsEnabledDeviceUsage`), and the pre-existing (no-increment) code path is retained as the default fall-through. With those flags in their default (disabled) state the patched and unpatched binaries are behaviorally identical on this path, and no use-after-free is reachable. The change is servicing scaffolding for a refcount-balancing scheme, not a delivered, unconditionally active security fix.

## 2. Change Summary

- **Severity:** None (no delivered, reachable security change)
- **Change Class:** Feature-staged reference-count balancing (CWE-416 lifetime class, but not reachable in the delivered configuration)
- **Affected Function:** `VIDMM_GLOBAL::VidMmMapGpuVirtualAddressInternal` (unpatched `0x1C0066CB0`, patched `0x1C0066C70`)

### What actually differs
In `VidMmMapGpuVirtualAddressInternal`, the mapping request is split by `D3DDDI_MAPGPUVIRTUALADDRESS.Flags` bit 3 (`test byte [rdi+0x38], 8`):

- **Commit branch** (bit 3 clear): both builds unconditionally execute `lock inc dword [<obj>+0x80]` before calling `CommitVirtualAddressRange`.
- **Uncommit branch** (bit 3 set): the unpatched build calls `UncommitVirtualAddressRange` with no preceding increment. The patched build inserts `lock inc dword [rsi+0x80]` before the same call, **but only when both `Feature_3895685435__private_IsEnabledDeviceUsage()` and `Feature_Servicing_VARangeHoldReference__private_IsEnabledDeviceUsage()` return nonzero**. When either flag is disabled, control falls through to `loc_1C0066EE3`, which matches the unpatched behavior exactly.

The increment exists to balance a reference that the uncommit path can drop. Inside `UncommitVirtualAddressRangeSystemCommand`, the block that adds the VA range back to the VAD range list and then calls `CleanupVaRangeReference` (which calls `VIDMM_MAPPED_VA_RANGE::ReleaseVaRangeReference`) is guarded by `Feature_3895685435__private_IsEnabledDeviceUsage()` **and** the managed-VAD flag `[obj+0x40] & 0x2000`. This guard is present **identically in both builds**. `ReleaseVaRangeReference` (`0x1C0001338`, identical in both builds) atomically decrements the refcount at `+0x80` via `lock xadd` and invokes the deleting destructor only when the pre-decrement value was 1.

Consequently the reference-holding scheme is entirely conditioned on runtime feature-flag state:

- **Both flags disabled (default):** the uncommit path never reaches `CleanupVaRangeReference` (the `Feature_3895685435` guard skips the whole block), so no reference is dropped there; the caller also skips the increment in both builds. Patched and unpatched are equivalent; there is no imbalance and no free.
- **Flags enabled:** the uncommit `CleanupVaRangeReference` drops a reference; the patched caller adds a matching one beforehand and the patched SystemCommand adds a compensating release on the `AddVaRangeToVadRangeList` failure path. This is the balancing logic being staged.

Because the delivered default configuration exhibits no behavioral difference and no reference is dropped on the uncommit path, there is no attacker-reachable use-after-free in either binary as shipped. The feature flags are internal servicing/velocity gates, not attacker-controllable input.

### Reachability
The function is reachable from user mode via `D3DKMTMapGpuVirtualAddress` → `dxgkrnl.sys` dispatch → `VidMmMapGpuVirtualAddress` (static thunk `0x1C00012D0` → `VIDMM_GLOBAL::VidMmMapGpuVirtualAddress` `0x1C0066BF0`) → `VidMmMapGpuVirtualAddressInternal`. Reaching the security-relevant divergence additionally requires the internal `Feature_3895685435` feature to be enabled at runtime (to make the uncommit path drop a reference) and the VA range to carry the managed-VAD flag `0x2000` — neither of which is present in the default configuration.

## 3. Pseudocode Diff

```c
// --- UNPATCHED VidMmMapGpuVirtualAddressInternal (uncommit branch) ---
if (Flags & 0x8) {
    // uncommit branch: no reference increment here
    result = UncommitVirtualAddressRange(this, allocator, vaRange, 0, pendingOp);
} else {
    // commit branch: unconditional increment (both builds)
    *(vaRange + 0x80) += 1;
    result = CommitVirtualAddressRange(this, allocator, pagingQueue, vaRange, ...);
}
// join point (both branches):
if (*(this + 0xa018))
    RecordVaPagingHistoryMapGpuVa(this, *(allocator + 0x60), vaRange, pagingQueue, ...);
ReleaseVaRangeReferenceSafe(vaRange, allocator);
```

```c
// --- PATCHED VidMmMapGpuVirtualAddressInternal (uncommit branch) ---
if (Flags & 0x8) {
    // increment is added but fully gated; old path retained on the else/fall-through
    if (Feature_3895685435__private_IsEnabledDeviceUsage()
            && Feature_Servicing_VARangeHoldReference__private_IsEnabledDeviceUsage())
        *(vaRange + 0x80) += 1;
    result = UncommitVirtualAddressRange(this, allocator, vaRange, 0, pendingOp);
} else {
    // commit branch unchanged (unconditional increment)
    *(vaRange + 0x80) += 1;
    result = CommitVirtualAddressRange(this, allocator, pagingQueue, vaRange, ...);
}
```

## 4. Assembly Analysis

### Unpatched `VidMmMapGpuVirtualAddressInternal` (`0x1C0066CB0`)
```assembly
; Flags bit 3 check (NoCommit/Reserve):
00000001C0066EF8  test    byte ptr [rdi+38h], 8
00000001C0066F0E  jz      short loc_1C0066F34    ; bit clear -> commit branch

; UNCOMMIT branch (bit set) — no reference increment:
00000001C0066F10  mov     rax, [rsp+0B8h+arg_10]
00000001C0066F18  xor     r9d, r9d
00000001C0066F1B  mov     r8, rbp                ; rbp = VIDMM_MAPPED_VA_RANGE*
00000001C0066F1E  mov     [rsp+0B8h+var_98], rax
00000001C0066F23  call    ?UncommitVirtualAddressRange@VIDMM_GLOBAL@@...  ; 0x1C00643F0
00000001C0066F30  mov     edi, eax
00000001C0066F32  jmp     short loc_1C0066F90

; COMMIT branch (bit clear) — unconditional increment:
00000001C0066F34  lock inc dword ptr [rbp+80h]   ; reference increment (commit path)
00000001C0066F64  call    ?CommitVirtualAddressRange@VIDMM_GLOBAL@@...    ; 0x1C00677B0

; Join point — both branches:
00000001C0066F90  cmp     [r15+0A018h], rbx       ; paging-history recording enabled?
00000001C0066F97  jz      short loc_1C0066FB9
00000001C0066FA9  mov     r8, rbp
00000001C0066FB4  call    ?RecordVaPagingHistoryMapGpuVa@VIDMM_GLOBAL@@... ; 0x1C00BE100
00000001C0066FBC  mov     rcx, rbp
00000001C0066FBF  call    ?ReleaseVaRangeReferenceSafe@VIDMM_MAPPED_VA_RANGE@@... ; 0x1C0060244
```

### Patched `VidMmMapGpuVirtualAddressInternal` (`0x1C0066C70`)
```assembly
00000001C0066EB8  test    byte ptr [rdi+38h], 8
00000001C0066EC8  jz      short loc_1C0066F0D    ; bit clear -> commit branch

; UNCOMMIT branch — increment fully gated behind two feature flags:
00000001C0066ECA  call    Feature_3895685435__private_IsEnabledDeviceUsage
00000001C0066ECF  test    eax, eax
00000001C0066ED1  jz      short loc_1C0066EE3    ; flag off -> skip increment (== unpatched)
00000001C0066ED3  call    Feature_Servicing_VARangeHoldReference__private_IsEnabledDeviceUsage
00000001C0066ED8  test    eax, eax
00000001C0066EDA  jz      short loc_1C0066EE3    ; flag off -> skip increment (== unpatched)
00000001C0066EDC  lock inc dword ptr [rsi+80h]   ; the staged increment (rsi = VA range)
00000001C0066EE3  mov     rax, [rsp+0B8h+arg_10]  ; loc_1C0066EE3: common continuation
00000001C0066EEE  mov     r8, rsi
00000001C0066EFC  call    ?UncommitVirtualAddressRange@VIDMM_GLOBAL@@...  ; 0x1C0062D14

; COMMIT branch — unchanged, unconditional increment:
00000001C0066F0D  lock inc dword ptr [rsi+80h]
00000001C0066F43  call    ?CommitVirtualAddressRange@VIDMM_GLOBAL@@...    ; 0x1C0067790
```

### The reference-drop path (both builds) — `UncommitVirtualAddressRangeSystemCommand`
```assembly
; Unpatched 0x1C0064484 / Patched 0x1C0062DA8 — same guard structure:
...  call    Feature_3895685435__private_IsEnabledDeviceUsage   ; unpatched 0x1C0064536 / patched 0x1C0062E5A
...  test    eax, eax
...  jz      <skip>                                             ; feature off -> block skipped entirely
...  test    dword ptr [rbx+40h], 2000h                         ; managed-VAD flag
...  jz      <skip>
...  call    ?AddVaRangeToVadRangeList@CVirtualAddressAllocator@@...
;   PATCHED ONLY (0x1C0062EA7): compensating release on failure path
...  call    Feature_Servicing_VARangeHoldReference__private_IsEnabledDeviceUsage
...  test    eax, eax
...  jz      <skip release>
...  test    esi, esi                                           ; AddVaRangeToVadRangeList result
...  jns     <skip release>                                     ; only on failure (< 0)
...  call    ?ReleaseVaRangeReference@VIDMM_MAPPED_VA_RANGE@@... ; 0x1C0001338
...  call    CleanupVaRangeReference                            ; -> ReleaseVaRangeReference (drops one ref)
```

### `ReleaseVaRangeReference` (`0x1C0001338`, identical in both builds)
```assembly
00000001C000133E  or      ebx, 0FFFFFFFFh
00000001C0001341  lock xadd [rcx+80h], ebx        ; ebx = pre-decrement refcount, refcount -= 1
00000001C0001349  sub     ebx, 1
00000001C000134C  jz      short loc_1C0001357      ; pre-value was 1 -> now 0 -> destroy
00000001C0001357  test    rcx, rcx
00000001C000135A  jz      short loc_1C000134E
00000001C000135C  call    ??_GVIDMM_MAPPED_VA_RANGE@@AEAAPEAXI@Z  ; deleting destructor -> free
```

## 5. Trigger / Reachability Notes

`VidMmMapGpuVirtualAddressInternal` is reachable from user mode:
1. `D3DKMTMapGpuVirtualAddress` (user mode)
2. `dxgkrnl.sys` system-call dispatch
3. `VidMmMapGpuVirtualAddress` static thunk (`0x1C00012D0`) → `VIDMM_GLOBAL::VidMmMapGpuVirtualAddress` (`0x1C0066BF0`)
4. `VIDMM_GLOBAL::VidMmMapGpuVirtualAddressInternal`

Reaching the code that actually differs between builds requires, in addition:
- The `Feature_3895685435` feature enabled at runtime, so that `UncommitVirtualAddressRangeSystemCommand` executes the `CleanupVaRangeReference` (reference-dropping) block on the uncommit path.
- The VA range object carrying the managed-VAD flag (`[obj+0x40] & 0x2000`).

In the default configuration (feature disabled) neither branch drops the reference, both binaries behave identically, and no lifetime imbalance occurs. The feature flags are internal servicing gates and are not influenced by the `D3DDDI_MAPGPUVIRTUALADDRESS` input.

## 6. Exploit Primitive

No exploit primitive is present in the delivered binaries. The reference-count divergence between the two builds is confined to code paths that are inert unless internal servicing feature flags are enabled, and the pre-existing (no-increment) path is retained as the default. In the shipped configuration the uncommit path does not drop a reference on the `VIDMM_MAPPED_VA_RANGE` object, so `RecordVaPagingHistoryMapGpuVa` and `ReleaseVaRangeReferenceSafe` operate on a live object. There is no demonstrable use-after-free, no pool-reclaim window, and no read/write primitive to characterize.

## 7. Verification Anchors

The following addresses were used to verify the change directly against both disassemblies:

- Uncommit vs commit split: unpatched `0x1C0066EF8` (`test byte [rdi+0x38], 8`), patched `0x1C0066EB8`.
- Commit-branch increment (unconditional, both builds): unpatched `0x1C0066F34`, patched `0x1C0066F0D` (`lock inc dword [<obj>+0x80]`).
- Staged uncommit-branch increment (patched only, gated): `0x1C0066EDC`, preceded by feature checks at `0x1C0066ECA` and `0x1C0066ED3`.
- Join-point uses of the object pointer: `RecordVaPagingHistoryMapGpuVa` (unpatched `0x1C0066FB4`, patched `0x1C0066F94`) and `ReleaseVaRangeReferenceSafe` (unpatched `0x1C0066FBF`, patched `0x1C0066F9F`).
- Reference-drop guard (both builds): `Feature_3895685435` check at unpatched `0x1C0064536` / patched `0x1C0062E5A`; `CleanupVaRangeReference` call at unpatched `0x1C0064586` / patched `0x1C0062EBF`.
- Compensating release (patched only): `0x1C0062EB7`, gated at `0x1C0062EA7`.
- `ReleaseVaRangeReference` decrement/free: `0x1C0001341` (`lock xadd`), free branch at `0x1C000135C`.

### Verified struct offsets (`VIDMM_MAPPED_VA_RANGE`)
- `+0x38`: request flags field; bit 3 (`0x8`) selects the uncommit branch.
- `+0x40`: flags field; bit `0x2000` marks a managed VAD (guards the reference-drop block).
- `+0x80`: reference count (uint32), manipulated by `lock inc` and by `ReleaseVaRangeReference`'s `lock xadd`.

## 8. Changed Functions — Full Triage

1. **`VIDMM_GLOBAL::VidMmMapGpuVirtualAddressInternal`** (unpatched `0x1C0066CB0`, patched `0x1C0066C70`)
   - **Similarity:** 0.9562
   - **Change Type:** Feature-staged (behavioral, gated)
   - **Notes:** Adds `lock inc dword [rsi+0x80]` in the uncommit branch at `0x1C0066EDC`, gated behind `Feature_3895685435` and `Feature_Servicing_VARangeHoldReference`. The unpatched (no-increment) path is retained as the fall-through. No effect when the flags are disabled.
2. **`VIDMM_GLOBAL::UncommitVirtualAddressRangeSystemCommand`** (unpatched `0x1C0064484`, patched `0x1C0062DA8`)
   - **Similarity:** 0.9045
   - **Change Type:** Feature-staged (behavioral, gated) plus telemetry
   - **Notes:** Adds one `ReleaseVaRangeReference` call (`0x1C0062EB7`) on the `AddVaRangeToVadRangeList` failure path, gated behind `Feature_Servicing_VARangeHoldReference`, to release the extra reference that the caller adds under the same flags. The `Feature_3895685435`-guarded reference-drop block itself is present identically in both builds. WdLog assertion code changed `0x551F` → `0x552B` (telemetry only).
3. **`VIDMM_MAPPED_VA_RANGE::scalar deleting destructor`** (unpatched `0x1C000136C`, patched `0x1C000148C`)
   - **Similarity:** 0.2239
   - **Change Type:** Refactoring
   - **Notes:** The inline destruction logic (list unlinking, pushlock acquire/release, `operator delete`) was extracted into a standalone `~VIDMM_MAPPED_VA_RANGE` at `0x1C000136C`. The patched scalar deleting destructor (`0x1C000148C`) is reduced to 10 instructions: it calls `~VIDMM_MAPPED_VA_RANGE`, then `operator delete`, then returns. Register allocation shifted accordingly. Not security-relevant.

## 9. Unmatched Functions

- **Added:** None
- **Removed:** None

## 10. Confidence & Caveats

- **Confidence:** High that the change is feature-gated and has no delivered, default-configuration effect. Both feature-flag checks and the retained fall-through were confirmed directly in the patched disassembly, and the reference-drop guard (`Feature_3895685435` + managed-VAD flag) was confirmed present identically in both builds.
- **Caveat:** The runtime default state of `Feature_3895685435` and `Feature_Servicing_VARangeHoldReference` cannot be determined from the binaries alone. This report rates the delivered configuration, in which the pre-existing path is the active one and no reference imbalance occurs on the uncommit path.
</content>
</invoke>
