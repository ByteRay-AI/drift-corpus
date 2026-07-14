Title: classpnp.sys — zone-command CDB builder unchanged; async dispatch placed behind a registry flag
Date: 2026-06-09
Slug: classpnp_3950aa3d-classpnp-report-20260628-172518
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Informational
KBDate: 2026-06-09

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | `classpnp_unpatched.sys` (10.0.20348.5256) |
| Patched binary | `classpnp_patched.sys` (10.0.28000.2336) |
| Overall similarity | 0.7332 |
| Functions matched | 592 |
| Functions changed | 472 |
| Functions identical | 120 |
| Functions unmatched (either direction) | 0 |

**Verdict:** The two binaries are different build branches (10.0.20348.5256 vs 10.0.28000.2336; the older build was selected as "any strictly older distinct version"), so the bulk of the 472 changed functions differ by recompilation only. `ClasspProcessCloseZone` (`sub_1C0037854`, patched `ClasspProcessCloseZone` `sub_14002F770`) is functionally identical across both builds: the same two descriptor-offset scan loops, the same per-entry bounds checks (`offset >= 0x80`, `offset < bufferSize`, `offset+0x28 <= bufferSize` for type 0x40/0x42, `offset+0x38 <= bufferSize` for type 0x41), and the same post-loop pointer dereference are present in both. The working pointer (`r8`) is set only inside the second loop from fully-validated offsets in both versions; the first loop never sets it. The only behavioral change is a new check on the `ProcessZoneCommandAsynchronously` global (a registry-controlled feature flag) that gates the asynchronous zone-command call; the remaining differences are register reallocation and instruction reordering. No out-of-bounds read/write is introduced or removed by this change, and no CVE is attributed to it.

---

## 2. Vulnerability Summary

### Finding 1 — ClasspProcessCloseZone descriptor scan (no patch-introduced OOB)

| Field | Value |
|---|---|
| **Severity** | Informational |
| **Class** | Zone-command CDB construction; descriptor-offset scan bounded in both builds |
| **Function** | `ClasspProcessCloseZone` (`sub_1C0037854`) |
| **Patched equivalent** | `ClasspProcessCloseZone` (`sub_14002F770`) |
| **Entry point** | SCSI zone-management (ZBC) command build path — `ClasspProcessCloseZone` builds a CLOSE ZONE CDB and calls `ClassSendSrbSynchronous` |

**What the function does.** `ClasspProcessCloseZone` builds a SCSI zone-management (Close Zone) request. It reads an array of descriptor offsets at `arg3+0x78` (indexed by a 32-bit counter, 4-byte elements), and for each offset validates `offset >= 0x80` and `offset < bufferSize` (`bufferSize` = `[arg3+0x10]`). Based on the descriptor type byte at `arg3+offset` (0x40/0x41/0x42) it validates a type-specific extent (`offset+0x28 <= bufferSize` for 0x40/0x42, `offset+0x38 <= bufferSize` for 0x41) and, on a match, sets the working pointer (`r8`) to an in-buffer location (`arg3+0x18+offset`, `arg3+0x20+offset`, or the default `arg3+0x48`). It then fills CDB bytes at that pointer (constant opcode `0x94` = ZONE MANAGEMENT OUT / Close Zone, plus masked flags) and issues the SRB.

**Cross-build comparison.** The unpatched and patched CDB fill is the same sequence (the working pointer is held in `r8`):

```
al = *(r8+1); al &= 0xE1; *r8 = 0x94; al |= 1; *(r8+1) = al;   // present in BOTH builds
```

In both builds the first scan loop only sets a status flag (`r10b`) and writes the `+0xa` field; it never assigns the dereferenced working pointer. The working pointer is assigned only inside the second loop, and only from offsets that passed the type-specific extent check. There is no stale-pointer carry between the two loops in either build, and the two loops, their bounds checks, and the post-loop dereference are byte-for-byte equivalent after normalizing addresses and register allocation.

**What actually changed:**
- A new check on the `ProcessZoneCommandAsynchronously` global (`cmp cs:ProcessZoneCommandAsynchronously, 0; jz` at `0x14002F7C4`) gates the asynchronous zone-command call in the patched build. That global is set at driver init from the `ProcessZoneCommandAsync` registry value (`setnz cs:ProcessZoneCommandAsynchronously` at `0x140029CD3`), so it is a registry-gated feature toggle.
- Register reallocation (the second-loop flag moved from `r11b` to `dil`; the descriptor count moved to `r11d`) and minor instruction reordering.
- The `[rbp+23Ch]`, `[rbp+248h]`, `[rbp+250h]`, `[rbx+10h]`, `[rbx+78h]` offsets and surrounding logic are identical in both builds.

**Reachability note.** The scan operates on an SRB/CDB buffer (`arg3`) built during zone-management command processing. The working-pointer = NULL fall-through path (when the second loop matches nothing under the `[arg3+2] == 0x28` branch) leads to the same dereference in both builds, so any latent risk there is not specific to this patch.

---

## 3. Change Diff

### `ClasspProcessCloseZone` — unpatched (`0x1C0037854`) vs. patched (`0x14002F770`)

The descriptor scan is identical across builds. The single behavioral change is that the patched build guards the asynchronous zone-command dispatch behind the `ProcessZoneCommandAsynchronously` global, which is populated from a registry value at driver init.

**The one real delta — async dispatch gate.**

Unpatched (`0x1C00378A8`):

```
00000001C00378A8  test    r9b, r9b
00000001C00378AB  jnz     short loc_1C00378CC
00000001C00378AD  mov     r9d, 80000016h
00000001C00378B6  mov     rcx, r14; DeviceObject
00000001C00378B9  call    ClasspProcessZoneCommandAsynchronously
```

Patched (`0x14002F7C4`) adds the leading global check:

```
000000014002F7C4  cmp     cs:ProcessZoneCommandAsynchronously, 0
000000014002F7CB  jz      short loc_14002F7F1        ; skip async unless the registry flag is set
000000014002F7CD  test    r9b, r9b
000000014002F7D0  jnz     short loc_14002F7F1
000000014002F7D2  mov     r9d, 80000016h
000000014002F7DB  mov     rcx, r14; DeviceObject
000000014002F7DE  call    ClasspProcessZoneCommandAsynchronously
```

The `ProcessZoneCommandAsynchronously` global is set at init from the `ProcessZoneCommandAsync` registry value (`setnz cs:ProcessZoneCommandAsynchronously` at `0x140029CD3`, following a `ZwQueryValueKey`). This is a registry-gated feature toggle, not a bounds or validation change.

**The descriptor scan — identical in both builds.** Both builds run the same two offset-array scans over `arg3+0x78` (4-byte elements). Each offset is validated `>= 0x80` and `< bufferSize` (`[arg3+0x10]`); the type byte at `arg3+offset` selects a type-specific extent check (`offset+0x28 <= bufferSize` for types 0x40/0x42, `offset+0x38 <= bufferSize` for type 0x41). The working pointer (held in `r8`) is set only inside the second loop from an offset that passed its extent check; otherwise it defaults to `arg3+0x48` or 0. The first loop only sets a status flag and writes the `arg3+offset+0xa` field; it never sets the working pointer. The post-loop CDB fill (`mov al,[r8+1]; mov byte[r8],0x94; mov [r8+1],al`) is byte-for-byte equivalent after normalizing addresses and register allocation.

---

## 4. Assembly Analysis

### Unpatched `ClasspProcessCloseZone` (`0x1C0037854`) — Descriptor Scan Sequence

First scan loop (validates each offset; sets only the `r10` flag and the `+0xa` field; does NOT set the working pointer):

```
00000001C0037978  mov     ecx, [rbx+r9*4+78h]     ; load 4-byte descriptor offset from arg3+0x78
00000001C003797D  cmp     ecx, 80h               ; offset >= 0x80
00000001C0037983  jb      short loc_1C00379CE
00000001C0037985  mov     r8d, [rbx+10h]         ; r8 = bufferSize (arg3+0x10)
00000001C0037989  cmp     ecx, r8d               ; offset < bufferSize
00000001C003798C  jnb     short loc_1C00379CE
00000001C003798E  mov     edx, ecx
00000001C0037990  mov     ecx, [rcx+rbx]         ; read type byte at arg3+offset
00000001C00379A2  lea     rcx, [rdx+28h]         ; type 0x42: offset+0x28
00000001C00379A6  cmp     rcx, r8                ; offset+0x28 <= bufferSize?
00000001C00379AD  lea     rcx, [rdx+38h]         ; type 0x41: offset+0x38
00000001C00379B1  cmp     rcx, r8                ; offset+0x38 <= bufferSize?
00000001C00379D9  mov     byte ptr [rdx+rbx+0Ah], 10h   ; write field inside buffer
```

Second scan loop (`0x1C0037A06` start): loads each offset, revalidates `>= 0x80` and `< bufferSize`, reads the type byte, and sets the working pointer `r8` only after the type-specific extent check passes, e.g.:

```
00000001C0037A89  lea     r8, [rbx+18h]
00000001C0037A8D  add     r8, rdx                ; r8 = arg3+0x18+offset (after offset+0x28 <= bufferSize)
```

If nothing matches, `r8` keeps its initialized value (0 or `arg3+0x48`).

Post-loop dereference and CDB fill (identical in both builds):

```
00000001C0037A9D  mov     al, [r8+1]
00000001C0037AA4  and     al, 0E1h
00000001C0037AA6  mov     byte ptr [r8], 94h     ; opcode 0x94 (ZONE MANAGEMENT OUT / Close Zone)
00000001C0037AB1  mov     [r8+1], al
00000001C0037B11  mov     ebx, 0C000000Dh        ; error exit: STATUS_INVALID_DEVICE_REQUEST
```

### Patched `ClasspProcessCloseZone` (`0x14002F770`) — differences

After normalizing addresses and register allocation, the two builds match. The only differences:

- A new `cmp cs:ProcessZoneCommandAsynchronously, 0; jz` at `0x14002F7C4` gates the asynchronous zone-command call (ahead of the existing `test r9b, r9b` gate).
- Register reallocation: the second-loop flag moves from `r11b` to `dil`, and the descriptor count moves to `r11d`.
- Minor instruction reordering (e.g., the `[rbx+26h]`/`[rbx+20h]` field writes; `and qword [rsi+38h], 0` at `0x1C0037B16` becomes `mov qword [rsi+38h], 0` at `0x14002FA3B`).
- No `arg3+N` offset shift: `[rbx+10h]`, `[rbx+78h]`, `[rbp+23Ch]`, `[rbp+248h]`, `[rbp+250h]` are identical in both builds.

---

## 5. Trigger Conditions

No patch-introduced vulnerability exists in `ClasspProcessCloseZone`. The descriptor-offset scan is bounded identically in both builds, and the working pointer used for the CDB fill is set only from offsets that passed both the per-entry range check (`>= 0x80`, `< bufferSize`) and the type-specific extent check. There is no attacker-reachable out-of-bounds condition introduced or removed by this patch, so there is no trigger to describe.

---

## 6. Exploit Primitive & Development Notes

None. No out-of-bounds read or write is introduced or removed by this patch. The working-pointer writes (opcode `0x94` plus masked flag bytes) target an in-buffer CDB location built from validated offsets, and this sequence is identical in both builds.

---

## 7. Debugger PoC Playbook

Not applicable: no vulnerability was confirmed. For reference during any manual review, the CDB fill after the two scan loops is at `0x1C0037A9D` (unpatched) / `0x14002F9BF` (patched) and behaves identically in both builds. The single behavioral difference is the registry-gated async-dispatch check at `0x14002F7C4` in the patched build; the global it tests is set from the `ProcessZoneCommandAsync` registry value at `0x140029CD3`.

---


## 8. Changed Functions — Full Triage

### Reviewed Changes

| Function | Similarity | Change Type | Note |
|---|---|---|---|
| `ClasspProcessCloseZone` (`0x1C0037854` → `0x14002F770`) | 0.9657 | recompilation + feature gate | Functionally identical across builds. Only change: a check on the `ProcessZoneCommandAsynchronously` global (a registry-set feature flag) gating the async zone-command call, plus register reallocation and instruction reordering. The descriptor-offset scan, its bounds checks, and the post-loop CDB fill are the same in both builds. |
| `ClasspServiceIdleRequest` (`sub_1C00014B0`) vs `ClassReadWrite` (`sub_140001640`) | 0.0052 | mismatched pair | The 0.0052 score is a bad cross-build match between two unrelated functions: unpatched `ClasspServiceIdleRequest` (a small helper) and patched `ClassReadWrite`. The true counterpart of patched `ClassReadWrite` (`sub_140001640`) is unpatched `ClassReadWrite` (`sub_1C0002990`), which already contains `ExAcquireRundownProtectionCacheAware`, `IoGetIoPriorityHint`, and the transfer-length check (`[r14+0x18] >> [rdi+0x282] > 0xFFFFFFFF` → `STATUS_INVALID_PARAMETER` 0xC000000D). Those guards are present in both builds; they were not added by this patch. |

### Behavioral Changes (Not Directly Exploitable)

| Function | Similarity | Change Type | Note |
|---|---|---|---|
| `ClassReadDriveCapacity` | 0.921 | behavioral | MDL cleanup refactored into helper `ClasspFreeDeviceMdl` (`sub_14001920C`); condition simplification (`ClasspIsManagedZonedDevice` `sub_1C002B5C4` now called directly, dropping the `sub_1C00162C8` feature-flag gate); struct offset differences; `STATUS_DEVICE_BUSY` recovery path restructured. |
| `ClassDeviceControl` | 0.6308 | behavioral | Major recompilation from struct layout change; pool API migration (`ExAllocatePoolWithTag` → `ExAllocatePool2`); new `ExAcquireResourceExclusiveLite` and `ExAcquireRundownProtectionCacheAware` locking. |
| `ClassInterpretSenseInfo` | 0.7055 | behavioral | Heavy recompilation from struct offset shifts; SCSI sense code interpretation paths restructured. |
| `ClassInitialize` | 0.8184 | behavioral | Struct layout differences; initialization differences; global-state initialization differences between builds. |

### Cosmetic / Modernization Changes

| Function | Similarity | Change Type | Note |
|---|---|---|---|
| `ClassGetDescriptor` | 0.9013 | cosmetic | Pool API modernization (`ExAllocatePoolWithTag` → `ExAllocatePool2` with `POOL_FLAG_NON_PAGED`); minor error/log path reordering. No security impact. |

> The remaining 465 changed functions (out of 472 total) are dominated by cross-build recompilation, struct/offset differences, and pool API migration (`ExAllocatePoolWithTag` → `ExAllocatePool2`). These are mechanical artifacts of comparing two build branches, not security-relevant logic changes.

---

## 9. Unmatched Functions

The diff reported no unmatched functions (`unmatched_unpatched: 0`, `unmatched_patched: 0`). Because the two files are different build branches, function matching is approximate and can pair unrelated functions (as with `ClasspServiceIdleRequest` vs `ClassReadWrite` at 0.0052). Note:
- `ClassReadWrite`'s rundown protection and transfer-length check exist in both builds; they were not added here.

---

## 10. Confidence & Caveats

### Confidence: **High** that no patch-introduced OOB exists in `ClasspProcessCloseZone`

**Rationale:**
- After normalizing addresses and register allocation, unpatched `0x1C0037854` and patched `0x14002F770` are functionally identical: same two scan loops, same bounds checks, same post-loop dereference sequence.
- The first loop never assigns the dereferenced working pointer (`r8`); it is set only inside the second loop from offsets that passed their type-specific extent check. There is no stale-pointer carry in either build.
- The `arg3`/`rbp` offsets in this function are identical across both builds.
- The only behavioral delta is the `ProcessZoneCommandAsynchronously` feature-flag gate on the async call.

**Verified facts:**

1. **Function identity.** `sub_1C0037854` and `sub_14002F770` both resolve to `ClasspProcessCloseZone` (exact-address headers present in both `.asm`).

2. **Pointer at `0x1C0037A9D`.** `r8` (not r12/r13/r14) holds the working pointer; it is set to `arg3+0x18+offset`, `arg3+0x20+offset`, `arg3+0x48`, or NULL. The instruction reads/writes an in-buffer CDB, identical in both builds.

3. **Descriptor offset array semantics.** `arg3+0x78` is scanned as 4-byte elements (`[rbx + r9*4 + 0x78]`), each validated `>= 0x80` and `< [arg3+0x10]`, confirmed in both builds.

4. **Second finding pairing.** Patched `sub_140001640` = `ClassReadWrite`; its true unpatched counterpart is `ClassReadWrite` (`sub_1C0002990`), which already contains the rundown protection and transfer-length check. The report's `sub_1C00014B0` anchor is `ClasspServiceIdleRequest`, an unrelated function.

5. **CVE attribution.** No CVE is attributed to this change.

6. **Sibling functions.** `sub_1C0037B58` = `ClasspProcessFinishZone` and `sub_1C0037E5C` = `ClasspProcessOpenZone` share the scan structure; both compare identically to their patched counterparts apart from the same async-gate/recompilation deltas.

**Follow-up for a researcher:**
- Confirm the async-gate is the sole behavioral change by comparing `ClasspProcessCloseZone` across the two builds (normalize addresses/registers first).
- If hunting a real classpnp issue, compare against the immediate predecessor build rather than this cross-branch pair to isolate a single servicing change.
