Title: fvevol.sys — No security-relevant change (major OS-build refresh; the one flagged edit adds a pointer test after the pointer is already dereferenced)
Date: 2026-06-28
Slug: fvevol_f8fc4d23-fvevol-report-20260628-232542
Category: Corpus
Author: Argus
Summary: KB5094128

## 1. Overview

*   **Unpatched Binary:** `fvevol_unpatched.sys`
*   **Patched Binary:** `fvevol_patched.sys`
*   **Overall Similarity Score:** 0.7398 (indicates a broad version difference or major update, not a single targeted hotfix)
*   **Diff Statistics:**
    *   Matched Functions: 1379
    *   Changed Functions: 1140
    *   Identical Functions: 239
    *   Unmatched Functions: 0 (Added: 0, Removed: 0)
*   **Verdict:** No security-relevant change was delivered in this patch. The one instruction-level edit that survived scrutiny is in `FveEowBuildBootSector`: the patched build inserts `test rdx, rdx; jz` on the search-miss fallback path. That test guards a pointer (`arg1 + 0xF0`) that the immediately preceding instruction (`movdqu [rdx], xmm0`) has already dereferenced, so it cannot prevent any dereference and delivers no protection. It is a code-generation artifact, not a fix. Every other flagged difference (physical-memory mapping in `GetKeyRing`, and the low-similarity behavioral functions) is OS-build churn: pool-API migration (`ExAllocatePoolWithTag` to `ExAllocatePool2`), WPP/ETW tracing, feature-staging gates, and register-allocation/struct-offset shifts. The pre-existing validations in those functions are present identically in both builds.

---

## 2. Vulnerability Summary

### Finding 1: `FveEowBuildBootSector` — Added pointer test on the fallback path is a no-op guard (no security effect)
*   **Severity:** None (No security-relevant change)
*   **Vulnerability Class:** N/A (no reachable dereference is prevented)
*   **Affected Function:** `FveEowBuildBootSector` @ `0x1C00033EC` (Unpatched) / `0x140012A74` (Patched)
*   **What actually differs:** `FveEowBuildBootSector` calls `FveEowFindGuidRecognition`, which scans the caller-supplied buffer (`arg1`) for the EOW information GUID and returns a pointer to the matching entry, or `NULL` when the GUID is not present. On a `NULL` return both builds fall back to `rdx = arg1 + 0xF0`, write default GUID data there (`movdqu [rdx], xmm0`), and then, if `arg3` and `arg4` are non-NULL, write through `rdx` at `+0x10`, `+0x20`, and in a two-iteration loop. The single difference is that the patched build inserts `test rdx, rdx; jz` (`0x140012AA4`/`0x140012AA7`) between the fallback write and the `arg3` check.
*   **Why this is not a security fix:**
    1.  The inserted `test rdx, rdx` runs *after* `movdqu [rdx], xmm0` at `0x140012AA0`, which has already dereferenced the same `rdx`. If `rdx` were an unmappable address, the fault occurs at the `movdqu`, one instruction before the new test. The test cannot prevent that access.
    2.  `rdx` is `arg1 + 0xF0` computed by `lea` from a caller-supplied context pointer. It is zero only if `arg1 == -0xF0` (`0xFFFFFFFFFFFFFF10`). The decompiled patched condition makes this explicit: `result != 0 || (v7 = v5 + 240, *(_OWORD *)(v5 + 240) = EOW_INFORMATION_OFFSET_GUID, v5 != -240)`. The added branch is `v5 != -240`, a condition that is false only for that one impossible input.
    3.  The sole caller, `FvepWriteBootSectors`, passes a driver-allocated pool buffer as `arg1` (non-NULL, mappable) in both builds, so the fallback pointer is a valid in-buffer offset. There is no attacker-controlled path that makes `arg1 + 0xF0` NULL or unmappable.
*   **Direction check:** The patched build adds an instruction, but it adds no reachable protection; the unpatched build is not exposed to a NULL/invalid-pointer dereference on this path.

### Finding 2: `GetKeyRing` Physical Memory Mapping via `MmMapIoSpaceEx` — No change in this patch
*   **Severity:** Informational (no patch-introduced security change)
*   **Vulnerability Class:** N/A (function's mapping path identical in both builds)
*   **Affected Function:** `GetKeyRing` @ `0x1C00C2CC8` (Unpatched) / `0x140D8078` (Patched)
*   **What the function does:** `GetKeyRing` is the only function in the driver that calls `MmMapIoSpaceEx`. It parses a decimal ASCII string into a physical address value (accumulated in `r14` via a `r14 = r14*10 + digit` loop), maps `0x1000` bytes at that physical address with `Protect = 4` (`PAGE_READWRITE`) at the first call site, validates the mapped region with `FveKeyringIsValid`, unmaps it, and remaps using the size read from the mapped header (`[rsi+8]`) at the second call site.
*   **Patch status:** The `MmMapIoSpaceEx` call setup (physical address in `rcx`, size in `edx`, protection in `r8d`) is byte-for-byte identical between the unpatched and patched builds at both call sites (`0x1C00C305E`/`0x1C00C30B8` unpatched, `0x1400D840D`/`0x1400D8467` patched). The only difference inside `GetKeyRing` between builds is an equivalent restatement of a character test during string parsing: the unpatched build uses `mov ecx, 0FFDFh; test [rdx], cx; jz` (accept the terminator when the character is `0x00` or `0x20` after masking bit `0x20`), while the patched build splits this into `test ax, ax; jz` plus `cmp ax, 0x20; jz`. Both express the same "character is NUL or space" condition. No bounds check on the physical address or size was added in this patch.

---

## 3. Pseudocode Diff

### Finding 1: `FveEowBuildBootSector`
The only difference is the added `v5 != -240` term in the guarding condition; the writes themselves are unchanged.

```c
// --- UNPATCHED FveEowBuildBootSector (0x1C00033EC) ---
result = FveEowFindGuidRecognition(a1, 0x2000);
v7 = result;
if ( result == 0 )
{
    v7 = v5 + 240;                                   // fallback: derive pointer from arg1
    *(_OWORD *)(v5 + 240) = EOW_INFORMATION_OFFSET_GUID; // write default GUID data (dereferences v5+240)
}
if ( a3 != 0 && v6 != nullptr )
{
    *(_OWORD *)(v7 + 16) = *(_OWORD *)a3;
    *(_QWORD *)(v7 + 32) = v9;
    // two-iteration loop writing (char*)v6 + (v7 - v6) + 40
}
return result;

// --- PATCHED FveEowBuildBootSector (0x140012A74) ---
result = FveEowFindGuidRecognition(a1, 0x2000u);
v7 = result;
// The fallback write STILL happens as part of the condition, dereferencing v5+240
// before the new "v5 != -240" term is ever evaluated:
if ( result != 0
  || (v7 = v5 + 240, *(_OWORD *)(v5 + 240) = EOW_INFORMATION_OFFSET_GUID, v5 != -240) )
{
    if ( a3 != 0 && v6 != nullptr )
    {
        *(_OWORD *)(v7 + 16) = *(_OWORD *)a3;
        *(_QWORD *)(v7 + 32) = v9;
        // same loop
    }
}
return result;
```

The added `v5 != -240` term (`test rdx, rdx`) is evaluated only after `*(_OWORD *)(v5 + 240) = ...` has already written through — and thus dereferenced — `v5 + 240`. It provides no protection.

---

## 4. Assembly Analysis

### Finding 1: `FveEowBuildBootSector`
The fallback write at `0x1C0003418` / `0x140012AA0` dereferences `rdx`; the patched build's added `test rdx, rdx` follows that write.

```assembly
; --- UNPATCHED FveEowBuildBootSector (0x1C00033EC) ---
00000001C00033FD  call    FveEowFindGuidRecognition
00000001C0003402  mov     rdx, rax
00000001C0003405  test    rax, rax
00000001C0003408  jnz     short loc_1C000341C     ; GUID found -> skip fallback
00000001C000340A  movups  xmm0, cs:EOW_INFORMATION_OFFSET_GUID
00000001C0003411  lea     rdx, [rcx+0F0h]         ; rdx = arg1 + 0xF0
00000001C0003418  movdqu  xmmword ptr [rdx], xmm0 ; write default GUID data (dereferences rdx)
00000001C000341C  test    rbx, rbx               ; check arg3
00000001C000341F  jz      short loc_1C0003451
00000001C0003421  test    r11, r11               ; check arg4
00000001C0003424  jz      short loc_1C0003451
00000001C0003426  movups  xmm0, xmmword ptr [rbx]
00000001C0003433  movups  xmmword ptr [rdx+10h], xmm0
00000001C0003437  movsd   qword ptr [rdx+20h], xmm1
00000001C000343C  sub     rdx, r11
00000001C000343F  mov     rax, [r11]
00000001C0003442  mov     [rdx+r11+28h], rax

; --- PATCHED FveEowBuildBootSector (0x140012A74) ---
0000000140012A85  call    FveEowFindGuidRecognition
0000000140012A8A  mov     rdx, rax
0000000140012A8D  test    rax, rax
0000000140012A90  jnz     short loc_140012AA9     ; GUID found -> skip fallback AND the added test
0000000140012A92  movups  xmm0, cs:EOW_INFORMATION_OFFSET_GUID
0000000140012A99  lea     rdx, [rcx+0F0h]         ; rdx = arg1 + 0xF0
0000000140012AA0  movdqu  xmmword ptr [rdx], xmm0 ; dereferences rdx (same as unpatched)
0000000140012AA4  test    rdx, rdx               ; ADDED, but rdx was already dereferenced above
0000000140012AA7  jz      short loc_140012ADE     ; taken only if arg1 == -0xF0 (impossible for a real buffer)
0000000140012AA9  test    rbx, rbx
0000000140012AAC  jz      short loc_140012ADE
0000000140012AAE  test    r11, r11
0000000140012AB1  jz      short loc_140012ADE
0000000140012AB3  movups  xmm0, xmmword ptr [rbx]
0000000140012AC0  movups  xmmword ptr [rdx+10h], xmm0
0000000140012AC4  movsd   qword ptr [rdx+20h], xmm1
0000000140012AC9  sub     rdx, r11
0000000140012ACC  mov     rax, [r11]
0000000140012ACF  mov     [r11+rdx+28h], rax
```

Note the GUID-found branch (`jnz`) targets `loc_140012AA9` in the patched build, i.e. it skips the added `test rdx, rdx` entirely; the test is reachable only on the fallback path, where `rdx = arg1 + 0xF0` has already been written through at `0x140012AA0`.

### Finding 2: `GetKeyRing`
The `MmMapIoSpaceEx` setup is identical across builds. Side-by-side of the first call site:

```assembly
; --- UNPATCHED GetKeyRing (0x1C00C2CC8) ---
00000001C00C304B  mov     ebx, 1000h
00000001C00C3050  mov     r8d, 4            ; Protect = PAGE_READWRITE
00000001C00C3056  mov     edx, ebx          ; NumberOfBytes = 0x1000
00000001C00C3058  mov     rcx, r14          ; PhysicalAddress (parsed from ASCII string)
00000001C00C305B  mov     r15d, ebx
00000001C00C305E  call    cs:__imp_MmMapIoSpaceEx

; --- PATCHED GetKeyRing (0x140D8078) ---
00000001400D83FA  mov     ebx, 1000h
00000001400D83FF  mov     r8d, 4
00000001400D8405  mov     edx, ebx
00000001400D8407  mov     rcx, r14
00000001400D840A  mov     r15d, ebx
00000001400D840D  call    cs:__imp_MmMapIoSpaceEx
```

The register setup, mapping size, and protection are the same in both builds; no validation was added before the mapping call.

---

## 5. Trigger Conditions

### Finding 1 (`FveEowBuildBootSector`)
No security-relevant condition is introduced or removed. On the search-miss fallback path both builds write default GUID data to `arg1 + 0xF0` and then, when `arg3`/`arg4` are non-NULL, write adjacent fields through that same offset. `arg1` is a driver-allocated pool buffer supplied by `FvepWriteBootSectors`, so `arg1 + 0xF0` is a valid in-buffer address in both builds. The patched build's added `test rdx, rdx` is reachable only after that pointer has already been dereferenced, and is taken only for the impossible input `arg1 == -0xF0`, so it changes no observable behavior.

### Finding 2 (`GetKeyRing`)
No patch-introduced security condition. The physical-memory mapping behavior is identical in both builds.

---

## 6. Exploit Primitive & Development Notes

*   **Primitive Provided:** None. Finding 1's added instruction delivers no protection and the unpatched build has no reachable dereference on this path; Finding 2's mapping path is unchanged between builds.
*   **Finding 1:** The fallback write targets `arg1 + 0xF0` (plus `+0x10`, `+0x20`, and the loop offset), all inside the driver-allocated buffer passed by the caller. There is no attacker-controlled way to make that offset NULL or unmappable, and the added `test rdx, rdx` executes after the pointer is already dereferenced, so it cannot gate the access.
*   **Finding 2:** The `MmMapIoSpaceEx` mapping in `GetKeyRing` (physical address parsed from a string, `0x1000`-byte `PAGE_READWRITE` map) is present identically in both builds and is not addressed by this patch.
*   **Mitigations:** Not applicable — this patch does not change a security-relevant behavior in either function.

---

## 7. Debugger PoC Playbook

For a kernel debugger (KD/WinDbg) attached to either binary. These are observation aids only; there is no vulnerability to trigger.

### Observing Finding 1 (`FveEowBuildBootSector`)

**Breakpoints (unpatched):**
```text
bp fvevol_unpatched!FveEowBuildBootSector
bp fvevol_unpatched!FveEowBuildBootSector+0x16   ; 0x1C0003402: rax = search result (0 selects the fallback path)
bp fvevol_unpatched!FveEowBuildBootSector+0x2C   ; 0x1C0003418: movdqu [rdx], xmm0 - fallback write through rdx = arg1+0xF0
```

**What to inspect:**
*   At function entry: `arg1` (`rcx`, the driver-allocated buffer), `arg3` (`r8`), `arg4` (`r9`).
*   At `0x1C0003402`: `rax` is the search result; `0` selects the fallback path.
*   At `0x1C0003411`: `rdx` becomes `rcx + 0xF0`, an offset inside the same buffer.
*   At `0x1C0003418`: the fallback write dereferences `rdx`. In the patched build the added `test rdx, rdx` at `0x140012AA4` runs after this same write; setting a breakpoint there shows `rdx` is non-zero for any real buffer, so the branch at `0x140012AA7` is not taken.

### Regarding Finding 2 (`GetKeyRing`)

**Breakpoints (to observe the mapping behavior, identical in both builds):**
```text
bp fvevol_unpatched!GetKeyRing
bp fvevol_unpatched!GetKeyRing+0x396   ; 0x1C00C305E: MmMapIoSpaceEx call 1
bp fvevol_unpatched!GetKeyRing+0x3F0   ; 0x1C00C30B8: MmMapIoSpaceEx call 2
```

**What to inspect:**
*   `rcx` holds the physical address (parsed from the ASCII string into `r14`), `edx` holds `NumberOfBytes` (`0x1000` at the first site, `[rsi+8]` at the second), `r8d` holds `Protect` (`4`).
*   Comparing the same offsets in the patched build shows identical register setup, confirming no validation was added.

---

## 8. Changed Functions — Full Triage

*   **`FveEowBuildBootSector` @ `0x1C00033EC` (Sim: 0.9555)**: **[Not security relevant]** The only difference is an added `test rdx, rdx; jz` on the fallback path, executed after `movdqu [rdx], xmm0` has already dereferenced `rdx = arg1 + 0xF0`. It gates no reachable dereference and is a code-generation artifact.
*   **`GetKeyRing` @ `0x1C00C2CC8` (Sim: 0.9767)**: **[Not security relevant]** Sole `MmMapIoSpaceEx` caller; the mapping setup is byte-identical in both builds. The only change is an equivalent restatement of a NUL/space character test during string parsing.
*   **`FveTryInlineWriteEncrypt` @ `0x1C0048B28` (Sim: 0.3232)**: **[Not security relevant]** The size-driven allocation/`IoAllocateMdl` decision is functionally identical (De-Morgan-refactored); the same length flows to the MDL and to `memmove` in both builds with no new guard. New code is feature staging (`Feature_SteelixInlineNvmeCryptoEngine`, `Feature_BitLockerEphemeralVolumeSupport`) and the `ExAllocatePoolWithTag` to `ExAllocatePool2` migration.
*   **`FveConfigManageLoad` @ `0x1C00222F8` (Sim: 0.8548)**: **[Not security relevant]** The integer-overflow guard (`RtlULongToUShort` with a negative-return check) and the `MmProbeAndLockPages`/`memmove` flow are present identically in both builds. Only the pool-API migration and struct-offset shifts differ.
*   **`FveWipeInfoFileCreate` @ `0x1C008221C` (Sim: 0.4008)**: **[Not security relevant]** The patched build consolidates a manual `FveAllocateUnicodePath`/`FveFileGetPath`/`ZwCreateFile`/`ZwFsControlFile` fallback into a second `FveFileOpenEx` call. Refactor/consolidation, no added validation.
*   **`FveInitialDataReadEDrv` @ `0x1C006D52C` (Sim: 0.3343)**: **[Not security relevant]** Adds a `Feature_BitLockerEphemeralVolumeSupport` report and a device/feature-flag gate on internal `Context` fields (not on attacker-supplied buffer contents). The pre-existing `FveValidateInformation` corruption check is present in both builds; remaining differences are the pool-API migration and codegen.

*(Note: The 0.7398 similarity reflects a major OS build jump, so the 1140 changed functions are dominated by register-allocation/cosmetic variation, WPP/ETW trace churn, `ExAllocatePool2` migration, and feature staging. No function among the changed set delivers a security-relevant validation change.)*

---

## 9. Unmatched Functions

*   **Added:** None.
*   **Removed:** None.

---

## 10. Confidence & Caveats

*   **Confidence:** High that this patch contains no security-relevant change. The `FveEowBuildBootSector` edit is a single added `test rdx, rdx; je` at `0x140012AA4`, verified in both disassembly and decompilation; it follows the fallback write that already dereferences the same pointer, and the guarded condition (`arg1 == -0xF0`) is not reachable for the driver-allocated buffer the caller supplies, so it prevents nothing.
*   **Finding 2:** The `MmMapIoSpaceEx` mapping code in `GetKeyRing` is identical across both builds; this patch makes no change to the physical-memory mapping path. The lone in-function difference is an equivalent character-test refactor during string parsing.
*   **Caveats / Assumptions:**
    *   The four low-similarity behavioral functions were compared in both `.c` and `.asm`; their surviving validations (`RtlULongToUShort` overflow guard, `MmProbeAndLockPages`, `FveValidateInformation`) exist in both builds, and the new code is feature staging plus pool-API modernization, not input validation.
