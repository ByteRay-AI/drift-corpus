Title: mssecwfp.sys — WFP guard-policy struct layout revision and gated comparison-mode addition
Date: 2026-07-03
Slug: mssecwfp_c5fb4ff2-mssecwfp-report-20260703-220917
Category: Corpus
Author: Argus
Summary: KB5075912
Severity: Unknown
KBDate: 2026-02-10

## 1. Overview

- **Unpatched binary:** `mssecwfp_unpatched.sys`
- **Patched binary:** `mssecwfp_patched.sys`
- **Overall similarity:** 0.8839
- **Diff statistics:** 113 matched functions, 8 changed, 105 identical, 0 unmatched in either direction.

**Verdict:** The changes to the WFP guard-policy comparison engine are a structure-layout revision plus the addition of a new, config-gated comparison mode (prefix/suffix blob operators and an operator/type-validation dispatcher) together with an expanded ETW audit record. The 4-byte field shift in the stored-value structure is applied **consistently** to both the configuration parser (`SecSetWfpGuardConfiguration`) and the comparison engine, so each build is internally consistent. There is no reachable filter bypass and no out-of-bounds read. This is not a security fix.

---

## 2. Change Summary

### Finding 1 — No security-relevant change: stored-value struct layout revision + new gated comparison mode

- **Severity:** None (informational).
- **Nature:** Refactor / feature addition. The driver's guard-policy rule entry (`SecWfpGuardPolicyConfig`, stride `0x30`) had its stored byte-blob **size** field moved by 4 bytes, and a byte at rule `+0x1C` was repurposed as a per-condition comparison-mode selector. Both the code that *writes* these fields and the code that *reads* them changed together.
- **Affected functions (unpatched → patched):**
  - `SecWfpShouldEnforcePolicyOnFilterCondition` `0x1400081D0` → `0x140008838` — per-condition dispatch.
  - `SecWfpAreValuesEqual` `0x140007DA4` → split into `SecWfpAreSimpleTypesEqual` `0x140007F78` and `SecWfpAreValuesEqual` `0x1400080F0`.
  - `SecWfpAreValuesMatch` `0x140007F80` → `0x140008188` (retained), plus new `SecWfpEvaluateConditionComparison` `0x140008394`.
  - `SecWfpIsIpV4MaskMatch` `0x1400080BC` → `0x14000871C`.
  - `SecWfpIsValueInRange` `0x1400080F4` → `0x14000875C`.
  - `SecSetWfpGuardConfiguration` `0x140007AB4` → `0x140007C88` — the configuration parser that populates the stored-value structure (the decisive evidence below).

#### Why this is not a vulnerability

The report thesis that the unpatched engine reads stored-value fields at offsets "4 bytes too low" against a "new" structure is not supported by the binaries. The stored-value structure is built entirely by this driver from the IOCTL configuration buffer, and the parser was revised in lockstep with the comparator:

| Field | Unpatched parser writes | Unpatched comparator reads | Patched parser writes | Patched comparator reads |
|---|---|---|---|---|
| byte-blob size | rule `+0x20` (`SecSetWfpGuardConfiguration`, `lea r12,[rbp+20h]`; `mov ecx,[r12]`) | rule `+0x20` (`SecWfpAreValuesEqual`, `mov ecx,[rdx+10h]`, `rdx`=rule`+0x10`) | rule `+0x24` (`lea r12,[rbp+24h]`; `mov ecx,[r12]`) | rule `+0x24` (`mov eax,[rdx+14h]`) |
| byte-blob data ptr | rule `+0x28` (`mov [rdi+r12+8],rbp`) | rule `+0x28` (`mov rcx,[rdx+18h]`) | rule `+0x28` (`mov [rdi+r12+4],rbp`) | rule `+0x28` (`mov rax,[rdx+18h]`) |

Within a single running build the offset that is written always equals the offset that is read. No build ever runs the "old" reader against the "new" writer. The `+0x20`→`+0x24` shift is a structure revision (the blob-data pointer is unchanged at `+0x28` in both builds), not a bug.

The byte at rule `+0x1C` is likewise not a "wrong offset." In the unpatched build it is consulted only on the `0x101` condition path (`SecWfpShouldEnforcePolicyOnFilterCondition`, `mov al,[rdx+0Ch]` with `rdx`=rule`+0x10`, i.e. rule `+0x1C`). In the patched build the same field at rule `+0x1C` is read as a mode selector (`cmp dword [rdi+1Ch],0`) that, when non-zero, routes the condition to the new `SecWfpEvaluateConditionComparison` dispatcher; when zero, the legacy inline dispatch is retained. That field is populated from the configuration buffer, so it is a per-condition opt-in, not a security gate on existing behavior.

#### What the patched build adds

- A new operator/type-validation dispatcher `SecWfpEvaluateConditionComparison` (`0x140008394`) reached only when rule `+0x1C` is non-zero. It dispatches by operator value read from stored-value `+0xC` and enforces value-type compatibility per operator, returning `STATUS_INVALID_PARAMETER` (`0xC000000D`) / `STATUS_NOT_SUPPORTED` (`0xC00000BB`) for mismatches.
- Two new blob-match operators: `SecIsPrefixMatch` (`0x140007B38`) and `SecIsSuffixMatch` (`0x140007C40`), replacing the single unpatched `SecArePrefixBlobs` (`0x1400078E4`).
- An expanded audit path: `SecWfpAuditMatchedCondition` (`0x1400081FC`) with helpers `SecWfpGetConditionSimpleValueInfo` (`0x140008588`), `SecWfpGetSidAsUnicodeString` (`0x140007A50`) and `SecWfpGetSecurityDescriptorAsUnicodeString` (`0x1400079AC`), emitting additional fields (SID/security-descriptor strings) into the existing `Event_WfpWfpGuardBlock` ETW event.

None of these changes removes a reachable memory-safety defect or a reachable policy bypass from the unpatched build; they add a new, opt-in comparison mode and richer telemetry.

#### Entry point and mechanism

The dispatch is **not** a per-packet classify callback and the compared data is **not** live network traffic. The reachable entry point is the WFP filter-assignment guard:

1. `SecWfpShouldForbidFiltersAssignment` (`0x140008390` → `0x1400089B0`) — registered through NETIO (`KfdRegisterLayerEventNotifyEx`; deregistered via `KfdDeregisterLayerEventNotify` in `SecShutdownWfpGuard`). Invoked when WFP filters are being added/assigned; acquires `SecWfpGuardPolicyConfigLock` shared and iterates the incoming filter's conditions.
2. `SecWfpShouldForbidFilterAssignment` (`0x140008334` → `0x140008958`) — iterates the guard-policy rule set for one condition.
3. `SecWfpShouldEnforcePolicyOnFilterCondition` — matches one filter condition against one guard-policy rule.
4. `SecWfpAreValuesMatch` / `SecWfpAreValuesEqual` / `SecWfpIsIpV4MaskMatch` / `SecWfpIsValueInRange` — value comparison.

When a to-be-assigned filter matches a protected guard-policy rule, the callback returns `STATUS_ACCESS_DENIED` (`0xC0000022`) to forbid the assignment. This is an anti-tamper guard on WFP filter creation, not a data-plane packet filter.

---

## 3. Pseudocode Diff

### Stored-value struct revision — parser and comparator move together

```c
// ===== UNPATCHED SecSetWfpGuardConfiguration (parser) =====
v12 = v7 + 8;                      // size field at entry +0x20
...
size = *v12;                       // read blob size from +0x20
blob = ExAllocatePoolWithTag(1025, size, 'sGw');
*(void**)((char*)v12 + v14 + 8) = blob;   // store blob ptr at +0x28
memmove(blob, src, *v12);

// ===== PATCHED SecSetWfpGuardConfiguration (parser) =====
v12 = v7 + 9;                      // size field at entry +0x24
...
size = *v12;                       // read blob size from +0x24
blob = ExAllocatePoolWithTag(1025, size, 'sGw');
*(void**)((char*)v12 + v14 + 4) = blob;   // store blob ptr at +0x28 (unchanged)
memmove(blob, src, *v12);
```

```c
// ===== UNPATCHED SecWfpAreValuesEqual — type 0xc path (comparator) =====
size = *(uint32_t*)(arg2 + 0x10);  // stored-value +0x10 == rule +0x20 (matches parser)
blob = *(void**)  (arg2 + 0x18);   // rule +0x28
*arg3 = SecArePrefixBlobs(incoming_blob, &{size, blob});

// ===== PATCHED SecWfpAreValuesEqual — type 0xc path (comparator) =====
size = *(uint32_t*)(arg2 + 0x14);  // stored-value +0x14 == rule +0x24 (matches revised parser)
blob = *(void**)  (arg2 + 0x18);   // rule +0x28 (unchanged)
*arg3 = SecIsSuffixMatch(incoming_blob, &{size, blob});
```

### Dispatch — new mode selector at rule +0x1C

```c
// ===== UNPATCHED SecWfpShouldEnforcePolicyOnFilterCondition =====
cond_type = *(uint32_t*)(cond + 8);
switch (cond_type) {
  case 0x102: status = SecWfpIsValueInRange(cond+8, rule+0x10, &result); break;
  case 0x100: status = SecWfpIsIpV4MaskMatch(cond+8, rule+0x10, &result); break;
  case 0x101:                                   // consults byte at rule +0x1C
    status = *(uint8_t*)(rule+0x1C) ? 0xC00000BB : 0;
    break;
  default:    status = SecWfpAreValuesMatch(cond, rule+0x10, &result); break;
}

// ===== PATCHED SecWfpShouldEnforcePolicyOnFilterCondition =====
if (*(uint32_t*)(rule + 0x1C) != 0) {           // new: opt-in validated mode
    status = SecWfpEvaluateConditionComparison(cond, rule+0x10, &result);
} else {                                        // legacy dispatch retained
    cond_type = *(uint32_t*)(cond + 8);
    switch (cond_type) {
      case 0x102: status = SecWfpIsValueInRange(cond+8, rule+0x10, &result); break;
      case 0x100: status = SecWfpIsIpV4MaskMatch(cond+8, rule+0x10, &result); break;
      case 0x101: continue; /* skip */                                        break;
      default:    status = SecWfpAreValuesMatch(cond, rule+0x10, &result);    break;
    }
}
```

---

## 4. Assembly Analysis

### Decisive evidence: parser and comparator agree within each build

```asm
; ===== UNPATCHED SecSetWfpGuardConfiguration @ 0x140007AB4 =====
0000000140007BC5  lea     r12, [rbp+20h]            ; size field at entry +0x20
0000000140007C67  mov     r8d, [r12]                ; size = *(entry+0x20)
0000000140007C43  mov     [rdi+r12+8], rbp          ; blob ptr at entry +0x28

; ===== UNPATCHED SecWfpAreValuesEqual @ 0x140007DA4 (type 0xc) =====
0000000140007F50  mov     ecx, [rdx+10h]            ; rdx=rule+0x10 -> size at rule +0x20
0000000140007F57  mov     rcx, [rdx+18h]            ; blob ptr at rule +0x28
0000000140007F69  call    SecArePrefixBlobs
```

```asm
; ===== PATCHED SecSetWfpGuardConfiguration @ 0x140007C88 =====
0000000140007D99  lea     r12, [rbp+24h]            ; size field at entry +0x24
0000000140007E3B  mov     r8d, [r12]                ; size = *(entry+0x24)
0000000140007E17  mov     [rdi+r12+4], rbp          ; blob ptr at entry +0x28 (unchanged)

; ===== PATCHED SecWfpAreValuesEqual @ 0x1400080F0 (type 0xc) =====
0000000140008159  mov     eax, [rdx+14h]            ; rdx=rule+0x10 -> size at rule +0x24
0000000140008164  mov     rax, [rdx+18h]            ; blob ptr at rule +0x28
0000000140008172  call    SecIsSuffixMatch
```

The write offset equals the read offset in each build. The `+0x20`→`+0x24` shift is a structure revision, not a read against a mismatched layout.

### Dispatch mode selector at rule +0x1C

```asm
; ===== UNPATCHED SecWfpShouldEnforcePolicyOnFilterCondition @ 0x1400081D0 =====
0000000140008227  lea     rdx, [rbp+10h]            ; rdx = rules_base + 0x10
000000014000822B  add     rdx, rdi                  ; rdx = &rule[i] + 0x10
...
000000014000827E  cmp     eax, 101h                 ; type 0x101 path
0000000140008285  mov     al, [rdx+0Ch]             ; byte at rule[i] +0x1C
0000000140008288  neg     al
000000014000828A  sbb     eax, eax
000000014000828C  and     eax, 0C00000BBh           ; STATUS_NOT_SUPPORTED if non-zero

; ===== PATCHED SecWfpShouldEnforcePolicyOnFilterCondition @ 0x140008838 =====
00000001400088A6  cmp     dword [rdi+1Ch], 0        ; same field, now a mode selector
00000001400088AA  jnz     0x1400088EE              ; non-zero -> validated dispatcher
00000001400088F6  call    SecWfpEvaluateConditionComparison
```

### `SecWfpIsIpV4MaskMatch` validity check (struct-field reshuffle)

```asm
; ===== UNPATCHED @ 0x1400080BC =====
00000001400080C1  cmp     [rdx+0Ch], al             ; rdx=rule+0x10 -> byte at rule +0x1C
00000001400080C4  jz      short 0x1400080F2         ; if zero, no result set

; ===== PATCHED @ 0x14000871C =====
0000000140008721  cmp     [rdx+0Ch], eax            ; rule +0x1C
0000000140008724  jnz     short 0x140008732         ; proceed
0000000140008726  cmp     [rdx+10h], al             ; rule +0x20 (freed by size-field move)
0000000140008729  jnz     short 0x140008732         ; proceed
000000014000872B  mov     eax, 0C00000BBh           ; else STATUS_NOT_SUPPORTED
```

Both variants read fields of the same stored-value structure that each build's parser populates; the reshuffle tracks the `+0x1C`/`+0x20`/`+0x24` layout revision.

---

## 5. Trigger Conditions

The reachable path is the WFP filter-assignment guard, exercised when a WFP filter is added to a layer the driver watches:

1. The guard policy is configured via `DeviceIoControl` to `\Device\MsSecWfp` (`SecDeviceIoControl` → `SecSetWfpGuardConfiguration`). The device security descriptor is set at init, restricting who may configure the policy.
2. A WFP filter is added on a monitored layer, invoking `SecWfpShouldForbidFiltersAssignment` (via NETIO `KfdRegisterLayerEventNotifyEx`).
3. The callback iterates the new filter's conditions against the guard-policy rule set. If a condition matches a protected rule, the assignment is forbidden with `STATUS_ACCESS_DENIED` (`0xC0000022`).

Configuring the guard policy and adding WFP filters are privileged operations; the comparison operates on driver-managed structures, not on attacker-supplied packet data. No condition path produces an out-of-bounds access (see §6).

---

## 6. Memory-Safety Assessment

- **No out-of-bounds read.** The blob comparator `SecArePrefixBlobs` (`0x1400078E4`) bounds the compare: it requires `size1 != 0`, `size2 != 0` and `size1 <= size2`, then `memcmp`s `size1` bytes. The rule blob is pool-allocated at exactly its stored size in `SecSetWfpGuardConfiguration`, and the stored size read by the comparator is the same field. The patched `SecIsPrefixMatch` / `SecIsSuffixMatch` apply the same bounding.
- **No offset mismatch inside any single build.** As shown in §2–§4, each build writes and reads the stored-value size/pointer at matching offsets.
- **No policy bypass introduced or removed.** The legacy dispatch is retained in the patched build for rules whose `+0x1C` selector is zero; rules that set the selector opt into the new validated dispatcher. Behavior for existing (selector-zero) configurations is unchanged apart from the layout offset, which is transparent to callers.

There is no exploit primitive: no filter bypass of live traffic (the callback guards filter *assignment*, not packet flow), no info leak, and no memory corruption.

---

## 7. Debugger Notes

Assume WinDbg/KD attached to a machine running `mssecwfp_unpatched.sys`. These breakpoints let an analyst confirm that the parser and comparator use matching offsets (i.e. that there is no mismatch to exploit).

```text
bp mssecwfp+0x7AB4  ".echo [+] SecSetWfpGuardConfiguration (parser)"
bp mssecwfp+0x7BC5  ".echo [+] parser: size field lea r12,[rbp+20h] (entry+0x20)"
bp mssecwfp+0x7DA4  ".echo [+] SecWfpAreValuesEqual (comparator)"
bp mssecwfp+0x7F50  ".echo [+] comparator: size read [rdx+0x10] (rule+0x20); dd rdx L8"
bp mssecwfp+0x81D0  ".echo [+] SecWfpShouldEnforcePolicyOnFilterCondition (dispatch)"
bp mssecwfp+0x8285  ".echo [+] type 0x101 path: byte [rdx+0xC] == rule+0x1C selector"
bp mssecwfp+0x8390  ".echo [+] SecWfpShouldForbidFiltersAssignment (guard entry)"
```

### What to inspect

| BP | Register / Memory | Why |
|---|---|---|
| `+0x7BC5` | `r12 = rbp+0x20` | Parser writes the blob-size field at entry `+0x20` in the unpatched build. |
| `+0x7F50` | `dword [rdx+0x10]` (`rdx`=rule`+0x10`) | Comparator reads size from rule `+0x20` — the same offset the parser wrote. |
| `+0x8285` | `byte [rdx+0xC]` (`rdx`=rule`+0x10`) | The rule `+0x1C` field; in the patched build the same field becomes the comparison-mode selector at `+0x8838`/`+0x88A6`. |
| `+0x8390` | `ecx` (callout id, must be 1), filter-condition array | Confirms the entry point is filter-assignment notification, returning `STATUS_ACCESS_DENIED` to forbid. |

### Struct notes (guard-policy rule entry, stride `0x30`)

| Offset | Size | Field |
|---|---|---|
| `+0x00` | DWORD | rule ID |
| `+0x04` | DWORD | rule sub-ID |
| `+0x08` | BYTE | action |
| `+0x0A` | WORD | layer ID |
| `+0x0C` | DWORD | session ID |
| `+0x10` | — | stored condition value (base for comparator `rdx`) |
| `+0x1C` | DWORD | comparison-mode selector (patched) / `0x101` presence byte (unpatched) |
| `+0x20` | DWORD | blob size (unpatched layout) |
| `+0x24` | DWORD | blob size (patched layout) |
| `+0x28` | PVOID | blob data pointer (both builds) |

**Rule base / count:** `SecWfpGuardPolicyConfig` (pointer), `SecWfpGuardPolicyConfigCount` (count).

---

## 8. Changed Functions — Full Triage

### Comparison-engine group (refactor / feature addition, not security fixes)

- **`SecWfpShouldEnforcePolicyOnFilterCondition` `0x1400081D0` → `0x140008838`** (sim 0.81) — Adds the rule `+0x1C` mode selector that routes to `SecWfpEvaluateConditionComparison`; otherwise the legacy inline dispatch is retained. The `0x101` inline path (unpatched) reads the same `+0x1C` field the patched build repurposes. Also swaps the inline audit call for `SecWfpAuditMatchedCondition`.
- **`SecWfpAreValuesEqual` `0x140007DA4` → `SecWfpAreSimpleTypesEqual` `0x140007F78` + `SecWfpAreValuesEqual` `0x1400080F0`** (sim 0.55) — Split into a simple-type comparator and a value comparator; blob-size offset tracks the parser's `+0x20`→`+0x24` revision; blob compare now calls `SecIsSuffixMatch`. Type checks present in both builds.
- **`SecWfpAreValuesMatch` `0x140007F80` → `0x140008188`** (retained) plus new **`SecWfpEvaluateConditionComparison` `0x140008394`** — New operator/type-validation dispatcher reached only via the `+0x1C` selector; validates value-type compatibility per operator.
- **`SecWfpIsIpV4MaskMatch` `0x1400080BC` → `0x14000871C`** (sim 0.13) — Validity check reads the revised stored-value fields (`+0x1C`/`+0x20`); returns `STATUS_NOT_SUPPORTED` when both are zero. Layout-revision tracking, not a bounds fix.
- **`SecWfpIsValueInRange` `0x1400080F4` → `0x14000875C`** (sim 0.00 by address, matched by content) — Presence flag read moves from stored-value `+0xC` to `+0x10`, tracking the same layout revision.
- **`SecSetWfpGuardConfiguration` `0x140007AB4` → `0x140007C88`** (parser) — Writes the revised blob-size offset (`+0x20`→`+0x24`); blob pointer unchanged at `+0x28`. This is the write side that keeps each build internally consistent.

New patched-only helpers supporting the above: `SecIsPrefixMatch` (`0x140007B38`), `SecIsSuffixMatch` (`0x140007C40`), `SecWfpAuditMatchedCondition` (`0x1400081FC`), `SecWfpGetConditionSimpleValueInfo` (`0x140008588`), `SecWfpGetSidAsUnicodeString` (`0x140007A50`), `SecWfpGetSecurityDescriptorAsUnicodeString` (`0x1400079AC`). Unpatched-only `SecArePrefixBlobs` (`0x1400078E4`) is superseded by the prefix/suffix pair.

### Behavioral (non-security)

- **`SecAddWfpCallouts` `0x140007144` → `0x1400071EC`** (sim 0.87) — Adds a `KclIsWindows8`-family feature/version check gating the `PsReferencePrimaryToken` / `PsImpersonateClient` / `PsRevertToSelf` sequence. Register allocation otherwise cosmetic. Feature/version staging.
- **`SecInitializeGlobalData` `0x1400077AC` → `0x14000782C`** (sim 0.65) — Adds calls that populate new feature/version flags and resolves `SeConvertSecurityDescriptorToString` via `MmGetSystemRoutineAddress` (used by the new SID/SD-to-string audit helpers). Init churn.
- **`KclGetProtectionLevel` `0x140008AF0` → `0x1400091B4`** (sim 0.88) — Adds a `KclIsWindows8` short-circuit that returns `0` early on that version before `ZwQueryInformationProcess`. Version gating.
- **`SecAuditWfpGuardBlock` `0x140007000`** (sim 0.94) — ETW descriptor set expanded (8 → 14 fields), adds process-start-key and a bounded (`< 0x400`) field. Telemetry expansion.

### Cosmetic / register-allocation

Several changed functions differ only in register allocation and call-target displacement caused by inserted code. None affect semantics.

---

## 9. Unmatched Functions

`unmatched_unpatched` and `unmatched_patched` are both `0` in the diff summary. The patched build does introduce new named functions (prefix/suffix match, condition-value/SID/SD audit helpers, `KclIsWindows8`), which appear as content-relocated additions rather than a change in the matched/unmatched counts. No mitigation helper was removed.

---

## 10. Confidence & Caveats

**Confidence:** High that this is not a security-relevant change. The decisive point is directly visible: within each build the configuration parser (`SecSetWfpGuardConfiguration`) writes the stored-value blob size at the same offset the comparator reads it (`+0x20` unpatched, `+0x24` patched), and the blob data pointer is unchanged at `+0x28` in both builds. No single build runs a reader against a mismatched writer, so the "offset mismatch" premise does not hold.

**Notes:**

- The compared operands are driver-managed structures (the stored guard-policy rule and the incoming filter's conditions), not live packet payloads. The reachable callback (`SecWfpShouldForbidFiltersAssignment`) forbids WFP *filter assignment* with `STATUS_ACCESS_DENIED`; it is an anti-tamper guard, not a data-plane packet filter.
- The rule `+0x1C` field is a per-condition comparison-mode selector sourced from the configuration buffer. When zero (the default for existing configurations) the legacy dispatch is used unchanged; when non-zero the condition opts into the new validated dispatcher with prefix/suffix operators. The old path is fully retained.
- The blob comparator bounds its `memcmp` by the smaller of the two sizes, and rule blobs are allocated at exactly their stored size, so no out-of-bounds read arises on either the stored or the incoming side.
