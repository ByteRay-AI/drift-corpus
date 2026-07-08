Title: netio.sys — No security-relevant change (NSI pool allocation refactored to a low-priority wrapper; size arithmetic unchanged in both builds)
Date: 2026-07-03
Slug: netio_7eaf807a-netio-report-20260703-220743
Category: Corpus
Author: Argus
Summary: KB5082142
Severity: None

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `netio_unpatched.sys` |
| Patched binary | `netio_patched.sys` |
| Overall similarity | 0.6138 |
| Matched functions | 1582 |
| Changed functions | 1250 |
| Identical functions | 332 |
| Unmatched (either direction) | 0 |

**Verdict:** No security-relevant change was delivered in the NSI (Network Store Interface) enumeration/parameter path. The originally-suspected integer overflow in `NsiEnumerateObjectsAllParametersEx` is not a delivered fix: the 32-bit size-accumulation sequence is present and unchanged in **both** builds, and the values it sums are NSI module-provider registration constants, not attacker-controlled input. The only concrete delta in these functions is that direct `ExAllocatePool3` calls were replaced with a new low-page-priority allocation wrapper (`NsipAllocateLowPriority`), plus WPP trace-record and register/basic-block churn. Separately, the binary carries a large servicing update (WFP firewall "audit mode", feature-staging gates, DNS settings RPC, stream-inspection functions), none of which is a memory-safety fix to the NSI path.

---

## 2. Vulnerability Summary

### Finding #1 — No security-relevant change: `NsiEnumerateObjectsAllParametersEx`

**Class:** Originally reported as CWE-190 (Integer Overflow) → CWE-787 (Out-of-bounds Write). **Not substantiated.**
**Function:** `netio!NsiEnumerateObjectsAllParametersEx` (unpatched `0x1C00153F0`, patched `0x14002F5C0`).
**Severity:** None (no delivered change to the arithmetic; inputs are not attacker-controlled).

**What the code actually does:**

The function computes a per-entry record size by summing a handful of field widths taken from the targeted NSI module provider's descriptor table, then multiplies by the entry count and allocates a pool buffer. The per-entry sum is accumulated in a 32-bit register in **both** builds. The field widths (`*v32`, `v32[1]`, `v32[2]`, `v32[3]` in the decompilation; `[rsi]`, `[rsi+4]`, `[rsi+8]`, `[rsi+0Ch]` in assembly) come from the provider's registration descriptor at `provider_table + index*0x68`. These are fixed sizes declared by the kernel NSI provider (for example the built-in TCP/IP modules), not values supplied by the user-mode caller. A medium-integrity user cannot register an NSI module provider (that path requires a kernel NMR provider registration), so these widths are trusted constants.

Because the summed widths are small provider-defined constants and the entry count is clamped to the request's element count in both builds, the 32-bit accumulation does not wrap in practice, and there is no attacker-reachable primitive.

**Direction of the change (important):** The patch did **not** widen the arithmetic or add a clamp. In fact the unpatched build contains an explicit 64-bit post-multiplication guard (`if (product > 0xFFFFFFFF) return STATUS_INTEGER_OVERFLOW`) that the patched build **removes**, and the patched multiply is performed in 32 bits (`v34 * v38`). Given the trusted, small provider inputs this removal is a harmless refactor, not a regression, but it means the report's original claim (that the patch strengthened this arithmetic) is the opposite of what the binaries show.

**Count clamp exists in both builds:** the request count is clamped to the reported element count in the unpatched build (`if (LODWORD(v106[11]) <= v25) v25 = v106[11];`) and in the patched build (`if (LODWORD(v100[7]) > v33) v34 = *(_DWORD *)(v4 + 104);`). It was not added by the patch.

### Finding #2 — No security-relevant change: `NsiGetParameterEx`

**Class:** Originally reported as related integer overflow / OOB write. **Not substantiated.**
**Function:** `netio!NsiGetParameterEx` (unpatched `0x1C0016180`, patched `0x14002E730`).
**Severity:** None.

The size check here is performed in **64-bit** arithmetic in both builds: two 32-bit fields are zero-extended and summed with a 64-bit `add`, then compared against `0xFFFFFFFF`. The sum of two 32-bit values cannot wrap a 64-bit register, so the check is effective. The only difference between builds is the branch sense (unpatched `ja` to the error path vs patched `jbe` to the success path), which is basic-block ordering, not a semantic change, and the allocation being routed through `NsipAllocateLowPriority`. There is no 32-bit overflow and no added or removed validation.

---

## 3. Pseudocode Diff

### Finding #1 — `NsiEnumerateObjectsAllParametersEx`

```c
// =================== UNPATCHED (0x1C00153F0) ===================
Size = *v24;                       // key size from provider descriptor
v30  = Size + 4;                   // 32-bit accumulation
if ( v27 != 0 ) v30 += v24[1];     // provider-defined field widths
if ( v29 != 0 ) v30 += v24[3];
if ( v28 != 0 ) v30 += v24[2];
SizeOfElements = v30;
v34 = v25 * (unsigned __int64)v30; // 64-bit product
if ( v34 > 0xFFFFFFFF )            // explicit overflow guard PRESENT
{
    v9 = 0xC0000095;               // STATUS_INTEGER_OVERFLOW
    goto LABEL_61;
}
Pool3 = ExAllocatePool3(64, (unsigned int)v34, 'NsIr', v103, 1);
// copy loop uses memmove with the provider field widths

// =================== PATCHED (0x14002F5C0) ===================
Size = *v32;                       // key size from provider descriptor
v38  = Size + 4;                   // STILL 32-bit accumulation (unchanged)
if ( v36 != 0 ) v38 += v78;        // provider-defined field widths
if ( v37 != 0 ) v38 += v26;
if ( v39 != 0 ) v38 += v28;
SizeOfElements = v38;
LowPriority = (char *)NsipAllocateLowPriority(v34 * v38);  // 32-bit product, NO 0xFFFFFFFF guard
// copy loop uses memmove with the provider field widths
```

The accumulation width is identical (32-bit) in both builds. The patch removed the `> 0xFFFFFFFF` guard and moved the allocation into `NsipAllocateLowPriority`. `NsipAllocateLowPriority` (`0x14002F490`) is a thin wrapper that calls `ExAllocatePool3` with pool flags `0x40`, tag `'NsIr'`, and a low page-priority extended parameter; it performs no size validation.

### Finding #2 — `NsiGetParameterEx`

```c
// =================== UNPATCHED (0x1C0016180) ===================
v_sum = (unsigned __int64)*(unsigned int *)(a1 + 0x48)
      + (unsigned int)*(unsigned int *)(a1 + 0x4C);   // 64-bit add of two 32-bit fields
if ( v_sum > 0xFFFFFFFF ) { /* error path */ }

// =================== PATCHED (0x14002E730) ===================
v_sum = (unsigned __int64)*(unsigned int *)(a1 + 0x48)
      + (unsigned int)*(unsigned int *)(a1 + 0x4C);   // identical 64-bit add
if ( v_sum <= 0xFFFFFFFF ) { /* success path */ }     // same check, inverted branch sense
```

---

## 4. Assembly Analysis

### Finding #1 — `NsiEnumerateObjectsAllParametersEx`

Unpatched size computation and guard (`0x1C00153F0`), copied from the disassembly:

```asm
00000001C00156C7  mov     eax, [rsi]            ; key size from provider descriptor
00000001C00156D1  add     eax, 4
00000001C00156D8  mov     r14d, eax             ; r14d = key_size + 4 (32-bit)
00000001C00156FE  mov     r8d, [rsi+4]          ; provider field width
00000001C0015702  add     r14d, r8d             ; 32-bit add
00000001C0015714  mov     r8d, [rsi+0Ch]
00000001C0015718  add     r14d, r8d             ; 32-bit add
00000001C001572A  mov     r8d, [rsi+8]
00000001C001572E  add     r14d, r8d             ; 32-bit add
00000001C001573E  mov     eax, r14d
00000001C0015745  imul    rax, rcx             ; rax = entry_size * count (64-bit)
00000001C001574D  mov     ecx, 0FFFFFFFFh
00000001C0015752  cmp     rax, rcx
00000001C0015755  ja      loc_1C0037677         ; product > 0xFFFFFFFF -> STATUS_INTEGER_OVERFLOW
00000001C0015784  call    cs:__imp_ExAllocatePool3
...
00000001C0037677  mov     edi, 0C0000095h       ; STATUS_INTEGER_OVERFLOW
```

Patched size computation (`0x14002F5C0`), copied from the disassembly:

```asm
000000014002FA0B  mov     ecx, [rsi]            ; key size from provider descriptor
000000014002FA11  add     ecx, 4                ; 32-bit
000000014002FA2D  add     ecx, [rsp+1D0h+var_168]  ; 32-bit
000000014002FA3A  add     ecx, edi              ; 32-bit
000000014002FA45  add     ecx, r15d             ; 32-bit
000000014002FA4C  imul    ecx, r12d            ; entry_size * count (32-bit multiply)
000000014002FA50  call    NsipAllocateLowPriority   ; no 0xFFFFFFFF guard
```

The accumulation is 32-bit in both builds. The unpatched build additionally validates the 64-bit product against `0xFFFFFFFF`; the patched build performs the multiply in 32 bits and drops the explicit guard. The per-entry copies use `memmove` in both builds, not a private copy helper.

### Finding #2 — `NsiGetParameterEx`

Unpatched (`0x1C0016180`) and patched (`0x14002E730`) share the identical size check:

```asm
; unpatched 0x1C001623C
00000001C001623C  mov     eax, [rdi+48h]
00000001C0016243  mov     ecx, [rdi+4Ch]
00000001C0016246  add     rcx, rax             ; 64-bit add of two zero-extended 32-bit fields
00000001C0016249  mov     eax, 0FFFFFFFFh
00000001C001624E  cmp     rcx, rax
00000001C0016251  ja      loc_1C00381ED        ; sum > 0xFFFFFFFF -> error

; patched 0x14002E918
000000014002E918  mov     eax, [rdi+48h]
000000014002E91B  mov     ecx, [rdi+4Ch]
000000014002E91E  add     rcx, rax             ; identical 64-bit add
000000014002E921  mov     eax, 0FFFFFFFFh
000000014002E926  cmp     rcx, rax
000000014002E929  jbe     short loc_14002E95A  ; same check, inverted branch sense
```

The add is 64-bit in both builds; the two 32-bit source fields cannot sum to a value that wraps the register. The check is effective in both, and nothing was strengthened or weakened.

---

## 5. Trigger Conditions

Not applicable. The size arithmetic in `NsiEnumerateObjectsAllParametersEx` sums NSI module-provider registration constants, which a user-mode caller cannot set; the accumulation is identical in both builds; and the `NsiGetParameterEx` size check is 64-bit and effective in both builds. There is no attacker-reachable overflow to trigger.

The `\Device\NSI` enumeration path is reachable from user mode via `NtDeviceIoControlFile`, but reaching this code does not expose control over the provider descriptor widths that the size computation reads.

---

## 6. Exploit Primitive & Development Notes

None. There is no controlled pool overflow here:

- The per-entry size is a sum of small, fixed provider-registration widths, not attacker-supplied values.
- The 32-bit accumulation is present in both builds, so nothing was "fixed" in a direction that implies a prior exploitable state changed.
- The unpatched build already validated the 64-bit product against `0xFFFFFFFF`; the patched build merely refactored the allocation and dropped that (in-practice unnecessary) guard.

No exploit chain, KASLR-defeat, pool-grooming, or control-flow-hijack primitive is demonstrable from this diff.

---

## 7. Debugger PoC Playbook

Not applicable. Because there is no attacker-controlled overflow, there is no reproducible crash to script. The relevant instruction anchors, for reference only when reading the two builds, are:

- Unpatched size accumulation: `0x1C00156C7`–`0x1C001572E`; product guard `0x1C0015745`–`0x1C0015755`; allocation `0x1C0015784`.
- Patched size accumulation: `0x14002FA0B`–`0x14002FA45`; 32-bit multiply `0x14002FA4C`; allocation via `NsipAllocateLowPriority` at `0x14002FA50`.

---

## 8. Changed Functions — Full Triage

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `NsiEnumerateObjectsAllParametersEx` | 0.8544 | not security-relevant | 32-bit size accumulation present and unchanged in both builds; count clamp present in both; patched dropped the 64-bit product guard and routed allocation through `NsipAllocateLowPriority`. Provider-registration inputs, not attacker-controlled. |
| `NsiGetParameterEx` | 0.8544 | not security-relevant | Size check is 64-bit `add` + `cmp 0xFFFFFFFF`, identical and effective in both builds; only the branch sense and the allocation wrapper differ. |
| `NsiAllocateAndGetTable` | 0.7686 | behavioral | Four direct `ExAllocatePool3` calls replaced with `NsipAllocateLowPriority`; the existing `0xFFFFFFFF` size check is retained. Allocator refactor, not a security change. |
| `FwppCopyStreamDataToBuffer` | 0.6447 | behavioral | Stream-data copy path refactored (part of the WFP stream-inspection servicing update). No delivered memory-safety fix identified. |
| `FeAcquireWritableLayerDataPointer` | 0.7261 | behavioral | Per-processor SLIST allocation refactored to lookaside-list helpers; lock/trace churn. Not a security change. |
| `WfpStreamInspectReceive` | 0.7018 | behavioral | Stream-inspection context allocation refactored (SLIST → lookaside list); NBL-chain handling inlined. Behavioral refactor, not a security patch. |

**Common cross-cutting deltas** across the larger changed set: (a) replacement of direct `ExAllocatePool3` with the new `NsipAllocateLowPriority` wrapper at NSI allocation sites, (b) additional WPP trace records, and (c) basic-block/register reallocation from a compiler rebuild. None is independently exploitable.

---

## 9. Added / Removed Functions

The diff engine reports 0 unmatched functions, but the two builds differ substantially because the patched binary carries a servicing/feature update. Newly present function groups include WFP firewall "audit mode" (`WfpSetAuditMode`, `FwAuditModeAuditEvent`, `IoctlEnableAuditMode`, `Feature_Firewall_AuditMode__*`), feature-staging gates (`Feature_*__private_IsEnabled*`, `wil_details_*`), DNS settings RPC handlers (`R_DnsGetSettingsImpHandle`, `R_DnsSetSettingsImpHandle`, …), stream-inspection helpers (`StreamBuildStreamData`, `StreamCalloutProcessingLoop`, …), the `NsipAllocateLowPriority` allocation wrapper, and a large set of new `WPP_SF_*` trace thunks. These are feature additions and staged-rollout scaffolding, not memory-safety fixes to the NSI path.

---

## 10. Confidence & Caveats

**Confidence:** High that neither `NsiEnumerateObjectsAllParametersEx` nor `NsiGetParameterEx` received a delivered security fix. This is established directly from both builds' decompilation and disassembly: the 32-bit accumulation in `NsiEnumerateObjectsAllParametersEx` is byte-for-byte the same pattern in both, its inputs are provider-registration constants, and the `NsiGetParameterEx` size check is 64-bit and identical in both.

**Basis:**
- The per-entry field widths are read from the NSI provider descriptor (`provider_table + index*0x68`), populated by kernel provider registration, not by the user-mode request.
- `NsipAllocateLowPriority` (`0x14002F490`) is a low-page-priority `ExAllocatePool3` wrapper with no size validation; the switch to it is an allocation-policy refactor.
- The copy operations are `memmove`; there is no private copy helper at the addresses cited in the original write-up.

**Independent diff:** The changed-function set was enumerated directly from both builds rather than trusting a pre-supplied list. The bulk of the delta is the WFP audit-mode / feature-staging / stream-inspection servicing update. No omitted security-relevant fix to the NSI enumeration or parameter path was found.
