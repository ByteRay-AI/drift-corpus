Title: mssecwfp.sys — No security-relevant change (feature-staged WFP filter-condition matching rollout with the old comparison path retained)
Date: 2026-06-29
Slug: mssecwfp_04ed7c5a-mssecwfp-report-20260629-144748
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview

- **Unpatched Binary:** `mssecwfp_unpatched.sys`
- **Patched Binary:** `mssecwfp_patched.sys`
- **Overall Similarity Score:** `0.8904`

**Verdict:** The patch does **not** fix a memory-safety vulnerability. The change is a staged rollout of a new WFP filter-condition matching path in the WFP-Guard policy engine. A new comparison dispatcher (`SecWfpEvaluateConditionComparison`) that adds prefix/suffix and SID-in-security-descriptor match operators, plus expanded audit telemetry, is introduced. It is reached **only** when a new per-policy-entry flag (dword at offset `0x1C`) is non-zero; when that flag is zero the driver executes the **same comparison code as the unpatched build, unchanged**. The specific comparison code the change was thought to harden (the 16-byte `FWP_BYTE_ARRAY16` compare in `SecWfpAreValuesEqual`) is byte-for-byte identical in both builds and is therefore not the subject of any fix.

---

## 2. Nature of the Change

- **Severity:** None (no security-relevant change)
- **Class:** Feature staging / added functionality + telemetry, old path retained
- **Functions involved:** `SecWfpShouldEnforcePolicyOnFilterCondition` (match loop), `SecWfpAreValuesEqual` / new `SecWfpAreSimpleTypesEqual` (value equality), `SecWfpIsIpV4MaskMatch`, `SecWfpIsValueInRange`, and the newly added `SecWfpEvaluateConditionComparison`, `SecIsPrefixMatch`, `SecIsSuffixMatch`, `SecWfpAuditMatchedCondition`, `SecWfpGetConditionSimpleValueInfo`, `SecWfpGetSecurityDescriptorAsUnicodeString`, `SecWfpGetSidAsUnicodeString`.

### What the driver does
`mssecwfp.sys` is a WFP-Guard policy engine. A LocalSystem-only IOCTL (`0x222008`, handled by `SecSetWfpGuardConfiguration`) installs a table of protected filter patterns into `SecWfpGuardPolicyConfig` / `SecWfpGuardPolicyConfigCount`. When another party attempts to add WFP filters, the callout `SecWfpShouldForbidFiltersAssignment` walks the incoming filter conditions and, via `SecWfpShouldForbidFilterAssignment` → `SecWfpShouldEnforcePolicyOnFilterCondition`, compares each incoming condition against the installed policy patterns. A match causes the driver to return `STATUS_ACCESS_DENIED` (`0xC0000022`) and forbid the filter assignment. This is a filter-management authorization callout; it is **not** a per-packet data-path callout.

### What actually changed
The patched match loop `SecWfpShouldEnforcePolicyOnFilterCondition` (`0x140008838`) adds one new branch at its top:

```
0x1400088A6  cmp     dword ptr [rdi+1Ch], 0     ; NEW: per-policy-entry format flag
0x1400088AA  jnz     0x1400088EE                 ; if set -> new SecWfpEvaluateConditionComparison
```

When the flag is zero the loop dispatches exactly as the unpatched loop does (operator `0x102` → `SecWfpIsValueInRange`, `0x100` → `SecWfpIsIpV4MaskMatch`, `0x101` → skip, otherwise → `SecWfpAreValuesMatch`). When the flag is set, evaluation is routed through the new `SecWfpEvaluateConditionComparison` dispatcher, which supports additional operators the old path rejected (`0x101` previously returned `STATUS_NOT_SUPPORTED`): prefix match, suffix match, and SID-in-security-descriptor match. On a match it emits richer telemetry via `SecWfpAuditMatchedCondition` (which formats SIDs and security descriptors as strings using the newly resolved `SeConvertSecurityDescriptorToStringSecurityDescriptor`).

Because the old comparison path is retained verbatim for the default (flag == 0) case, this is a staged-rollout refactor, not a delivered security fix.

---

## 3. The reported OOB read is not fixed (present unchanged in both builds)

The prior hypothesis was that `SecWfpAreValuesEqual` reads a fixed number of bytes for `FWP_BYTE_ARRAY16` (type `0xb`) without validating a buffer size. That comparison code is **identical** in both builds, which by itself rules out a fix:

Unpatched `SecWfpAreValuesEqual` (`0x140007D9C`), type `0xb` handler:
```c
v27 = *(_QWORD **)(a1 + 8);      // incoming condition value pointer
v28 = *(_QWORD **)(a2 + 24);     // policy-entry value pointer
v29 = *v27 - *v28;               // read 8 bytes each side
if ( *v27 == *v28 )
    v29 = v27[1] - v28[1];       // read next 8 bytes each side
```

Patched `SecWfpAreSimpleTypesEqual` (`0x140007F78`), type `0xb` handler:
```c
v25 = *(_QWORD **)(a1 + 8);
v26 = *(_QWORD **)(a2 + 24);
v27 = *v25 - *v26;
if ( *v25 == *v26 )
    v27 = v25[1] - v26[1];
```

The two are the same instruction sequence (unpatched `0x140007F17`–`0x140007F2F`; patched `0x1400080BB`–`0x1400080D3`). The prior read is therefore not the target of any patch.

Additionally, the premise itself does not hold. `FWP_BYTE_ARRAY16` is a fixed-size 16-byte structure and `FWP_V4_ADDR_AND_MASK` is a fixed-size 8-byte structure; for these condition types the length is inherent to the data type, not carried in a separate attacker-chosen size field. The type-tag consistency check that gates these reads exists in **both** builds:

```
; unpatched SecWfpAreValuesEqual
0x140007DEF  cmp     r9d, [rdx+8]     ; incoming type == policy-entry type
0x140007DF3  jz      0x140007DFF      ; else STATUS_INVALID_PARAMETER
; patched SecWfpAreSimpleTypesEqual
0x140007F90  cmp     r9d, [rdx+8]
0x140007F94  jz      0x140007FA0
```

---

## 4. The new dispatcher adds type-tag checks, not buffer-size bounds

`SecWfpEvaluateConditionComparison` (`0x140008394`) switches on the operator field (`[rdx+0Ch]`) and, before delegating, checks the `FWP_DATA_TYPE` tag of both operands for the operators it newly supports:

```
; prefix match (operator 8)
0x1400084D0  cmp     dword ptr [rcx+8], 0Ch      ; both must be FWP_BYTE_BLOB
0x1400084D4  jnz     0x140008496                  ; else STATUS_INVALID_PARAMETER
0x1400084D6  cmp     dword ptr [rdx+8], 0Ch
; suffix match (operator 9) -- same 0xC/0xC check at 0x1400084A0
; SID-in-SD (operator 0xA)
0x140008474  cmp     dword ptr [rcx+8], 0Eh       ; FWP_SECURITY_DESCRIPTOR_TYPE
0x14000847A  cmp     dword ptr [rdx+8], 0Dh       ; FWP_SID
; IPv4 mask (operator 6)
0x14000842F  cmp     dword ptr [rcx], 100h
0x140008437  cmp     dword ptr [rdx+8], 3
```

These compare the data **type tag** (the same field checked at `0x140007DEF` above), not an allocation size. Equivalent type-tag checks are already present in the unpatched build for the operators it supports: `SecWfpIsIpV4MaskMatch` (`0x1400080B4`) already checks `cmp dword ptr [rdx+8], 3` at `0x1400080BE`, and `SecWfpIsValueInRange` (`0x1400080EC`) already checks `cmp dword ptr [rcx], 102h` at `0x140008115`. The new checks exist because the new operators (prefix/suffix/SID-in-SD) did not previously exist, not because an old check was missing.

---

## 5. Reachability / attack-surface reality

- The policy table (`SecWfpGuardPolicyConfig`) is installed only through IOCTL `0x222008`, and device access is restricted to LocalSystem (`SecDeviceOpen` → `KclIsProcessLocalSystem`). Both comparison operands — the installed policy pattern and the WFP filter condition being authorized — are therefore privileged inputs, not low-privilege attacker data.
- The config parser `SecSetWfpGuardConfiguration` performs the same input-buffer bounds validation in both builds (the series of `cmp … jbe/ja STATUS_INVALID_PARAMETER` checks bounding every parsed offset against the IOCTL input range) and allocates each condition's data buffer to exactly the declared size before `memmove`. The only difference between builds is a 4-byte shift of the per-entry data-pointer/size sub-fields (`[rbp+20h]`/`+8` → `[rbp+24h]`/`+4`) to accommodate the new rule-format fields; the entry stride remains `0x30` and the bounds checks are unchanged.
- The invocation path is the WFP filter-assignment authorization callout (`SecWfpShouldForbidFiltersAssignment`), reached when filters are added, not a per-packet network callout.

---

## 6. Exploit Primitive

None. The comparison code alleged to over-read is present, unchanged, in the patched build, so there is no delivered fix and nothing to weaponize. No arbitrary-read, info-leak, KASLR-bypass, or pool-grooming primitive is demonstrable from these binaries.

---

## 7. Debugger Notes

There is no fix to instrument. For orientation only, the relevant addresses in the patched build are: the new format gate at `0x1400088A6` in `SecWfpShouldEnforcePolicyOnFilterCondition`, and the new dispatcher entry `SecWfpEvaluateConditionComparison` at `0x140008394`. The IOCTL that installs policy is `0x222008`, dispatched by `SecDeviceIoControl` (`0x140007680`, comparison at `0x1400076B4`) to `SecSetWfpGuardConfiguration`.

---

## 8. Changed Functions — Full Triage

- **`SecWfpShouldEnforcePolicyOnFilterCondition` (`0x1400081C8` → `0x140008838`)** (feature staging): Adds the new format-flag branch (`cmp dword ptr [rdi+1Ch], 0`) that routes flagged policy entries through `SecWfpEvaluateConditionComparison` and logs via `SecWfpAuditMatchedCondition`. The unflagged path is the same dispatch as the unpatched build.
- **`SecWfpAreValuesEqual` (`0x140007D9C` → split into `SecWfpAreSimpleTypesEqual` `0x140007F78` + thin `SecWfpAreValuesEqual` `0x1400080F0`)** (refactor, no behavior change): The core type switch is relocated into `SecWfpAreSimpleTypesEqual` verbatim; the wrapper handles the security-descriptor and prefix/suffix operator special cases. The `FWP_BYTE_ARRAY16` read is unchanged.
- **`SecWfpAreValuesMatch` (`0x140007F78` → `0x140008188`)** (refactor): Relocated; still delegates to the value-equality routine with the same operator handling.
- **`SecWfpIsIpV4MaskMatch` (`0x1400080B4` → `0x14000871C`)** (behavioral, layout): The presence gate changed from a byte test at entry offset `0x0C` to a dword test at `0x0C` plus a byte test at the new `0x10`; the `type == 3` check and the mask compare are unchanged.
- **`SecWfpIsValueInRange` (`0x1400080EC` → `0x14000875C`)** (behavioral, layout): The presence-flag field moved from entry offset `0x0C` to `0x10`; the `0x102` type check, the equality/greater comparisons, and the existing `lfence` speculation barriers are unchanged.
- **`SecSetWfpGuardConfiguration` (`0x140007AAC` → `0x140007C88`)** (behavioral, layout): Same input-buffer bounds validation and per-entry allocation/copy; the per-entry data sub-field offsets shift by 4 bytes for the new rule format.
- **`SecInitializeGlobalData` (`0x14000778C` → `0x14000782C`)** (behavioral): Resolves the additional routine `SeConvertSecurityDescriptorToStringSecurityDescriptor` (used by the new SID/SD telemetry helpers) and updates version-check helper references.
- **`SecAuditWfpGuardBlock` (`0x140007000`, both)** (behavioral, telemetry): ETW UserData descriptor count grows from 8 to 14 to carry additional fields; a new length parameter is clamped to `0x400` (`cmp [rbp+arg_68], 0x400` / `cmovb`) before it is written into the driver's own event, bounding self-emitted telemetry.

---

## 9. Added / Removed Functions

- **Added (patched only):** `SecWfpEvaluateConditionComparison`, `SecWfpAreSimpleTypesEqual`, `SecWfpAuditMatchedCondition`, `SecWfpGetConditionSimpleValueInfo`, `SecWfpGetSecurityDescriptorAsUnicodeString`, `SecWfpGetSidAsUnicodeString`, `SecIsPrefixMatch`, `SecIsSuffixMatch`.
- **Removed (unpatched only):** `SecArePrefixBlobs` (superseded by `SecIsPrefixMatch` / `SecIsSuffixMatch`).

These additions implement the new prefix/suffix/SID-in-SD match operators and the associated audit telemetry that the offset-`0x1C` flag gates.

---

## 10. Confidence & Caveats

- **Confidence:** High that this is not a memory-safety fix. The comparison code alleged to over-read executes the identical read sequence in both builds, the new dispatcher's checks are data-type-tag checks (with equivalents already present in the old path), and the new validated path is reached only behind a per-policy-entry format flag with the old path retained for the default case.
- **Caveat:** The comparison operands both originate from privileged sources (a LocalSystem-only IOCTL-installed policy table and a WFP filter being authorized), so even the retained comparison code is not an attacker-controlled primitive.
