Title: nwifi.sys — No security-relevant change (WIL feature-usage reporting cache dedup guard)
Date: 2026-07-03
Slug: nwifi_e4f5b8cd-nwifi-report-20260703-213713
Category: Corpus
Author: Argus
Summary: KB5075912

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `nwifi_unpatched.sys` |
| Patched binary | `nwifi_patched.sys` |
| Overall similarity | 0.9928 |
| Matched functions | 1336 |
| Changed functions | **1** (`wil_details_FeatureReporting_RecordUsageInCache`, sim 0.981) |
| Identical functions | 1335 |
| Unmatched (added/removed) | 0 / 0 |

**Verdict:** The patch adds a single two-instruction guard (`cmp dword ptr [r11+10h], 0` / `jnz`) at `0x1C0002567` inside `wil_details_FeatureReporting_RecordUsageInCache`, a Windows Implementation Library (WIL) feature-usage telemetry routine. The guard suppresses the rewrite of an output usage-record when the value being recorded was already present in the feature-usage cache. The affected shared word is the WIL feature-staging variable `Feature_H2E_WPA3SAE__private_reporting`, and the only consumer is the WIL usage-reporting path (`wil_details_FeatureReporting_ReportUsageToServiceDirect`, which forwards to `g_wil_details_recordFeatureUsage` and `RtlNotifyFeatureUsage`). This is feature-usage telemetry bookkeeping. It is not attacker-reachable, involves no memory-safety operation, and carries no demonstrable security impact. **No security-relevant change.**

---

## 2. Change Summary

### Finding #1 — Feature-usage cache dedup guard in `wil_details_FeatureReporting_RecordUsageInCache`

- **Severity:** None (no security-relevant change)
- **Change class:** WIL feature-usage telemetry cache bookkeeping; output-record write suppressed when the value was already cached.
- **Affected function:** `wil_details_FeatureReporting_RecordUsageInCache` @ `0x1C000243C`. Direct caller: `wil_details_FeatureReporting_ReportUsageToServiceDirect` @ `0x1C0002708`.
- **Entry point:** Internal WIL feature-usage reporting. Invoked when nwifi code records usage of the WPA3-SAE Hash-to-Element (H2E) feature via WIL; the caller forwards the result to the WIL usage callback and `RtlNotifyFeatureUsage`. This is telemetry/feature-staging infrastructure, not an NDIS OID or 802.11 frame-parsing path.

#### What the function does

`wil_details_FeatureReporting_RecordUsageInCache(a1, a2, a3, a4)` records a feature-usage event into an in-memory cache word and produces an output "usage record" for the caller to forward:

- `a1` — pointer to a 0x18-byte output usage record on the caller's stack. It is zero-initialized at function entry in **both** builds (`*(_OWORD *)a1 = 0; *(_QWORD *)(a1+16) = 0;`).
- `a2` — pointer to the WIL feature-reporting state word. At the observed call site this is `&Feature_H2E_WPA3SAE__private_reporting`.
- `a3` — the WIL reporting-kind selector (enum). Distinct value bands select different bookkeeping branches; the band `[0x140, 0x17F]` selects the branch that atomically updates `*(a2+4)`.
- `a4` — an auxiliary reporting parameter.

For `a3` in `[0x140, 0x17F]`, a compare-and-swap loop (`lock cmpxchg [rdi+4], edx`) atomically folds the reporting value into `*(a2+4)` and writes into `a1[4]` (offset `+0x10`) a flag indicating whether that value was *already* present in the cache.

#### What actually changed

**Unpatched:** after the CAS loop, the function unconditionally writes three output fields:

```
a1[+0x08] = a3    ; the reporting value
a1[+0x04] = 1
a1[+0x0C] = a4
```

**Patched:** the same three writes are guarded so they are skipped when `a1[+0x10] != 0` (value already in cache):

```c
if (a1[+0x10] == 0) {   // only when this usage was NOT already recorded
    a1[+0x08] = a3;
    a1[+0x04] = 1;
    a1[+0x0C] = a4;
}
```

The caller reads back `a1[+0x10]` (`v12`) and returns `(_DWORD)v12 == 0`, i.e. "was this a new usage record". The record fields are handed to the WIL usage callback `g_wil_details_recordFeatureUsage`. The net effect of the guard is that an already-cached (duplicate) usage event no longer restamps the forwarded record with a fresh value/index; it leaves the zero-initialized record intact so the caller reports "already recorded". This is a telemetry-accuracy / deduplication refinement.

#### Why this is not a security issue

- **No memory-safety operation.** The three writes target a fixed-size, caller-zero-initialized 0x18-byte stack struct at fixed offsets. There is no attacker-controlled length, no index computed from input, and no out-of-bounds access in either build. The guard adds a branch; it does not add or remove a bounds check.
- **Not attacker-reachable as a security primitive.** The routine is part of WIL feature-usage reporting for the `Feature_H2E_WPA3SAE` staging flag. It is driven by WIL's own usage-recording machinery (feature-staging / telemetry), not by 802.11 frame parsing or NDIS OID buffers. The output record feeds `g_wil_details_recordFeatureUsage` and `RtlNotifyFeatureUsage`, both telemetry sinks.
- **No state-machine corruption of security relevance.** The "state" involved is a WIL feature-usage cache word, not radio/PHY/channel state. The caller consumes only the "new vs. already-recorded" flag and the record for telemetry; nothing in the observed consumer path makes a security-relevant decision from the restamped fields.

Consistent with common servicing categories, WIL feature-staging / feature-usage-reporting changes are not security fixes.

---

## 3. Pseudocode Diff

### `wil_details_FeatureReporting_RecordUsageInCache` — reporting-kind band `[0x140, 0x17F]`

```c
// === UNPATCHED ===
// a2 = &Feature_H2E_WPA3SAE__private_reporting (WIL feature-usage state)
*(_OWORD *)a1 = 0;              // zero the 0x18-byte output usage record
*(_QWORD *)(a1 + 16) = 0;
...
// a3 - 0x140 in [0, 0x40): CAS loop folds the value into *(a2+4)
//   and sets a1[+0x10] = "value already present in cache"
do {
    old = *(a2 + 4);
    a1[+0x10] = (already_present ? 1 : 0);
    nx  = (old & 0xFFFFF81F) | bits | 0x10;
} while (InterlockedCompareExchange((a2+4), nx, old) != old);

// unconditional restamp of the forwarded record:
a1[+0x08] = a3;
a1[+0x04] = 1;
a1[+0x0C] = a4;
return;

// === PATCHED ===
//   ... identical up to and including the CAS loop ...

// restamp only when this usage was NOT already recorded:
if (a1[+0x10] == 0) {
    a1[+0x08] = a3;
    a1[+0x04] = 1;
    a1[+0x0C] = a4;
}
return;
```

---

## 4. Assembly Analysis

Instruction text is transcribed from the authoritative disassembly (address + mnemonic, as it appears there).

### CAS loop and the changed site — unpatched (`0x1C000243C`)

```asm
00000001C000254D  xor     edx, edx
00000001C000254F  mov     [r11+10h], edx            ; a1[+0x10] = already-present flag
00000001C0002553  mov     edx, eax
00000001C0002555  and     edx, 0FFFFF81Fh
00000001C000255B  or      edx, r9d
00000001C000255E  or      edx, ecx
00000001C0002560  lock cmpxchg [rdi+4], edx         ; atomic update of *(a2+4)
00000001C0002565  jnz     short loc_1C0002538       ; retry
; --- unconditional restamp (no guard on a1[+0x10]) ---
00000001C0002567  mov     [r11+8], r10d             ; a1[+0x08] = a3
00000001C000256B  mov     [r11+4], ebx              ; a1[+0x04] = 1
00000001C000256F  mov     [r11+0Ch], esi            ; a1[+0x0C] = a4
00000001C0002573  jmp     loc_1C00026E9             ; return
```

### Same site — patched, with the guard

```asm
00000001C0002560  lock cmpxchg [rdi+4], edx
00000001C0002565  jnz     short loc_1C0002538
00000001C0002567  cmp     dword ptr [r11+10h], 0    ; a1[+0x10] != 0 (already cached)?
00000001C000256C  jnz     loc_1C00026F4             ; if so, skip the restamp
00000001C0002572  mov     [r11+8], r10d             ; a1[+0x08] = a3   (guarded)
00000001C0002576  mov     [r11+4], ebx              ; a1[+0x04] = 1    (guarded)
00000001C000257A  mov     [r11+0Ch], esi            ; a1[+0x0C] = a4   (guarded)
00000001C000257E  jmp     loc_1C00026F4             ; return
```

### Function entry and dispatch context (unpatched)

```asm
00000001C000243C  mov     rax, rsp
00000001C000243F  mov     [rax+8], rbx
00000001C0002443  mov     [rax+10h], rsi
00000001C0002447  mov     [rax+18h], rdi
00000001C000244B  mov     [rax+20h], r15
00000001C000244F  xor     eax, eax
00000001C0002451  xorps   xmm0, xmm0
00000001C0002454  mov     esi, r9d                  ; esi = a4
00000001C0002457  mov     r10d, r8d                 ; r10d = a3 (reporting-kind selector)
00000001C000245A  mov     rdi, rdx                  ; rdi = a2 (feature-usage state ptr)
00000001C000245D  mov     r11, rcx                  ; r11 = a1 (output record ptr)
00000001C0002460  movups  xmmword ptr [rcx], xmm0   ; zero a1[0..0x0F]
00000001C0002463  mov     [rcx+10h], rax            ; zero a1[0x10..0x17]
00000001C0002467  lea     ebx, [rax+1]              ; ebx = 1
00000001C000246A  test    r8d, r8d                  ; a3 == 0?
00000001C000246D  jz      loc_1C0002627
...
00000001C0002518  add     r8d, 0FFFFFEC0h           ; r8d = a3 - 0x140
00000001C000251F  cmp     r8d, 40h                  ; a3 in [0x140, 0x180)?
00000001C0002523  jnb     short loc_1C0002567       ; out of band -> skip CAS, reach the writes
```

Key observations:

- The output record `a1` is zero-initialized at entry in both builds; the caller (`wil_details_FeatureReporting_ReportUsageToServiceDirect`) always passes a fresh stack buffer. There is no uninitialized-read or info-leak angle.
- The changed writes are to fixed offsets of that fixed-size buffer. No bounds check exists or was added; the delta is purely the `cmp`/`jnz` dedup branch.
- The out-of-band path (`0x1C0002523 jnb`) also lands on the write site; in that path `a1[+0x10]` is zero, so the new guard is a no-op there.

---

## 5. Trigger Conditions

There is no security condition to trigger. For completeness, the code-level condition under which the two builds diverge is:

- `a3` (the WIL reporting-kind selector) lies in `[0x140, 0x17F]`, **and**
- the same reporting value is already present in the feature-usage cache word `*(&Feature_H2E_WPA3SAE__private_reporting + 4)`, so the CAS loop sets `a1[+0x10] != 0`.

In that case the unpatched build restamps the forwarded telemetry record while the patched build leaves it zeroed. Both behaviors operate entirely on a caller-provided, zero-initialized 0x18-byte stack buffer and a WIL feature-usage cache word. Neither is driven by attacker-controlled 802.11 frame data or NDIS OID buffer contents, and neither performs an out-of-bounds access.

---

## 6. Impact Assessment

- **Memory safety:** None. No overflow, OOB, or uninitialized use in either build.
- **Information disclosure:** None. The output buffer is zero-initialized by the caller in both builds.
- **State/logic:** The only observable difference is whether a duplicate feature-usage event restamps its telemetry record. This affects WIL usage reporting fidelity, not any security-relevant driver decision. `RtlNotifyFeatureUsage` invocation in the caller depends on the feature-enable flags (`v3 & 0x400`, `v3 & 0x800`), not on the restamped fields.
- **Reachability as a primitive:** None demonstrated. The routine is WIL feature-staging/telemetry infrastructure.

No exploit primitive exists. Claims of denial of service, channel misconfiguration, out-of-bounds follow-ons, KASLR/pool-spray, or BSOD are not supported by the binaries and are not made.

---

## 7. Verification Notes

- The change was localized by a normalized whole-binary comparison (addresses and relocation-dependent labels canonicalized). The **only** difference across the entire disassembly is the two added instructions at `0x1C0002567` (`cmp dword ptr [r11+10h], 0` and `jnz loc_1C00026F4`). No other function differs; the report's "1 changed / 0 added / 0 removed" tally is confirmed independently, and no omitted security-relevant change exists.
- Function identity confirmed from the disassembly symbol `wil_details_FeatureReporting_RecordUsageInCache @ 0x1C000243C` and decompilation, and the caller symbol `wil_details_FeatureReporting_ReportUsageToServiceDirect @ 0x1C0002708`, whose `a2` argument is `&Feature_H2E_WPA3SAE__private_reporting`.
- Direction confirmed: the patched build is the one that adds the guard (skips the writes). The change is present only in the patched build.

---

## 8. Changed Functions — Full Triage

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `wil_details_FeatureReporting_RecordUsageInCache` @ `0x1C000243C` | 0.981 | Not security-relevant (WIL telemetry) | Two-instruction guard (`cmp [r11+10h],0 / jnz`) added at `0x1C0002567`, suppressing the restamp of the forwarded feature-usage record when the value was already present in the WIL feature-usage cache. All register allocation, control flow, and CAS-loop semantics are otherwise unchanged. |

No other functions changed. The independent normalized diff found exactly the two added instructions above and nothing else.

---

## 9. Unmatched Functions

| Removed | Added |
|---|---|
| (none) | (none) |

No sanitizers or mitigation helpers were added or removed. The delta is a single localized WIL feature-usage-cache guard.

---

## 10. Confidence & Caveats

**Confidence: High.**

- The diff is unambiguous: exactly one function changed, and the change is the two-instruction dedup guard at `0x1C0002567`.
- Every other instruction across both builds matches after canonicalizing addresses/relocation labels.
- The function and its caller carry real WIL feature-reporting symbols, and the state operand is the `Feature_H2E_WPA3SAE` feature-staging variable, placing this change squarely in feature-usage telemetry bookkeeping rather than any 802.11 or NDIS security path.

**Bottom line:** This is a WIL feature-usage reporting cache deduplication refinement. It is not a memory-safety fix, not attacker-reachable as a security primitive, and carries no demonstrable security impact. No CWE applies. Severity: none.
