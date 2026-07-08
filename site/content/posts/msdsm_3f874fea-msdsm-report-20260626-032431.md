Title: msdsm.sys — toolchain rebuild; DsmInquire allocation/copy logic identical in both builds
Date: 2026-06-26
Slug: msdsm_3f874fea-msdsm-report-20260626-032431
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Unknown
KBDate: 2026-01-13

## 1. Overview

| Property | Value |
|---|---|
| Unpatched binary | `msdsm_unpatched.sys` |
| Patched binary | `msdsm_patched.sys` |
| Overall similarity | 0.8669 |
| Matched functions | 257 |
| Changed functions | 208 |
| Identical functions | 49 |
| Unmatched (either side) | 0 / 0 |

**Verdict:** No security-relevant change was delivered between these two builds. The difference is a full compiler/toolchain rebuild: the two binaries carry different WPP tracing GUIDs, Control Flow Guard / XFG dispatch thunks were added (`_guard_dispatch_icall`, `_guard_xfg_dispatch_icall_nop`), the TraceLogging provider metadata was regenerated (`_Tlg*` → `_tlg*`), and new CRT helper variants appear (`__cpu_features_init`, `__memset_*`). Every one of the ~208 changed functions is explained by register reallocation, basic-block reordering, and this tracing/toolchain churn. In particular, the `DsmInquire` allocation-size computation and inquiry-data copy are semantically identical in both builds, and both builds already contain the same wrap-around guard.

---

## 2. Vulnerability Summary

### Finding 1 — `DsmInquire` allocation-size computation: no security-relevant change

- **Severity:** None (informational)
- **Vulnerability class:** No security-relevant change
- **Affected function:** `msdsm!DsmInquire` (unpatched `0x1C0001870`, patched `0x140001890`)
- **Entry point:** MPIO DSM `DsmInquire` callback.

#### What actually changed

The only difference in the size-computation region is instruction selection:

- **Unpatched** computes the allocation size in two steps: `lea r13d, [rdx-0x28]` (size − 0x28, 32-bit) then `lea eax, [r13+0xf0]` (result truncated to 32-bit).
- **Patched** computes it in one step: `add eax, 0xc8`.

Both produce the same 32-bit value. Because the intermediate `r13d` is a 32-bit result that is truncated again by the second `lea`, the two-step sequence evaluates to `(size − 0x28 + 0xf0) mod 2^32 = (size + 0xc8) mod 2^32`, which is exactly what the single `add eax, 0xc8` produces. The zero-extension of `r13d` into `r13` does not change the low 32 bits that are actually used, so there is no "overflow masking" — the two forms are arithmetically equivalent for every input.

#### Why there is no overflow in either build

Both builds enforce the same three conditions before allocating and copying:

1. `size >= 0x28` (unpatched `cmp edx, 0x28; jnb`; patched `cmp eax, 0x28; jb error`).
2. Allocation size `= size + 0xc8`.
3. `size + 0xc8 >= 0xf0` (unpatched `cmp eax, 0xf0; cmovnb; jnb`; patched `cmp eax, 0xf0; jnb`). This comparison rejects any input where `size + 0xc8` wrapped past 2^32 to a small value, because a wrapped result is necessarily `< 0xf0`.

The subsequent `memmove` copies exactly `*(arg4 + 4) = size` bytes to `buffer + 0xc8`. Since the allocation is `size + 0xc8`, the copy ends exactly at the end of the allocation (`0xc8 + size`). The copy length equals `allocation − 0xc8` by construction in both builds, so no bytes are written past the block. The wrap guard present in **both** builds prevents the only case (`size` near `0xFFFFFFFF`) where the arithmetic could produce a small allocation.

There is therefore no undersized allocation, no oversized copy, and no attacker-reachable pool overflow in either build. The change is compiler code generation only.

---

## 3. Pseudocode Diff

```c
// ============================================================
// UNPATCHED — msdsm!DsmInquire (size region)
// ============================================================
size = *(arg4 + 4);                 // from SCSI INQUIRY
if (size < 0x28) goto error;        // cmp edx,0x28 / (fall-through path is the error)
alloc = (size - 0x28) + 0xf0;       // == size + 0xc8 (mod 2^32)
if (alloc < 0xf0) goto error;       // wrap-around rejected here
buf = DsmpAllocatePool(NonPagedPoolNx, alloc, 'ZZ05');
...
memmove(buf + 0xc8, arg4, *(arg4 + 4));   // copies exactly `size` bytes; fits (alloc - 0xc8 == size)

// ============================================================
// PATCHED — msdsm!DsmInquire (size region)
// ============================================================
size = *(arg4 + 4);
if (size < 0x28) goto error;
alloc = size + 0xc8;                // single 32-bit add; same value as unpatched
if (alloc < 0xf0) goto error;       // same wrap-around rejection
buf = DsmpAllocatePool(NonPagedPoolNx, alloc, 'ZZ05');
...
memmove(buf + 0xc8, arg4, *(arg4 + 4));   // identical copy
```

The lower-bound check (`size >= 0x28`), the allocation value (`size + 0xc8`), the wrap guard (`>= 0xf0`), and the copy (`memmove` of `size` bytes to `+0xc8`) are present and identical in both builds.

---

## 4. Assembly Analysis

### UNPATCHED size region (`0x1C0001F44`–`0x1C0002076`)

```asm
0x1C0001F44  mov     edx, [rsi+4]          ; edx = *(arg4+4) = size
0x1C0001F47  lea     r13d, [rdx-28h]       ; r13d = size - 0x28 (32-bit)
0x1C0001F4B  cmp     edx, 28h
0x1C0001F4E  jnb     0x1C0001FA3           ; size >= 0x28 -> continue (else error path)
0x1C0001FA3  lea     eax, [r13+0F0h]       ; eax = (size-0x28)+0xf0 = size+0xc8 (mod 2^32)
0x1C0001FAA  mov     edx, 0F0h
0x1C0001FAF  cmp     eax, edx
0x1C0001FB1  cmovnb  ecx, eax              ; if size+0xc8 >= 0xf0, ecx = size+0xc8
0x1C0001FB4  jnb     0x1C0001FE5           ; wrap-around (< 0xf0) falls through to error
0x1C0001FE5  mov     edx, ecx              ; Size = size+0xc8
0x1C0001FE7  mov     r8d, 35305A5Ah        ; Tag 'ZZ05'
0x1C0001FED  mov     ecx, 200h             ; PoolType (NonPagedPoolNx)
0x1C0001FF2  call    DsmpAllocatePool
...
0x1C0002054  lea     rbx, [rdi+0C8h]       ; copy destination = buf + 0xc8
0x1C000206C  mov     r8d, [rsi+4]          ; Size = *(arg4+4) = size
0x1C0002070  mov     rdx, rsi              ; Src = arg4
0x1C0002073  mov     rcx, rbx
0x1C0002076  call    memmove               ; copies `size` bytes; alloc - 0xc8 == size
```

### PATCHED size region (`0x140001F5A`–`0x14000206B`)

```asm
0x140001F5A  mov     eax, [rsi+4]          ; eax = size
0x140001F5D  cmp     eax, 28h
0x140001F60  jb      0x140001FB8           ; size < 0x28 -> error
0x140001F62  add     eax, 0C8h             ; eax = size + 0xc8 (single 32-bit add)
0x140001F67  cmp     eax, 0F0h
0x140001F6C  jnb     0x140001FE4           ; wrap-around (< 0xf0) -> error
0x140001FE4  mov     edx, eax              ; Size = size+0xc8
0x140001FE6  mov     ecx, 200h             ; PoolType (NonPagedPoolNx)
0x140001FEB  mov     r8d, 35305A5Ah        ; Tag 'ZZ05'
0x140001FF1  call    DsmpAllocatePool
...
0x140002049  lea     rbx, [rdi+0C8h]       ; copy destination = buf + 0xc8
0x140002061  mov     r8d, [rsi+4]          ; Size = size
0x140002065  mov     rdx, rsi              ; Src = arg4
0x140002068  mov     rcx, rbx
0x14000206B  call    memmove               ; identical copy
```

**Key takeaways from the diff:**

- The two-step `lea r13d, [rdx-0x28]` + `lea eax, [r13+0xf0]` and the single `add eax, 0xc8` compute the identical 32-bit value `size + 0xc8`.
- The `>= 0xf0` wrap-around guard exists in **both** builds (`cmp eax, 0xf0` at `0x1C0001FAF` and at `0x140001F67`).
- The `size >= 0x28` lower bound and the `memmove` of `size` bytes to `buf + 0xc8` are byte-for-byte equivalent in both builds.
- The remaining differences in the function (WPP GUID names, register choices such as `r13` vs `r12`/`r15`, and block ordering) are toolchain churn.

---

## 5. Trigger Conditions

Not applicable. Because both builds compute the same allocation size, enforce the same lower bound and the same wrap-around guard, and copy the same number of bytes into a buffer sized to hold them exactly, there is no state in which a crafted SCSI INQUIRY response causes a different (undersized) allocation in one build versus the other. No trigger produces memory corruption in either build via this path.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive exists. The allocation is `size + 0xc8` and the copy is `size` bytes at offset `0xc8`, so the write always ends exactly at the end of the allocation. The `size >= 0x28` and `size + 0xc8 >= 0xf0` checks are present in both builds, and the wrap-around case (`size` near `0xFFFFFFFF`) is rejected identically. There is no undersized allocation to overflow, hence nothing to groom, leak, or hijack.

---

## 7. Debugger PoC Playbook

Not applicable. There is no reproducible corruption to observe: the unpatched and patched `DsmInquire` size arithmetic, guards, and copy are equivalent. Setting breakpoints at the size read (`0x1C0001F44`), the guard (`0x1C0001FAF`), the allocation call, or the `memmove` (`0x1C0002076`) will show `allocation == size + 0xc8` and `copy length == size == allocation − 0xc8` for every accepted input, in both builds.

---

## 8. Changed Functions — Full Triage

### Security-relevant

None.

### No security-relevant change (examined in detail)

- **`DsmInquire`** (similarity 0.9226) — Size computation changed from two-step LEA (`lea r13d, [rdx-0x28]` + `lea eax, [r13+0xf0]`) to a single `add eax, 0xc8`. Both forms compute `size + 0xc8` and both carry the identical `cmp …, 0xf0; jnb` wrap guard and `size >= 0x28` lower bound; the `memmove` (`size` bytes to `buf + 0xc8`) is unchanged. The serial-number fallback path selection on the field at `arg4 + 0x18` is re-expressed with the same predicate (skip when the field is `0` or `0xFFFFFFFF`). Compiler code generation only.

- **`DsmpBuildDeviceNameLegacyPage0x80`** (similarity 0.8443) — The offset-field validation on the device-context fields (`+0xd4`, `+0xd8`, `+0xe0`) is re-expressed but semantically identical. Unpatched uses `lea eax, [rdx-1]; cmp eax, 0xFFFFFFFD; ja skip`; patched uses `test eax, eax; jz skip; cmp eax, 0xFFFFFFFF; jz skip`. Both accept the same value range and skip the strlen-style scan only when the field is `0` or `0xFFFFFFFF`. No bound was added or tightened. Compiler code generation only.

### Behavioral / cosmetic (tracing and codegen churn)

- **`DsmGlobalSetData`** (similarity 0.9411) — Register reallocation and WPP tracing GUID changes. Not security-relevant.
- **`DsmpSetLoadBalancePolicy`** (similarity 0.8288) — WPP tracing changes and codegen churn. No size-check or validation change identified. Not security-relevant.
- **`DsmpValidateSetLBPolicyInput`** (similarity 0.9397) — Register reallocation and stride-computation instruction selection (`mul` vs `shl`). Compiler artifacts.
- **`DsmpReportTargetPortGroups`** (similarity 0.724) — Register reallocation, basic-block reordering, and WPP GUID changes. No semantic change.

The remaining changed functions are the same class of churn: WPP tracing GUID regeneration, Control Flow Guard / XFG dispatch thunks (`_guard_dispatch_icall`, `_guard_xfg_dispatch_icall_nop`), regenerated TraceLogging provider metadata (`_Tlg*` → `_tlg*`), new CRT helper variants (`__cpu_features_init`, `__memset_*`), register reallocation, and block reordering. An independent function-by-function comparison of the external-data-parsing functions (`DsmpParseTargetPortGroupsInformation`, `DsmpBuildDeviceName`, `DsmpBuildHardwareId`, `DsmpUpdateTargetPortGroupEntry`, `DsmpBuildTargetPortGroupEntry`, `DsmpSetTargetPortGroups`, `DsmpPersistentReserveOut`, `DsmpPersistentReserveIn`, `DsmpPersistentReservationKeysRegister`, `DsmpFindSupportedDevice`, `RtlUnicodeStringCatString`) found the same allocation-size sources, the same copy-length guards, and the same accepted-range constants in both builds. No function adds or tightens a real bound on attacker-influenced data.

---

## 9. Unmatched Functions

Both `unmatched_unpatched` and `unmatched_patched` are **0** for matched-symbol accounting. The patched build additionally contains toolchain-provided helpers (`_guard_dispatch_icall`, `_guard_xfg_dispatch_icall_nop`, `__cpu_features_init`, `__memset_*` variants, and lowercase `_tlg*` TraceLogging stubs), and drops the corresponding uppercase `_Tlg*` and older WPP `WPP_SF_*` stub variants — consistent with a compiler/library upgrade rather than a code fix.

---

## 10. Confidence & Caveats

**Confidence: High that no security-relevant change was delivered.**

Rationale:

- The `DsmInquire` size arithmetic is arithmetically equivalent between builds: `(size − 0x28) + 0xf0` and `size + 0xc8` are the same value mod 2^32, and the low 32 bits are all that is used. The `>= 0xf0` wrap-around guard and the `>= 0x28` lower bound are present in both builds, and the `memmove` copies exactly `allocation − 0xc8` bytes, so no overflow is reachable in either build.
- The secondary `DsmpBuildDeviceNameLegacyPage0x80` offset check is the same predicate expressed with different instructions; no bound was added or removed.
- The whole-binary delta is dominated by WPP GUID regeneration, CFG/XFG additions, TraceLogging provider regeneration, and register/block churn — the signature of a toolchain rebuild, not a targeted security fix.

Caveats:

- This assessment covers the two supplied builds only. If a genuine `DsmInquire` fix exists, it is not present in this diff.
- Function matching was done by symbol name and by instruction content across relocations; the external-data-parsing functions were compared directly and showed no semantic bound changes.
