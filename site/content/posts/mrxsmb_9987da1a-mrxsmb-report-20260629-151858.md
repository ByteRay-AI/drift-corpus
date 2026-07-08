Title: mrxsmb.sys — connection-info parser refactor and alternative-port feature staging
Date: 2026-06-29
Slug: mrxsmb_9987da1a-mrxsmb-report-20260629-151858
Category: Corpus
Author: Argus
Summary: KB5077179
Severity: Unknown
KBDate: 2026-02-10

### 1. Overview

*   **Unpatched Binary:** `mrxsmb_unpatched.sys`
*   **Patched Binary:** `mrxsmb_patched.sys`
*   **Overall Similarity Score:** 0.9498
*   **Diff Statistics:** 1231 matched functions (1189 identical, 42 changed), 0 unmatched functions in either direction.
*   **Verdict:** No security-relevant change. The patch does not add or remove any bounds check, null check, integer-overflow guard, or access check on any reachable path. The change to `SmbCeInitializeConnectionInfo` is a control-flow/register restructuring with identical parsing semantics, plus staging of the `AlternativePort_Dcr` feature (byte-swapped alternate-port handling gated behind a feature flag, with the original code path retained). The earlier claim of an out-of-bounds read from a missing 64-bit pointer wraparound check is a false positive: the null-buffer guard and the wrap-to-zero loop termination are present in BOTH builds.

---

### 2. Analysis Summary

*   **Severity:** None (no security-relevant change)
*   **Class:** N/A — refactor and feature staging
*   **Affected Function:** `SmbCeInitializeConnectionInfo` (unpatched `0x140018FC0`, patched `0x140037410`)

**What was examined:**
`SmbCeInitializeConnectionInfo` parses a buffer of fixed-stride connection-info entries during SMB connection setup. It runs a first pass that counts entries and validates each entry's 32-bit size field, then allocates a pool array (`count * 0x138`) and a second pass that copies `0x98` bytes per entry into that array.

**Why there is no vulnerability change:**
Both builds walk the buffer with a pointer and track a 32-bit cumulative offset. Every iteration validates the entry size against the total buffer size (`arg3`, in `r8d`) with three 32-bit comparisons, and only advances if the new cumulative offset is still `<= arg3`. Because the cumulative offset is capped at `arg3` on every iteration, the walk pointer can advance at most `arg3` bytes past the start of the buffer; it cannot wrap the 64-bit address space. In addition, both builds terminate the loop if the walk pointer becomes zero. The unpatched build performs this wrap-to-zero test at the top of the loop (`test r9, r9`); the patched build performs the equivalent test immediately after advancing the pointer (`jnz` following `add r10, rcx`). These are the same check in a different location. The null-buffer entry guard is likewise present in both builds.

The only behavioral delta is in the second (copy) pass: the patched build adds a call to `Feature_Servicing_AlternativePort_Dcr__private_IsEnabledDeviceUsageNoInline`. When that feature flag is enabled, the port field is read from a different structure offset (`[rdi+0x354]`) and byte-swapped (`ror ax, 8`) for network order; when the flag is disabled, the original offset (`[rdi+0x2EA]`) path is taken unchanged. The IPv6 link-local test that the unpatched build performed via a call to `IN6_IS_ADDR_LINKLOCAL` is inlined in the patched build. Neither of these is a security boundary change.

---

### 3. Pseudocode Diff

The parsing logic is semantically identical. The difference is where the wrap-to-zero test sits and which registers hold the offset and walk pointer.

```c
// UNPATCHED first pass (0x140018FC0). Walk pointer = r9, offset = r10d, total = r8d.
while (true) {
    if (walk == NULL) break;                 // wrap-to-zero / null test at loop top
    if ((total - offset) < 4) return 0xC00000C3;
    uint32_t size = *(uint32_t*)walk;
    uint32_t chk  = size ? size : (total - offset);
    if (chk < 0x98) return 0xC00000C3;
    if (offset > total) return 0xC00000C3;
    if (chk    > total) return 0xC00000C3;
    offset = chk + offset;                    // 32-bit
    if (offset > total) return 0xC00000C3;    // offset capped at total every iteration
    count++;
    if (size == 0) { walk = NULL; continue; } // stop on zero size
    if (((size + 7) & ~7) != size) return 0xC00000C3;  // require 8-byte alignment
    walk += size;                             // advance; wrap-to-zero caught at loop top
    continue;
}

// PATCHED first pass (0x140037410). Walk pointer = r10, offset = r9d, total = r8d.
if (buf == NULL) goto allocate;               // null test at entry (same guard)
while (true) {
    if ((total - offset) < 4) return 0xC00000C3;
    uint32_t size = *(uint32_t*)walk;
    uint32_t chk  = size ? size : (total - offset);
    if (chk < 0x98) return 0xC00000C3;
    if (offset > total) return 0xC00000C3;
    if (chk    > total) return 0xC00000C3;
    offset = chk + offset;
    if (offset > total) return 0xC00000C3;
    count++;
    if (size == 0) break;
    if (((size + 7) & ~7) != size) return 0xC00000C3;
    walk += size;
    if (walk == 0) break;                     // wrap-to-zero caught right after advance
}
```

Both versions: (a) reject a null buffer before parsing, (b) validate each size against the total, (c) cap the cumulative offset at the total on every iteration, (d) require 8-byte alignment, and (e) stop the loop if the walk pointer becomes zero. Nothing about the safety of the walk changed.

---

### 4. Assembly Analysis

**Wrap-to-zero termination is present in the unpatched build.** After advancing the walk pointer, control returns to the loop top, which tests the pointer for zero:

```assembly
; UNPATCHED SmbCeInitializeConnectionInfo @ 0x140018FC0
0x1400191D5  add     r9, rdx              ; advance walk pointer by entry size
0x1400191D8  jmp     0x140018FE6          ; back to loop top
...
0x140018FE6  test    r9, r9               ; wrap-to-zero / null test
0x140018FE9  jnz     0x14001903D          ; if zero, fall through and stop parsing
```

**The patched build performs the equivalent test in place** (this is what the earlier report mislabeled as an added fix):

```assembly
; PATCHED SmbCeInitializeConnectionInfo @ 0x140037410
0x14003748B  add     r10, rcx             ; advance walk pointer by entry size
0x14003748E  jnz     0x140037440          ; if pointer became zero, exit loop
```

**The null-buffer guard is present in both builds.** In the unpatched build the initial walk pointer is the buffer argument (`mov r9, rdx`), so the same `test r9, r9` at `0x140018FE6` skips parsing when the buffer is null. In the patched build the equivalent test is hoisted to the function entry:

```assembly
; PATCHED entry
0x140037433  test    rdx, rdx             ; null buffer?
0x140037436  jz      0x14003749C          ; skip parse loop if null
```

**The 32-bit bounds checks are identical** (only the registers holding offset and walk pointer were renamed; unpatched `r10d`/`r9` become patched `r9d`/`r10`):

```assembly
; UNPATCHED                          ; PATCHED
0x14001905F  cmp  r10d, r8d          0x140037462  cmp  r9d, r8d
0x140019068  cmp  eax,  r8d          0x140037467  cmp  eax, r8d
0x140019078  cmp  ecx,  r8d          0x140037472  cmp  eax, r8d
```

**The actual behavioral change is the AlternativePort feature gate in the copy pass.** The patched build selects an alternate port offset with a byte swap when the feature is enabled, and otherwise takes the original offset used by the unpatched build:

```assembly
; PATCHED copy pass, type-2 branch
0x1400375A2  call    Feature_Servicing_AlternativePort_Dcr__private_IsEnabledDeviceUsageNoInline
0x1400375A7  test    eax, eax
0x1400375A9  jz      0x1400375C7          ; feature OFF -> original path
0x1400375AB  movzx   eax, word ptr [rdi+354h]  ; alternate port offset
0x1400375B2  ror     ax, 8                ; network byte order
0x1400375B6  mov     [r15+rbx*8+12h], ax
...
0x1400375C7  movzx   eax, word ptr [rdi+2EAh]  ; original offset (== unpatched)
0x1400375CE  mov     [r15+rbx*8+12h], ax
```

For comparison, the unpatched copy pass uses the same original offset unconditionally:

```assembly
; UNPATCHED copy pass, type-2 branch
0x140019129  movzx   eax, word ptr [rbx+2EAh]
0x140019130  mov     [r8+12h], ax
```

The IPv6 link-local test (type-`0x17` branch) is a `call IN6_IS_ADDR_LINKLOCAL` at `0x1400191FF` in the unpatched build and is inlined in the patched build (`cmp byte [r15+rbx*8+18h], 0FEh` / `and 0C0h` / `cmp 80h` at `0x14003760D`-`0x14003761D`). Same test, no boundary change.

---

### 5. Trigger Conditions

No security-relevant trigger exists. `SmbCeInitializeConnectionInfo` is reachable when a Windows client processes connection-info entries during SMB connection setup, but the parse loop enforces the same validation in both builds:

*   Each entry's size field must be `>= 0x98` and 8-byte aligned.
*   The cumulative offset is re-checked against the total buffer size (`arg3`) on every iteration and never allowed to exceed it, which bounds how far the walk pointer can advance.
*   The loop stops if the walk pointer becomes zero.

Because these checks are byte-for-byte equivalent across both builds, there is no crafted-input condition that behaves differently before and after the patch.

---

### 6. Exploit Primitive & Development Notes

*   **Primitive:** None. There is no memory-safety primitive introduced or removed by this patch.
*   **Why:** The claimed out-of-bounds read depended on the walk pointer wrapping the 64-bit address space with no termination check. In both builds the cumulative 32-bit offset is capped at the total buffer size every iteration, so the walk pointer stays within `[buffer, buffer + arg3]`, and both builds additionally terminate the loop on a zero walk pointer. The unpatched build is not weaker than the patched build here.
*   **Alternate-port feature:** The `AlternativePort_Dcr` staging changes which structure field supplies a port value and applies a byte swap when the feature flag is on. It does not read attacker-controlled lengths and does not affect the bounds of the copy.

---

### 7. Verification Notes

There is no vulnerability to reproduce. The following observations anchor the "no change" conclusion to the binaries:

*   Unpatched wrap-to-zero termination: `add r9, rdx` at `0x1400191D5` returns to `test r9, r9` at `0x140018FE6`.
*   Patched wrap-to-zero termination: `add r10, rcx` / `jnz` at `0x14003748B`-`0x14003748E`.
*   Unpatched null guard: `test r9, r9` at `0x140018FE6` with `r9 = rdx` (the buffer argument).
*   Patched null guard: `test rdx, rdx` / `jz` at `0x140037433`-`0x140037436`.
*   Per-iteration offset cap in both builds: `cmp <offset>, r8d; ja error` after computing the new offset (`0x140019078` unpatched, `0x140037472` patched).
*   Behavioral delta confined to the feature gate at `0x1400375A2` / `0x1400375E5` (patched only).

---

### 8. Changed Functions — Full Triage

*   **`SmbCeInitializeConnectionInfo`** (unpatched `0x140018FC0`, patched `0x140037410`)
    *   *Change:* Not security-relevant. Parse loop restructured (loop-top wrap-to-zero test moved to a post-advance `jnz`; offset/walk registers renamed) with identical validation semantics. The behavioral addition is the `AlternativePort_Dcr` feature gate in the copy pass (alternate port offset `0x354` with `ror` byte swap when enabled; original offset `0x2EA` path retained when disabled) and inlining of the IPv6 link-local test.
*   **`SmbCeFindSessionEntry`** (unpatched `0x140008700`, patched `0x1400334F0`)
    *   *Change:* Behavioral, not a security boundary change. Adds `ExBlockOnAddressPushLock`-based waiting on session-entry lifecycle flags (session init / invalidation in progress). The `SeAccessCheck` call is present in the unpatched build already (at `0x140059BBB` inside this function) and is unchanged; it was not added by the patch. The patched build also retains an `SmbCeFindSessionEntry_Old` copy (feature-staging leftover) that contains its own `SeAccessCheck`, which accounts for the raw call-count difference.
*   **`MRxSmbProcessClientMoveNotification`**
    *   *Change:* Behavioral. Adds a byte-swap (`ror`) for SMB2 dialect port/endpoint fields, gated on the SMB2-dialect check. Endian handling, not a security boundary change.
*   **`MRxSmbValidateAndGetTransportParameters`**
    *   *Change:* Behavioral. Adds a mode parameter to separate validation from storage of transport parameters; the patched build retains an `MRxSmbValidateAndGetTransportParameters_Old` copy. Feature staging, not a security fix.
*   **`sub_14001A320 / sub_140033EE0`**
    *   *Change:* Behavioral. Expanded for multichannel/dialect handling with push-lock synchronization and additional pool allocations. Entry counts feeding the size computations are capped at `0x40` by `SmbCeInitializeConnectionInfo` before this function is reached; no unbounded attacker-controlled multiplier is introduced.
*   **`sub_140009D00 / sub_14002C160`**
    *   *Change:* Refactor. Session reconnection/credential-refresh logic restructured. No security check added or removed.
*   **`RxCeEstablishConnection`**
    *   *Change:* Refactor. Split into helper subroutines (with a retained `RxCeEstablishConnection_Old` copy). The array-bounds check that guarded the transport lookup in the unpatched build is preserved verbatim in the patched helper. No security check added or removed.

---

### 9. Unmatched / Added Functions

The similarity tool reported 0 unmatched functions because it folded the new routines into its matched set, but the patched build does introduce feature-staging support code that has no counterpart in the unpatched build: the `AlternativePort_Dcr` port helpers (effective-port computation and port-scope lookup/insert/remove), the WIL feature-flag accessors (`Feature_Servicing_AlternativePort_Dcr__private_IsEnabled*` and related `wil_*` helpers), and retained `_Old` copies of several functions (`SmbCeFindSessionEntry_Old`, `MRxSmbValidateAndGetTransportParameters_Old`, `RxCeEstablishConnection_Old`, and others). These are the mechanical footprint of staged feature rollout, not new security routines.

---

### 10. Confidence & Caveats

*   **Confidence:** High. The null-buffer guard, the wrap-to-zero loop termination, and all three 32-bit bounds comparisons are present in both builds; only their register assignment and control-flow placement changed. The single behavioral difference in the parser is the `AlternativePort_Dcr` feature gate with the original code path retained.
*   **Conclusion:** The reported out-of-bounds read / integer-overflow finding does not hold. The patch is dominated by the `AlternativePort_Dcr` feature staging plus refactoring and does not deliver a security fix in this diff.
