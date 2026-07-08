Title: ipfltdrv.sys — No security-relevant change (recompilation: register allocation and basic-block scheduling)
Date: 2026-06-29
Slug: ipfltdrv_52b4de3d-ipfltdrv-report-20260629-000502
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: None
KBDate: 2026-03-10

### 1. Overview

* **Unpatched Binary:** `ipfltdrv_unpatched.sys`
* **Patched Binary:** `ipfltdrv_patched.sys`
* **Overall Similarity Score:** 0.9875 (98.75%)
* **Diff Statistics:**
  * Matched Functions: 166
  * Changed Functions: 2
  * Identical Functions: 164
  * Unmatched Functions (Unpatched/Patched): 0 / 0
* **Verdict:** No security-relevant change. The two functions flagged as changed (`MatchFilterp` at `0x1C00010D0` and `MatchV6Filter` at `0x1C00074F0`) differ only in register allocation, basic-block ordering, and local stack-slot naming. These are artifacts of recompilation. Every reference-counting, null-check, and list-management instruction is present identically in both builds.

### 2. Assessment of the Reference-Count Imbalance Hypothesis

The change in `MatchFilterp` was initially examined as a possible reference-count imbalance leading to Use-After-Free. Direct comparison of both builds refutes this. The reference count at object offset `+0x10` is incremented and decremented the same way in both binaries:

* The claimed "missing" decrement `lock dec dword ptr [rbx+10h]` is present in the **unpatched** build. It appears 14 times in the unpatched function versus 13 times in the patched function (the patched build has one fewer, not one more, due to two exit paths being merged into a shared tail during recompilation).
* At the specific location the finding pointed to (around `0x1C00016BA`), both builds decrement the reference count:
  * Unpatched: `0x1C00016C3  lock dec dword ptr [rbx+10h]`
  * Patched:   `0x1C00016BA  lock dec dword ptr [rbx+10h]`
* The reference-count increment is likewise present in both:
  * Unpatched: `0x1C00013F3  lock inc dword ptr [rbx+10h]`
  * Patched:   `0x1C00013F3  lock inc dword ptr [rcx+10h]` (same instruction; the base register was renamed `rbx`→`rcx` by the register allocator).

The other instructions described as "added by the patch" are also present in both builds:

* `test r14, r14` (the reverse-direction context null check): 4 occurrences in each build.
* `mov qword ptr [rbx+38h], r14` (storing the reverse-direction context): identical set of writes in both builds — unpatched at `0x1C0008D60`, `0x1C0008F00`, `0x1C000906C`; patched at `0x1C0008D84`, `0x1C0008F24`, `0x1C00090A2` (same code, relocated by the surrounding layout shift).
* The interlocked list management and the call into `LookForFilter` (`0x1C0001CA8` unpatched / `0x1C0001C8C` patched) exist in both builds.

Acquire/release balance of the NDIS read/write lock is unchanged: both builds acquire the lock twice (`NdisAcquireReadWriteLock`) and release it along every exit path. The patched build shows 19 release sites versus 18 in the unpatched build; this is one duplicated exit tail produced by basic-block re-layout, not an added lock release. In the unpatched build several exits reach a shared release tail via `jmp loc_1C0008A97`; the patched build inlines that tail in one additional place.

### 3. What Actually Changed

The differences between the two versions of `MatchFilterp` are limited to:

* **Register allocation.** Whole-function register swaps such as `r12`↔`r15`, `r9`↔`r11`, and `rsi`↔`r12`. For example, the unpatched `xor r15d, r15d` (zero accumulator) becomes `xor r12d, r12d`; the same value is then used everywhere the other register was used.
* **Basic-block scheduling.** Exit and lock-release tails are emitted in a different order and occasionally duplicated or merged, changing jump targets and the count of otherwise-identical instructions.
* **Local stack-slot naming.** The same local is referenced as `var_18` in one build and `var_8` in the other (e.g. `mov dword ptr [rbp+var_18], eax` vs `mov dword ptr [rbp+var_8], eax`), with no change to what is stored.

None of these alter control flow, data flow, bounds, reference counting, or reachable behavior.

### 4. Changed Functions — Full Triage

* **`MatchFilterp`** (`0x1C00010D0`, Similarity: 0.966)
  * **Change Type:** Non-security (recompilation).
  * **Note:** Packet/filter matching routine. The reference-count increments and decrements at object offset `+0x10`, the `test r14, r14` null checks, the `mov [rbx+0x38], r14` context stores, the interlocked list operations, and the NDIS lock acquire/release pairs are all present in both builds. The diff is register allocation, basic-block scheduling, and stack-slot renaming.
* **`MatchV6Filter`** (`0x1C00074F0`, Similarity: 0.9929)
  * **Change Type:** Non-security (recompilation ripple).
  * **Note:** No semantic change. Call and jump targets shifted by a small constant as a side effect of the layout change in the preceding code. Logic is identical.

### 5. Unmatched Functions

There were no unmatched functions added or removed in this patch diff. All changes are contained within the existing function graph.

### 6. Confidence & Caveats

* **Confidence Level:** High. Every instruction described as "missing in unpatched / added in patched" was located, present, in the unpatched build at a concrete address. The reference-count decrement, the null check, and the context store are all present in both builds.
* **Conclusion:** The patch delivers no security-relevant change to `ipfltdrv.sys` in the analyzed functions. The two changed functions are recompilation artifacts (register allocation and basic-block scheduling). No Use-After-Free, reference-count imbalance, or lock-leak is introduced or removed.
