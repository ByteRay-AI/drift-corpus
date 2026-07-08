Title: mssecflt.sys — Use-after-free during process-context enumeration under shared lock (CWE-416) fixed
Date: 2026-06-29
Slug: mssecflt_d7e598a5-mssecflt-report-20260629-151630
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Medium
KBDate: 2026-03-10

### 1. Overview
- **Unpatched Binary:** `mssecflt_unpatched.sys`
- **Patched Binary:** `mssecflt_patched.sys`
- **Overall Similarity Score:** 0.9862
- **Diff Statistics:** 877 matched, 25 changed, 852 identical, 0 unmatched (in both directions).
- **Verdict:** The patch adds a reference-and-snapshot enumeration path to `SecEnumerateProcessContexts` that pins each process-context entry with a reference count and releases the shared push lock before invoking the per-entry callback. This removes a use-after-free / race window in which a callback (or a concurrent path) could free the entry that enumeration was still using. The new path is on by default; the old in-lock path is retained behind a registry-controlled feature bit.

---

### 2. Vulnerability Summary

#### Finding 1: Callback-Under-Shared-Lock Use-After-Free (Medium)
- **Vulnerability Class:** Use-After-Free / Race Condition (CWE-416, CWE-362, CWE-667)
- **Affected Function:** `SecEnumerateProcessContexts` (unpatched @ `0x14002CF04`)
- **Root Cause:** The unpatched code iterates the 128-bucket process-context hash table (`SecProcessTable`, buckets at `[SecProcessTable+0x140]`) while holding only a *shared* push lock (`FltAcquirePushLockSharedEx` on `SecProcessTable+8`). For each list node it computes the entry object at `node-0x10`, advances the next pointer, and invokes an indirect, CFG-dispatched callback (`__guard_dispatch_icall_fptr` on the pointer in `rax`, originally `rcx`) with the entry as the first argument. No reference is taken on the entry across the callback. If the callback (a per-process policy handler such as `SecApplyReadWriteTelemetryPolicyForProcess`, `SecApplyFileOpenMonitoringForProcess`, or `SecApplyTiLocalExecProtectVmForProcess`) drops the entry's last reference or otherwise triggers its teardown, the entry can be freed/recycled while enumeration continues to use it and its next pointer, producing a use-after-free.
- **The Fix:** The patched `SecEnumerateProcessContexts` (@ `0x14002CFC0`) adds a code path selected when `SecData+0x510` bit 0 is **clear**. On this path the function walks the table under the shared lock, calls `SecReferenceProcessContext` on every entry to pin it, stores the pinned entry pointers into a pool buffer sized from the entry count at `[SecProcessTable+0x148]` (tag `'Scce'`), releases the shared lock, and only *then* invokes the callback on each pinned entry, calling `SecReleaseProcessContext` after each. The old in-lock traversal is preserved and runs only when the bit is set.
- **Attacker-Reachable Entry Point:** The enumerator is invoked from the driver-configuration/policy-apply paths (`SecSetDriverConfiguration`) and from process create/exit and timer maintenance. The configuration path is reachable through the `\MicrosoftSecFilterControlPort` minifilter communication port via `SecMessage`, but sending policy-configuration messages to that port normally requires the privileged management service; an unprivileged attacker is not shown to reach it.
- **Data Flow (a reachable chain):**
  1. `SecMessage` (the port message handler) dispatches a configuration message to `SecSetDriverConfiguration`.
  2. `SecSetDriverConfiguration` applies policy and calls `SecEnumerateProcessContexts` with a per-process callback.
  3. `SecEnumerateProcessContexts` acquires the shared lock and, on the unpatched build, invokes the callback on each entry while the lock is held.

#### Finding 2: Timer/Notification-Driven Enumeration Race (Low)
- **Vulnerability Class:** Use-After-Free / Race Condition (CWE-416, CWE-362)
- **Affected Function:** `SecPerformProcessAssertionsForAllProcesses` (unpatched @ `0x14002DD1C`)
- **Root Cause:** Same in-lock-traversal shape as Finding 1. Under the shared `SecProcessTable` lock it iterates every bucket and, for each entry, calls `PsLookupProcessByProcessId` on the entry's process id (`[entry+0x20]`), then `SecDetPerformProcessAssertionsWithContext`, then `ObfDereferenceObject`, without pinning the entry across the work.
- **The Fix:** The patched version (@ `0x14002DF1C`) adds the same `SecData+0x510` bit-0 check; when the bit is clear (default) it delegates to `SecEnumerateProcessContexts` (the reference-and-snapshot path) instead of traversing under the lock. The old in-lock traversal is kept only when the bit is set.
- **Attacker-Reachable Entry Point:** Autonomous. Called from the timer-driven maintenance routine `SecDetTimerPerformDeferredAssertionsImpl` (@ `0x140042400`). Process creation/termination populates and mutates the same table, so the race is driven by process-lifetime activity rather than a direct user-mode request.

---

### 3. Pseudocode Diff

High-level logic of the unpatched `SecEnumerateProcessContexts` and its patched replacement, focusing on the traversal.

```c
// UNPATCHED: SecEnumerateProcessContexts @ 0x14002CF04
void SecEnumerateProcessContexts(callback_t callback, void* context) {
    if (!(SecData->flags_4f8 & 4)) return;          // not initialized

    FltAcquirePushLockSharedEx(SecProcessTable + 8, 0);   // SHARED lock

    for (bucket = 0; bucket < 0x80; bucket++) {
        node = SecProcessTable->buckets[bucket];    // [SecProcessTable+0x140]
        while (node != sentinel) {
            entry = node - 0x10;                    // process-context object
            node  = *node;                          // advance BEFORE callback
            callback(entry, context);               // *** callback WHILE lock held,
                                                    //     entry NOT reference-pinned ***
        }
    }

    FltReleasePushLockEx(SecProcessTable + 8, 0);
}

// PATCHED: SecEnumerateProcessContexts @ 0x14002CFC0
void SecEnumerateProcessContexts(callback_t callback, void* context) {
    if (!(SecData->flags_4f8 & 4)) return;

    FltAcquirePushLockSharedEx(SecProcessTable + 8, 0);

    if (SecData[0x510] & 1) {
        // Old in-lock path, retained; runs only when the feature bit is SET
        // ... same callback-under-shared-lock traversal ...
        FltReleasePushLockEx(SecProcessTable + 8, 0);
        return;
    }

    // Default path (feature bit CLEAR): reference + snapshot, then release, then call
    int count = SecProcessTable->entry_count;       // [SecProcessTable+0x148]
    if (count <= 0) { FltReleasePushLockEx(SecProcessTable + 8, 0); return; }

    void** snap = ExAllocatePoolWithTag(PagedPool, count * 8, 'Scce');
    if (!snap) { FltReleasePushLockEx(SecProcessTable + 8, 0); return; }

    int n = 0;
    for (bucket = 0; bucket < 0x80; bucket++) {
        node = SecProcessTable->buckets[bucket];
        while (node != sentinel) {
            entry = node - 0x10;
            SecReferenceProcessContext(entry);      // pin each entry
            snap[n++] = entry;
            node = *node;
        }
    }
    FltReleasePushLockEx(SecProcessTable + 8, 0);    // release BEFORE callbacks

    for (int i = 0; i < n; i++) {
        callback(snap[i], context);                 // safe: entries are pinned
        SecReleaseProcessContext(snap[i]);
    }
    SecFreePool(snap, 'Scce');
}
```

---

### 4. Assembly Analysis

Unpatched `SecEnumerateProcessContexts`, showing the callback invoked while the shared lock is held with no reference on the entry.

```assembly
; ---- SecEnumerateProcessContexts @ 0x14002CF04 (unpatched) ----
000000014002CF29  mov     r8d, [rax+4F8h]
000000014002CF30  test    r8b, 4                    ; initialization flag
000000014002CF34  jz      short loc_14002CFAF
000000014002CF36  mov     rcx, cs:SecProcessTable
000000014002CF3F  add     rcx, 8
000000014002CF43  call    FltAcquirePushLockSharedEx_0   ; SHARED lock — window opens
000000014002CF53  mov     ebp, 80h                  ; 128 buckets
000000014002CF58  mov     r8, [rax+140h]            ; bucket array base
000000014002CF5F  mov     rsi, [rbx+r8]             ; node = bucket head
000000014002CF65  lea     rcx, [rsi-10h]            ; entry = node-0x10 (arg1)
000000014002CF69  mov     rdx, r14                  ; context (arg2)
000000014002CF6C  mov     rsi, [rsi]                ; advance node = node->next
000000014002CF6F  mov     rax, r15                  ; callback pointer
000000014002CF72  call    cs:__guard_dispatch_icall_fptr ; callback(entry, context)
                                                    ; *** invoked under SHARED lock,
                                                    ;     entry not reference-pinned ***
000000014002CF78  mov     rax, cs:SecProcessTable
000000014002CF7F  mov     r8, [rax+140h]
000000014002CF86  lea     rax, [rdi+r8]
000000014002CF8A  cmp     rsi, rax
000000014002CF8D  jnz     short loc_14002CF65
000000014002CF97  sub     rbp, 1
000000014002CF9B  jnz     short loc_14002CF5F        ; next bucket
000000014002CFAA  call    FltReleasePushLockEx_0     ; window closes
```

The patched reference-and-snapshot path (default) collects and pins entries, then releases the lock before the callbacks:

```assembly
; ---- SecEnumerateProcessContexts @ 0x14002CFC0 (patched), snapshot path ----
000000014002D013  test    byte ptr cs:xmmword_14001B740+8, 1  ; SecData+0x510 bit 0
000000014002D01A  jz      short loc_14002D086        ; bit CLEAR -> snapshot path (default)
                                                     ; bit SET   -> old in-lock path
000000014002D08D  movsxd  rax, dword ptr [rcx+148h]  ; entry count
000000014002D0C9  call    cs:__imp_ExAllocatePoolWithTag     ; tag 'Scce' (65636353h)
000000014002D121  call    SecReferenceProcessContext ; pin each entry under lock
000000014002D12C  mov     [rsi+rax*8], rbx           ; store pinned entry in snapshot
000000014002D166  call    FltReleasePushLockEx_0      ; release BEFORE callbacks
000000014002D189  call    cs:__guard_dispatch_icall_fptr ; callback on pinned entry
000000014002D192  call    SecReleaseProcessContext   ; release reference
000000014002D1A9  call    SecFreePool                ; free snapshot buffer (tag 'Scce')
```

---

### 5. Trigger Conditions

For Finding 1 the following conditions must coincide:

1. The minifilter is loaded and the process-context table has entries (populated as processes are tracked via `SecCreateProcessContext`).
2. An enumeration is in progress: a policy/configuration apply (`SecSetDriverConfiguration` → `SecEnumerateProcessContexts`), a process create/exit notification, or timer maintenance drives a traversal that invokes callbacks on each entry.
3. Concurrently, the entry currently being enumerated has its last reference dropped — either by the callback itself or by a concurrent teardown (`SecCleanupProcessContexts`, which unlinks entries and releases them) — so the entry is freed or recycled to the process-context lookaside list while enumeration still holds a raw pointer to it.
4. The freed/recycled entry (or its stale next pointer) is then used by the callback or the following loop iteration.

Observable effect: a dereference of freed or recycled pool memory in kernel context. Depending on timing and pool state this manifests as a kernel bugcheck (denial of service); a controllable memory-corruption primitive is not demonstrated by the diff.

---

### 6. Impact Assessment

- **Primitive:** Kernel-pool use-after-free of a process-context object during shared-lock enumeration. The object is an internal, reference-counted structure managed by `SecReferenceProcessContext` / `SecReleaseProcessContext` and recycled through the process-context lookaside list at `SecProcessTable+0xC0`.
- **Demonstrable impact:** Loss of memory safety in kernel mode during enumeration — a potential denial of service (bugcheck) and, in principle, a local elevation-of-privilege surface if the freed allocation can be reclaimed with attacker-influenced contents. The reclamation and any control-flow or write primitive are not demonstrated by this diff and are not claimed here.
- **Why the fix matters:** By pinning every entry with a reference and moving all callbacks outside the lock, the patched path guarantees that no entry can be freed while a callback is operating on it, closing the window regardless of what the callback does.

---

### 7. Debugger Notes

For examination of the **unpatched** binary:

#### Breakpoints
```text
bp mssecflt_unpatched!SecEnumerateProcessContexts+0x3f   ; 0x14002cf43 FltAcquirePushLockSharedEx
bp mssecflt_unpatched!SecEnumerateProcessContexts+0x68   ; 0x14002cf6c mov rsi,[rsi] (advance)
bp mssecflt_unpatched!SecEnumerateProcessContexts+0x6e   ; 0x14002cf72 callback dispatch
bp mssecflt_unpatched!SecCleanupProcessContexts          ; 0x14002c3a4 entry teardown
```
*Why these matter:*
- `+0x3f` — acquisition of the shared lock; start of the enumeration window.
- `+0x68` — the next-pointer read; if `rsi` refers to freed/recycled pool the traversal is following a stale node.
- `+0x6e` — the CFG-dispatched callback on the entry at `rcx = node-0x10`; the entry is not reference-pinned here.
- `SecCleanupProcessContexts` — unlinks and releases process-context entries; if it runs concurrently and drops the last reference on the enumerated entry, the pointer held by the enumerator becomes stale.

#### Watch values
- `r15` (callback pointer) and `r14` (callback context) captured at entry.
- `r8` at `0x14002cf58` = bucket array base (`[SecProcessTable+0x140]`).
- `rsi` at `0x14002cf65` = current list node; `rcx` at `0x14002cf72` = entry object (`node-0x10`).
- `[SecData+0x4f8]` bit 2 = initialization flag gating the traversal.
- Patched only: `[SecProcessTable+0x148]` = entry count used to size the snapshot; `[SecData+0x510]` bit 0 = path selector (clear = snapshot, set = old path).

---

### 8. Changed Functions — Full Triage

**Security-relevant fixes:**
- `SecEnumerateProcessContexts` (unpatched `0x14002CF04` → patched `0x14002CFC0`, Sim 0.1295): adds the default reference-and-snapshot path (pin each entry, release the shared lock, then invoke callbacks and release references). Old in-lock callback path retained behind the `SecData+0x510` bit-0 feature bit.
- `SecPerformProcessAssertionsForAllProcesses` (unpatched `0x14002DD1C` → patched `0x14002DF1C`, Sim 0.8106): adds the same feature-bit check; delegates to `SecEnumerateProcessContexts` (snapshot path) when the bit is clear (default), old in-lock traversal retained when set.

**Supporting changes:**
- `SecCleanupProcessContexts` (`0x14002C3A4`, Sim 0.9898): decrements the entry count at `[SecProcessTable+0x148]` on removal, keeping the count the snapshot path uses for allocation sizing accurate.
- `SecCreateProcessContext` (`0x14002C550`, Sim 0.9923): increments the entry count at `[SecProcessTable+0x148]` on insertion; the insertion feature-flag test is updated (bit `2` → bit `4`).
- `SecInitializeBootConfig` / boot-config population (report-listed as `sub_140029EF0`, Sim 0.8862): extends the feature-flag block copied into `SecData+0x508` from a single 8-byte value to two 8-byte values (16 bytes, zero-initialized then optionally loaded from the `BootFeatureFlags` registry binary value), so the second qword — which holds the `SecData+0x510` bit-0 path selector — is now read.

**Feature-staging / servicing churn (not security fixes):**
- `sub_14003BC14` (Sim 0.6076): adds a `SeGetCachedSigningLevel` fast path gated by a feature bit in `xmmword_14001B740`, plus a speculation barrier before the second query. Feature-gated; old path retained.
- `sub_14003BA6C` (Sim 0.7844): adds a signing-level check path gated by `SecData+0x510` bit 2.
- `sub_14002F788` (Sim 0.9677): adds an early-exit path gated by `SecData+0x510` bit 4.
- `sub_140032D20` (Sim 0.8544): dispatch-table handlers now capture return values.
- `sub_14004054C` (Sim 0.9084): widens a feature-flag early-exit test (adds a bit-1 check).
- `sub_14003F6CC` (Sim 0.9438): adds a bit-1 feature check alongside the existing bit-0 check.
- `sub_14003F9DC` (Sim 0.9498): adds a bit-1 feature check; captures the argument into a register at entry.
- `sub_14003EBD8` (Sim 0.8815): adds a feature-gated early-return condition.
- `sub_140029EF0` behavioral extension is listed above under supporting changes.

**Cosmetic / relocation changes:**
- `sub_140024910`, `sub_1400393F8` (version string `0x3f` → `0x41`), `sub_14003C294` (feature-bit reordering), `SecMessage` (`0x140021CA0`), `SecSetDriverConfiguration` (`0x14003A814`, call targets updated to the patched enumerator), `sub_14000AC40`, `sub_14002CEA4`, `sub_140039F98` (feature-word store widened to a 128-bit write), `SecDetTimerPerformDeferredAssertionsImpl` (`0x140042400`, call target updated to the patched `SecPerformProcessAssertionsForAllProcesses`), `j_sub_14002f788`, and `sub_140029CE0` are address shifts, jump-thunk updates, and recompilation differences with no behavioral change.

---

### 9. Unmatched Functions
- **Removed:** None
- **Added:** None

---

### 10. Confidence & Caveats

- **Confidence:** High for the mechanism. The unpatched callback-under-shared-lock traversal and the patched reference-pin + snapshot + release-then-callback path are both present in the disassembly of `SecEnumerateProcessContexts`, and the same treatment applies to `SecPerformProcessAssertionsForAllProcesses`.
- **Direction:** The default (feature bit clear) path is the safe one; the old vulnerable path runs only when `SecData+0x510` bit 0 is set. The feature block is zero-initialized and then optionally overwritten from a registry binary value, so the safe path is the default and the old path is a registry-controlled fallback.
- **Caveats:**
  - The severity is bounded by demonstrable impact: a kernel-mode use-after-free/race during enumeration. Reclaiming the freed allocation with controlled contents, and any resulting control-flow or write primitive, are not demonstrated by the diff and are not claimed.
  - The policy-configuration entry point via `\MicrosoftSecFilterControlPort` normally requires the privileged management service; unprivileged reachability of that path is not established. The timer and process-notification paths (Finding 2) are autonomous and driven by process-lifetime activity.
