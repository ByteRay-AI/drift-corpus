Title: ataport.sys — Use-after-free fix in `IdePortTickHandler`: periodic tick now holds the device remove lock (plus an unrelated ATA error-retry refactor)
Date: 2026-06-28
Slug: ataport_4c92ca01-ataport-report-20260628-170736
Category: Corpus
Author: Argus
Summary: KB5082142
Severity: Medium

## 1. Overview

| | |
|---|---|
| **Unpatched binary** | `ataport_unpatched.sys` |
| **Patched binary** | `ataport_patched.sys` |
| **Overall similarity** | 0.6819 |
| **Matched functions** | 550 |
| **Changed functions** | 328 |
| **Identical functions** | 222 |
| **Unmatched (unpatched → patched)** | 0 / 0 |

**Verdict:** The patch contains one real security fix plus one non-security refactor.

1. **Security fix (CWE-416, use-after-free) — see Section 11.** The periodic timer DPC `IdePortTickHandler` was rewritten to acquire the per-device `IO_REMOVE_LOCK` (at device-extension `+0xB0`) before touching the device (timeout-counter update, target reset, channel reset), and to skip the device if that acquisition fails. The **unpatched** `IdePortTickHandler` performed the same per-device work with **no** `IoAcquireRemoveLockEx`/`IoReleaseRemoveLockEx` anywhere in its body — it relied only on the driver's own `RefNextPdoExtensionWithTag`/`UnRefPdoExtensionWithTag` tag counter. Device teardown (`RemovePdoExtension`) synchronizes with concurrent users **only** through `IoReleaseRemoveLockAndWaitEx` on that same `+0xB0` remove lock, not through the tag counter, so a PnP remove concurrent with a tick could free the device extension while the tick handler still used it. The patch closes that window.

2. **Non-security refactor (unchanged conclusion) — Sections 2–10.** The delta in the ATA request-completion area is a code refactoring, not a security fix. The per-retry state-reset block that clears a set of per-attempt request fields and bumps the retry counter was **already present in the unpatched build** (inline in three different functions). The patch factors that identical block into a single shared helper, `PrepareCrbForRetry (sub_1C000C700)`, and inlines the separate error-interpretation routine `IdepInterpretTransportErrors (sub_1C0004A3C)` into the completion routine `IdeProcessCompletedRequests`. The reset runs on the error/retry path in both builds. No field is left stale in one build and cleared in the other, and no attacker-controlled value reaches a size/transfer decision through these fields.

---

## 2. Change Summary

**Severity:** None (no security-relevant behavioral change).
**Vulnerability class:** None. The change is an extract-helper plus inline-callee refactor of ATA transport-error retry handling.
**Primary changed function:** `IdeProcessCompletedRequests` — unpatched `sub_1C000D8D0`, patched `sub_1C00036A0`.
**New helper:** `PrepareCrbForRetry (sub_1C000C700)` (patched only), which contains logic that existed inline in the unpatched build.

### What actually changed

Two mechanical transformations account for the size growth of the patched completion routine (similarity 0.5168):

1. **Extract-helper.** The unpatched build has an identical per-retry reset block — zero `+0x3EB`, `+0x3F3`, `+0x428`, `+0x420`, `+0x3EA`, `+0x410`; conditionally increment the retry counter at `+0x23` (only if it is `< 1`); clear `+0x28` — copied inline in three functions:
   - `IdepInterpretTransportErrors (sub_1C0004A3C)` at `0x1C0004B73`–`0x1C0004BA9`.
   - `PrepareCrbForPioRetry (sub_1C0005A24)` at `0x1C0005B3D`–`0x1C0005B76`.
   - `ProcessParityError (sub_1C00056D0)` at `0x1C000576F`–`0x1C00057A8`.

   The patched build replaces all three inline copies with a `call PrepareCrbForRetry (sub_1C000C700)`. The helper body is the same instruction sequence.

2. **Inline-callee.** The unpatched completion routine `IdeProcessCompletedRequests (sub_1C000D8D0)` calls out to the error interpreter `IdepInterpretTransportErrors (sub_1C0004A3C)` (which itself calls `IdeMapError` and dispatches the transport-error handlers). In the patched build that error-mapping-and-dispatch logic is inlined directly into `IdeProcessCompletedRequests (sub_1C00036A0)` as a jump-table switch (`IdeMapError` is now called at `0x1C0003A1F`, inside the completion routine). This is why the patched completion routine roughly tripled in size.

### The recycle site is identical in both builds

The point the earlier draft treated as the "bug location" — the push of the request's SLIST entry onto the controller list — is byte-for-byte equivalent in both builds and clears nothing extra in either:

- Unpatched `0x1C000DADB`–`0x1C000DAF6`: `lea rcx,[r12+1480h]; mov rdx,[r13+408h]; call ExpInterlockedPushEntrySList; and qword [r13+408h],0`.
- Patched `0x1C0003818`–`0x1C0003833`: `lea rcx,[r12+1480h]; mov rdx,[rsi+408h]; call ExpInterlockedPushEntrySList; mov qword [rsi+408h],0`.

Neither build zeros `+0x3EA/+0x3EB/+0x3F3/+0x410/+0x420/+0x428/+0x23/+0x28` at this push, and the reset helper is not invoked on this path in either build. The reset belongs to the transport-error retry path, not to the free-list recycle path.

### The `SrbData` fields feed telemetry, not transfer sizing

The `SrbData` dereference and the assembly of `*(rdi+0x4F)<<8 | *(rdi+0x50)` in the unpatched completion routine (`0x1C000DD18`, `0x1C000DD67`) store into a local (`var_D0`) that is consumed only as an argument to the WPP software-trace call `WPP_SF_DDDDDqDDDDiDdd` at `0x1C000DF06`. These values drive an ETW/WPP trace record; they are not used for DMA/transfer sizing or any bounds decision.

---

## 3. Pseudocode Diff

### Per-retry reset — UNPATCHED (inline in `IdepInterpretTransportErrors`)

```c
// sub_1C0004A3C, transport-error retry preparation (0x1C0004B48..0x1C0004BAC)
if (*(uint16_t*)(req + 0x3E8) == 0x404) {
    *(uint8_t*)(req + 0x3EA) = 6;
} else {
    if ((mapped_error & 0x5F) == 0x44)          // 'D'
        *(uint16_t*)(req + 0x20) |= 0x100;      // requeue flag
    *(uint16_t*)(req + 0x3EB) = 0;
    *(uint8_t *)(req + 0x3F3) = 0;
    *(uint64_t*)(req + 0x428) = 0;
    *(uint64_t*)(req + 0x420) = 0;
    *(uint8_t *)(req + 0x3EA) = 0;
    *(uint64_t*)(req + 0x410) = 0;
    if (*(uint8_t*)(req + 0x23) < 1) *(uint8_t*)(req + 0x23) += 1;
    *(uint32_t*)(req + 0x28) = 0;
}
```

### Per-retry reset — PATCHED (same logic, factored into helper)

```c
// inside IdeProcessCompletedRequests (sub_1C00036A0), error switch (0x1C0007F87..0x1C0007FBC)
if (*(uint16_t*)(req + 0x3E8) == 0x404) {
    *(uint8_t*)(req + 0x3EA) = 6;
} else {
    if ((*(uint8_t*)(req + 0x3EA) & 0x5F) == 0x44)
        *(uint16_t*)(req + 0x20) |= 0x100;      // requeue flag
    PrepareCrbForRetry(req);                     // sub_1C000C700
}

// PrepareCrbForRetry (sub_1C000C700):
void PrepareCrbForRetry(void *req) {
    *(uint16_t*)(req + 0x3EB) = 0;               // clears 0x3EB and 0x3EC (word store)
    *(uint8_t *)(req + 0x3F3) = 0;
    *(uint64_t*)(req + 0x428) = 0;
    *(uint64_t*)(req + 0x420) = 0;
    *(uint8_t *)(req + 0x3EA) = 0;
    *(uint64_t*)(req + 0x410) = 0;
    if (*(uint8_t*)(req + 0x23) < 1) *(uint8_t*)(req + 0x23) += 1;
    *(uint32_t*)(req + 0x28) = 0;
}
```

The two are behaviorally equivalent. The only differences are that the field-zeroing lives in a callee and the surrounding error switch is now inlined into the completion routine.

---

## 4. Assembly Analysis

### UNPATCHED — inline reset in `IdepInterpretTransportErrors (sub_1C0004A3C)`

```asm
0x1C0004B48 : mov     eax, 404h
0x1C0004B4D : cmp     [rdi+3E8h], ax
0x1C0004B54 : jnz     short 0x1C0004B62
0x1C0004B56 : mov     byte ptr [rdi+3EAh], 6
0x1C0004B5D : jmp     0x1C0004C02
0x1C0004B62 : and     cl, 5Fh
0x1C0004B65 : cmp     cl, 44h                  ; 'D'
0x1C0004B68 : jnz     short 0x1C0004B73
0x1C0004B6A : mov     eax, 100h
0x1C0004B6F : or      [rdi+20h], ax            ; requeue flag
0x1C0004B73 : xor     ecx, ecx
0x1C0004B75 : mov     [rdi+3EBh], cx
0x1C0004B7C : mov     [rdi+3F3h], cl
0x1C0004B82 : mov     [rdi+428h], rcx
0x1C0004B89 : mov     [rdi+420h], rcx
0x1C0004B90 : mov     [rdi+3EAh], cl
0x1C0004B96 : mov     [rdi+410h], rcx
0x1C0004B9D : mov     al, [rdi+23h]
0x1C0004BA0 : cmp     al, 1
0x1C0004BA2 : jnb     short 0x1C0004BA9
0x1C0004BA4 : inc     al
0x1C0004BA6 : mov     [rdi+23h], al            ; conditional retry-counter bump
0x1C0004BA9 : mov     [rdi+28h], ecx
```

### PATCHED — same path, now calling the helper (inside `IdeProcessCompletedRequests`)

```asm
0x1C0007F87 : mov     eax, 404h
0x1C0007F8C : cmp     [rbx+3E8h], ax
0x1C0007F93 : jnz     short 0x1C0007FA2
0x1C0007F95 : mov     byte ptr [r13+3EAh], 6
0x1C0007F9D : jmp     def_1C0003EC8
0x1C0007FA2 : movzx   eax, byte ptr [r13+3EAh]
0x1C0007FAA : and     al, 5Fh
0x1C0007FAC : cmp     al, 44h                  ; 'D'
0x1C0007FAE : jnz     short 0x1C0007FB9
0x1C0007FB0 : mov     eax, 100h
0x1C0007FB5 : or      [rbx+20h], ax            ; requeue flag
0x1C0007FB9 : mov     rdx, rbx
0x1C0007FBC : call    PrepareCrbForRetry       ; sub_1C000C700
```

### PATCHED — `PrepareCrbForRetry (sub_1C000C700)` helper body

```asm
0x1C000C700 : xor   ecx, ecx
0x1C000C702 : mov   word  [rdx + 0x3EB], cx
0x1C000C709 : mov   byte  [rdx + 0x3F3], cl
0x1C000C70F : mov   qword [rdx + 0x428], rcx
0x1C000C716 : mov   qword [rdx + 0x420], rcx
0x1C000C71D : mov   byte  [rdx + 0x3EA], cl
0x1C000C723 : mov   qword [rdx + 0x410], rcx
0x1C000C72A : mov   al,   byte [rdx + 0x23]
0x1C000C72D : cmp   al, 1
0x1C000C72F : jnb   0x1C000C736
0x1C000C731 : inc   al
0x1C000C733 : mov   byte [rdx + 0x23], al       ; conditional retry-counter bump
0x1C000C736 : mov   dword [rdx + 0x28], ecx
0x1C000C739 : retn
```

### Recycle site — identical in both builds (no reset added here)

```asm
; UNPATCHED IdeProcessCompletedRequests (sub_1C000D8D0)
0x1C000DADB : lea     rcx, [r12+1480h]          ; ListHead (controller_ext + 0x1480)
0x1C000DAE3 : mov     rdx, [r13+408h]           ; ListEntry = req + 0x408
0x1C000DAEA : call    ExpInterlockedPushEntrySList
0x1C000DAF6 : and     qword ptr [r13+408h], 0

; PATCHED IdeProcessCompletedRequests (sub_1C00036A0)
0x1C0003818 : lea     rcx, [r12+1480h]          ; ListHead
0x1C0003820 : mov     rdx, [rsi+408h]           ; ListEntry = req + 0x408
0x1C0003827 : call    ExpInterlockedPushEntrySList
0x1C0003833 : mov     qword ptr [rsi+408h], 0
```

---

## 5. Reachability / Trigger

There is no security-relevant trigger to describe. The reset block runs on the transport-error retry path in both builds, so an attacker who reaches this code observes the same field-clearing behavior on either binary. The lookaside push at `controller_ext+0x1480` is identical in both builds and clears no extra state in either. The `SrbData`-derived values (`*(rdi+0x4F)`, `*(rdi+0x50)`, etc.) reach only the WPP trace call `WPP_SF_DDDDDqDDDDiDdd`, so they do not feed a size, bounds, or transfer decision that could be corrupted by residual state.

---

## 6. Exploit Primitive

None. No stale-state, type-confusion, or improper-initialization primitive is present, because the per-retry field reset exists in both builds and the differing code is a refactor. There is no delta that grants a controlled read, write, or size primitive.

---

## 7. Debugger Notes

To confirm the equivalence directly, compare the same request object at the retry-preparation site in both builds:

- Unpatched: break at `IdepInterpretTransportErrors + <offset>` reaching `0x1C0004B73`; the fields `+0x3EA/+0x3EB/+0x3F3/+0x410/+0x420/+0x428/+0x28` are zeroed inline and `+0x23` is conditionally bumped.
- Patched: break at `0x1C0007FBC` (`call PrepareCrbForRetry`); the helper `sub_1C000C700` performs the identical zeroing and conditional bump.

The recycle sites (`0x1C000DAEA` unpatched, `0x1C0003827` patched) show the same operation in both builds and do not touch those fields.

Image base for the disassembly listings is `0x1C0000000`; rebase to the runtime load address of `ataport.sys` (`lm m ataport`, then `runtime = loadBase + (addr - 0x1C0000000)`).

---

## 8. Changed Functions — Full Triage

### Security fix (CWE-416 use-after-free)

- **`IdePortTickHandler` (unpatched `0x1C000DFB0` → patched `0x1C0004990`)** (periodic timer DPC `DeferredRoutine`). Matched by content/role across relocation, not address. The patched build acquires the device-extension remove lock (`IoAcquireRemoveLockEx` on `[dev+0xB0]`, call at `0x1C0004B51`), checks the returned status (`test eax,eax; jns`) and skips the device on failure, then releases it (`IoReleaseRemoveLockEx` at `0x1C0004BFE` and `0x1C0008C14`) around the per-device timeout/reset work. The unpatched routine has **zero** remove-lock calls in its body and used only `RefNextPdoExtensionWithTag`/`UnRefPdoExtensionWithTag` tag counting, which the device-teardown path (`RemovePdoExtension`, `IoReleaseRemoveLockAndWaitEx` at `0x1C0006C9A`) does not wait on. Full analysis in Section 11.

### Refactor (extract-helper / inline-callee) — not a security change

- **`IdeProcessCompletedRequests` (unpatched `sub_1C000D8D0` → patched `sub_1C00036A0`)** (ATA request completion routine). Similarity **0.5168**. The patched routine inlines the error-interpretation logic that the unpatched build reached via a separate call to `IdepInterpretTransportErrors (sub_1C0004A3C)` (now `IdeMapError` is called at `0x1C0003A1F` within the routine), and replaces the inline retry-reset with a call to `PrepareCrbForRetry (sub_1C000C700)`. The SLIST recycle path is unchanged. No behavioral difference in the reset itself.
- **`PrepareCrbForRetry (sub_1C000C700)`** (NEW helper). Similarity 0.0 (no removed counterpart). Contains the field-zeroing + conditional retry-counter bump that existed inline in three unpatched functions. Called from three sites in the patched binary (`sub_1C00036A0` at `0x1C0007FBC`, `sub_1C000C53C` at `0x1C000C659`, `sub_1C000C9F4` at `0x1C000CA7F`).
- **`PrepareCrbForPioRetry (sub_1C0005A24) → sub_1C000C53C`** (request re-issue / retry path). Similarity **0.9214**. Inline field-zeroing block (`0x1C0005B3D`–`0x1C0005B76`) replaced by `call PrepareCrbForRetry`. Semantically identical.
- **`ProcessParityError (sub_1C00056D0) → sub_1C000C9F4`** (parity/CRC error handling). Similarity **0.9329**. Inline field-zeroing block (`0x1C000576F`–`0x1C00057A8`) replaced by `call PrepareCrbForRetry`. Caller is the (now inlined) transport-error interpreter. Semantically identical.

### Cosmetic / compiler artifacts

The following are compiler restructurings with no semantic change:

- **`IdeInitCrbWithTaskFileAndDataPayload (sub_1C000C59C) → sub_1C0001444`** (ATA command opcode dispatch switch). Similarity 0.9538. If/else cascade over `*(arg2+6)` reordered; opcode mapping table identical.
- **`DeviceHandleDeviceTelemetryIoctl (sub_1C0024AD8) → sub_1C00294D8`** (magic-number IRP dispatch). Similarity 0.9232. 64-bit magic-constant comparison restructured from two-test-and to subtract-and-test. Logic equivalent.
- **`ChannelFilterResourceRequirements (sub_1C0025BB0) → sub_1C002B1B0`** (IRP-completion GUID / telemetry buffer parser). Similarity 0.9683. Compiler switched to wide vector register usage and renumbered labels. Allocation size arithmetic (count*0x20 + base, with overflow check) is identical.

No other behavioral changes were identified across the remaining changed functions beyond register allocation and label reordering.

---

## 9. Unmatched Functions

| Direction | Functions |
|---|---|
| Removed (unpatched only) | None |
| Added (patched only) | None |

Note: `PrepareCrbForRetry (sub_1C000C700)` appears as a *changed* function (similarity 0.0) rather than *added*. Functionally it is a new helper, but it has no removed counterpart because its reset logic was previously inlined in `IdepInterpretTransportErrors (sub_1C0004A3C)`, `PrepareCrbForPioRetry (sub_1C0005A24)`, and `ProcessParityError (sub_1C00056D0)`.

---

## 10. Confidence & Caveats

**Confidence:** High that the ATA error-retry refactor (Sections 2–9) is not a security-relevant change. This scope statement is about that refactor only; the separate `IdePortTickHandler` remove-lock fix (Section 11) is a confirmed security change.

**Rationale:**

- The per-retry reset block (`+0x3EB/+0x3F3/+0x428/+0x420/+0x3EA/+0x410`, conditional bump of `+0x23`, clear `+0x28`, plus the `0x100` requeue flag) is present in the **unpatched** build in three functions (`0x1C0004B73`, `0x1C0005B3D`, `0x1C000576F`). The patch only factors these into the shared helper `PrepareCrbForRetry (sub_1C000C700)`. There is no build in which the reset is missing.
- The SLIST recycle path (`ExpInterlockedPushEntrySList` at `0x1C000DAEA` unpatched / `0x1C0003827` patched) is identical and touches none of those fields in either build.
- The `SrbData` fields (`+0x4F/+0x50/+0x48/+0x52..0x55`) feed only the WPP trace call `WPP_SF_DDDDDqDDDDiDdd`; they do not influence transfer size or any bounds decision.
- The size growth of the patched completion routine is explained by inlining `IdepInterpretTransportErrors`'s error-mapping switch, not by added security logic.

---

## 11. Added Finding — `IdePortTickHandler` device-removal use-after-free (CWE-416)

**Severity:** Medium.
**Vulnerability class:** Use-after-free via device-removal race (CWE-416; the underlying defect is a missing removal-synchronization lock, CWE-362).
**Function:** `IdePortTickHandler` — unpatched `0x1C000DFB0`, patched `0x1C0004990` (relocated and rewritten; matched by content and role, not by address).
**Status:** CONFIRMED, and omitted from the earlier triage.

### The object and its remove lock

Each channel device extension carries an `IO_REMOVE_LOCK` at offset `+0xB0`, initialized once in both builds:

```asm
; UNPATCHED init (device-extension setup)
0x1C0021664 : mov     rdi, [rax+40h]           ; rdi = device extension = DeviceObject+0x40
0x1C0021674 : lea     rcx, [rdi+0B0h]; Lock     ; the IO_REMOVE_LOCK
0x1C002167F : mov     edx, 50656449h; AllocateTag   ; 'IdeP'
0x1C00216B2 : mov     [rdi+54h], r14d           ; device key stored at +0x54
0x1C00216B6 : mov     [rsp+50h+..], 20h; RemlockSize
0x1C00216BE : call    cs:__imp_IoInitializeRemoveLockEx
```

Device teardown is `RemovePdoExtension (0x1C0006C0C)`. It walks the channel's device hash table (keyed by `+0x54`) under the channel spinlock (`[chan+0x98]`), then blocks on the **same** remove lock before unlinking and freeing the extension:

```asm
; RemovePdoExtension teardown wait (unpatched)
0x1C0006C8A : lea     rcx, [rbx+0B0h]; RemoveLock
0x1C0006C91 : mov     r8d, 20h; RemlockSize
0x1C0006C9A : call    cs:__imp_IoReleaseRemoveLockAndWaitEx
; ... then unlink from hash bucket and dec device count:
0x1C0006CC1 : mov     [r14+98h], rcx
0x1C0006CE1 : dec     dword ptr [rdi+54h]
```

`IoReleaseRemoveLockAndWaitEx` waits only for holders of that `+0xB0` remove lock. It does **not** wait for the driver's own `RefNextPdoExtensionWithTag`/`UnRefPdoExtensionWithTag` tag counter. So any code that touches the device after a remove IRP arrives must hold the remove lock, or it races the free.

### Unpatched: periodic tick touches the device with no remove lock

`IdePortTickHandler` is registered as a timer DPC `DeferredRoutine` (`lea rdx, IdePortTickHandler; DeferredRoutine` at `0x1C000E0AD`/`0x1C000E0BC` region of the DPC init). The unpatched body (`0x1C000DFB0`–`0x1C000E115`) enumerates PDO extensions with the tag counter and performs per-device timeout/reset work with **no** remove-lock acquisition anywhere:

```asm
; UNPATCHED IdePortTickHandler — enumeration + per-device work, no remove lock
0x1C000E07F : mov     rcx, rdi                  ; rdi = device extension
0x1C000E082 : call    DeviceUpdateRequestTimeoutCounter
0x1C000E0A8 : call    IdeTargetReset
0x1C000E0B7 : call    UnRefPdoExtensionWithTag  ; tag counter, not the remove lock
0x1C000E0C6 : call    RefNextPdoExtensionWithTag
0x1C000E0F9 : call    IdeChannelReset
```

There is no `IoAcquireRemoveLockEx`/`IoReleaseRemoveLockEx` in the entire function body. If a remove IRP for the device is being processed on another CPU, `RemovePdoExtension` can complete its `IoReleaseRemoveLockAndWaitEx` (nothing to wait for) and free the extension while this DPC is still dereferencing it in `DeviceUpdateRequestTimeoutCounter` / `IdeTargetReset` / `IdeChannelReset` — a use-after-free.

### Patched: acquire the remove lock, skip the device on failure, release it

The patched body (`0x1C0004990`–`0x1C0008CB8`) walks the device hash table under the channel spinlock (the same structure `RemovePdoExtension` uses), and once a device is matched it acquires the remove lock before doing any per-device work:

```asm
; PATCHED IdePortTickHandler — acquire remove lock before per-device work
0x1C0004B2E : lea     rcx, [rsi+0B0h]; RemoveLock   ; rsi = matched device extension
0x1C0004B35 : mov     [rsp+88h+RemlockSize], 20h; RemlockSize
0x1C0004B3D : mov     r9d, 1; Line
0x1C0004B43 : lea     r8, File; File
0x1C0004B4A : lea     rdx, IdePortTickHandler; Tag
0x1C0004B51 : call    cs:__imp_IoAcquireRemoveLockEx
0x1C0004B5D : test    eax, eax
0x1C0004B5F : jns     loc_1C0004A2F                 ; success: proceed to per-device work
0x1C0004B65 : jmp     loc_1C0008BE0                 ; failure: release spinlock, skip device
```

The per-device timeout/reset work then runs (`DeviceUpdateRequestTimeoutCounter` at `0x1C0004BC1`, `IdeTargetReset` at `0x1C0008C6E`, `IdeChannelReset` at `0x1C0008CAA`), and every exit path releases the lock:

```asm
; PATCHED release paths
0x1C0004BEA : lea     rcx, [rsi+0B0h]; RemoveLock
0x1C0004BF1 : mov     r8d, 20h; RemlockSize
0x1C0004BFE : call    cs:__imp_IoReleaseRemoveLockEx
; and the early-skip path:
0x1C0008C00 : lea     rcx, [rsi+0B0h]; RemoveLock
0x1C0008C14 : call    cs:__imp_IoReleaseRemoveLockEx
```

If `IoAcquireRemoveLockEx` returns a failure status (a remove IRP has already been received for the device), the patched handler skips that device entirely, so it never touches a device that is on its way out.

### Reachability / trigger

`IdePortTickHandler` is a periodic timer DPC that fires whenever the driver has active channels. The removal side is driven by the PnP subsystem: unplug/eject of a removable ATA/ATAPI device, "Disable" in Device Manager, or a stop/remove during driver teardown. Winning the race requires the tick DPC to be mid-flight on a device extension at the moment `RemovePdoExtension` frees it. This is a local, PnP-triggered race, not remotely reachable, and not directly forced by attacker-supplied data; hence Medium rather than High.

### Impact

Kernel use-after-free on a paged/non-paged device extension: reads and writes performed by `DeviceUpdateRequestTimeoutCounter`, `IdeTargetReset`, and `IdeChannelReset` land on freed pool if the race is won, which can corrupt pool state and, depending on reallocation, escalate to arbitrary kernel memory corruption. Correct CWE: **CWE-416 (Use After Free)**.

### Direction check / exclusions

- Direction is strictly tightening: patched adds a lock and a skip-on-removal branch; it never relaxes an existing check.
- Not WIL/feature-staging: the old tag-only path is gone, not retained behind a flag.
- Not telemetry, not relocation-only, not API modernization for its own sake: the acquired lock semantically coordinates with `IoReleaseRemoveLockAndWaitEx` in `RemovePdoExtension`, which the previous tag counter did not.
- Not init-only/unreachable: it is a live periodic DPC.
- Global remove-lock call sites increase from the unpatched to the patched build (e.g. `IoReleaseRemoveLockEx` sites rise from 8 to 25), consistent with newly added protection rather than a rename.
