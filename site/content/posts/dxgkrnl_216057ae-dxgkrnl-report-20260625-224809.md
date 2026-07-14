Title: dxgkrnl.sys — DXGSYNCOBJECT refcount integer-overflow guard made unconditional (CWE-190) fixed
Date: 2026-02-10
Slug: dxgkrnl_216057ae-dxgkrnl-report-20260625-224809
Category: Corpus
Author: Argus
Summary: KB5075912
Severity: Low
KBDate: 2026-02-10

### 1. Overview
- **Unpatched Binary:** `dxgkrnl_unpatched.sys`
- **Patched Binary:** `dxgkrnl_patched.sys`
- **Overall Similarity Score:** 0.9918
- **Diff Statistics:** 6888 matched, 16 changed, 6872 identical, 0 unmatched (in both directions).
- **Verdict:** The patch removes a feature-flag gate (`Feature_2066527547__private_IsEnabledDeviceUsage`) around the `DXGSYNCOBJECT` reference-count increment. In the unpatched build, when that flag resolves to disabled, the increment is a plain `lock inc dword [obj+0x18]` with no upper-bound check; when enabled it goes through an overflow-checked atomic path. The patch deletes the gate and makes the overflow-checked path unconditional. This is a real, directionally-correct hardening change, but the guarded condition (a 32-bit refcount wrapping at `0xFFFFFFFF`) is not reachable in practice, so the impact is defense-in-depth, not a demonstrable Use-After-Free.

### 2. Vulnerability Summary

- **Severity:** Low
- **Vulnerability Class:** Missing upper-bound check on a reference-count increment (CWE-190, Integer Overflow)
- **Affected Functions:** `DXGSYNCOBJECT::AddReference` (0x1C0026804 unpatched / 0x1C00267A4 patched), `DXGSYNCOBJECT::Open` (0x1C010DAE0 unpatched / 0x1C0110550 patched)
- **Entry Point:** `DxgkOpenSyncObjectFromNtHandle2Impl` (0x1C00E1138), reachable from user mode via the `D3DKMTOpenSyncObjectFromNtHandle2` runtime API.

**Root Cause Analysis:**
The `DXGSYNCOBJECT` structure holds a 32-bit reference count at offset `0x18`. In the unpatched build the increment is gated by the WIL feature flag `Feature_2066527547__private_IsEnabledDeviceUsage`:

- When the flag resolves to enabled, `AddReference` reads the count, compares it to `0xFFFFFFFF`, and rejects the increment with `STATUS_INTEGER_OVERFLOW` (`0xC0000017`) if it is already at the maximum, otherwise performing an atomic `lock cmpxchg` increment.
- When the flag resolves to disabled, the increment is a bare `lock inc dword [rbx+0x18]` with no comparison against `0xFFFFFFFF`, so a count already at `0xFFFFFFFF` would wrap to `0`.

`DXGSYNCOBJECT::Open` mirrors this: when the flag is enabled it takes the reference early via `AddReference` (overflow-checked) and rolls it back with `lock dec` on error paths; when the flag is disabled it skips `AddReference` and instead performs a single bare `lock inc dword [rdi+0x18]` on the success path only. The reference accounting is balanced in both flag states — the disabled path simply defers its single increment to the success path and therefore takes no reference to roll back on the error paths.

The patched `AddReference` and `Open` remove the flag entirely and always use the overflow-checked increment. The net security-relevant delta is that the `0xFFFFFFFF` bound check on the increment becomes mandatory.

**Reachability of the overflow:** Wrapping the count requires `0xFFFFFFFF` (~4.29 billion) simultaneous live references. Each successful `Open` that increments the count also allocates a handle in the calling process's handle table (`HMGRTABLE::AllocHandle` at 0x1C010DFC1), and each reference is released when its handle/object is torn down. Accumulating ~4.29 billion concurrent references would require ~4.29 billion concurrent handles/objects, far beyond per-process handle-table and memory limits. No path was found that increments the count without a corresponding live resource, so the wrap is not reachable and no premature free / UAF could be demonstrated against the unpatched build.

**Call Chain (to the guarded increment):**
1. `D3DKMTOpenSyncObjectFromNtHandle2` (user-mode runtime API)
2. `DxgkOpenSyncObjectFromNtHandle2Impl` (0x1C00E1138)
3. `DXGSYNCOBJECT::Open` (0x1C010DAE0) — increments the refcount at `+0x18` (flag-disabled: bare `lock inc` at 0x1C010E125; flag-enabled: via `AddReference`)

### 3. Pseudocode Diff

**`DXGSYNCOBJECT::AddReference`**
```c
// ==========================================
// UNPATCHED (0x1C0026804)
// ==========================================
NTSTATUS DXGSYNCOBJECT::AddReference() {
    if (Feature_2066527547__private_IsEnabledDeviceUsage()) {
        // overflow-checked atomic increment
        for (;;) {
            uint32_t old = this->refcount;           // [this+0x18]
            if (old == 0xFFFFFFFF)
                return STATUS_INTEGER_OVERFLOW;      // 0xC0000017, logged
            if (InterlockedCompareExchange(&this->refcount, old + 1, old) == old)
                break;
        }
    } else {
        // flag disabled: bare increment, no upper-bound check
        InterlockedIncrement(&this->refcount);       // lock inc [this+0x18]
    }
    return STATUS_SUCCESS;
}

// ==========================================
// PATCHED (0x1C00267A4)
// ==========================================
NTSTATUS DXGSYNCOBJECT::AddReference() {
    // feature gate removed; overflow-checked path is unconditional
    for (;;) {
        uint32_t old = this->refcount;               // [this+0x18]
        if (old == 0xFFFFFFFF)
            return STATUS_INTEGER_OVERFLOW;
        if (InterlockedCompareExchange(&this->refcount, old + 1, old) == old)
            break;
    }
    return STATUS_SUCCESS;
}
```

### 4. Assembly Analysis

**Unpatched `DXGSYNCOBJECT::AddReference` (0x1C0026804)**
```assembly
00000001C0026804  push    rbx
00000001C0026806  sub     rsp, 20h
00000001C002680A  mov     rbx, rcx
00000001C002680D  call    Feature_2066527547__private_IsEnabledDeviceUsage
00000001C0026812  test    eax, eax
00000001C0026814  jz      short loc_1C0026858        ; flag disabled -> bare-increment path
; --- overflow-checked path (flag enabled) ---
00000001C0026816  mov     eax, [rbx+18h]
00000001C0026819  cmp     eax, 0FFFFFFFFh            ; upper-bound check
00000001C002681C  jz      short loc_1C002682A        ; reject at max -> STATUS_INTEGER_OVERFLOW
00000001C002681E  lea     ecx, [rax+1]
00000001C0026821  lock cmpxchg [rbx+18h], ecx
00000001C0026826  jz      short loc_1C002685C
00000001C0026828  jmp     short loc_1C0026816        ; retry on contention
; --- bare-increment path (flag disabled) ---
00000001C0026858  lock inc dword ptr [rbx+18h]       ; no upper-bound check
00000001C002685C  xor     eax, eax
00000001C002685E  add     rsp, 20h
00000001C0026862  pop     rbx
00000001C0026863  retn
```

**Patched `DXGSYNCOBJECT::AddReference` (0x1C00267A4)** — gate removed, check unconditional
```assembly
00000001C00267A4  push    rbx
00000001C00267A6  sub     rsp, 20h
00000001C00267AA  mov     rbx, rcx
00000001C00267AD  mov     eax, [rcx+18h]
00000001C00267B0  cmp     eax, 0FFFFFFFFh            ; always checks the upper bound
00000001C00267B3  jz      short loc_1C00267C3
00000001C00267B5  lea     edx, [rax+1]
00000001C00267B8  lock cmpxchg [rcx+18h], edx
00000001C00267BD  jnz     short loc_1C00267AD        ; retry on contention
00000001C00267BF  xor     eax, eax
00000001C00267C1  jmp     short loc_1C00267EF
```

**Unpatched `DXGSYNCOBJECT::Open` — flag-disabled increment (0x1C010DAE0)**
```assembly
00000001C010E11C  call    Feature_2066527547__private_IsEnabledDeviceUsage
00000001C010E121  test    eax, eax
00000001C010E123  jnz     short loc_1C010E129        ; flag enabled: ref already taken via AddReference
00000001C010E125  lock inc dword ptr [rdi+18h]       ; flag disabled: single bare increment on success
```
The two `lock dec dword [rdi+18h]` sites at 0x1C010E001 and 0x1C010E111 are the flag-enabled rollbacks of the early `AddReference` (0x1C010DE74). They are correctly skipped when the flag is disabled because that path takes no reference until the success site above, so the accounting is balanced in both flag states.

**Patched `DXGSYNCOBJECT::Open` (0x1C0110550)** — gate removed; the reference is always taken via `AddReference` (0x1C01108D8) and always rolled back via `lock dec` on error (0x1C0110A5F, 0x1C0110B5C); the bare `lock inc [rdi+0x18]` success-path increment is gone.

### 5. Trigger Conditions

To reach the unpatched flag-disabled increment path:
1. Open a D3D adapter handle from user mode (e.g. `D3DKMTOpenAdapterFromLuid`).
2. Create a synchronization object via `D3DKMTCreateSynchronizationObject`.
3. Call `D3DKMTOpenSyncObjectFromNtHandle2` on the object's NT handle, which reaches `DxgkOpenSyncObjectFromNtHandle2Impl` -> `DXGSYNCOBJECT::Open` -> the `lock inc dword [rdi+0x18]` at 0x1C010E125 (when `Feature_2066527547` resolves to disabled).

Reaching the actual `0xFFFFFFFF -> 0` wrap the patch guards against is not achievable: it needs ~4.29 billion concurrent references, each pinned by a live handle/object, which exceeds process handle-table and memory limits well before the count can approach `0xFFFFFFFF`.

### 6. Impact Assessment

- **Demonstrable primitive:** None against the unpatched build. The change adds a mandatory upper-bound check on a reference-count increment, but the count cannot be driven to `0xFFFFFFFF` because every increment is tied to a live handle/object and the required ~4.29 billion concurrent references are not attainable.
- **Nature of the fix:** Defense-in-depth. Microsoft graduated an existing overflow-check from a feature-gated state to an always-on state, removing the configuration in which the check could be skipped.
- No Use-After-Free, arbitrary read/write, information-leak, or code-execution primitive is established by this diff. Claims of a reachable UAF, pool spray, or mitigation bypass are not supported by the binaries and are not made here.

### 7. Debugger Reference Points

Real, verified addresses in the unpatched build for observing the guarded increment:

- `0x1C0026804` — `DXGSYNCOBJECT::AddReference` entry; `rcx` = `DXGSYNCOBJECT* this`. Refcount is `dword [rcx+0x18]`.
- `0x1C0026858` — the flag-disabled bare `lock inc dword [rbx+0x18]` inside `AddReference`.
- `0x1C0026819` — the flag-enabled upper-bound check `cmp eax, 0xFFFFFFFF`.
- `0x1C0026914` — `Feature_2066527547__private_IsEnabledDeviceUsage`; reads `Feature_2066527547__private_featureState`, tests bit `0x10` (WIL override-present bit); if clear it falls back to the feature descriptor default. This flag selects the checked vs. bare increment path.
- `0x1C010E125` — the flag-disabled bare `lock inc dword [rdi+0x18]` inside `DXGSYNCOBJECT::Open`; `rdi` = `DXGSYNCOBJECT*`.
- `0x1C0107068` — `DXGSYNCOBJECT::Close`; the `lock add dword [rdi+0x18], 0xFFFFFFFF` at `0x1C01070F7` decrements the count and `setz al` at `0x1C0107101` reports whether it reached 0. This is ordinary reference counting and is unchanged by the patch.

### 8. Changed Functions — Full Triage

* **`DXGSYNCOBJECT::AddReference`** (Sim: 0.683): Feature gate `Feature_2066527547` removed; the overflow-checked `cmpxchg` increment path becomes unconditional in place of the flag-disabled bare `lock inc`. Directionally-correct hardening (CWE-190), not reachably exploitable.
* **`DXGSYNCOBJECT::Open`** (Sim: 0.9526): Same feature gate removed; the reference is now always taken via `AddReference` (overflow-checked) with unconditional `lock dec` rollback on error, replacing the flag-disabled bare `lock inc` on the success path. Refcount accounting was already balanced in both builds; the only delta is the mandatory overflow check.
* **`DXGDEVICESYNCOBJECT::Initialize`** (Sim: 0.9691): Same `Feature_2066527547` gate around the `AddReference` call removed so the checked path and its return status are used unconditionally. Hardening, same theme.
* **`DxgkDestroySynchronizationObjectImpl`** (Sim: 0.9367): Removes a different WIL gate (`Feature_202674488`) around an object-ownership validation and a conditional destruction path, plus register renaming. Not the primary change; no reachable security impact established.
* **`DXG_HOST_GLOBAL_VMBUS::VmBusCreateProcess`** (Sim: 0.9178): Removes WIL gates (`Feature_530541883`) around host-side VM process reference counting and error rollback, plus register renaming. Host-side VM bus path, not user-mode reachable; no security impact established.

**Cosmetic / Optimization Changes:**
The remaining changed functions (`DXG_HOST_VIRTUALGPU_VMBUS::VmBusCreateAllocation`, `VmBusCddGdiCommand`, `DXGDEVICE::CreateAllocation`, `VmBusMapGpuVirtualAddress`, `VmBusMakeResident`, and the unnamed routines at `0x1C012BD68`, `0x1C015B983`, `0x1C0117B64`, `0x1C015BB7D`, `0x1C0107232`, `0x1C012D660`) show only register allocation and structural cleanup with no logic or security change.

### 9. Unmatched Functions
No functions were added or removed. The patch modifies existing functions by removing conditional feature-flag branches.

### 10. Confidence & Caveats
- **Confidence:** High on the mechanism and direction — the unpatched flag-disabled `lock inc` sites (0x1C0026858, 0x1C010E125), the flag-enabled overflow-checked path, and the patched unconditional check are all verified in both builds. The presence of the `0xFFFFFFFF` check in the enabled path confirms the developers treated an unbounded increment as undesirable, consistent with a defense-in-depth intent.
- **Severity rationale:** Rated Low because the guarded condition (a 32-bit reference count wrapping) is not reachable: each increment is bound to a live handle/object and ~4.29 billion concurrent references are not attainable within process handle-table and memory limits. No premature free, UAF, or downstream primitive is demonstrable from this diff, so CWE-416 does not apply.
- **Feature-flag default:** `Feature_2066527547` is a WIL staged feature; its runtime default is resolved from the feature descriptor / servicing configuration and is not fixed by this static diff. The security-relevant fact is only that the patched build no longer allows the unchecked increment in any configuration.
