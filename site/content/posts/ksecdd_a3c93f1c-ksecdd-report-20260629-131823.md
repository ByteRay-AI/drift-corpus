Title: ksecdd.sys — No security-relevant change (feature-gated defense-in-depth address-range check in protected-process free path)
Date: 2026-06-29
Slug: ksecdd_a3c93f1c-ksecdd-report-20260629-131823
Category: Corpus
Author: Argus
Summary: KB5082123
Severity: Informational

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `ksecdd_unpatched.sys` |
| Patched binary | `ksecdd_patched.sys` |
| Overall similarity | **0.9901** (very small, targeted delta) |
| Matched functions | 356 |
| Changed functions | 5 |
| Identical functions | 351 |
| Unmatched (unpatched) | 0 |
| Unmatched (patched) | 0 |

**Verdict:** The only behavioral delta is the addition of a **feature-staging-gated** `MmHighestUserAddress` range check in the Protected-Process (PPL) branch of two memory-free helpers (`SecFreeForKsecCaller` at `0x1C0001240` and `SecFreeCommon` at `0x1C0004F30`). When the staging feature `g_Feature_4032523578_59197666` evaluates enabled, a kernel-space `BaseAddress` in the protected branch is routed through `KsecRemoveValidAddressCommon` (the same removal helper the non-protected branch already uses) instead of `KsecRemoveValidVm`. The old path is retained unchanged when the feature evaluates disabled, so this is a **staged-rollout / defense-in-depth** change. No reachable arbitrary-free primitive is demonstrable in the unpatched build (see §5–§6): every attacker-seedable tracking-table entry carries a null handle, and the free is skipped when the handle is null. The remaining three changed functions are pure Windows-Feature-staging plumbing (recompilation of the `EvaluateCurrentState` call convention).

---

## 2. Change Summary

### Finding 1 — Feature-gated `MmHighestUserAddress` range check added to the protected-process free branch

- **Severity:** Informational (no demonstrated reachable impact).
- **Nature:** Defense-in-depth / staged rollout (Windows Feature staging via `EvaluateCurrentState` + `EvaluateFeature`).
- **Affected functions:** `SecFreeForKsecCaller` (`0x1C0001240`) and `SecFreeCommon` (`0x1C0004F30` unpatched / `0x1C0004F70` patched).
- **CWE:** Not substantiated. The change is a range check on a code path for which no attacker-controlled reachable free primitive was demonstrated.

**What the code does.** `ksecdd.sys` maintains a per-process tracking table (`KsecValidVm`) of `(handle, EPROCESS, address, end, flags)` records. `SecFreeForKsecCaller` and `SecFreeCommon` free a caller-supplied `BaseAddress`. After passing a state/silo guard (`KsecddLsaStateRef::IsValid`, not-System, not-current), and — only for a Protected Process (`PsIsProtectedProcess` true) — they take a "protected" branch that calls `KsecRemoveValidVm(process, BaseAddress)` to locate and remove the tracking record. `KsecRemoveValidVm` returns the **stored handle** from that record; the caller frees only if that handle is non-null (it first `ZwClose`s it). The non-protected branch instead calls `KsecRemoveValidAddressCommon`. Both branches converge on a common free site that selects `ExFreePoolWithTag(BaseAddress, 0)` for `BaseAddress >= *MmUserProbeAddress` and `ZwFreeVirtualMemory` otherwise.

**The delta.** The patch inserts, immediately after `PsIsProtectedProcess` returns true, an evaluation of Windows Feature `g_Feature_4032523578_59197666` and, if enabled, a comparison of `BaseAddress` against `*MmHighestUserAddress`. A kernel-space address is redirected to the `KsecRemoveValidAddressCommon` path rather than `KsecRemoveValidVm`. If the feature evaluates disabled, control falls through to the original `KsecRemoveValidVm` call — the pre-patch behavior is preserved verbatim.

**Why this is not a delivered vulnerability fix.**
- The gating is Windows Feature staging (`EvaluateCurrentState(&g_Feature_4032523578_59197666_FeatureDescriptorDetails)` → `EvaluateFeature`), with the original path retained on the disabled branch. This is the shape of a staged/velocity rollout, not an unconditionally enforced fix.
- The arbitrary-kernel-free condition the check would guard is not demonstrably reachable in the unpatched build (§6): the only tracking-table entries an attacker can seed with a kernel address are inserted with a **null** handle, so `KsecRemoveValidVm` returns null and the free is skipped.
- Both branches are PPL-gated regardless.

**Entry points.**

SSPI path:
1. `FreeContextBuffer` (`0x1C001D8A0`, exported) calls `SecFreeForKsecCaller(pvContextBuffer)` directly.
2. `SecFreeForKsecCaller` (`0x1C0001240`) branches on the state guard + `PsIsProtectedProcess`.
3. Protected branch: `KsecRemoveValidVm` (`0x1C0003918`) → common free site.

IOCTL path:
1. `KsecFastIoDeviceControl` (`0x1C0003B40`) dispatches IOCTL `0x39002C` (= 3735596) to `KsecIoctlFreePool` (`0x1C000DC7C`).
2. `KsecIoctlFreePool` calls `SecFreeCommon(KsecSystemProcessHandle, *inBuf, 28, package)` where `package = *((_DWORD*)inBuf + 2)` (the dword at input offset 8).
3. `SecFreeCommon` takes the protected branch only when `package == 0xFFFFFFFD (-3)` **and** `PsIsProtectedProcess` is true; then `KsecRemoveValidVm` → common free site.

---

## 3. Pseudocode Diff

### `SecFreeForKsecCaller` (`0x1C0001240`) — UNPATCHED

```c
void SecFreeForKsecCaller(void *BaseAddress) {
    EPROCESS *cur = PsGetCurrentProcess();
    KsecddLsaStateRef state;                       // ctor
    if ( state.IsValid()
         && cur != KsecSystemProcess
         && cur != *state ) {
        if ( PsIsProtectedProcess(cur) ) {
            // PROTECTED BRANCH
            HANDLE h = KsecRemoveValidVm(cur, BaseAddress);  // returns stored handle
            if ( h == nullptr ) goto cleanup;                // free SKIPPED if handle null
            ZwClose(h);
            goto free_site;
        }
    }
    // NON-PROTECTED BRANCH
    if ( !KsecRemoveValidAddressCommon(BaseAddress, 0) ) goto cleanup;
free_site:
    if ( (uintptr_t)BaseAddress >= MmUserProbeAddress )
        ExFreePoolWithTag(BaseAddress, 0);
    else
        ZwFreeVirtualMemory((HANDLE)-1, &BaseAddress, &RegionSize, MEM_RELEASE);
cleanup:
    ; // state dtor
}
```

### `SecFreeForKsecCaller` — PATCHED (delta shown)

```c
        if ( PsIsProtectedProcess(cur) ) {
+           // Windows Feature staging gate + kernel-address redirect
+           if ( EvaluateCurrentState(&g_Feature_4032523578_59197666_FeatureDescriptorDetails)
+                && (uintptr_t)BaseAddress > MmHighestUserAddress )
+               goto common_remove;   // route kernel addr to KsecRemoveValidAddressCommon
            HANDLE h = KsecRemoveValidVm(cur, BaseAddress);
            ...
        }
+ common_remove:
    if ( !KsecRemoveValidAddressCommon(BaseAddress, 0) ) goto cleanup;
```

The same delta is mirrored in `SecFreeCommon` (`0x1C0004F30` → `0x1C0004F70`), reached via IOCTL `0x39002C`.

---

## 4. Assembly Analysis

### `SecFreeForKsecCaller` (`0x1C0001240`) — UNPATCHED (protected branch and free site)

```
00000001C000128E  mov     rcx, rbx
00000001C0001291  call    cs:__imp_PsIsProtectedProcess
00000001C000129D  test    eax, eax
00000001C000129F  jz      short loc_1C00012C8            ; not protected -> non-protected branch
00000001C00012A1  mov     rdx, [rsp+28h+BaseAddress]     ; BaseAddress
00000001C00012A6  mov     rcx, rbx                        ; process
00000001C00012A9  call    KsecRemoveValidVm               ; returns stored handle
00000001C00012AE  test    rax, rax
00000001C00012B1  jz      loc_1C0001341                   ; handle == null -> free SKIPPED
00000001C00012B7  mov     rcx, rax
00000001C00012BA  call    cs:__imp_ZwClose
00000001C00012C6  jmp     short loc_1C00012D8
00000001C00012C8  mov     rcx, [rsp+28h+BaseAddress]      ; non-protected branch
00000001C00012CD  xor     edx, edx
00000001C00012CF  call    KsecRemoveValidAddressCommon
00000001C00012D4  test    eax, eax
00000001C00012D6  jz      short loc_1C0001341
00000001C00012D8  mov     rax, cs:MmUserProbeAddress
00000001C00012DF  mov     rcx, [rsp+28h+BaseAddress]
00000001C00012E4  cmp     rcx, [rax]                      ; selects free routine (not a security gate)
00000001C00012E7  jnb     short loc_1C000130E
00000001C00012E9  mov     r9d, 8000h                      ; MEM_RELEASE
00000001C00012F9  mov     rcx, 0FFFFFFFFFFFFFFFFh
00000001C0001300  call    cs:__imp_ZwFreeVirtualMemory
00000001C000130E  xor     edx, edx
00000001C0001310  call    cs:__imp_ExFreePoolWithTag      ; kernel-address free routine
```

### `SecFreeForKsecCaller` — PATCHED (inserted gate)

```
00000001C000129D  test    eax, eax
00000001C000129F  jz      short loc_1C00012E7             ; not protected -> non-protected branch
00000001C00012A1  lea     rcx, g_Feature_4032523578_59197666_FeatureDescriptorDetails
00000001C00012A8  call    ?EvaluateCurrentState@@YAHPEBUreg_FeatureDescriptor@@@Z
00000001C00012AD  mov     rcx, [rsp+28h+BaseAddress]
00000001C00012B2  test    eax, eax
00000001C00012B4  jz      short loc_1C00012C2            ; feature disabled -> legacy path
00000001C00012B6  mov     rax, cs:__imp_MmHighestUserAddress
00000001C00012BD  cmp     rcx, [rax]
00000001C00012C0  ja      short loc_1C00012EC            ; kernel addr -> KsecRemoveValidAddressCommon
00000001C00012C2  mov     rdx, rcx                        ; user addr -> legacy protected path
00000001C00012C5  mov     rcx, rbx
00000001C00012C8  call    KsecRemoveValidVm
...
00000001C00012EC  xor     edx, edx
00000001C00012EE  call    KsecRemoveValidAddressCommon
```

The `cmp rcx, [MmUserProbeAddress]` free-site comparison exists identically in both builds and merely selects `ExFreePoolWithTag` vs `ZwFreeVirtualMemory`; it is not a security boundary and is unchanged. What the patched build adds is the feature-gated redirect that runs before `KsecRemoveValidVm`, and only when the feature is enabled.

### `SecFreeCommon` (`0x1C0004F30` unpatched / `0x1C0004F70` patched) — same delta

UNPATCHED protected branch:
```
00000001C0004F95  cmp     esi, 0FFFFFFFDh                 ; package == -3 ?
00000001C0004F98  jnz     short loc_1C0004FD3
00000001C0004F9D  call    cs:__imp_PsIsProtectedProcess
00000001C0004FA9  test    eax, eax
00000001C0004FAB  jz      short loc_1C0004FD3
00000001C0004FAD  mov     rdx, [rbp+BaseAddress]
00000001C0004FB4  call    KsecRemoveValidVm
00000001C0004FB9  test    rax, rax
00000001C0004FBC  jz      loc_1C0005045                   ; handle == null -> free SKIPPED
```
PATCHED inserts the identical `EvaluateCurrentState(&g_Feature_4032523578_59197666...)` + `cmp BaseAddress, MmHighestUserAddress` + `ja KsecRemoveValidAddressCommon` sequence at `0x1C0004FED`, with the legacy `KsecRemoveValidVm` call retained on the feature-disabled fall-through.

---

## 5. Trigger Conditions (as coded)

For the protected branch to run at all in either build:

1. **PPL caller.** `PsIsProtectedProcess(EPROCESS)` must be true (e.g. an LSA/PPL process). This is the dominant gate; the branch is not reachable from an ordinary user-mode process.
2. **State/silo guard.** `KsecddLsaStateRef::IsValid` true, current process not `KsecSystemProcess`, and not equal to the silo state's process.
3. **Tracking-table membership.** `KsecRemoveValidVm(process, BaseAddress)` must locate a record for `(process, BaseAddress)`.
4. **Non-null stored handle.** The located record's handle field must be non-null; otherwise `KsecRemoveValidVm` returns null and the caller skips the free entirely.
5. **IOCTL variant additionally** requires the input `package` dword (offset 8 of a 16-byte buffer) to equal `0xFFFFFFFD (-3)`; IOCTL `0x39002C` on `\Device\KsecDD` routes to `KsecIoctlFreePool` → `SecFreeCommon`.

The free routine actually invoked (`ExFreePoolWithTag` vs `ZwFreeVirtualMemory`) is then decided by the `BaseAddress >= *MmUserProbeAddress` comparison at the shared free site.

---

## 6. Reachability / Impact Assessment

The report title's earlier framing of an "arbitrary kernel pool free" is **not substantiated** by the binaries. The chain that would be required — seed a kernel address into the tracking table, then free it via `ExFreePoolWithTag` on the protected branch — does not close in the unpatched build:

- `KsecRemoveValidVm` returns the **handle** stored in the tracking record (record field 0), and `SecFreeForKsecCaller`/`SecFreeCommon` proceed to the free **only when that handle is non-null** (`test rax,rax; jz skip`).
- The tracking table `KsecValidVm` is populated by three callers of `KsecInsertValidVm`:
  - `KsecIoctlInsertProtectedProcessAddress` (`0x1C0002BB4`): inserts an **attacker-supplied address** but with handle = **`nullptr`**.
  - `KsecInsertValidAddress` (`0x1C00018C0`): inserts with handle = **`nullptr`**.
  - `KsecIoctlAllocVm` (`0x1C00037A4`): inserts with a **non-null** handle, but the address is one the driver itself allocated via `ZwAllocateVirtualMemory` into a target process — i.e. **user-space**, which takes the `ZwFreeVirtualMemory` branch, never `ExFreePoolWithTag`.
- Consequently, an address an attacker can steer to the `ExFreePoolWithTag` free routine either is not in the table with a usable (non-null) handle, or is a driver-allocated user-space allocation. No path stores a kernel-space address together with a non-null handle, so the "free an arbitrary kernel pool chunk" primitive is not demonstrable.

The patched redirect (kernel addresses → `KsecRemoveValidAddressCommon`) is therefore defense-in-depth hardening around a branch that is already gated by the null-handle check and by the PPL requirement, and it is itself conditioned on a Windows Feature-staging flag with the legacy path retained. No exploit primitive (pool UAF, write-what-where, token/privilege manipulation, KASLR/info-leak) is established by this diff; such claims are not supported and are omitted.

---

## 7. Observation Aids

These are the real instruction offsets for observing the two code paths in a kernel debugger against the modules. They confirm control flow only; they do not constitute an exploit, and (per §6) the protected branch does not reach `ExFreePoolWithTag` with an attacker-chosen kernel address via the seeding IOCTLs.

- `ksecdd!FreeContextBuffer` (`0x1C001D8A0`) — `rcx` = buffer pointer entering `SecFreeForKsecCaller`.
- `ksecdd+0x12A9` (unpatched) — `call KsecRemoveValidVm`; `rcx` = EPROCESS, `rdx` = `BaseAddress`.
- `ksecdd+0x12B1` (unpatched) — `jz` taken when the returned handle is null (free skipped).
- `ksecdd+0x1310` (unpatched) — `call ExFreePoolWithTag` (kernel-address free routine at the shared free site).
- `ksecdd+0x3B40` — `KsecFastIoDeviceControl`; inspect the IOCTL code (`0x39002C` = 3735596 dispatches to `KsecIoctlFreePool`).
- `ksecdd+0x4FB4` (unpatched) — `call KsecRemoveValidVm` inside `SecFreeCommon`; `ksecdd+0x5014` — its `ExFreePoolWithTag` site.
- Patched: `ksecdd+0x12A8` / `ksecdd+0x4FF4` — `call EvaluateCurrentState`; the following `cmp BaseAddress, [MmHighestUserAddress]` (`__imp_MmHighestUserAddress`) with `ja` to the `KsecRemoveValidAddressCommon` path is the inserted redirect.

Referenced globals: `MmUserProbeAddress` (free-site routine selector, both builds); `__imp_MmHighestUserAddress` (patched redirect only); `KsecSystemProcess` (the "not System" guard); tracking table `KsecValidVm` with 40-byte `(handle, EPROCESS, address, end, flags)` records.

---

## 8. Changed Functions — Full Triage

| Function (name @ address) | Change type | Note |
|---|---|---|
| `EvaluateCurrentState` (`0x1C00065D0` → `0x1C0006630`) | Feature-staging plumbing | Refactored from a hardcoded-descriptor form (unpatched evaluates `g_Feature_263211323_55489181` and ignores its argument) to a parameterized form that dereferences the passed `reg_FeatureDescriptor*`. Return contract unchanged: `state != 1`. Not security-relevant. (Note: `0x1C00065D0` is reused in the patched build for `rbc_InitializeFeatureStaging`.) |
| `SecFreeForKsecCaller` (`0x1C0001240`) | Behavioral (feature-gated) | Adds the `EvaluateCurrentState(&g_Feature_4032523578_59197666)` + `MmHighestUserAddress` redirect before the protected-branch `KsecRemoveValidVm` call. Legacy path retained when the feature is disabled. Defense-in-depth (see §6). |
| `SecFreeCommon` (`0x1C0004F30` → `0x1C0004F70`) | Behavioral (feature-gated) | Mirror of the same redirect, reached via IOCTL `0x39002C` → `KsecIoctlFreePool`. |
| `KsecInsertValidAddress` (`0x1C00018C0`) | Feature-staging plumbing | Only change: passes the explicit `&g_Feature_263211323_55489181_FeatureDescriptorDetails` to the now-parameterized `EvaluateCurrentState` (unpatched passed an uninitialized argument the old evaluator ignored). No change to insertion/validation logic. |
| `KsecRemoveValidAddressCommon` (`0x1C0001360` → `0x1C0001380`) | Feature-staging plumbing | Same `EvaluateCurrentState` argument change as above. No change to removal/validation logic. |

**Summary.** Three of the five changed functions (`EvaluateCurrentState`, `KsecInsertValidAddress`, `KsecRemoveValidAddressCommon`) are pure Windows-Feature-staging recompilation churn. The only behavioral delta is the feature-gated redirect in `SecFreeForKsecCaller` and `SecFreeCommon`.

An independent content-normalized diff of both builds (matching by function content across relocations) found no additional function with a logic change; all other apparent differences are label/address relocation from the image rebuild. The patched build also carries a 4-instruction wrapper `KSecAllocateContextBuffer` (`0x1C001D580`, `call SecAllocateForcePool`) not separately named in the unpatched listing; it is not security-relevant.

---

## 9. Unmatched Functions

The diff reports `unmatched_unpatched = 0` and `unmatched_patched = 0`; no sanitizer was removed and no new validation helper was introduced (the redirect reuses the pre-existing `KsecRemoveValidAddressCommon` and `EvaluateCurrentState`). See §8 for the small `KSecAllocateContextBuffer` wrapper observed in the patched listing.

---

## 10. Confidence & Caveats

**Confidence: High** that the delta is a feature-staging-gated `MmHighestUserAddress` redirect in two free helpers, with the legacy path retained on the disabled branch, and that the accompanying three changes are feature-staging plumbing. All names, addresses, and instructions above were read directly from the two disassemblies and decompilations.

**Confidence: High** that the "arbitrary kernel pool free" primitive is not demonstrable in the unpatched build via the seeding IOCTLs, because the attacker-seedable tracking-table entries carry a null handle and the free is skipped when the handle is null (§6).

**Caveats.**
- Whether Windows Feature `g_Feature_4032523578_59197666` is enabled by default on shipping builds cannot be determined from the binary alone; regardless, the retained legacy branch makes this a staged rollout rather than an unconditionally enforced change.
- The return semantics of `KsecRemoveValidAddressCommon` for an address absent from the `KsecValidAddresses` table are feature/flag dependent and were not exhaustively enumerated; this does not affect the §6 conclusion, which rests on the upstream null-handle skip.
