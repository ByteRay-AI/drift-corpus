Title: ksecdd.sys — No security-relevant change (staged, feature-gated address-space check in protected-process free paths)
Date: 2026-06-29
Slug: ksecdd_527d8cd3-ksecdd-report-20260629-011930
Category: Corpus
Author: Argus
Summary: KB5082200

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `ksecdd_unpatched.sys` |
| Patched binary | `ksecdd_patched.sys` |
| Overall similarity | 0.9887 |
| Matched functions | 380 |
| Changed | 7 |
| Identical | 373 |
| Unmatched (either direction) | 0 |

**Verdict.** The only behavioral delta between the two builds is an addition to the two internal free routines `SecFreeForKsecCaller` (`0x1C00017F0`) and `SecFreeCommon` (`0x1C00051FC`). For the protected-process branch, the patched build inserts a check that is gated on the WIL velocity feature `Feature_4099632442__private_IsEnabledDeviceUsage` (`0x1C0006690`): when that feature is enabled *and* the caller-supplied `BaseAddress` is above `MmHighestUserAddress`, the free is routed through the shared `KsecRemoveValidAddressCommon` validation instead of the per-process `KsecRemoveValidVm` validation. When the feature is disabled the pre-existing path is retained unchanged, so on shipping systems where the velocity feature is off the two builds behave identically.

This is a staged (feature-gated) defense-in-depth refinement, not a delivered fix for a demonstrable exploitable condition. In both builds the free is already gated on a tracking-table membership check; neither build performs an attacker-controlled arbitrary free (see §2 and §5). No demonstrable arbitrary-free primitive exists in the unpatched build, so severity is not warranted.

The remaining changed functions are WIL feature-staging plumbing that supports the new `Feature_4099632442` gate (see §8). All other functions that appear in a raw byte diff differ only by relocation (address shifts caused by the newly emitted feature-staging functions), not by content.

---

## 2. Change Summary

### The single behavioral change — protected-process free routing

- **Affected functions:**
  - `SecFreeForKsecCaller` (`0x1C00017F0`) — reached via the SSPI `FreeContextBuffer` internal free path.
  - `SecFreeCommon` (`0x1C00051FC`) — reached via the `KsecIoctlFreePool` (`0x1C000EA08`) IOCTL handler.

**What the code does (plain English).** Both routines free a caller-supplied `BaseAddress`. They first classify the caller. If the KSec LSA state is valid and the caller is the registered `KsecSystemProcess` or the context owner, the free goes through the shared validated path (`KsecRemoveValidAddressCommon`). Otherwise, if `PsIsProtectedProcess(PsGetCurrentProcess())` is true, the code takes a "protected process" branch that calls `KsecRemoveValidVm(process, BaseAddress)`.

`KsecRemoveValidVm` (`0x1C0003EB4`) looks the `(EPROCESS*, BaseAddress)` pair up in the `KsecValidVm` tracking table under `KsecValidAddressLock`. It returns the entry's first qword — the tracked *handle* — or `0` if the pair is not present. The free dispatcher then runs only if that returned handle is non-null: it `ZwClose`s the handle and, at `0x1C00018BE`/`0x1C00018D6`, frees `BaseAddress` via `ExFreePoolWithTag` when `BaseAddress >= MmUserProbeAddress`, otherwise via `ZwFreeVirtualMemory`.

**Why this is gated, not exploitable.** In both builds the free is reached only when the address is present in a tracking table *and* the associated handle is non-null. The entries in `KsecValidVm` are inserted by `KsecInsertValidVm` (`0x1C0003FC8`). The IOCTL-reachable insert `KsecIoctlInsertProtectedProcessAddress` (`0x1C0002CBC`) passes `a1 = nullptr` as the entry handle, so an address staged through that IOCTL is recorded with a null handle. `KsecRemoveValidVm` then returns `0` for it, and the free branch is not taken (`test rax,rax; jz`). The other `KsecInsertValidVm` call sites record addresses that KSec itself allocated, together with a real handle. There is therefore no path by which a caller stages an arbitrary chosen kernel address *and* obtains a non-null handle for it, so the "arbitrary kernel pool free" primitive is not demonstrable.

**The patched addition.** In the protected-process branch, the patched build inserts, before the `KsecRemoveValidVm` call:

```c
// PATCHED, SecFreeForKsecCaller / SecFreeCommon protected-process branch
if (Feature_4099632442__private_IsEnabledDeviceUsage()
    && BaseAddress > *MmHighestUserAddress)
    goto common_validated_path;   // KsecRemoveValidAddressCommon
// else: unchanged — KsecRemoveValidVm(process, BaseAddress)
```

`Feature_4099632442__private_IsEnabledDeviceUsage` (`0x1C0006690`) is a WIL (Windows velocity) feature-state check: it reads `Feature_4099632442__private_featureState`, tests bit `0x10`, and otherwise falls back to `Feature_4099632442__private_IsEnabledFallback` → `wil_details_IsEnabledFallback`. It is not a VBS/HVCI runtime flag. When the feature is disabled the added comparison is skipped and the pre-existing `KsecRemoveValidVm` path runs, so the change is a staged rollout with the old path retained.

---

## 3. Pseudocode Diff

### `SecFreeForKsecCaller` (`0x1C00017F0`) — protected-process branch

```c
// ============================ UNPATCHED ============================
if (!KsecddLsaStateRef::IsValid(&state)
    || curproc == KsecSystemProcess
    || curproc == state->OwnerProcess)
{
    if (KsecRemoveValidAddressCommon(BaseAddress, 0))   // shared validated path
        goto do_free;
    goto cleanup;
}
else
{
    if (!PsIsProtectedProcess(curproc))
        goto shared_path;                               // 0x1C0001878

    HANDLE h = KsecRemoveValidVm(curproc, BaseAddress);  // per-process table lookup
    if (!h)
        goto cleanup;                                    // null handle -> no free
    ZwClose(h);
    goto do_free;
}

do_free:
    if (BaseAddress >= *MmUserProbeAddress)
        ExFreePoolWithTag(BaseAddress, 0);
    else
        ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, ...);

// ============================ PATCHED ============================
// ... same prologue ...
else
{
    if (!PsIsProtectedProcess(curproc))
        goto shared_path;                               // 0x1C0001890

    // *** ADDED (feature-gated) ***
    if (Feature_4099632442__private_IsEnabledDeviceUsage()
        && BaseAddress > *MmHighestUserAddress)
        goto shared_path;                               // KsecRemoveValidAddressCommon

    HANDLE h = KsecRemoveValidVm(curproc, BaseAddress);
    if (!h)
        goto cleanup;
    ZwClose(h);
    goto do_free;
}
```

`SecFreeCommon` (`0x1C00051FC`) receives the identical addition; only the source of `BaseAddress` differs (IOCTL input vs. `FreeContextBuffer` argument).

---

## 4. Assembly Analysis

### `SecFreeForKsecCaller` (`0x1C00017F0`) — UNPATCHED

```asm
00000001C00017F0  push    rbx
00000001C00017F2  sub     rsp, 20h
00000001C00017F6  mov     [rsp+28h+BaseAddress], rcx
00000001C00017FB  mov     [rsp+28h+RegionSize], 0
00000001C0001804  call    cs:__imp_PsGetCurrentProcess
00000001C0001810  lea     rcx, [rsp+28h+arg_8]
00000001C0001815  mov     rbx, rax
00000001C0001818  call    ??0KsecddLsaStateRef@@QEAA@XZ
00000001C000181D  lea     rcx, [rsp+28h+arg_8]
00000001C0001822  call    ?IsValid@KsecddLsaStateRef@@QEAA_NXZ
00000001C0001827  test    al, al
00000001C0001829  jz      short loc_1C0001878
00000001C000182B  cmp     rbx, cs:KsecSystemProcess
00000001C0001832  jz      short loc_1C0001878
00000001C0001834  mov     rcx, [rsp+28h+arg_8]
00000001C0001839  cmp     rbx, [rcx]
00000001C000183C  jz      short loc_1C0001878
00000001C000183E  mov     rcx, rbx
00000001C0001841  call    cs:__imp_PsIsProtectedProcess
00000001C000184D  test    eax, eax
00000001C000184F  jz      short loc_1C0001878
00000001C0001851  mov     rdx, [rsp+28h+BaseAddress]
00000001C0001856  mov     rcx, rbx
00000001C0001859  call    KsecRemoveValidVm
00000001C000185E  test    rax, rax
00000001C0001861  jz      loc_1C00018F1
00000001C0001867  mov     rcx, rax
00000001C000186A  call    cs:__imp_ZwClose
00000001C0001876  jmp     short loc_1C0001888
00000001C0001878  mov     rcx, [rsp+28h+BaseAddress]
00000001C000187D  xor     edx, edx
00000001C000187F  call    KsecRemoveValidAddressCommon
00000001C0001884  test    eax, eax
00000001C0001886  jz      short loc_1C00018F1
00000001C0001888  mov     rax, cs:MmUserProbeAddress
00000001C000188F  mov     rcx, [rsp+28h+BaseAddress]
00000001C0001894  cmp     rcx, [rax]
00000001C0001897  jnb     short loc_1C00018BE
00000001C0001899  mov     r9d, 8000h
00000001C000189F  lea     r8, [rsp+28h+RegionSize]
00000001C00018A4  lea     rdx, [rsp+28h+BaseAddress]
00000001C00018A9  mov     rcx, 0FFFFFFFFFFFFFFFFh
00000001C00018B0  call    cs:__imp_ZwFreeVirtualMemory
00000001C00018BC  jmp     short loc_1C00018CC
00000001C00018BE  xor     edx, edx
00000001C00018C0  call    cs:__imp_ExFreePoolWithTag
00000001C00018CC  cmp     cs:DebugInfoLevel, 0
00000001C00018D3  jz      short loc_1C00018F1
00000001C00018D5  mov     r9, [rsp+28h+BaseAddress]
00000001C00018DA  lea     rdx, aDMemFree0xP
00000001C00018E1  mov     r8d, 0FFFFFFFDh
00000001C00018E7  mov     ecx, 8
00000001C00018EC  call    LsapDebugOut
00000001C00018F1  lea     rcx, [rsp+28h+arg_8]
00000001C00018F6  call    ??1KsecddLsaStateRef@@QEAA@XZ
00000001C00018FB  add     rsp, 20h
00000001C00018FF  pop     rbx
00000001C0001900  retn
```

### `SecFreeForKsecCaller` (`0x1C00017F0`) — PATCHED (added guard)

```asm
00000001C000184F  jz      short loc_1C0001890
00000001C0001851  call    Feature_4099632442__private_IsEnabledDeviceUsage
00000001C0001856  mov     rcx, [rsp+28h+BaseAddress]
00000001C000185B  test    eax, eax
00000001C000185D  jz      short loc_1C000186B          ; feature off -> old path
00000001C000185F  mov     rax, cs:__imp_MmHighestUserAddress
00000001C0001866  cmp     rcx, [rax]
00000001C0001869  ja      short loc_1C0001895          ; kernel addr -> KsecRemoveValidAddressCommon
00000001C000186B  mov     rdx, rcx                     ; old path resumes
00000001C000186E  mov     rcx, rbx
00000001C0001871  call    KsecRemoveValidVm
00000001C0001876  test    rax, rax
00000001C0001879  jz      loc_1C0001909
00000001C000187F  mov     rcx, rax
00000001C0001882  call    cs:__imp_ZwClose
00000001C000188E  jmp     short loc_1C00018A0
00000001C0001890  mov     rcx, [rsp+28h+BaseAddress]
00000001C0001895  xor     edx, edx
00000001C0001897  call    KsecRemoveValidAddressCommon
```

The added sequence is the `Feature_4099632442__private_IsEnabledDeviceUsage` call plus `cmp rcx, [MmHighestUserAddress]; ja`. When the feature is off, execution falls through at `0x1C000185D` to `0x1C000186B` and the original `KsecRemoveValidVm` path runs unchanged.

### `SecFreeCommon` (`0x1C00051FC`) — added guard (delta only)

```asm
00000001C0005289  call    Feature_4099632442__private_IsEnabledDeviceUsage
00000001C000528E  mov     rcx, [rbp+BaseAddress]
00000001C0005292  test    eax, eax
00000001C0005294  jz      short <old_path>
00000001C0005296  mov     rax, cs:__imp_MmHighestUserAddress
00000001C000529D  cmp     rcx, [rax]
00000001C00052A0  ja      short <common_validated_path>
```

The unpatched `SecFreeCommon` protected-process branch is the same shape as unpatched `SecFreeForKsecCaller`: `mov rdx, BaseAddress; mov rcx, process; call KsecRemoveValidVm; test rax,rax; jz <skip>; ...` with no `MmHighestUserAddress` comparison.

---

## 5. Reachability Assessment

1. **The added check is gated on a WIL velocity feature.** `Feature_4099632442__private_IsEnabledDeviceUsage` (`0x1C0006690`) reads `Feature_4099632442__private_featureState` and falls back to `wil_details_IsEnabledFallback`. It is not a VBS/HVCI flag. When the feature is disabled the patched and unpatched code paths are identical.

2. **The free is tracking-table-gated in both builds.** The protected-process branch frees `BaseAddress` only when `KsecRemoveValidVm(process, BaseAddress)` returns a non-null handle, i.e. the pair is present in `KsecValidVm` with a non-null entry handle.

3. **The IOCTL insert cannot stage a freeable arbitrary address.** `KsecIoctlInsertProtectedProcessAddress` (`0x1C0002CBC`) calls `KsecInsertValidVm(nullptr, CurrentProcess, addr, size, 1)` — the entry handle is `nullptr`. `KsecRemoveValidVm` returns that handle (`0`), so the free branch is skipped for IOCTL-staged addresses. The remaining `KsecInsertValidVm` call sites record addresses that KSec itself allocated together with a real handle.

4. **No demonstrable arbitrary-free primitive.** Because a caller cannot both choose an arbitrary kernel address and obtain a non-null tracked handle for it, the unpatched code does not provide an attacker-controlled `ExFreePoolWithTag` sink. The patched addition narrows which validation table is consulted for kernel-range addresses on the protected-process branch; it does not close a demonstrated exploitable hole.

---

## 6. Independent Diff (both directions)

A content-level diff of every function in the two builds (matching by symbol and by normalized body across relocation) yields exactly these genuine changes:

- `SecFreeForKsecCaller` (`0x1C00017F0`) — the feature-gated address-space check described above.
- `SecFreeCommon` (`0x1C00051FC`) — the same addition.
- `Feature_4099632442__private_IsEnabledDeviceUsage` / `Feature_4099632442__private_IsEnabledFallback` — new WIL feature-gate functions for the new feature id.
- `wil_details_IsEnabledFallback`, `wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath`, `wil_details_FeatureReporting_ReportUsageToService`, `wil_details_FeatureReporting_ReportUsageToServiceDirect`, `Feature_4155525435__private_IsEnabledFallback` — WIL feature-staging plumbing threading a per-instance context/tag through the reporting path.
- `KSecAllocateContextBuffer` (`0x1C001D860`) — a new four-instruction thunk that tail-calls `SecAllocateForcePool`; not security relevant.

Every other function that appears in a raw byte diff (for example `KsecFastIoDeviceControl`, `KsecDispatch`, `memmove`, `memset`, `CredpMarshalBytes`, the `Sspi*`/`PendingCall*` helpers) differs only by relocated `loc_`/`jpt_`/`def_` labels and shifted global-data references. The fast-I/O dispatch `KsecFastIoDeviceControl` (`0x1C00040D0`) and every `KsecIoctl*` handler are byte-identical apart from jump-table label relocation; no `ProbeForRead`, double-fetch, or bounds-check change was added or removed in the IOCTL paths (`ProbeForRead` appears zero times in both builds). No security-relevant change was omitted from this triage.

---

## 7. Function Name / Address Reference

| Address | Symbol |
|---|---|
| `0x1C00017F0` | `SecFreeForKsecCaller` |
| `0x1C00051FC` | `SecFreeCommon` |
| `0x1C0001910` (unpatched) / `0x1C0001920` (patched) | `KsecRemoveValidAddressCommon` |
| `0x1C0003EB4` | `KsecRemoveValidVm` |
| `0x1C0003FC8` | `KsecInsertValidVm` |
| `0x1C0004640` | `KsecFindValidVm` |
| `0x1C0002CBC` | `KsecIoctlInsertProtectedProcessAddress` |
| `0x1C000EA08` | `KsecIoctlFreePool` |
| `0x1C00040D0` | `KsecFastIoDeviceControl` |
| `0x1C0006690` | `Feature_4099632442__private_IsEnabledDeviceUsage` |

---

## 8. Changed Functions — Full Triage

### Behavioral change (feature-gated, not a delivered fix)

| Function | Change | Note |
|---|---|---|
| `SecFreeForKsecCaller` (`0x1C00017F0`) | Feature-gated | Adds `Feature_4099632442`-gated `MmHighestUserAddress` check that routes protected-process kernel-range frees to `KsecRemoveValidAddressCommon` instead of `KsecRemoveValidVm`. Old path retained when the feature is off. |
| `SecFreeCommon` (`0x1C00051FC`) | Feature-gated | Same addition on the `KsecIoctlFreePool`-reachable variant. |

### WIL feature-staging plumbing (non-security)

These functions were changed to support the new `Feature_4099632442` gate: they thread a per-instance context pointer and read the reporting tag / provider from that context, and add the new feature id's fast-path/fallback handling. No security-relevant behavioral change.

- `Feature_4099632442__private_IsEnabledDeviceUsage` / `Feature_4099632442__private_IsEnabledFallback` — new WIL feature-state check + fallback.
- `Feature_4155525435__private_IsEnabledFallback` — fallback tail adjusted.
- `wil_details_IsEnabledFallback` — passes the context through to the state-cache/report helpers.
- `wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath` — fast-path enable now sourced from the per-instance state word.
- `wil_details_FeatureReporting_ReportUsageToService` / `wil_details_FeatureReporting_ReportUsageToServiceDirect` — reporting tag/provider read from the per-instance context.
- `KSecAllocateContextBuffer` (`0x1C001D860`) — new allocate thunk tail-calling `SecAllocateForcePool`.

---

## 9. Unmatched Functions

No sanitizer, bounds check, or validation routine was removed in either direction. The new functions in the patched build (`Feature_4099632442__private_IsEnabledDeviceUsage`, `Feature_4099632442__private_IsEnabledFallback`, `KSecAllocateContextBuffer`) are the WIL feature-gate for the new feature id and a small allocate thunk.

---

## 10. Confidence & Caveats

**Confidence: high.** The diff is minimal and fully accounted for. The single behavioral change is the feature-gated address-space check in `SecFreeForKsecCaller` / `SecFreeCommon`; everything else is WIL feature-staging plumbing or relocation.

**Basis for the "no security-relevant change" classification:**

- The added check is gated behind the WIL velocity feature `Feature_4099632442__private_IsEnabledDeviceUsage`, with the pre-existing path retained when the feature is disabled (staged rollout).
- In both builds the protected-process free is reached only when `KsecRemoveValidVm` returns a non-null tracked handle. The IOCTL insert path records a null handle, and the other insert sites record KSec's own allocations, so there is no attacker-controlled arbitrary `ExFreePoolWithTag` sink to fix.
- The change narrows which validation table is consulted for kernel-range addresses on the protected-process branch. It is a defense-in-depth refinement rather than a fix for a demonstrable reachable primitive.
