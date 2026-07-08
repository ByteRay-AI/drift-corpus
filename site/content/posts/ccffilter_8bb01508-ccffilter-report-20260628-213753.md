Title: ccffilter.sys — ECP lifetime use-after-free / double-free in CCFPreCreate (CWE-416) fixed
Date: 2026-06-28
Slug: ccffilter_8bb01508-ccffilter-report-20260628-213753
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Medium

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `ccffilter_unpatched.sys` |
| Patched binary | `ccffilter_patched.sys` |
| Overall similarity | **0.9733** |
| Matched functions | 85 |
| Changed functions | **2** (1 security-relevant, 1 cosmetic) |
| Identical functions | 83 |
| Unmatched (either direction) | 0 |

**Verdict:** The patch addresses a medium-severity kernel pool lifetime bug in the Cluster Shared Volume (CSV) minifilter's `IRP_MJ_CREATE` pre-operation callback (`CCFPreCreate`). After the app-instance `Extra Create Parameter` (ECP) is inserted into the create IRP's ECP list, the unpatched code leaves its local pointer live; if a later ECP sub-step fails, the function's error-cleanup frees that ECP while it is still linked into the IRP's ECP list. The IRP's ECP list retains that dangling pointer, so the filter manager's later ECP-list teardown re-frees / dereferences freed pool — a double-free / use-after-free of the ECP context. Reaching the bug requires a CSV-backed create carrying the app-instance EA **and** a subsequent version/CSV ECP sub-step failing (typically an internal allocation failure); that secondary failure is not directly attacker-controlled, and the demonstrable impact is kernel pool corruption (local denial of service). The patched build adds the local-pointer clear on the success path, but delivers it **behind a Windows Feature Staging runtime flag** (`EvaluateCurrentState`), so the fix is a staged rollout: with the feature not active the patched binary retains the unpatched behavior.

---

## 2. Vulnerability Summary

### Finding #1 — ECP Lifetime / Use-After-Free in `CCFPreCreate`

- **Severity:** Medium
- **Class:** Use-after-free / double-free, kernel pool lifetime (CWE-416)
- **Affected function:** `CCFPreCreate` (`sub_1c0007760`), the `IRP_MJ_CREATE` pre-operation callback registered via `FltRegisterFilter`.

#### Root Cause

`ccffilter.sys` is the FltMgr minifilter that backs Windows Cluster Shared Volumes. When a user-mode process opens a file on a CSV path with an EA buffer carrying a "CCFF" app-instance EA, the create path in `CCFPreCreate` allocates a `GUID_ECP_NETWORK_APP_INSTANCE` Extra Create Parameter (0x14 bytes, pool tag "CCFF") and passes it to `CCFAddEcpToCreate` (`sub_1c00090a8`). That helper:

1. Obtains the IRP's ECP list via `FltGetEcpListFromCallbackData`.
2. Allocates a new list (`FltAllocateExtraCreateParameterList` + `FltSetEcpListIntoCallbackData`) if none exists.
3. Calls **`FltInsertExtraCreateParameter`** to link the freshly-allocated ECP into the IRP's ECP list.
4. Zeroes its byref out-flag (`var_b8`) before returning.

`FltInsertExtraCreateParameter` **transfers ownership** of the ECP to the filter manager — the ECP now lives for the lifetime of the IRP. The bug is that on the `CCFAddEcpToCreate` success path the unpatched `CCFPreCreate` does **not** clear its local copy of the ECP pointer (the clear it does have sits inside an `if (var_b8 != 0)` branch that is never taken, because `CCFAddEcpToCreate` just zeroed `var_b8`). Execution then continues into the version/CSV ECP sub-flow (`CCFFindAppInstanceVersionEcp` / `CCFLookupAndAddVersionEcpToCreate`). If that sub-step returns an error, control reaches the function's error-cleanup, which runs `if (status < 0 && EcpContext) FltFreeExtraCreateParameter(filter, EcpContext)` — freeing the app-instance ECP that is **still linked in the IRP's ECP list**. The freed pool block remains referenced by the list, so any subsequent ECP-list traversal (IRP completion teardown, `FltFindExtraCreateParameter`, or another minifilter querying the list) dereferences stale pool — kernel pool use-after-free / pool corruption.

The patch clears the local ECP pointer on the `CCFAddEcpToCreate` success path (so the error-cleanup can no longer free the still-listed ECP), gating the clear behind a Windows Feature Staging flag via the new helper `EvaluateCurrentState` (`sub_1c00017b8`). That helper calls `EvaluateFeature` (`sub_1c0001740`) on the feature descriptor `g_Feature_2963746106_60258290` and returns `(cachedstate != 1)`. The practical effect is that, with the feature enabled, the local ECP pointer is nulled immediately after a successful insert, so the later error path no longer double-frees the ECP that FltMgr already owns.

#### Attacker-Reachable Entry Point & Data Flow

`NtCreateFile` / `CreateFileW` on a CSV-backed path → FltMgr `IRP_MJ_CREATE` dispatch → `CCFPreCreate` pre-op callback.

1. **User mode:** `NtCreateFile` / `CreateFileW` against a CSV-mounted path (e.g. `C:\ClusterStorage\Volume1\<file>`), supplying an `EaBuffer` containing a CCFF app-instance EA.
2. **FltMgr** routes the create IRP to `CCFPreCreate` (`sub_1c0007760`).
3. `CCFFilterAppInstanceEA` parses the create's `EaBuffer`, sets `var_b7`, drives the app-instance branch.
4. `CCFPreCreate` allocates the ECP: `FltAllocateExtraCreateParameter(filter, &GUID_ECP_NETWORK_APP_INSTANCE, 0x14, ...) → EcpContext_1`.
5. `CCFPreCreate` calls `CCFAddEcpToCreate` → `FltInsertExtraCreateParameter` — the ECP is now **owned by the IRP's ECP list**; `var_b8` is cleared.
6. On success `CCFPreCreate` leaves `EcpContext_1` non-null and proceeds to the version/CSV ECP sub-flow.
7. If a version/CSV ECP step fails, the error-cleanup calls **`FltFreeExtraCreateParameter(filter, EcpContext_1)`** on the still-listed ECP → **dangling ECP-list entry**.
8. Subsequent ECP-list operation (IRP completion / `FltFindExtraCreateParameter` / list teardown) dereferences freed pool → **UAF**.

---

## 3. Pseudocode Diff

```c
// =============== UNPATCHED CCFPreCreate — ECP allocate/insert + success path ===============
LABEL_60:
    strncpy(&PoolTag, "CCFF", 4);
    FltAllocateExtraCreateParameter(
        filter, &GUID_ECP_NETWORK_APP_INSTANCE, 0x14, 0, nullptr, "CCFF", &EcpContext);
    ...
    *(WORD*)EcpContext = 0x14;                   // init ECP context length
    ...
    v4 = CCFAddEcpToCreate(CallbackData, EcpContext, &var_b8);
    //         ^ inside: FltGetEcpListFromCallbackData / (FltAllocateExtraCreateParameterList +
    //           FltSetEcpListIntoCallbackData) / FltInsertExtraCreateParameter
    //           *** OWNERSHIP TRANSFERRED TO IRP ECP LIST; var_b8 zeroed ***

    if (v4 >= 0) {                               // STATUS_SUCCESS
        if (var_b8) {                            // never taken (var_b8 cleared by callee)
            FltFreeExtraCreateParameter(filter, EcpContext);
            EcpContext = nullptr;
        }
        goto LABEL_72;                           // *** EcpContext still non-null & still listed ***
    }
    ...
LABEL_87:
    if (v4 < 0) {                                // set by a failed version/CSV ECP step
        if (EcpContext != nullptr) {
            FltFreeExtraCreateParameter(filter, EcpContext);
            //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            //  *** BUG: ECP is still linked in the IRP's ECP list ***
            EcpContext = nullptr;
        }
        CallbackData->IoStatus.Status = v4;
    }

// =============== PATCHED CCFPreCreate — same success site ===============
    v4 = CCFAddEcpToCreate(CallbackData, EcpContext, &var_b8);
    if (v4 < 0) { ...; goto LABEL_90; }
    if (var_b8) {                                // still never taken
        FltFreeExtraCreateParameter(filter, EcpContext);
        EcpContext = (void*)((uintptr_t)EcpContext & -(int64_t)EvaluateCurrentState());
    }
    if (EvaluateCurrentState())                  // NEW: clear on the whole success path
        EcpContext = nullptr;                    // -> error-cleanup no longer frees the listed ECP
    goto LABEL_75;

// =============== EvaluateCurrentState (sub_1c00017b8, new patched helper) ===============
// Windows Feature Staging gate; returns (cachedstate != 1)
bool EvaluateCurrentState() {
    EvaluateFeature(&g_Feature_2963746106_60258290_FeatureDescriptorDetails);
    return g_Feature_2963746106_60258290_cachedstate != 1;
}
```

**Key observation:** the `FltFreeExtraCreateParameter` calls themselves are byte-for-byte identical between the two builds. The only behavioral change is *where* the local `EcpContext` pointer is nulled: the unpatched build nulls it only inside the never-taken `if (var_b8)` branch, so on the normal success path it stays live and the later error-cleanup can free the already-listed ECP. The patch nulls it on the whole success path (feature-gated) so that error-cleanup free can no longer reach the ECP FltMgr already owns.

---

## 4. Assembly Analysis

### `CCFPreCreate` — vulnerable region (unpatched, `sub_1c0007760`)

```asm
; ===== Block: CCFAddEcpToCreate call site (ownership transfer) =====
0x1c0007baa: call    CCFAddEcpToCreate         ; (rcx=CallbackData, rdx=EcpContext, r8=&var_b8)
                                                ;   => FltInsertExtraCreateParameter inside => IRP ECP list owns ECP; var_b8=0
0x1c0007bb5: test    eax, eax
0x1c0007bb7: jns     loc_1c0007bfd             ; if (CCFAddEcpToCreate >= 0) goto success

; ===== Block: never-taken consumed branch (var_b8 already zeroed) =====
0x1c0007bfd: cmp     byte [rsp+0x40], r14b      ; var_b8 (== 0)
0x1c0007c02: jz      0x1c0007c61               ; -> version/CSV ECP handling (taken)
...
0x1c0007c3d: mov     rdx, qword [rsp+0x48]      ; rdx = EcpContext
             mov     rax, qword [rsp+0x58]
             mov     rcx, qword [rax+0x8]       ; rcx = filter handle
0x1c0007c4b: call    cs:__imp_FltFreeExtraCreateParameter
0x1c0007c57: mov     qword [rsp+0x48], r14      ; EcpContext = NULL (inside never-taken branch)
             jmp     0x1c0007c61

; ===== Block: error-cleanup — THE vulnerable free =====
0x1c0007d43: test    edi, edi                   ; edi = status (set < 0 by a failed version/CSV ECP step)
0x1c0007d45: jns     0x1c0007d79               ; skip if success
0x1c0007d47: mov     rdx, qword [rsp+0x48]      ; rdx = EcpContext (still non-null; still in IRP ECP list)
0x1c0007d4c: test    rdx, rdx
0x1c0007d4f: jz      0x1c0007d6b
             mov     rax, qword [rsp+0x58]
             mov     rcx, qword [rax+0x8]       ; rcx = filter handle
0x1c0007d5a: call    cs:__imp_FltFreeExtraCreateParameter ; *** frees still-listed ECP -> UAF ***
0x1c0007d66: mov     qword [rsp+0x48], r14
```

### `CCFPreCreate` — patched region

```asm
0x1c0007c4b: call    cs:__imp_FltFreeExtraCreateParameter ; (never-taken branch; unchanged)
0x1c0007c57: call    EvaluateCurrentState        ; returns (cachedstate != 1)
0x1c0007c5c: neg     eax                         ; mask = (flag==1) ? 0 : -1
0x1c0007c5e: sbb     rcx, rcx                     ; rcx = mask
0x1c0007c61: and     rcx, qword [rsp+0x48]        ; rcx = mask & EcpContext
0x1c0007c66: mov     qword [rsp+0x48], rcx
0x1c0007c6b: call    EvaluateCurrentState        ; success-path clear (runs regardless of var_b8)
0x1c0007c70: mov     rcx, qword [rsp+0x48]
0x1c0007c75: test    eax, eax
0x1c0007c77: cmovnz  rcx, r14                     ; if (flag!=1) EcpContext = nullptr
0x1c0007c7b: mov     qword [rsp+0x48], rcx
0x1c0007c80: jmp     0x1c0007c85
; error-cleanup free relocated to 0x1c0007d87 (same guarded shape), now sees EcpContext == NULL after a successful insert
```

### `EvaluateCurrentState` (`sub_1c00017b8`, patch-only helper)

```asm
0x1c00017b8: sub     rsp, 0x28
0x1c00017bc: lea     rcx, g_Feature_2963746106_60258290_FeatureDescriptorDetails
0x1c00017c3: call    EvaluateFeature             ; sub_1c0001740
0x1c00017c8: mov     rax, cs:g_Feature_2963746106_60258290_FeatureDescriptorDetails
0x1c00017cf: mov     ecx, dword [rax]            ; ecx = cachedstate
0x1c00017d1: xor     eax, eax
0x1c00017d3: cmp     ecx, 0x1
0x1c00017d6: setnz   al                          ; return (cachedstate != 1)
0x1c00017d9: add     rsp, 0x28
0x1c00017dd: retn
```

**Annotation summary:**

- `0x1c0007baa` — `CCFAddEcpToCreate` call. After this returns `>= 0`, the ECP at `[rsp+0x48]` is owned by the IRP's ECP list and `var_b8` is `0`.
- `0x1c0007c4b` — consumed-branch `FltFreeExtraCreateParameter`; unchanged by the patch and unreached because `var_b8 == 0`.
- `0x1c0007d5a` — **the vulnerable instruction**: `call FltFreeExtraCreateParameter` on the still-listed ECP in the error-cleanup, reached when a version/CSV ECP step fails while `EcpContext` is still live.
- The patch adds the success-path clear at `0x1c0007c6b` (feature-gated) so the error-cleanup free sees `EcpContext == NULL`.

---

## 5. Trigger Conditions

1. **Target must have CSV mounted and `ccffilter.sys` loaded and filtering.** Confirm with `fltmc instances` (the minifilter is attached to CSV volumes).
2. **From a standard user process**, call `NtCreateFile` / `CreateFileW` against a path under a CSV mount, e.g. `C:\ClusterStorage\Volume1\<file>`.
3. **Supply an `EaBuffer`** that carries a CCFF app-instance EA, parsed by `CCFFilterAppInstanceEA`, so the `var_b7` flag drives the `GUID_ECP_NETWORK_APP_INSTANCE` allocation + `CCFAddEcpToCreate` insert path (label `0x1c0007a96`).
4. **The pre-existing app-instance ECP must NOT already be present** (i.e. `CCFFindAppInstanceEcp` returns `var_b8 == 0` at entry), so the allocate/insert sequence runs.
5. **The subsequent version/CSV ECP step must fail** so that the create status goes negative while `EcpContext` is still live — this is what drives execution into the error-cleanup `FltFreeExtraCreateParameter` at `0x1c0007d5a` on the still-listed ECP. This failure is a secondary error path (for example an internal ECP allocation/insert failure) and is not directly attacker-controlled.
6. **Observable effect:** the ECP context is freed while the IRP's ECP list still references it. Because the filter manager frees the ECPs in that list at create teardown, the block is freed a second time (or walked after free), which can corrupt the kernel pool and bugcheck the machine. With Driver Verifier Special Pool enabled on the `CCFF` tag, the invalid free/dereference is caught at the point it occurs.

---

## 6. Exploit Primitive & Development Notes

### Primitive

**Kernel pool double-free / use-after-free.** The freed ECP context is a small pool allocation (0x14 bytes, tag `CCFF`). After the error-cleanup `FltFreeExtraCreateParameter` at `0x1c0007d5a`, the block is freed while it is still linked in the IRP's ECP list. The filter manager frees the ECPs remaining in that list when the create tears down, so the same block is freed a second time (or its stale contents are walked before that), corrupting the kernel pool.

### Reachability and Impact

- The primitive is only reached on an error path: a create that carries the app-instance EA succeeds in allocating and inserting the ECP, and then a subsequent version/CSV ECP sub-step returns a failure status. That secondary failure is not directly attacker-controlled — it is driven by internal conditions such as an ECP allocation/insert failure — so triggering is non-deterministic.
- No control over the freed block's replacement contents, timing, or a follow-on function-pointer/write primitive is demonstrable from these binaries. The concrete, reachable impact is kernel pool corruption, i.e. a local denial of service (bugcheck). There is no demonstrated path to privilege escalation.
- The environment is constrained: `ccffilter.sys` only attaches to Cluster Shared Volume volumes, so a CSV-backed host is required.

---

## 7. Debugger PoC Playbook

Assumes WinDbg/KD attached to the **unpatched** `ccffilter_unpatched.sys` on a system with a Cluster Shared Volume mounted.

### Breakpoints

```text
bp ccffilter_unpatched!CCFPreCreate
```
**Why:** Entry to the `IRP_MJ_CREATE` pre-op. Confirm the create targets a CSV path by dumping the file name from the callback data. `rcx = FLT_CALLBACK_DATA* (arg1)`, `rdx = FLT_RELATED_OBJECTS* (arg2)`.

```text
bp 0x1c0007baa
```
**Why:** `CCFAddEcpToCreate` call site — the `FltInsertExtraCreateParameter` ownership transfer happens inside. After this returns `>= 0`, the ECP at `[rsp+0x48]` is owned by the IRP's ECP list and `var_b8` is `0`.

```text
bp 0x1c0007d5a
```
**Why:** **The vulnerable `FltFreeExtraCreateParameter` call** in the error-cleanup. `rcx = filter handle`, `rdx = EcpContext` (the still-listed ECP). This block is reached only when the status (`edi`) is negative — i.e. a version/CSV ECP step failed while `EcpContext` was still live.

### What to Inspect at Each Breakpoint

| Breakpoint | Register / Memory | Meaning |
|---|---|---|
| `CCFPreCreate` entry | `rcx` | `FLT_CALLBACK_DATA*` — follow `->Iopb->TargetFileObjectName->Buffer` to confirm CSV path. |
| `CCFPreCreate` entry | `rdx` | `FLT_RELATED_OBJECTS*` — `rdx->[0x8]` is the filter handle passed to Flt ECP APIs. |
| `0x1c0007baa` (pre-call) | `rdx` | `EcpContext` — the freshly allocated 0x14-byte `CCFF`-tagged ECP about to be inserted. |
| `0x1c0007baa` (post-return) | `rax` | Status from `CCFAddEcpToCreate`. Must be `>= 0` to leave the ECP listed and live. |
| `0x1c0007d5a` (pre-free) | `rdx` | The ECP being freed (still in IRP ECP list). Note this value — it is the dangling pointer. |
| `0x1c0007d5a` (pre-free) | `edi` | Status; must be `< 0` (a failed version/CSV ECP step) to reach this block. |

### Key Instructions / Offsets

| Offset | Instruction | Significance |
|---|---|---|
| `0x1c0007baa` | `call CCFAddEcpToCreate` | `FltInsertExtraCreateParameter` ownership transfer inside; `var_b8` zeroed. |
| `0x1c0007bb7` | `jns 0x1c0007bfd` | Branch into success path (`v4 >= 0`). |
| `0x1c0007c4b` | `call FltFreeExtraCreateParameter` | Consumed-branch free; unchanged and unreached (`var_b8 == 0`). |
| `0x1c0007d43` | `test edi, edi / jns` | Error-cleanup gate (status `< 0`). |
| `0x1c0007d5a` | `call cs:__imp_FltFreeExtraCreateParameter` | **`FltFreeExtraCreateParameter` on the still-listed ECP — THE bug.** |
| `0x1c0007760` | — | `CCFPreCreate` entry. |

### Trigger Setup (from user mode)

1. Confirm CSV mounted and `ccffilter.sys` filtering:
   ```text
   fltmc instances
   ```
2. Build an `EaBuffer` containing a CCFF app-instance EA so that `CCFFilterAppInstanceEA` sets `var_b7` and forces the `GUID_ECP_NETWORK_APP_INSTANCE` allocation in `label_1c0007a96`. Ensure no pre-existing app-instance ECP is present so `CCFFindAppInstanceEcp` leaves `var_b8 == 0` at entry, and arrange for the subsequent version/CSV ECP step to fail so the create status goes negative.
3. From a standard user, open the file with `NtCreateFile` supplying the CCFF app-instance `EaBuffer`, under conditions that force the subsequent version/CSV ECP sub-step to fail (for example an ECP allocation/insert failure), so the create status goes negative while `EcpContext` is still live.

### Expected Observation

- At `0x1c0007d5a`: `rdx` is the ECP being freed. Step over; the ECP at `rdx` is now freed but the IRP's ECP list still references it.
- Subsequently, when the filter manager tears down the create's ECP list, the same block is freed again / walked after free, producing kernel pool corruption and a bugcheck.
- With Driver Verifier Special Pool enabled on the `CCFF` tag, the invalid free/dereference is caught at the point it occurs, with the faulting address at the freed ECP.

### Struct / Offset Notes

- ECP context: 0x14 bytes total. `[ECP+0]` = length word (`= 0x14`), `[ECP+2]` zeroed at init, `[ECP+4]` = 16-byte app-instance payload.
- Pool tag: `"CCFF"` (`0x46464343`).
- `FLT_CALLBACK_DATA (arg1, rcx)` → `->Iopb` → `->Parameters.Create.EaBuffer` is the parsed EA buffer.
- `arg2[1]` (`rdx->[0x8]`) = filter handle passed to every `Flt*` ECP API.

---

## 8. Changed Functions — Full Triage

### `CCFPreCreate` (`sub_1c0007760`) — **security-relevant**
- **Similarity:** 0.9658
- **Change type:** behavioral / security-relevant
- **What changed:** On the `CCFAddEcpToCreate` success path, the unpatched code clears the local ECP pointer (`mov qword [rsp+0x48], r14`) only inside the `if (var_b8 != 0)` branch, which is never taken because `CCFAddEcpToCreate` zeroes `var_b8`. So after a successful insert the local `EcpContext` stays live, and the function's error-cleanup (`0x1c0007d5a`) frees it while it is still linked in the IRP's ECP list if a version/CSV ECP step fails. The patch adds a success-path clear of `EcpContext` (via new helper `EvaluateCurrentState` / `sub_1c00017b8`, which calls `EvaluateFeature` / `sub_1c0001740` on `g_Feature_2963746106_60258290` and returns `cachedstate != 1`), using `neg eax; sbb rcx,rcx; and rcx,[rsp+0x48]` at the first site and a second `EvaluateCurrentState`-gated `cmovnz` at `0x1c0007c6b`. The `FltFreeExtraCreateParameter` calls themselves are identical on both sides; only the local-pointer clear placement changed, so the error-cleanup no longer frees the still-listed ECP. **This is the only behavioral change in the patch.**

### `DriverEntry` — cosmetic
- **Similarity:** 0.9922
- **Change type:** cosmetic (symbol / label stripping only)
- **What changed:** Symbol names and addresses shifted between builds (`CCFDispatchUnsupported (sub_1c00081f0)`, `CCFDispatchDeviceControl (sub_1c0007f30)`, `CCFProcessNotification (sub_1c0008270)`, `CCFApplyDeviceAcl (sub_1c00096d8)`, `CCFUnload (sub_1c0007590)`, `WPP_SF_d (sub_1c0001034)`). Global addresses shifted (`data_1c00041a8 → 0x1c00041c8`, `CCFCacheGuardedMutex → 0x1c0004180`). Logic — `FltRegisterFilter`, `IoCreateDevice` (`\Device\CCFFilter`, `DeviceType=0x14`, `Characteristics=0x100`), `PsSetCreateProcessNotifyRoutine`, `FltStartFiltering`, device-ACL application, unload-on-failure — is equivalent. The `IRP_MJ_DEVICE_CONTROL` dispatch (`CCFDispatchDeviceControl` / `sub_1c0007f30`) handles IOCTL codes `0x140000 / 0x14400c / 0x144018 / 0x144004 / 0x144008` with explicit `InputBufferLength` / `OutputBufferLength` checks (`cmp r9d, 0x20 / 0x28 / 0x10 / 0x8`). **No behavioral change.**

---

## 9. Unmatched Functions

None in the top-level matched set. The patched build additionally introduces the Feature Staging helpers `EvaluateCurrentState` (`sub_1c00017b8`), `EvaluateCurrentStateFromRegistry` (`sub_1c0001518`), `EvaluateFeature` (`sub_1c0001740`), and `rbc_InitializeFeatureStaging` (`sub_1c00017e4`), which back the success-path clear in `CCFPreCreate`.

---

## 10. Confidence & Caveats

**Confidence: High.**

- The ownership transfer is unambiguous: `CCFAddEcpToCreate` calls `FltInsertExtraCreateParameter` (the IRP's ECP list now owns the ECP) and zeroes its out-flag `var_b8`.
- The unpatched success path leaves the local `EcpContext` live (the clear is inside the never-taken `if (var_b8)` branch), and the error-cleanup at `0x1c0007d5a` (`call FltFreeExtraCreateParameter`) frees that still-listed ECP when a version/CSV ECP step fails. Both are directly visible in the disassembly and the decompilation.
- The patch's success-path clear via `EvaluateCurrentState` (`sub_1c00017b8`) is consistent with a deliberate lifetime/ownership fix, gated by a Windows Feature Staging flag rather than a refactor.

**Assumptions to verify manually:**

1. **EA buffer format.** The exact byte layout of the "CCFF app-instance EA" that drives `CCFFilterAppInstanceEA` into the `var_b7` branch was inferred from context, not reconstructed field-by-field. A PoC author should reverse `CCFFilterAppInstanceEA` to build the EA precisely.
2. **Failure of the version/CSV ECP step.** Reaching the error-cleanup free requires the subsequent `CCFFindAppInstanceVersionEcp` / `CCFLookupAndAddVersionEcpToCreate` sub-step to return an error while `EcpContext` is still live. Confirm the input conditions that force that failure.
3. **CSV volume presence.** The minifilter only attaches to CSV volumes — a PoC requires a host with CSV configured, or an environment where the filter can be coerced into attaching (lab cluster setup).
4. **Manifestation.** The concrete fault is the second free / stale-pointer walk performed by the filter manager's ECP-list teardown at create completion. Confirming the exact teardown site and timing (and whether a given build catches it as a double-free or a use-after-free) requires dynamic observation; no follow-on read/write or code-execution primitive is claimed.
5. **Feature-staging state.** The success-path clear is applied when `EvaluateCurrentState` returns nonzero, i.e. when `g_Feature_2963746106_60258290_cachedstate != 1` (`0x1c00017d3`: `cmp ecx, 1` / `setnz al`, consumed by the `cmovnz` at `0x1c0007c77`). When the cached state is `1` the patched build keeps the pointer live, matching the unpatched behavior. Because this is a runtime Feature Staging gate read from the registry, the fix is a staged rollout; a researcher should confirm the production feature state on the target to know whether the clear is active.
