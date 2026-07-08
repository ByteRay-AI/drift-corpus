Title: microsoft.bluetooth.legacy.leenumerator.sys — child-list enumeration refactor and trace-only updates
Date: 2026-06-29
Slug: microsoft.bluetooth.legacy.leenumerator_5a475369-microsoft.bluetooth.legacy-report-20260629-135416
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Unknown
KBDate: 2026-03-10

### 1. Overview
- **Unpatched Binary:** `microsoft.bluetooth.legacy.leenumerator_unpatched.sys`
- **Patched Binary:** `microsoft.bluetooth.legacy.leenumerator_patched.sys`
- **Overall Similarity Score:** 0.9887
- **Diff Statistics:** 180 unpatched functions, 181 patched. 178 identical, 2 changed (one materially, one trace-only), 1 function added (a WPP trace helper).
- **Verdict:** No security-relevant change. The only function with a material logic change is `RootFdo::EnumerateDevices` (unpatched `@ 0x1C00017B0`, patched `@ 0x1C00019B8`), which re-enumerates the driver's own child device PDOs. The patch (a) hoists a WDF child-list handle fetch to the function prologue and (b) adds an empty begin/end child-list scan on the "zero devices present" path so stale child PDOs are removed. Neither is a memory-safety fix. The remaining differences are WPP software-tracing updates.

---

### 2. Change Summary

- **Severity:** None (no reachable security impact)
- **Class:** Functional refactor / device-enumeration correctness (stale child-PDO cleanup) + tracing
- **Affected Function:** `Microsoft::Bluetooth::Legacy::LEEnumerator::RootFdo::EnumerateDevices` (unpatched `@ 0x1C00017B0`, patched `@ 0x1C00019B8` — matched by identical mangled symbol, not by reused address)

**What the function does:**
`RootFdo::EnumerateDevices` queries the local Bluetooth radio (via synchronous WDF I/O-target sends) for the set of currently present Bluetooth LE devices, then reports them as child devices of the root FDO through the KMDF static child-list API. It is invoked from `RootFdo::DeviceD0Entry` (`@ 0x1C000CD00`, power-up) and `RootFdo::s_PnPNotificationCallback` (`@ 0x1C000D690`, device-change notification).

**What actually changed:**
1. The call `WdfFdoGetDefaultChildList(*(this+0x1c8))` — decompiled as `WdfFunctions_01015 + 0x420` — was moved from a late position (after both radio queries and both pool allocations) to the function prologue. This call returns the FDO's persistent default child-list handle; the object at `*(this+0x1c8)` is the RootFdo's own `WDFDEVICE`, owned by the driver for the device's lifetime. Reordering when this handle is fetched has no object-lifetime consequence.
2. On the path where the radio reports zero present devices, the patched build now calls `WdfChildListBeginScan` (`+0x20`) immediately followed by `WdfChildListEndScan` (`+0x28`) with no `AddOrUpdate` in between. An empty begin/end scan marks all previously reported child PDOs missing and removes them. The unpatched build skipped the child-list update entirely on this path, so stale child device nodes would linger. This is a PnP enumeration-correctness change, not a security fix.
3. WPP software-trace calls were added (a new `WPP_RECORDER_SF_sL` helper is invoked; `WPP_RECORDER_SF_sq` at entry/exit), and the auto-generated WPP trace-GUID symbol was renamed build-wide. Tracing only.

---

### 3. Pseudocode Diff

The `WdfFunctions_01015 + N` calls are KMDF function-table dispatches. Relevant indices: `+0x420` = `WdfFdoGetDefaultChildList`, `+0x20` = `WdfChildListBeginScan`, `+0x28` = `WdfChildListEndScan`, `+0x48` = `WdfChildListAddOrUpdateChildDescriptionAsPresent` (WDFFUNCENUM indices 132, 4, 5, 9).

```c
// === UNPATCHED @ 0x1C00017B0 ===
void RootFdo::EnumerateDevices(RootFdo *this) {
    // radio query #1 (WdfFunctions+0x7b8) using *(this+0x1d0)
    // radio query #2 (WdfFunctions+0x5d0); read device count v33
    if (count == 0) { WPP_trace(); goto cleanup; }        // <-- no child-list update at all
    P = ExAllocatePoolWithTag(NonPagedPoolNx, 832*count+24, 0x646D4370);
    // radio query #3/#4 ...
    P2 = ExAllocatePoolWithTag(NonPagedPoolNx, 0x468, 0x646D4370);
    childlist = WdfFdoGetDefaultChildList(*(this+0x1c8));  // <-- fetched LATE, in success path only
    WdfChildListBeginScan(childlist);
    for (i = 0; i < count; ++i)
        WdfChildListAddOrUpdateChildDescriptionAsPresent(childlist, P2, 0);
    WdfChildListEndScan(childlist);
cleanup: /* free P, P2 */
}

// === PATCHED @ 0x1C00019B8 ===
void RootFdo::EnumerateDevices(RootFdo *this) {
    childlist = WdfFdoGetDefaultChildList(*(this+0x1c8));  // <-- fetched at ENTRY
    // radio query #1/#2; read device count v35
    if (count == 0) {                                      // <-- NEW: flush stale children
        WdfChildListBeginScan(childlist);
        WdfChildListEndScan(childlist);
        goto cleanup;
    }
    P = ExAllocatePoolWithTag(NonPagedPoolNx, 832*count+24, 0x646D4370);
    // radio query #3/#4 ...
    P2 = ExAllocatePoolWithTag(NonPagedPoolNx, 0x468, 0x646D4370);
    WdfChildListBeginScan(childlist);
    for (i = 0; i < count; ++i)
        WdfChildListAddOrUpdateChildDescriptionAsPresent(childlist, P2, 0);
    WdfChildListEndScan(childlist);
cleanup: /* free P, P2 */
}
```

---

### 4. Assembly Analysis

The only relocation-independent difference is the position of the `WdfFdoGetDefaultChildList` fetch (`WdfFunctions_01015 + 0x420`) and the added empty scan on the zero-device path. All indirect WDF calls go through the CFG guard thunk `__guard_dispatch_icall_fptr`.

**Unpatched (`@ 0x1C00017B0`) — child-list handle fetched late, after the radio queries:**
```
00000001C000180F  mov     rax, cs:WdfFunctions_01015
00000001C000181A  mov     rax, [rax+7B8h]        ; radio query #1  (executes FIRST)
00000001C0001821  call    cs:__guard_dispatch_icall_fptr
...
00000001C0001AAF  mov     rax, [rax+420h]        ; WdfFdoGetDefaultChildList (executes LATE)
00000001C0001AB6  call    cs:__guard_dispatch_icall_fptr
00000001C0001C22  mov     rax, [rax+48h]         ; AddOrUpdateChildDescriptionAsPresent (loop)
00000001C0001C4F  mov     rax, [rax+28h]         ; EndScan
```

**Patched (`@ 0x1C00019B8`) — child-list handle fetched in prologue, before the radio queries:**
```
00000001C0001A01  mov     rax, [rax+420h]        ; WdfFdoGetDefaultChildList (executes EARLY)
00000001C0001A08  call    cs:__guard_dispatch_icall_fptr
00000001C0001A80  mov     rax, [rax+7B8h]        ; radio query #1  (now AFTER the fetch)
...
00000001C0001B75  mov     rax, [rax+20h]         ; BeginScan  \  empty scan on the
00000001C0001B90  mov     rax, [rax+28h]         ; EndScan    /  zero-device path (NEW)
...
00000001C0001EAB  mov     rax, [rax+48h]         ; AddOrUpdateChildDescriptionAsPresent (loop)
00000001C0001ED8  mov     rax, [rax+28h]         ; EndScan (populated path)
```

`*(this+0x1c8)` (source: `mov rdx, [rcx+0x1c8]` in the prologue of the patched build) is the argument to `WdfFdoGetDefaultChildList`. It is the RootFdo's own `WDFDEVICE`, a long-lived object created by the driver, not a handle a remote Bluetooth peer can free.

---

### 5. Why this is not a Use-After-Free / TOCTOU

- `WdfFunctions_01015 + 0x420` is `WdfFdoGetDefaultChildList`, which returns the FDO's persistent default child-list handle. It is not a reference acquisition on a peer-controlled connection object. `+0x20` / `+0x28` / `+0x48` are `WdfChildListBeginScan` / `WdfChildListEndScan` / `WdfChildListAddOrUpdateChildDescriptionAsPresent`, i.e. a scan/report bracket, not addref/release.
- The object at `*(this+0x1c8)` is the driver's own root-FDO `WDFDEVICE`. Its lifetime is bound to the device stack, not to any Bluetooth LE connection; a remote disconnect or surprise-removal does not free it out from under this function.
- The preceding `WdfFunctions_01015 + 0x7b8` / `+0x5d0` calls are synchronous WDF I/O-target sends that query the local radio for the device list. They are not asynchronous request blocks racing a remote peer's disconnect.
- Reordering the child-list-handle fetch has no lifetime consequence: the handle is valid throughout the function in both builds. The change is a code-generation reorder plus the added stale-child cleanup on the empty path.

There is no attacker-controlled freed pointer, no reachable memory-corruption primitive, and therefore no exploit primitive, trigger sequence, or proof-of-concept to describe.

---

### 6. Changed Functions — Full Triage

- **`RootFdo::EnumerateDevices`** (unpatched `@ 0x1C00017B0` → patched `@ 0x1C00019B8`, 311 → 347 instructions): Not security-relevant. Hoisted `WdfFdoGetDefaultChildList` to the prologue; added an empty `WdfChildListBeginScan`/`EndScan` on the zero-device path to remove stale child PDOs; added WPP trace calls. A functional/refactor change.
- **WPP trace recorder helper `@ 0x1C00015C8`** (`WPP_RECORDER_SF_s_guid_` in the unpatched build; that address is occupied by a different helper, `WPP_RECORDER_SF_sL`, in the patched build): Not security-relevant. WPP software-tracing plumbing; same instruction count, only register/operand differences.

### 7. Unmatched Functions
- **Added (patched only):** `WPP_RECORDER_SF_sL` — a WPP software-trace recorder helper. Tracing only, not security-relevant. (The unpatched build has 180 functions; the patched build has 181.)
- **Removed:** None.

### 8. Confidence & Caveats
- **Confidence:** High. Matching by mangled symbol and by normalized instruction sequence shows exactly two changed functions plus one added WPP helper. The child-list identification follows from the KMDF function-table indices (`+0x420`/`+0x20`/`+0x28`/`+0x48` = WDFFUNCENUM 132/4/5/9) and the begin/add-in-loop/end structure.
- The prior classification of this diff as a Use-After-Free (CWE-416) is not supported by the binaries: the moved call is a child-list handle fetch on the driver's own FDO device, not a reference acquisition on a peer-freeable object.
