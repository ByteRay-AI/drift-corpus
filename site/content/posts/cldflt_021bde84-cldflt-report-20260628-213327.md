Title: cldflt.sys — Missing authorization on feature-gated sync-root disconnect and insert (CWE-862) fixed
Date: 2026-06-28
Slug: cldflt_021bde84-cldflt-report-20260628-213327
Category: Corpus
Author: Argus
Summary: KB5078885
Severity: Medium

## 1. Overview

* **Unpatched Binary:** `cldflt_unpatched.sys`
* **Patched Binary:** `cldflt_patched.sys`
* **Overall Similarity Score:** `0.9894` (High)
* **Diff Statistics:** 998 matched functions, 6 changed functions, 992 identical functions, 0 unmatched functions in either direction.
* **Verdict:** The patch removes a WIL (Windows Implementation Library) feature-staging gate (`Feature_565656888__private_IsEnabledDeviceUsage`, `sub_1C00097A4`) from the cloud sync-root service dispatcher so that the validated code paths are always taken. In the unpatched binary, when that feature is **disabled**, `CldiPortProcessServiceCommands` (`sub_1C0060514`) takes legacy branches: it disconnects a sync root through `CldSyncDisconnectRootDeprecated` (`sub_1C00630E8`), which looks the entry up by an attacker-supplied key and tears it down **without checking the caller-supplied token**, and it registers a sync root through a raw `RtlDeleteElementGenericTableAvl`/`RtlInsertElementGenericTableAvl` pair that **skips the owner/token check** performed by `CldiPortInsertSyncRootNoLock` (`sub_1C005DDB4`). The patched dispatcher (`0x1C00604E4`) deletes both legacy branches and always calls the token-checked `CldSyncDisconnectRoot` and the owner/token-validating `CldiPortInsertSyncRootNoLock`. The port `\CLDMSGPORT` is reachable by any authenticated user, so the disabled-feature path lets a caller tear down or overwrite another sync provider's sync-root state on a shared volume. Severity is Medium: impact is local integrity/denial of service against cloud sync-root state, and it is only reachable while the feature is disabled.

---

## 2. Vulnerability Summary

### Finding 1: Sync-Root Registration Branch Ordering - No Authorization Change
* **Severity:** None (not security-relevant)
* **Vulnerability Class:** N/A
* **Affected Function:** `CldSyncConnectRoot` (`sub_1C0062CC0`, patched `0x1C0062BD0`)

**Analysis:**
`CldSyncConnectRoot` registers cloud sync-root state in a push-lock-protected AVL table. The unpatched version calls `Feature_565656888__private_IsEnabledDeviceUsage` (`sub_1C00097A4`) to select between two branches, and the patched version (`0x1C0062BD0`) removes that call and keeps a single branch. This is **not** an authorization change: both unpatched branches perform the same ownership check - they compare the existing entry's owner field at offset `0x60` (`+96`) against `a2` and the token at offset `0` against `a7`, and both reject a mismatch with `STATUS_CLOUD_FILE_NOT_IN_SYNC` (`0xC000CF09`). The only difference between the two unpatched branches is the ordering of a preliminary test: the feature-disabled branch keys on the reference count at offset `0x30` (`+48`) first, while the feature-enabled branch keys on whether the owner field at `0x60` is `NULL` first. The patched function is byte-for-byte equivalent to the unpatched feature-enabled branch. No cross-owner overwrite is possible in either build through this function; the earlier claim of an ownership bypass here is not supported by the binaries.

### Finding 2: Feature-Gated Missing Authorization in the Service-Command Dispatcher
* **Severity:** Medium
* **Vulnerability Class:** Missing/Insufficient Authorization Check (CWE-862)
* **Affected Function:** `CldiPortProcessServiceCommands` (`sub_1C0060514`, patched `0x1C00604E4`)

**Root Cause:**
`CldiPortProcessServiceCommands` is the cloud-files service dispatcher reachable through `\CLDMSGPORT`. Both the sync-root **register** and **disconnect** operations are gated on the WIL feature toggle `Feature_565656888__private_IsEnabledDeviceUsage` (`sub_1C00097A4`). When the feature is **enabled** the dispatcher uses the validated helpers; when it is **disabled** it uses legacy paths that drop validation:

* **Disconnect path (primary gap):** enabled → `CldSyncDisconnectRoot`, which looks the entry up by key and tears it down only if the caller-supplied token matches the stored token (`*entry == a3`), rejecting a mismatch with `STATUS_CLOUD_FILE_NOT_SUPPORTED` (`0xC000CF0B`). Disabled → `CldSyncDisconnectRootDeprecated` (`sub_1C00630E8`), which takes no token argument and disconnects whatever entry the key resolves to, **with no token check at all**. Both the lookup key and the token are read from the user-mode message buffer, and this table (`v117+16`) is a per-volume table shared across connections, so on the disabled path a caller who knows only a sync-root key can disconnect another provider's sync root.
* **Register path (secondary gap):** enabled → `CldiPortInsertSyncRootNoLock` (`sub_1C005DDB4`), which rejects an insert when the existing entry has an owner set (offset `0x60`) and the token at offset `0x18` does not match. Disabled → a raw `RtlDeleteElementGenericTableAvl` + `RtlInsertElementGenericTableAvl` into the per-connection table at `a1+104`, **with no owner/token check**. This table is bound to a single sync-provider process (see `a1+80`), so the impact of the register gap is intra-connection state integrity rather than cross-process.

The patched dispatcher (`0x1C00604E4`) removes the feature gate and always calls the validated helpers: `CldiPortInsertSyncRootNoLock` (`sub_1C005DD94`) on register and `CldSyncDisconnectRoot` on disconnect.

Note: the `SrIn` size check is **not** the vulnerability. Both binaries contain the identical guard that rejects a declared size `< 0x18` with `STATUS_INVALID_PARAMETER` (`0xC000000D`); it is unchanged by the patch.

**Call Chain:**
1. `FilterSendMessage(\CLDMSGPORT)` [User Mode]
2. `CldiPortNotifyMessage` (`sub_1C00501B0`) [MessageNotifyCallback registered via `FltCreateCommunicationPort`]
3. `CldiPortProcessServiceCommands` (`sub_1C0060514`) [service-command dispatcher; feature-gated disconnect/register]

---

## 3. Pseudocode Diff

### Finding 1: `CldSyncConnectRoot` (`sub_1C0062CC0`) - ownership validated in both branches

```c
// --- UNPATCHED CldSyncConnectRoot (sub_1c0062cc0) ---
if (Feature_565656888__private_IsEnabledDeviceUsage() == 0) {
    // feature disabled: preliminary key on refcount at entry+0x30
    if (*(int*)(entry+48) > 0) {
        if (*(entry+96) == a2 && *entry == a7) { status = 0; *a8 = entry; } // owner + token
        else { status = STATUS_CLOUD_FILE_NOT_IN_SYNC; /* 0xc000cf09 */ }
    } else goto create_new_entry;
} else {
    // feature enabled: preliminary key on owner field at entry+0x60
    if (*(entry+96) == 0) goto create_new_entry;
    if (*(entry+96) == a2 && *entry == a7) {                                // owner + token
        if (*(int*)(entry+48) > 0) { status = 0; *a8 = entry; }
        else goto create_new_entry;
    }
    else { status = STATUS_CLOUD_FILE_NOT_IN_SYNC; TlmWriteSyncRootAlreadyConnected(); }
}

// --- PATCHED CldSyncConnectRoot (0x1c0062bd0): identical to the unpatched feature-enabled branch ---
if (entry == NULL || *(entry+96) == 0) goto create_new_entry;              // owner field at 0x60
if (*(entry+96) == a2 && *entry == a7) {                                    // owner + token
    if (*(int*)(entry+48) > 0) { status = 0; *a8 = entry; }
    else goto create_new_entry;
}
else { status = STATUS_CLOUD_FILE_NOT_IN_SYNC; TlmWriteSyncRootAlreadyConnected(); }
```

Both unpatched branches enforce the owner (`+0x60`) and token (`+0`) checks; the patch only drops the feature gate and the refcount-first ordering.

### Finding 2: `CldiPortProcessServiceCommands` (`sub_1C0060514`)

```c
// --- UNPATCHED sub_1c0060514, register path (after CldSyncConnectRoot succeeds) ---
if (Feature_565656888__private_IsEnabledDeviceUsage() != 0) {
    FltAcquirePushLockExclusiveEx(a1+96, 0);
    status = CldiPortInsertSyncRootNoLock(a1, key1, key0, token);  // validates owner/token
} else {
    // feature disabled: raw insert into per-connection table a1+104, NO owner/token check
    Buffer = { key0, key1 };
    FltAcquirePushLockExclusiveEx(a1+96, 0);
    RtlDeleteElementGenericTableAvl(a1+104, &Buffer);
    RtlInsertElementGenericTableAvl(a1+104, &Buffer, 0x10, &NewElement);
}

// --- UNPATCHED sub_1c0060514, disconnect path ---
if (Feature_565656888__private_IsEnabledDeviceUsage() != 0)
    status = CldSyncDisconnectRoot(volume, key, token, &out);      // checks stored token == token
else
    status = CldSyncDisconnectRootDeprecated(volume, key, &out);   // NO token check

// --- PATCHED sub_1c00604e4 ---
FltAcquirePushLockExclusiveEx(a1+96, 0);
status = CldiPortInsertSyncRootNoLock(a1, key1, key0, token);      // register: always validated
FltReleasePushLockEx(a1+96, 0);
...
status = CldSyncDisconnectRoot(volume, key, token, &out);          // disconnect: always token-checked

// --- CldiPortInsertSyncRootNoLock (sub_1c005dd94 / unpatched sub_1c005ddb4), both binaries ---
entry = CldiPortLookupSyncRootNoLock(a1, key0);
if (entry && *(entry+96) != 0 && *(entry+24) != token)            // owner set & token mismatch
    return STATUS_CLOUD_FILE_NOT_IN_SYNC;                          // 0xc000cf09
RtlDeleteElementGenericTableAvl(...); RtlInsertElementGenericTableAvl(...);

// --- CldSyncDisconnectRoot vs CldSyncDisconnectRootDeprecated (both binaries) ---
// CldSyncDisconnectRoot(a1, key, token, out): entry = lookup(key);
//     if (*entry == token) disconnect; else status = 0xc000cf0b;   // token enforced
// CldSyncDisconnectRootDeprecated(a1, key, out): entry = lookup(key);
//     if (entry) disconnect;                                        // no token check
```

---

## 4. Assembly Analysis

### Finding 1: `CldSyncConnectRoot`

Owner/token check in the unpatched feature-enabled branch (`sub_1c0062cc0`):
```assembly
00000001C0062D27  call    Feature_565656888__private_IsEnabledDeviceUsage
00000001C0062D2C  test    eax, eax
00000001C0062D2E  jz      loc_1C0062DE2          ; feature-disabled branch
00000001C0062D34  mov     rax, [rsi+60h]         ; owner field
00000001C0062D45  cmp     rax, rbx               ; owner check
00000001C0062D48  jnz     short loc_1C0062D70    ; -> STATUS_CLOUD_FILE_NOT_IN_SYNC
00000001C0062D4E  cmp     [rax], r15             ; token check
00000001C0062D51  jnz     short loc_1C0062D70
00000001C0062D62  xor     edi, edi               ; success only after both checks pass
```
The feature-disabled branch performs the same validation and rejects a mismatch with the same status:
```assembly
00000001C0062DE2  mov     eax, [rsi+30h]         ; refcount (entry+0x30), keyed first
00000001C0062DE7  jle     loc_1C0062E6E          ; refcount<=0 -> create new
00000001C0062E01  cmp     [rcx], rax             ; owner/token comparison
00000001C0062E04  jnz     short loc_1C0062E14
00000001C0062E14  mov     ebx, 0C000CF09h        ; STATUS_CLOUD_FILE_NOT_IN_SYNC on mismatch
```
The patched `CldSyncConnectRoot` at `0x1C0062BD0` has no call to the feature toggle; its single path is the owner/token-validated branch above.

### Finding 2: Feature-Gated Dispatcher Paths

**Unpatched `CldiPortProcessServiceCommands` (`sub_1c0060514`) register path:**
```assembly
00000001C00615B7  call    CldSyncConnectRoot
00000001C0061605  call    Feature_565656888__private_IsEnabledDeviceUsage  ; register gate
00000001C0061630  call    CldiPortInsertSyncRootNoLock                     ; enabled: validated insert
; feature-disabled branch (raw insert, no owner/token check):
00000001C0061677  lea     rcx, [rbx+68h]         ; Table = a1+104 (per-connection)
00000001C006167B  call    cs:__imp_RtlInsertElementGenericTableAvl
```

**Unpatched disconnect path:**
```assembly
00000001C006187A  call    Feature_565656888__private_IsEnabledDeviceUsage  ; disconnect gate
00000001C0061886  test    eax, eax
00000001C0061888  jz      short loc_1C0061899
00000001C0061892  call    CldSyncDisconnectRoot                            ; enabled: token-checked
00000001C006189D  call    CldSyncDisconnectRootDeprecated                  ; disabled: no token check
```

**Patched `CldiPortProcessServiceCommands` (`sub_1c00604e4`):**
```assembly
00000001C0061579  call    CldSyncConnectRoot
00000001C00615E3  call    CldiPortInsertSyncRootNoLock   ; unconditional validated insert
00000001C00617D3  call    CldSyncDisconnectRoot          ; unconditional token-checked disconnect
```
The patched dispatcher contains no call to `Feature_565656888__private_IsEnabledDeviceUsage`, no raw `RtlInsertElementGenericTableAvl` on the register path, and no `CldSyncDisconnectRootDeprecated`.

**Gate `Feature_565656888__private_IsEnabledDeviceUsage` (`sub_1c00097a4`, WIL feature toggle):**
```assembly
00000001C00097AE  mov     eax, dword [rel 0x1c0024780]  ; global feature descriptor
00000001C00097B8  test    al, 0x10                       ; feature-present bit
00000001C00097BC  and     eax, 0x1                       ; return enabled bit
00000001C00097CB  call    0x1c00097dc                    ; Feature_565656888__private_IsEnabledFallback
```

---

## 5. Trigger Conditions

1. Open the Cloud Files minifilter communication port `\CLDMSGPORT` with `FilterConnectCommunicationPort`. The port is created (in `CldiPortStart`) with the security descriptor built from SDDL `D:P(A;;GA;;;AU)` via `SeSddlSecurityDescriptorFromSDDL` and passed to `FltCreateCommunicationPort`, so any authenticated user can connect and send messages.
2. Send a `FilterSendMessage` that routes to the sync-root register or disconnect operation in `CldiPortProcessServiceCommands` (`sub_1C0060514`). The message parses a `SrIn` structure (magic `0x6E497253`); its declared size (`*(arg3+0x2a)`) must be `>= 0x18` and pass CRC and entry-count validation, or it is rejected with `STATUS_INVALID_PARAMETER` (`0xC000000D`) in both binaries.
3. The lookup key and token used by the register/disconnect operation are read from the message buffer, so both are attacker-supplied.
4. On an unpatched build where `Feature_565656888` is **disabled**, the disconnect operation reaches `CldSyncDisconnectRootDeprecated`, which disconnects the sync root matching the supplied key without checking the token, and the register operation reaches the raw `RtlInsertElementGenericTableAvl` at `0x1C006167B` without an owner/token check.

---

## 6. Exploit Primitive & Development Notes

### Primitive: Token-Free Sync-Root Disconnect
* **What it provides:** On the feature-disabled unpatched path, the ability to disconnect a cloud sync-root entry keyed by an attacker-supplied identifier on a per-volume sync-root table shared across connections, without proving knowledge of the stored token. A caller who knows only the sync-root key can tear down another sync provider's root.
* **Next steps for exploit:** Enumerate or predict the sync-root key of a target provider on the same volume and issue the disconnect operation, forcing the provider into an inconsistent/disconnected state (denial of service against cloud synchronization).
* **Mitigations:** Traditional kernel exploit mitigations (SMEP, SMAP, kASLR) do not apply to this logic issue. Reachability depends on `Feature_565656888` being disabled; the patched binary removes the unvalidated path.

### Secondary: Per-Connection Raw Insert
* **What it provides:** On the feature-disabled register path, a raw delete+insert into the per-connection sync-root table (`a1+104`) with no owner/token check. Because that table is bound to a single sync-provider process (`a1+80`), the effect is intra-connection state integrity rather than a cross-process overwrite.

---

## 7. Debugger PoC Playbook

Attach a kernel debugger to the unpatched system to observe the feature-gated paths.

### Breakpoints
```text
bp cldflt_unpatched!sub_1c0060514                    ; CldiPortProcessServiceCommands (dispatcher)
bp cldflt_unpatched!sub_1c00097a4                    ; Feature_565656888__private_IsEnabledDeviceUsage
bp cldflt_unpatched!sub_1c0060514+0x1167             ; 0x1c006167b raw RtlInsertElementGenericTableAvl
bp cldflt_unpatched!sub_1c00630e8                    ; CldSyncDisconnectRootDeprecated (no token check)
```
* **`CldiPortProcessServiceCommands` (`sub_1c0060514`)**: `RCX = arg1` (connection context), `DX = arg2` (operation type), `R8 = arg3` (input buffer), `R9D = arg4` (input length).
* **`Feature_565656888__private_IsEnabledDeviceUsage` (`sub_1c00097a4`)**: reads `data_1c0024780`, tests bit `0x10`, returns the feature-enabled bit; the return value selects the validated vs. legacy branch.
* **`0x1c006167b`**: the raw `RtlInsertElementGenericTableAvl` taken on the disabled register path (`RCX = [rbx+68h]` = `a1+104`).
* **`CldSyncDisconnectRootDeprecated` (`sub_1c00630e8`)**: reached on the disabled disconnect path; note it takes no token argument and calls `CldSyncDisconnectRootByObject` on the entry found by key.

### Memory & Register Inspection
* At `0x1c0061605`: step over the feature call. If `EAX == 0`, execution reaches `0x1c006167b` and inserts into the per-connection sync-root table without an owner/token check.
* At `0x1c006187a`: step over the feature call. If `EAX == 0`, execution reaches `CldSyncDisconnectRootDeprecated` (`0x1c006189d`) and disconnects the sync root by key with no token check.

### Trigger Setup (User Mode)
1. Open a handle to the port:
   ```c
   HANDLE hPort;
   FilterConnectCommunicationPort(L"\\CLDMSGPORT", 0, NULL, 0, NULL, &hPort);
   ```
2. Craft a `FilterSendMessage` payload for the sync-root register or disconnect operation with a valid `SrIn` structure (magic `0x6E497253`, declared size `>= 0x18`) and a target sync-root key.

### Expected Observation
* On the feature-disabled unpatched path, the disconnect operation reaches `CldSyncDisconnectRootDeprecated` and tears down the sync root matching the supplied key without a token check. On the patched binary, the same input flows through `CldSyncDisconnectRoot`, which rejects a token mismatch with `STATUS_CLOUD_FILE_NOT_SUPPORTED` (`0xC000CF0B`); the register path flows through `CldiPortInsertSyncRootNoLock`, which rejects an owner/token mismatch with `STATUS_CLOUD_FILE_NOT_IN_SYNC` (`0xC000CF09`).

---

## 8. Changed Functions - Full Triage

* **`Feature_565656888__private_IsEnabledDeviceUsage` (`sub_1C00097A4`) (Feature-Staging Toggle):** Similarity `0.123`. A WIL feature-staging check present in both binaries; in the patched binary a different feature occupies the slot (`Feature_Servicing_PostRelOutlookHangIssue__private_IsEnabledDeviceUsage`), which accounts for the low similarity. Not itself a security rewrite; it is the gate removed from its callers.
* **`CldSyncConnectRoot` (`sub_1C0062CC0`) (Behavioral, not security-relevant):** Similarity `0.8198`. Patched (`0x1C0062BD0`) removes the `Feature_565656888__private_IsEnabledDeviceUsage` call. Both unpatched branches already validate the owner field at `+0x60` and the token at `+0` and reject a mismatch with `STATUS_CLOUD_FILE_NOT_IN_SYNC`; the change is a branch-ordering refactor with no authorization difference.
* **`CldiPortProcessServiceCommands` (`sub_1C0060514`) (Security Relevant):** Similarity `0.9655`. Patched (`0x1C00604E4`) removes the feature gate around sync-root disconnect and insert: always calls `CldSyncDisconnectRoot` (token-checked) instead of `CldSyncDisconnectRootDeprecated`, and `CldiPortInsertSyncRootNoLock` (owner/token-validated) instead of the raw `RtlInsertElementGenericTableAvl`.
* **`HsmiOpUpdatePlaceholderFile` (`sub_1C007B554`) (Behavioral):** Similarity `0.9892`. Removed a `Feature_2400225592__private_IsEnabledDeviceUsage` (`sub_1C0019FB0`) call from an `if` condition; helper addresses shifted (relocation). Feature-staging churn, not a security fix.
* **`HsmiGrantLockRequest` (`sub_1C0047F10`) (Behavioral):** Similarity `0.9306`. Changed an allocation growth strategy behind a `Feature_98338106__private_IsEnabledDeviceUsage` (`sub_1C00163B8`) check; helper addresses shifted. Not security-relevant.
* **`CldSyncSendHydrationRequest` (`sub_1C00644D4`) (Cosmetic):** Similarity `0.9927`. Branch target adjustments due to relocation; logic unchanged.

---

## 9. Unmatched Functions

* **Removed:** None.
* **Added:** None.
*(Both `Feature_565656888__private_IsEnabledDeviceUsage` (`sub_1C00097A4`) and `CldiPortInsertSyncRootNoLock` (`sub_1C005DDB4` unpatched / `sub_1C005DD94` patched) exist in both binaries. `CldSyncDisconnectRootDeprecated` (`sub_1C00630E8`) remains present in the patched binary but is no longer called by the dispatcher.)*

---

## 10. Confidence & Caveats

* **Confidence:** High for the mechanism. The decompilation and disassembly of both binaries show the feature-gated legacy paths - `CldSyncDisconnectRootDeprecated` (no token check) and the raw `RtlInsertElementGenericTableAvl` at `0x1c006167b` (no owner/token check) - present in the unpatched dispatcher and absent in the patched dispatcher, which always calls the token-checked `CldSyncDisconnectRoot` and the owner/token-validating `CldiPortInsertSyncRootNoLock`.
* **Reachability:** The `\CLDMSGPORT` security descriptor is built from SDDL `D:P(A;;GA;;;AU)` in the driver, so any authenticated user can reach the dispatcher. The authorization gap is exercised only on builds where `Feature_565656888` is disabled.
* **Severity:** Medium. The demonstrable impact is local integrity/denial of service against cloud sync-root state (a caller can disconnect another provider's sync root without a token, or overwrite per-connection sync-root state without an owner/token check). There is no memory-corruption, information-disclosure, or elevation-to-SYSTEM primitive here, and the exposure is contingent on the feature being disabled.
* **Verification Required:** A researcher writing a PoC must map the internal sync-root key/token layout to the `SrIn` message format to reach the register/disconnect operations via `FilterSendMessage`.
