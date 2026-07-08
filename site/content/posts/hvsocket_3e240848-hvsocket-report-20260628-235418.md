Title: hvsocket.sys — One delivered security fix: an unconditional connection-establishment race hardening (CWE-362) in the AF_HYPERV connect() path (VmbusTlProviderConnect); the originally-claimed socket-address/authorization bypass remains a false positive (validation identical in both builds)
Date: 2026-06-28
Slug: hvsocket_3e240848-hvsocket-report-20260628-235418
Category: Corpus
Author: Argus
Summary: KB5094128

### 1. Overview
- **Unpatched Binary:** `hvsocket_unpatched.sys`
- **Patched Binary:** `hvsocket_patched.sys`
- **Overall Similarity:** 0.792 (79.2%)
- **Diff Statistics:** 272 matched functions, 177 changed functions, 95 identical functions, 0 unmatched functions in either direction.
- **Verdict:** One delivered security fix, plus the originally-framed bypass being a false positive. The socket-address validation gate that this report was originally framed around (`VmbusTlValidateSockAddress`, including its rejection of wildcard destination GUIDs and its caller-authorization call) is present and functionally identical in BOTH builds, and is invoked as a mandatory gate from `VmbusTlProviderConnect` in BOTH builds — so the originally-claimed authorization/wildcard bypass is not real. However, `VmbusTlProviderConnect` itself carries a genuine, unconditional (not feature-flag-gated) behavioral fix that this report's earlier triage missed: the patch reorders the connect path so that `VmbusTlAssociateConnectionToPartition` (which publishes the new connection into the partition's connection tables and makes it reachable to peer-driven endpoint-action processing) now runs while the connection's "connect complete" notification event (`endpoint+0x2C8`) is held cleared, and only signals that event after the transport is established. The unpatched build publishes the connection via association while that event is still in its initial signaled state. This narrows a connection-establishment race window (CWE-362) on an attacker-reachable path and is delivered by default. See section 5(c). The bulk of the remaining 177 changed functions is a mechanical migration of the object-free path from interlocked singly-linked-list pools to `ExFreeToNPagedLookasideList`, plus trace/ETW churn. Two further deltas are NOT delivered by default: (a) an Azure-configuration-gated denial of wildcard listeners in `VmbusTlAuthenticateWildcardListen`, with the original access-check path retained in the else branch, and (b) a WIL feature-flag-staged (`Feature_MSRC97534_57540200`) change to fast-mutex acquisition across several connection/service-association routines.

### 2. Vulnerability Summary
- **Severity:** Medium (delivered fix: connection-establishment race in `VmbusTlProviderConnect`, CWE-362). The originally-claimed authorization bypass is None (Informational / false positive).
- **Vulnerability Class:** Delivered fix — Race Condition / concurrent execution using shared state (CWE-362) on the AF_HYPERV connect path. The originally claimed Missing Authorization / Input Validation Bypass (CWE-862 / CWE-20) is NOT supported by the binaries.
- **Affected Functions examined:** `VmbusTlProviderConnect`, `VmbusTlValidateSockAddress`, `VmbusTlProcessNewConnection`, `VmbusTlAuthenticateWildcardListen`, the new `VmbusTlEndpointSetPendingConnectRequest` / `VmbusTlEndpointClearPendingConnectRequest` / `VmbusTlEstablishConnection` helpers, `VmbusTlSetupConnection`, `VmbusTlCreateConnection`, `VmbusTlEndpointActionWorkQueueRoutine`, and the `Feature_MSRC97534_57540200`-gated locking routines.

**Root Cause Analysis (as verified against both builds):**
The premise of the original finding — that the unpatched connect path lacks socket-address validation and wildcard rejection — is false. `VmbusTlValidateSockAddress` exists in both builds (`0x1C0019254` unpatched, `0x14001B1A0` patched). In both builds it performs exactly the same checks:
- address family must equal `0x22` (34, `AF_HYPERV`); otherwise it returns `0xC0000141` (`STATUS_INVALID_ADDRESS`) and traces `"Address family mismatch."`;
- the reserved field at offset `+2` must be zero; otherwise `0xC0000141` and `"Reserved field mismatch."`;
- the destination GUID at offset `+4` must not match the wildcard GUIDs (`HV_GUID_ZERO`, the all-zeros GUID, or `HV_GUID_CHILDREN`); if it matches, it returns `0xC0000141` and traces `"Cannot connect to wildcard addresses."`;
- it then resolves the partition (`VmbusTlResolvePartitionId`), references it (`VmbusTlFindAndReferencePartition`), and calls the caller-identity authorization routine `VmbusTlAuthenticateConnectSockAddress(partition, sockaddr, PEPROCESS)`.

The only difference between the two `VmbusTlValidateSockAddress` bodies is the object-dereference cleanup path: unpatched pushes the freed object onto an interlocked S-List (`ExpInterlockedPushEntrySList`), patched frees it via `ExFreeToNPagedLookasideList`. That is a memory-management refactor, not a security change.

**Attacker-Reachable Entry Point:**
`VmbusTlProviderConnect` is reached from an `AF_HYPERV` WinSock `connect()`/`WSAConnect()`, but because the validation and wildcard-rejection it depends on are identical in both builds, there is no reachable behavioral difference on this path.

**Call Chain (identical in both builds):**
1. User-mode process calls `connect()` / `WSAConnect()` on an `AF_HYPERV` socket.
2. WSK dispatch routes to the `hvsocket.sys` NMR provider.
3. `VmbusTlProviderConnect` (`0x1C001F9C0` unpatched, `0x140021AC0` patched) runs.
4. It calls `HvSocketResolveUniversalAddress`, then `HvSocketIsPassthruRequest`, then `VmbusTlValidateSockAddress` as a mandatory gate, and aborts if the return is negative before reaching `VmbusTlCreateConnection`. This gate is present in BOTH builds.

### 3. Code Comparison (verified)

Both `VmbusTlProviderConnect` bodies call the validation gate and reject on failure. Unpatched (`VmbusTlProviderConnect @ 0x1C001F9C0`, decompiled):

```c
IsPassthruRequest = HvSocketIsPassthruRequest(a1, (__int64)&v52, (__int64)v13, &v51);
v15 = VmbusTlValidateSockAddress(a1, (__int64)&v52, (int)v13, CurrentProcess, IsPassthruRequest, &v56);
v47 = v15;
if ( v15 >= 0 )
{
    v47 = VmbusTlCreateConnection(a1, CurrentProcess, &ListEntry);
    // ... proceed ...
}
```

Patched (`VmbusTlProviderConnect @ 0x140021AC0`, decompiled):

```c
IsPassthruRequest = HvSocketIsPassthruRequest(a1, (__int64)&v40, (__int64)v12, &v39);
v36 = VmbusTlValidateSockAddress(a1, &v40, (int)v12, CurrentProcess, IsPassthruRequest, (__int64)&v44);
v13 = v36;
if ( v36 < 0 )
{
    // trace + abort
    goto LABEL_63;
}
v36 = VmbusTlCreateConnection(a1, CurrentProcess, &Entry);
// ... proceed ...
```

The wildcard-rejection block inside `VmbusTlValidateSockAddress` is likewise present in both. Unpatched (`0x1C0019254`) expresses it as inline 8-byte comparisons; patched (`0x14001B1A0`) expresses it as `memcmp` against named GUID constants, but the logic is the same:

```c
// patched VmbusTlValidateSockAddress
if ( memcmp(a2 + 2, &HV_GUID_ZERO, 0x10u) != 0 && memcmp(a2 + 2, &HV_GUID_CHILDREN, 0x10u) != 0 )
{
    // not a wildcard -> resolve partition, reference it, authorize caller
    v14 = VmbusTlResolvePartitionId(a1, a3, ...);
    ...
    v6 = VmbusTlAuthenticateConnectSockAddress(v18, (__int64)a2, a4); // a4 = PEPROCESS
}
else
{
    // wildcard -> "Cannot connect to wildcard addresses.", returns STATUS_INVALID_ADDRESS
}
```

### 4. Assembly Anchors (real addresses)

- Unpatched `VmbusTlProviderConnect` calls the validation gate at `0x1C001FB98  call VmbusTlValidateSockAddress`.
- Patched `VmbusTlProviderConnect` calls the validation gate at `0x140021C94  call VmbusTlValidateSockAddress`.
- Unpatched `VmbusTlValidateSockAddress` calls the caller-authorization routine at `0x1C00193F2  call VmbusTlAuthenticateConnectSockAddress`.
- Patched `VmbusTlValidateSockAddress` calls it at `0x14001B325  call VmbusTlAuthenticateConnectSockAddress`.

Both the gate and the authorization call exist in both builds, so there is no missing-check delta on the connect path.

### 5. The two genuine deltas (neither delivered as a default-on security fix)

**(a) `VmbusTlAuthenticateWildcardListen` — Azure-config-gated wildcard-listen denial.**
Patched `VmbusTlAuthenticateWildcardListen` (`0x1400078B8`) adds a gate at the top of the function:

```c
if ( (unsigned __int8)HvSocketGetAzureFeatureSetEnabled() != 0 )
{
    // trace, then deny
    return 3221225992LL; // 0xC0000208
}
else
{
    // original logic: find wildcard descriptor, VmbusTlEndpointAccessCheck against its security descriptor
}
```

`HvSocketGetAzureFeatureSetEnabled` (`0x14001E5C4`) exists only in the patched build and reads a DWORD registry value under the virtualization key; it returns true only when that value is nonzero. When it is false — the default on an ordinary Hyper-V host — the function runs the exact same access-check path as the unpatched `VmbusTlAuthenticateWildcardListen` (`0x1C00081AC`), which already performs `VmbusTlEndpointAccessCheck` against the wildcard descriptor's / partition's security descriptor. In assembly, the denial is `0x1400078E5  call HvSocketGetAzureFeatureSetEnabled` followed by `0x1400078F5  mov ebx, 0C0000208h`. Because the original permissive path is retained in the else branch and the gate is off unless the registry value is set, this is a configuration-gated hardening for Azure-configured hosts, not a universally delivered fix. It also does not add any access check that was missing before; wildcard-listen access checking already exists in both builds.

**(b) `Feature_MSRC97534_57540200` — WIL feature-flag-staged locking change.**
The patched build introduces the WIL staging flag `Feature_MSRC97534_57540200` (the `MSRC97534` token is a Microsoft Security Response Center case identifier). It gates a second fast-mutex acquisition in roughly eight connection/service-association routines, including `VmbusTlAssociateConnectionToService`, `HvSocketBeginProcessingConnection`, `HvSocketPendConnection`, `VmbusTlConnectComplete`, `HvSocketAcceptIncomingConnection`, `VmbusTlAssociateListenerToPartition`, `VmbusTlCloseServiceEndpoints`, and `VmbusTlDissociateEndpointFromService`. Concretely, in `VmbusTlAssociateConnectionToService`:

```c
// unpatched (0x1C000A7A0): the (a2+16) fast mutex is taken UNCONDITIONALLY
KeEnterCriticalRegion();
ExAcquireFastMutexUnsafe((PFAST_MUTEX)(a2 + 16));
KeEnterCriticalRegion();
ExAcquireFastMutexUnsafe((PFAST_MUTEX)(a1 + 16));

// patched (0x1400096E0): the (a2+16) fast mutex is taken ONLY when the flag is enabled
if ( Feature_MSRC97534_57540200__private_IsEnabledNoReportingNoInline() != 0 )
{
    KeEnterCriticalRegion();
    ExAcquireFastMutexUnsafe((PFAST_MUTEX)(a2 + 16));
}
KeEnterCriticalRegion();
ExAcquireFastMutexUnsafe((PFAST_MUTEX)(a1 + 16));
```

This is a lock-discipline reorganization staged behind a runtime feature flag, with the pre-existing behavior reachable depending on the flag state. It carries an MSRC case tag, which indicates Microsoft is addressing a concurrency issue in these association paths, but the change is not delivered unconditionally in this build and its precise reachable impact (for example a specific race or lock-ordering defect) is not determinable from these two binaries alone. It is not the address-authorization issue the report was originally titled around.

### 5b. The delivered fix: connection-establishment race hardening in `VmbusTlProviderConnect` (CWE-362, delivered unconditionally)

Unlike the two feature/config-gated deltas above, `VmbusTlProviderConnect` (`0x1C001F9C0` unpatched / `0x140021AC0` patched) carries an **unconditional** reordering of the connect path that closes a race window between publishing a new connection and finishing its transport setup. No `Feature_MSRC97534_57540200` / `IsEnabled` gate guards this change; it is delivered by default.

**The synchronization object.** Each connection endpoint has a `NotificationEvent` at `endpoint+0x2C8`. It is created in `VmbusTlCreateConnection` and initialized **signaled**:

```
; unpatched VmbusTlCreateConnection @ 0x1C0018210
0x1C001832B  lea     rcx, [rbx+2C8h]; Event
0x1C0018332  mov     r8b, 1; State          ; State=1 -> event starts SIGNALED
0x1C0018335  xor     edx, edx; Type         ; Type=0 -> NotificationEvent
0x1C001833F  call    cs:__imp_KeInitializeEvent
```

This event is the "connect complete" gate. The peer-driven action processor waits on it before touching the connection's transport object at `endpoint+0x2E0`:

```
; unpatched VmbusTlEndpointActionWorkQueueRoutine @ 0x1C0005550
0x1C000580B  cmp     qword ptr [rbx+2E0h], 0
0x1C0005813  jz      loc_1C000591E            ; transport not published yet -> skip
0x1C000581F  lea     rcx, [rbx+2C8h]; Object
0x1C000582E  call    cs:__imp_KeWaitForSingleObject   ; block until connect-complete signaled
0x1C000583A  mov     rax, [rbx+2E0h]
...          call    cs:__guard_dispatch_icall_fptr   ; indirect call through the transport object
```

**Unpatched order (racy).** On the successful connect path, `VmbusTlProviderConnect` associates the connection FIRST, while the `+0x2C8` event is still in its initial signaled state, and only resets that event afterwards, inside `VmbusTlSetupConnection`:

```
; unpatched VmbusTlProviderConnect @ 0x1C001F9C0 (success path)
0x1C001FE1E  call    VmbusTlAssociateConnectionToPartition   ; publishes connection; event still SIGNALED
0x1C001FE79  mov     [rbx+2A0h], rax                         ; store pending connect request inline
0x1C001FED5  call    VmbusTlSetupConnection                  ; only now is the event reset

; unpatched VmbusTlSetupConnection @ 0x1C0018370
0x1C001839C  call    cs:__imp_KeResetEvent                   ; +0x2C8 cleared here (after association)
...
0x1C00184AE  call    cs:__imp_KeSetEvent                     ; re-signaled after establishment
```

`VmbusTlProviderConnect` in the unpatched build never touches the `+0x2C8` event itself. So between `VmbusTlAssociateConnectionToPartition` returning (which registers the connection into the partition's connection tables and makes it discoverable to inbound, peer-driven `VmbusTlEndpointActionWorkQueueRoutine` processing) and `VmbusTlSetupConnection` reaching its `KeResetEvent`, the connection is published while its "connect complete" event is still signaled. A concurrently scheduled endpoint-action routine can pass the `KeWaitForSingleObject` gate and operate on a connection whose transport establishment has not yet run.

**Patched order (barrier covers association).** The patch clears the event FIRST, before setup and before association, and only re-signals it after the transport is established in the newly split-out `VmbusTlEstablishConnection`:

```
; patched VmbusTlProviderConnect @ 0x140021AC0 (success path)
0x140021E06  mov     rcx, r14; Event                         ; r14 = [rbx+2C8h]
0x140021E29  call    cs:__imp_KeClearEvent                   ; event cleared BEFORE setup/association
0x140021E41  call    VmbusTlEndpointSetPendingConnectRequest ; new helper: records pending request at +0x2A0
0x140021E49  call    VmbusTlSetupConnection
0x140021E5F  call    VmbusTlAssociateConnectionToPartition   ; publishes connection while event is CLEARED
0x140021E6B  jns     loc_140021FE4                           ; on associate success ->
0x140021FED  call    VmbusTlEstablishConnection              ; new helper: dispatch transport, then KeSetEvent

; patched VmbusTlEstablishConnection @ 0x14001A658
0x14001A6B6  call    _guard_dispatch_icall                   ; establish transport
0x14001A6CC  lea     rcx, [rbx+2C8h]; Event
0x14001A6D8  call    cs:__imp_KeSetEvent                     ; connect-complete signaled only now

; on associate FAILURE the patch signals and unwinds the pending state
0x140021E79  call    cs:__imp_KeSetEvent
0x140021E88  call    VmbusTlEndpointClearPendingConnectRequest
```

Because the event is cleared before `VmbusTlAssociateConnectionToPartition`, any peer-driven `VmbusTlEndpointActionWorkQueueRoutine` that finds the newly published connection now blocks on the `+0x2C8` wait until `VmbusTlEstablishConnection` has finished dispatching the transport and signaled the event. The race window between publication and transport establishment is closed.

**New helpers, confirmed absent in the unpatched binary.** `VmbusTlEndpointSetPendingConnectRequest` (`0x14001A594`), `VmbusTlEndpointClearPendingConnectRequest` (`0x140002F7C`), and `VmbusTlEstablishConnection` (`0x14001A658`) do not exist by content or by name in `hvsocket_unpatched.asm`; the unpatched build performs the equivalent pending-request store inline at `0x1C001FE79` and bundles the establishment inside `VmbusTlSetupConnection`.

**Why this is a security fix, not a mechanical refactor.** The reorder changes observable ordering on shared endpoint state: in the unpatched build a connection becomes reachable to concurrent, peer-driven action processing (indirect call through `endpoint+0x2E0`) before its transport is set up and while its completion gate is open; in the patched build the completion gate is held closed across the publish-and-establish window. This is the same MSRC-tagged concurrency theme as delta 5(b), but it is delivered unconditionally rather than behind a WIL flag.

**Direction and gating (verified):** patched is stricter (barrier now covers association; unpatched leaves it open). Not a relaxation. Not WIL feature-staged — there is no `Feature_MSRC*`/`IsEnabled` check inside `VmbusTlProviderConnect`. Not telemetry, relocation, API modernization, or init-only: the connect path is reached directly from user-mode `connect()`/`WSAConnect()` on an AF_HYPERV socket.

**Severity note (honest scope).** This is rated **Medium / CWE-362**. The reachable window and the narrowing are demonstrable from the binaries and the fix is MSRC-tagged and shipped by default. A concrete memory-corruption primitive (for example a reliable use-after-free or a controlled indirect call) is **not** demonstrable from these two binaries alone: `VmbusTlEndpointActionWorkQueueRoutine` null-checks `endpoint+0x2E0` before use and dispatches through a CFG-guarded pointer, which bounds trivial exploitation. The finding is a genuine, attacker-reachable race that Microsoft closed unconditionally, without a proven corruption primitive from static comparison.

### 6. Exploit Primitive & Development Notes
None demonstrable. The originally claimed logical authorization/isolation bypass does not exist: the wildcard-address rejection and the caller-identity authorization it relied on are present in both builds. The two real deltas are a config-gated behavior and a feature-flag-staged locking change; neither yields a demonstrable, reachable primitive from these binaries. No memory-corruption, information-leak, or privilege-escalation primitive is present on the diffed paths.

### 7. Trigger / Reproduction
There is no differential trigger for the originally claimed bug: a `connect()` on an `AF_HYPERV` socket with a wildcard `DestinationVmId` is rejected with `STATUS_INVALID_ADDRESS` (`0xC0000141`) by `VmbusTlValidateSockAddress` in BOTH the unpatched and patched builds, because the wildcard-rejection block is identical in both. The `VmbusTlAuthenticateWildcardListen` denial only differs when the Azure feature-set registry value is set; the `Feature_MSRC97534_57540200` locking behavior only differs by the WIL flag state.

### 8. Changed Functions — Full Triage
- **VmbusTlProviderConnect (`0x1C001F9C0` unpatched / `0x140021AC0` patched):** **Delivered security change (CWE-362), see section 5b.** The `VmbusTlValidateSockAddress` gate is identical in both builds (not the originally-claimed delta), but the connect path was unconditionally reordered so that `VmbusTlAssociateConnectionToPartition` runs while the `endpoint+0x2C8` connect-complete event is held cleared (`KeClearEvent` at `0x140021E29`, before the association at `0x140021E5F`), with the event only re-signaled after transport establishment in the new `VmbusTlEstablishConnection`. The unpatched build associates first (`0x1C001FE1E`) while that event is still signaled and only resets it later inside `VmbusTlSetupConnection` (`KeResetEvent` `0x1C001839C`). This narrows a connection-establishment race window. The remaining differences (variable renumbering, trace-level constant renames, the S-List-to-lookaside free-path swap, and `ExAllocatePoolWithTag` to `ExAllocatePool2` modernization) are mechanical.
- **VmbusTlValidateSockAddress (`0x1C0019254` unpatched / `0x14001B1A0` patched):** Not a security change. Identical family / reserved / wildcard-GUID checks and identical `VmbusTlAuthenticateConnectSockAddress` caller-authorization call in both builds. Only the object-free cleanup path differs (S-List push vs `ExFreeToNPagedLookasideList`).
- **VmbusTlProcessNewConnection (`0x1C001B824` unpatched / `0x14001CD30` patched):** Not a security change. No authorization call was added; `VmbusTlAuthenticateConnectSockAddress` is invoked only from `VmbusTlValidateSockAddress` in both builds, never from this function. The difference is the S-List-to-lookaside refactor plus trace churn.
- **VmbusTlProcessNewConnectionForListener (`0x1C001ADA4` unpatched / `0x14001D2D4` patched):** Not a security change. S-List-to-lookaside refactor and refcount-cleanup restructuring.
- **VmbusTlAuthenticateWildcardListen (`0x1C00081AC` unpatched / `0x1400078B8` patched):** Behavioral, config-gated. Adds an Azure-feature-set-gated denial (`0xC0000208`) with the original access-check path retained; not a default-on fix. See section 5(a).
- **`Feature_MSRC97534_57540200`-gated routines:** Behavioral, feature-flag-staged. Conditional fast-mutex acquisition across the connection/service-association paths listed in section 5(b). Not delivered unconditionally.
- **Bulk (~170 functions):** Mechanical migration of the object-free path from interlocked S-List pools to `ExFreeToNPagedLookasideList`, `ExAllocatePoolWithTag` to `ExAllocatePool2`, and WPP/ETW trace argument and trace-level-constant churn. No security behavior change.

### 9. Unmatched Functions
0 unmatched functions in either direction. All modifications are alterations of existing functions. The `Feature_MSRC97534_57540200__private_IsEnabled*` and `HvSocketGetAzureFeatureSetEnabled` symbols are new in the patched build, but they are staging/config helpers rather than a delivered security gate.

### 10. Confidence & Caveats
- **Confidence:** High that the originally titled authentication/authorization-bypass finding is a false positive: the validation gate, the wildcard rejection, and the caller-identity authorization are all present and functionally identical in both builds, and are invoked from the connect path in both.
- **Confidence on the delivered fix (section 5b):** High that a real, unconditional behavioral change exists: the `endpoint+0x2C8` event is initialized signaled in `VmbusTlCreateConnection`, the patched `VmbusTlProviderConnect` clears it before association (`0x140021E29`) whereas the unpatched build associates while it is still signaled and resets it only later inside `VmbusTlSetupConnection`, and the three helper functions (`VmbusTlEndpointSetPendingConnectRequest`, `VmbusTlEndpointClearPendingConnectRequest`, `VmbusTlEstablishConnection`) are absent from the unpatched binary. Medium confidence on impact class (CWE-362 race) and honest that a concrete corruption primitive is not demonstrable from static comparison alone (the consumer null-checks `endpoint+0x2E0` and dispatches through a CFG-guarded pointer).
- **Caveat on the MSRC-tagged change:** The `Feature_MSRC97534_57540200` locking reorganization is real and MSRC-tagged, but it is staged behind a WIL feature flag with the prior path retained. Its exact security intent and reachable impact cannot be established from these two binaries alone, so it is not rated here beyond "concurrency-hardening, feature-staged, not delivered by default."
- **Caveat on the Azure gate:** The `VmbusTlAuthenticateWildcardListen` denial is real but conditioned on an Azure feature-set registry value and retains the original access-check path; it is environment-specific hardening, not a universally delivered fix.
