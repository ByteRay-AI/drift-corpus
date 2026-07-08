Title: hvsocket.sys — Feature-gated missing spinlock synchronization in VmbusTl loopback delivery queue (CWE-362/CWE-416) fixed
Date: 2026-06-29
Slug: hvsocket_2f28a6c9-hvsocket-report-20260629-003312
Category: Corpus
Author: Argus
Summary: KB5078885

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `hvsocket_unpatched.sys` |
| Patched binary | `hvsocket_patched.sys` |
| Overall similarity | **0.9745** |
| Matched functions | 288 |
| Changed functions | 14 |
| Identical functions | 274 |
| Unmatched (unpatched → patched) | 0 / 0 |

**Verdict:** The patch removes a WIL feature gate (`Feature_1274333499__private_IsEnabledDeviceUsage`) that conditionally selected between a spinlock-synchronized code path and an unsynchronized one across the Hyper-V Sockets `VmbusTl` loopback routines. In the unpatched build the gate's else-branch reads the shared per-endpoint delivery-queue head at `[endpoint+0x2B8]` without acquiring the endpoint's `KSPIN_LOCK` at `[endpoint+0x48]` and without taking a reference on the popped entry, while a concurrent `VmbusTlLoopbackDisconnect` can clear that head and drop the entry's reference to zero. This is a genuine race condition that can lead to a use-after-free / reference-count imbalance on the loopback delivery-queue object. The patched build deletes the gate in all affected functions and unconditionally calls the synchronized helper `VmbusTlLoopbackReferenceEndpointDeliveryQueue`, which acquires the spinlock and takes a reference before touching the head. The static image does not reveal whether the feature was enabled by default, so the real-world reachability of the unsynchronized branch in the unpatched build cannot be asserted from the binaries alone; the patch makes the synchronized path unconditional regardless.

---

## 2. Vulnerability Summary

### Finding 1 — Race / potential UAF in `VmbusTlLoopbackNotifyReceiveConsumed` (and sibling send/accept paths)

- **Severity:** Medium
- **Class:** Race Condition leading to Use-After-Free (CWE-362, CWE-416)
- **Affected functions:**
  - `VmbusTlLoopbackNotifyReceiveConsumed` (`sub_1C0007CF0`) — primary
  - `VmbusTlLoopbackSend` (`sub_1C0007388`)
  - `VmbusTlLoopbackAcceptConnection` (`sub_1C001D700`)
  - `VmbusTlNotifyListenerAccept` (`sub_1C0006C9C`)

**Root cause.** Each of these `VmbusTlLoopback*` routines contains two implementations selected at runtime by `Feature_1274333499__private_IsEnabledDeviceUsage` (`sub_1C000293C`), a standard WIL feature-staging gate that returns the cached state of `Feature_1274333499__private_featureState` (falling back to `Feature_1274333499__private_IsEnabledFallback` when the state is not yet cached). When the gate returns non-zero, the code calls `VmbusTlLoopbackReferenceEndpointDeliveryQueue` (`sub_1C0007ECC`), which acquires `KeAcquireSpinLockRaiseToDpc(endpoint+0x48)` first and reads the delivery-queue head at `[endpoint+0x2B8]` under the lock while incrementing the entry's reference count — the safe variant. When the gate returns zero, the code reads `[endpoint+0x2B8]` directly with no spinlock held and no reference taken.

A concurrent thread executing `VmbusTlLoopbackDisconnect` (which, on the safe branch, acquires the same lock) can clear `[endpoint+0x2B8]`, drop the entry's reference count, and — when it reaches zero — free it with `ExFreePoolWithTag(..., 'Vnpi')` (tag `0x69706E56`). In the unsynchronized branch the notify/send thread then dereferences the entry's back-pointer at `[rdi+0x68]` (`mov rdi, [rdi+0x68]` @ `0x1C0007E4F`) and writes to `[rdi+0x210]` (`or dword [rdi+0x210], 2` @ `0x1C0007E63`), and later decrements a reference it never took — a race that can produce a use-after-free or reference-count underflow on the delivery-queue object.

The patch removes every gate conditional and unconditionally calls the synchronized helper `VmbusTlLoopbackReferenceEndpointDeliveryQueue` (relocated to `sub_1C0007CD0` in the patched build), which always holds the spinlock and takes a reference while operating on the head.

**Entry point & data flow:**

1. User-mode HV socket API (`send`/`recv`/`closesocket` on an `AF_HYPERV` socket).
2. `hvsocket.sys` Tl dispatch (imported `TlDefaultRequestMessage`/`TlDefaultRequestResume`).
3. `VmbusTl` loopback callback path.
4. `VmbusTlLoopbackNotifyReceiveConsumed` (`sub_1C0007CF0`) — unsynchronized branch reads `[endpoint+0x2B8]`.
5. Dereference of the delivery-queue entry at `[rdi+0x68]` racing a concurrent free.

### Finding 2 — Concurrent unsynchronized head clear in `VmbusTlLoopbackDisconnect`

- **Severity:** Medium (writer side of Finding 1's race; same root cause)
- **Class:** Race Condition (CWE-362)
- **Affected function:** `VmbusTlLoopbackDisconnect` (`sub_1C00079D0`)

**Root cause.** `VmbusTlLoopbackDisconnect` gates the spinlock the same way. On the gate-off branch it reads and clears the shared head `[endpoint+0x2B8]` (`mov rsi, [rbx+0x2B8]` / `and qword [rbx+0x2B8], 0` @ `0x1C0007A26`) without holding the `KSPIN_LOCK` at `[endpoint+0x48]`, then drops the entry's reference count and can free it. This is the "freeing" side of the race in Finding 1: the disconnect clears/frees the head while a send/notify thread on the unsynchronized branch is reading it.

The function calls the gate three times (`0x1C0007A0A`, `0x1C0007A3E`, `0x1C0007A50`) to decide acquire, back-pointer clear, and release. These are separate inlined evaluations of the same feature gate rather than a cached boolean; the WIL feature state is effectively stable for the duration of the call, so this is not a demonstrable time-of-check/time-of-use lock imbalance. The security-relevant behavior is the unsynchronized head access, which the patch fixes by acquiring and releasing the spinlock unconditionally.

### Finding 3 — Feature-gate removal in `VmbusTlProcessNewConnectionForListener`

- **Severity:** Low (no demonstrable security impact)
- **Class:** Synchronization consolidation (CWE-362 context)
- **Affected function:** `VmbusTlProcessNewConnectionForListener` (`sub_1C001BEF4`)

**Root cause.** This function evaluates the same feature gate twice within the connection-acceptance path (`0x1C001C0F8` and `0x1C001C120`) and only reads the acceptance field at `[rcx_9+0x1A9]` on the gate-on branch. The patch removes both gate checks and reads the field unconditionally. This is part of the same gate-removal consolidation as Findings 1–2. There is no evidence in the binaries of an exploitable incorrect accept/reject decision; the change is a synchronization-behavior unification, recorded here for completeness.

---

## 3. Pseudocode Diff

### `VmbusTlLoopbackNotifyReceiveConsumed`

```c
// ===== UNPATCHED sub_1C0007CF0 =====
if (Feature_1274333499__private_IsEnabledDeviceUsage()) {   // WIL gate
    // SYNCHRONIZED BRANCH (gate on)
    entry = VmbusTlLoopbackReferenceEndpointDeliveryQueue(endpoint); // locks +0x48, refs entry
    if (!entry) goto done;
    obj = *(entry + 0x68);
    KeAcquireSpinLockRaiseToDpc(obj + 0x48);
    *(obj + 0x210) |= 2;
    VmbusTlTransitionDisconnectState(obj, 3);
    VmbusTlFinishDisconnectStateTransition(obj, ...);
    // drop reference under lock; free via ExFreePoolWithTag(entry,'Vnpi') if it hits 0
} else {
    // UNSYNCHRONIZED BRANCH (gate off)
    head = *(endpoint + 0x2B8);                 // read WITHOUT the +0x48 spinlock, no ref taken
    if (!head) return STATUS_INVALID_DEVICE_REQUEST;
    obj = *(head + 0x68);                        // races a concurrent free
    KeAcquireSpinLockRaiseToDpc(obj + 0x48);
    *(obj + 0x210) |= 2;
    VmbusTlTransitionDisconnectState(obj, 3);
    VmbusTlFinishDisconnectStateTransition(obj, ...);
}

// ===== PATCHED sub_1C0007B70 =====
entry = VmbusTlLoopbackReferenceEndpointDeliveryQueue(endpoint);  // ALWAYS synchronized + ref
if (!entry) return STATUS_INVALID_DEVICE_REQUEST;
obj = *(entry + 0x68);
KeAcquireSpinLockRaiseToDpc(obj + 0x48);
*(obj + 0x210) |= 2;
// ... same cleanup ...
```

### `VmbusTlLoopbackDisconnect`

```c
// ===== UNPATCHED sub_1C00079D0 =====
KeEnterCriticalRegion();
ExAcquireFastMutexUnsafe(endpoint + 0x10);

if (Feature_1274333499__private_IsEnabledDeviceUsage())        // check #1
    NewIrql = KeAcquireSpinLockRaiseToDpc(endpoint + 0x48);    // only if gate on

rsi = *(endpoint + 0x2B8);                                     // unsynchronized if gate off
*(endpoint + 0x2B8) = 0;                                       // unsynchronized clear
if (rsi) rbp = *(rsi + 0x68);

if (Feature_1274333499__private_IsEnabledDeviceUsage())        // check #2
    *(rsi + 0x68) = 0;

if (Feature_1274333499__private_IsEnabledDeviceUsage())        // check #3
    KeReleaseSpinLock(endpoint + 0x48, NewIrql);               // only if gate on

// ===== PATCHED sub_1C0007870 =====
NewIrql = KeAcquireSpinLockRaiseToDpc(endpoint + 0x48);        // UNCONDITIONAL
... shared access ...
KeReleaseSpinLock(endpoint + 0x48, NewIrql);                  // UNCONDITIONAL
```

### `VmbusTlLoopbackSend` & `VmbusTlLoopbackAcceptConnection`

Same shape: the gate-off branch reads `[endpoint+0x2B8]` (decompiled as `endpoint[0x57]`, i.e. `endpoint + 0x57*8 = endpoint + 0x2B8`) directly, without the spinlock or a reference; the gate-on branch calls `VmbusTlLoopbackReferenceEndpointDeliveryQueue`. In `VmbusTlLoopbackSend` this is `mov rbx, [r15+0x2B8]` @ `0x1C00073DC` (gate off) versus `call VmbusTlLoopbackReferenceEndpointDeliveryQueue` @ `0x1C00073C5` (gate on). Patched versions always call `VmbusTlLoopbackReferenceEndpointDeliveryQueue`.

---

## 4. Assembly Analysis

### `VmbusTlLoopbackNotifyReceiveConsumed` (`sub_1C0007CF0`, unpatched)

```asm
0x1C0007CF0: mov     [rsp+0x8], rbx
0x1C0007CF5: mov     [rsp+0x10], rsi
0x1C0007CFA: push    rdi
0x1C0007CFB: sub     rsp, 0x30
0x1C0007CFF: mov     rbx, rcx                      ; rbx = endpoint
0x1C0007D02: call    Feature_1274333499__private_IsEnabledDeviceUsage
0x1C0007D07: test    eax, eax
0x1C0007D09: jz      0x1C0007E43                    ; gate off -> UNSYNCHRONIZED branch

; === SYNCHRONIZED BRANCH (gate on) ===
0x1C0007D0F: mov     rcx, rbx
0x1C0007D12: call    VmbusTlLoopbackReferenceEndpointDeliveryQueue  ; locks +0x48, refs entry
0x1C0007D17: mov     rsi, rax
0x1C0007D1A: test    rax, rax
0x1C0007D1D: jz      0x1C0007E2A
0x1C0007D23: mov     rdi, [rax+0x68]                ; referenced under lock
0x1C0007D27: lea     rcx, [rdi+0x48]
0x1C0007D2B: call    qword [rel KeAcquireSpinLockRaiseToDpc]
0x1C0007D37: or      dword [rdi+0x210], 2
...
0x1C0007D8B: lock xadd [rsi+0x8], rax              ; atomic reference-count decrement
0x1C0007D91: sub     rax, 1
0x1C0007D95: jg      0x1C0007E86
                                                    ; ExFreePoolWithTag(rsi,'Vnpi') when it hits 0

; === UNSYNCHRONIZED BRANCH (gate off) ===
0x1C0007E43: mov     rdi, [rbx+0x2B8]               ; read head WITHOUT +0x48 spinlock, no ref
0x1C0007E4A: test    rdi, rdi
0x1C0007E4D: jz      0x1C0007E8A
0x1C0007E4F: mov     rdi, [rdi+0x68]                ; deref racing a concurrent free
0x1C0007E53: lea     rcx, [rdi+0x48]
0x1C0007E57: call    qword [rel KeAcquireSpinLockRaiseToDpc]
0x1C0007E63: or      dword [rdi+0x210], 2
0x1C0007E6A: mov     edx, 3
0x1C0007E6F: mov     rcx, rdi
0x1C0007E72: mov     bl, al
0x1C0007E74: call    VmbusTlTransitionDisconnectState
0x1C0007E79: mov     r8b, bl
0x1C0007E7C: mov     edx, eax
0x1C0007E7E: mov     rcx, rdi
0x1C0007E81: call    VmbusTlFinishDisconnectStateTransition
0x1C0007E86: xor     edi, edi
0x1C0007E88: jmp     0x1C0007EB0
```

The gate-off branch reads `[rbx+0x2B8]` at `0x1C0007E43` and dereferences `[rdi+0x68]` at `0x1C0007E4F` with the endpoint spinlock never taken and no reference held. A concurrent `VmbusTlLoopbackDisconnect` clearing `[endpoint+0x2B8]` and freeing the entry in that window produces the race.

### `VmbusTlLoopbackReferenceEndpointDeliveryQueue` (`sub_1C0007ECC`, unpatched — the synchronized helper)

```asm
0x1C0007ECC: ...
0x1C0007EDB: lea     rdi, [rcx+0x48]                ; endpoint spinlock
0x1C0007EDF: mov     rbx, rcx
0x1C0007EE2: mov     rcx, rdi
0x1C0007EE5: call    qword [rel KeAcquireSpinLockRaiseToDpc]   ; lock BEFORE reading head
0x1C0007EF1: mov     rbx, [rbx+0x2B8]               ; read head UNDER lock
```

This helper is what the gate-on branch calls and what the patch calls unconditionally. It acquires `[endpoint+0x48]` before reading `[endpoint+0x2B8]`.

### `VmbusTlLoopbackDisconnect` (`sub_1C00079D0`, unpatched)

```asm
0x1C00079EE: call    qword [rel KeEnterCriticalRegion]
0x1C00079FE: call    qword [rel ExAcquireFastMutexUnsafe]  ; endpoint+0x10
0x1C0007A0A: call    Feature_1274333499__private_IsEnabledDeviceUsage  ; check #1
0x1C0007A0F: test    eax, eax
0x1C0007A11: jz      0x1C0007A26                    ; skip acquire if gate off
0x1C0007A13: lea     rcx, [rbx+0x48]
0x1C0007A17: call    qword [rel KeAcquireSpinLockRaiseToDpc]
0x1C0007A23: mov     dil, al                        ; save IRQL

0x1C0007A26: mov     rsi, [rbx+0x2B8]               ; read head (no lock if gate off)
0x1C0007A2D: and     qword [rbx+0x2B8], 0           ; clear head (no lock if gate off)
0x1C0007A35: test    rsi, rsi
0x1C0007A38: jz      0x1C0007A4E
0x1C0007A3A: mov     rbp, [rsi+0x68]

0x1C0007A3E: call    Feature_1274333499__private_IsEnabledDeviceUsage  ; check #2
0x1C0007A43: test    eax, eax
0x1C0007A45: jz      0x1C0007A50
0x1C0007A47: and     qword [rsi+0x68], 0
0x1C0007A4C: jmp     0x1C0007A50

0x1C0007A50: call    Feature_1274333499__private_IsEnabledDeviceUsage  ; check #3
0x1C0007A55: test    eax, eax
0x1C0007A57: jz      0x1C0007A6C
0x1C0007A59: lea     rcx, [rbx+0x48]
0x1C0007A60: call    qword [rel KeReleaseSpinLock]  ; release only if gate on

; later in the free path:
0x1C0007BD3: lock xadd [rsi+0x8], rax               ; atomic reference-count decrement -> free
```

---

## 5. Trigger Conditions

1. **Open the target interface.** From user mode, create an HV socket:
   - `socket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW)`
   - `bind` with `SOCKADDR_HV`.
   - `listen()`.
2. **Establish a loopback connection.** A second socket in the same partition performs `connect()` to the listener — this builds the `VmbusTl` loopback endpoint whose `[endpoint+0x2B8]` delivery-queue head is the shared pointer.
3. **Spawn two racing threads:**
   - **Thread A (reader):** repeatedly `send()` / drive receive completion on the connected socket. This dispatches into `VmbusTlLoopbackSend` (`sub_1C0007388`) and `VmbusTlLoopbackNotifyReceiveConsumed` (`sub_1C0007CF0`), whose gate-off branch reads `[endpoint+0x2B8]` unsynchronized.
   - **Thread B (freer):** repeatedly closes and re-establishes the connection, invoking `VmbusTlLoopbackDisconnect` (`sub_1C00079D0`), which clears the head and drops the entry's reference count, freeing it via `ExFreePoolWithTag(..., 'Vnpi')` when it reaches zero.
4. **Race window.** The window is a handful of instructions between the head read at `0x1C0007E43` and the dereference at `0x1C0007E4F`. Reachability of the unsynchronized branch depends on the `Feature_1274333499` feature state on the running build, which is not observable from the static image.
5. **Observable effect (if the race fires):** a fault dereferencing a freed delivery-queue entry at `0x1C0007E4F`/`0x1C0007E63`, or a reference-count fail-fast (`int 29h`, `RtlFailFast`) from the mismatched decrement.

---

## 6. Impact Assessment

**Primitive.** A race on the per-endpoint loopback delivery-queue entry, a `Vnpi`-tagged nonpaged-pool object. In the unsynchronized branch the code reads the head without the endpoint spinlock and without incrementing the entry's reference count, then later decrements a reference it never took; concurrently `VmbusTlLoopbackDisconnect` can clear the head and free the entry. The demonstrable consequences are:

- Dereference of a delivery-queue entry that a concurrent disconnect may have freed (use-after-free read/write at `[rdi+0x68]` / `[rdi+0x210]`).
- Reference-count imbalance on the entry, which the driver guards with `RtlFailFast` (`int 29h`) on underflow — a bugcheck, not silent corruption, on the paths observed here.

The entry's destructor-style dispatch at `[entry+0x50]` is invoked through `__guard_dispatch_icall_fptr` (Control Flow Guard), so it is not a free indirect-call primitive. No arbitrary read/write, information-leak, or control-flow-hijack primitive is demonstrable from these binaries; those would require assumptions about pool reuse and object contents that the binaries do not support. The realistic impact is a kernel race that can manifest as a use-after-free / bugcheck (denial of service) on the loopback path, reachable only where `hvsocket.sys` loopback is available and the unsynchronized feature branch is active. This supports a Medium rating.

---

## 7. Debugging Notes

Assume `hvsocket_unpatched.sys` is loaded and a kernel debugger is attached. Use the loaded module base to translate the RVAs below (listed against the analyzed image base `0x1C0000000`).

### Breakpoints

```text
; Primary function — observe gate and branch selection
bp hvsocket_unpatched!VmbusTlLoopbackNotifyReceiveConsumed+0x12   ; 0x1C0007D02 — gate call
bp 0x1C0007E43                                                    ; unsynchronized head read

; Concurrent disconnect (writer side)
bp hvsocket_unpatched!VmbusTlLoopbackDisconnect                   ; entry — rcx = endpoint
bp 0x1C0007A26                                                    ; head read/clear (no lock if gate off)
bp 0x1C0007BD3                                                    ; lock xadd [rsi+0x8] (reference decrement)

; Synchronized helper (gate-on / patched path)
bp hvsocket_unpatched!VmbusTlLoopbackReferenceEndpointDeliveryQueue

; WIL feature gate
bp hvsocket_unpatched!Feature_1274333499__private_IsEnabledDeviceUsage
```

### What to inspect

- **At `VmbusTlLoopbackNotifyReceiveConsumed` entry:** `rcx` = endpoint. `poi(rcx+0x2B8)` is the shared delivery-queue head.
- **After the gate call (`0x1C0007D07`):** `eax == 0` selects the unsynchronized branch; non-zero selects the synchronized helper.
- **At `0x1C0007E43`:** `rbx` = endpoint; `poi(rbx+0x2B8)` is the head being read without the lock.
- **At `0x1C0007E4F`:** `rdi` is the entry; `poi(rdi+0x68)` is the back-pointer being dereferenced.
- **At the three gate calls in `VmbusTlLoopbackDisconnect` (`0x1C0007A0A`, `0x1C0007A3E`, `0x1C0007A50`):** each is an independent evaluation of the same feature state.
- **At `0x1C0007BD3`:** `lock xadd [rsi+0x8], rax` decrements the entry's reference count; reaching zero leads to `ExFreePoolWithTag(rsi, 'Vnpi')`.

### Key instruction offsets (RVA from `0x1C0000000`)

| Offset | Meaning |
|---|---|
| `+0x7D02` | Feature-gate call selecting the branch |
| `+0x7D09` | `jz` to the unsynchronized branch when the gate is off |
| `+0x7E43` | Unsynchronized head read (`mov rdi,[rbx+0x2B8]`) |
| `+0x7E4F` | Entry back-pointer dereference (`mov rdi,[rdi+0x68]`) |
| `+0x7E63` | Flag write (`or dword [rdi+0x210], 2`) |
| `+0x7A0A / +0x7A3E / +0x7A50` | Three feature-gate evaluations in disconnect |
| `+0x7A26` | Disconnect's unsynchronized `[rbx+0x2B8]` read/clear |
| `+0x7BD3` | Atomic reference-count decrement → free |

### Struct layout (observed from the free/dispatch paths)

```text
Loopback endpoint object (arg1):
  +0x10   FAST_MUTEX          (held during these routines)
  +0x48   KSPIN_LOCK          (the lock skipped on the gate-off branch)
  +0x2B8  delivery-queue head pointer (unsynchronized read target; decompiled as endpoint[0x57])
  +0x70   parent provider/listener object

Delivery-queue entry object (tag 'Vnpi', 0x69706E56):
  +0x08   LONG reference count  (atomic; lock xadd at 0x1C0007BD3)
  +0x50   destructor function pointer (invoked via __guard_dispatch_icall_fptr / CFG)
  +0x58   free-mode selector    (1 = ExFreePoolWithTag, 2 = SLIST return)
  +0x60   SLIST_HEADER*         (lookaside/return list)
  +0x68   back-pointer to endpoint object (dereferenced on the racing branch)
  +0x210  status flags          (target of the 'or dword [...,0x210], 2' write)
```

---

## 8. Changed Functions — Full Triage

### Security-relevant (covered above)

| Function | Sim. | Change | Note |
|---|---|---|---|
| `VmbusTlLoopbackNotifyReceiveConsumed` (`sub_1C0007CF0`) | 0.839 | security | Feature-gated unsynchronized head read → race/UAF; patch always uses the synchronized helper. |
| `VmbusTlLoopbackSend` (`sub_1C0007388`) | 0.883 | security | Same pattern on the send path (`[r15+0x2B8]` read on the gate-off branch). |
| `VmbusTlLoopbackDisconnect` (`sub_1C00079D0`) | 0.915 | security | Writer side: gate-off branch clears `[endpoint+0x2B8]` without the spinlock; patch acquires/releases unconditionally. |
| `VmbusTlLoopbackAcceptConnection` (`sub_1C001D700`) | 0.781 | security | Same unsynchronized `[endpoint+0x2B8]` read on the gate-off branch; patched to always use the synchronized helper. |
| `VmbusTlNotifyListenerAccept` (`sub_1C0006C9C`) | 0.803 | security | Gate-gated reference handling on the delivery queue; patch unifies to the synchronized path. |
| `VmbusTlProcessNewConnectionForListener` (`sub_1C001BEF4`) | 0.981 | low | Two gate evaluations removed; acceptance field read unconditionally. No demonstrable exploitable impact. |
| `VmbusTlProviderListen` (`sub_1C0020570`) | 0.598 | security | Feature-gated dual path for listener setup; patch unifies to the single synchronized path (large reduction in pseudo-C size). Establishes the loopback context the others operate on. |

### Behavioral (not directly exploitable)

- **`VmbusTlLoopbackSetupConnection` (`sub_1C001D290`)** (0.848): Error-path cleanup changed from a gate-conditional to an unconditional cleanup call. Runs inside the fast mutex; consistency change.
- **`VmbusTlCommonConnectCompletion` (`sub_1C0003254`)** (0.964): Removes a gate guard around a reference decrement on the abort path, making the decrement unconditional (fixes a potential reference leak on the gate-off branch, not a UAF).

### WIL feature-staging library churn (not security-relevant)

- **`wil_details_FeatureStateCache_TryEnableDeviceUsageFastPath` (`sub_1C00023EC`)** (0.818): WIL feature-state cache helper; `arg3` parameter dropped as the state source moves to the module's feature-state global. Library infrastructure.
- **`wil_details_IsEnabledFallback` (`sub_1C0002358`)** (0.954): WIL feature-state fallback helper. Library infrastructure.
- **`wil_details_FeatureReporting_ReportUsageToServiceDirect` (`sub_1C0001DFC`)** (0.977): WIL feature-usage reporting helper; uses the module feature-reporting singleton. Library infrastructure.

### Cosmetic / compiler-driven

- **`wil_details_FeatureReporting_ReportUsageToService` (`sub_1C0001EE4`)** (0.990): WIL reporting wrapper; compiler restructured an if-else dispatch into a subtract-and-compare cascade. Functionally equivalent.
- **`Feature_1043374394__private_IsEnabledFallback` (`sub_1C00040A8`)** (0.674): Small WIL fallback stub for a different feature ID; updated for relocated targets. No security impact.

---

## 9. Unmatched Functions

None. Both `unmatched_unpatched` and `unmatched_patched` are `0`. No sanitizer or helper was added or removed wholesale — the change is a code-path unification inside existing functions: the WIL feature gate is deleted (18 gate call sites in the unpatched build across 9 functions; 0 in the patched build) and the synchronized helper is called unconditionally.

---

## 10. Confidence & Caveats

**Confidence:** High for the structural diagnosis; Medium for real-world reachability.

Rationale:
- The feature-gated dual-path pattern is reproduced across the affected functions and corroborated by direct assembly. The unsynchronized read at `[endpoint+0x2B8]` and the subsequent `[+0x68]` dereference on the gate-off branch, versus the lock-then-read behavior of `VmbusTlLoopbackReferenceEndpointDeliveryQueue`, are unambiguous. The patch removes the gate and calls the synchronized helper unconditionally in every affected function.
- The gate is the WIL feature `Feature_1274333499__private_IsEnabledDeviceUsage`, which reads `Feature_1274333499__private_featureState` and falls back to `Feature_1274333499__private_IsEnabledFallback`. Whether the feature is enabled by default — and thus whether the unsynchronized branch runs on a default deployment — is not determinable from the static image.
- The `Vnpi` pool tag (`0x69706E56`), the `+0x08` reference count, `+0x48` spinlock, `+0x50` CFG-guarded destructor dispatch, `+0x58` free-mode selector, `+0x60` SLIST header, `+0x68` back-pointer, and `+0x210` flags are all read directly from the free/dispatch paths in the disassembly.

**Not determinable from the binaries (do not assume):**
- The default enablement state of `Feature_1274333499`, hence whether the unsynchronized branch is the shipped default.
- Any escalation beyond a race-induced use-after-free / bugcheck. The `[entry+0x50]` dispatch is CFG-guarded, and no pool-reuse, information-leak, or arbitrary read/write primitive is evidenced here.
