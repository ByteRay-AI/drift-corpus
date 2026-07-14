Title: hvsocket.sys — Velocity feature gate removed: guest-reachable listener accept-state validation (and loopback lifetime handling) promoted from a staged feature to unconditional
Date: 2026-06-09
Slug: hvsocket_f69c44ef-hvsocket-report-20260713-184122
Category: Corpus
Author: Argus
Severity: Low

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | hvsocket_unpatched.sys |
| Patched binary | hvsocket_patched.sys |
| Overall similarity | 0.9742 |
| Matched functions | 269 |
| Changed functions | 9 |
| Identical functions | 260 |
| Unmatched (unpatched / patched) | 0 / 0 |

**Verdict (corrected):** `over-claimed-but-real` — a **delivered** fix whose severity and mechanism were badly overstated by the original automated report.

The entire patch is the removal of **one Windows Feature-Management ("Velocity") staging gate** — feature `1542768955_57582472`, evaluated through the helper `EvaluateCurrentState()` — from every call site in the driver. In the unpatched build each of the 9 changed functions has two twin code paths selected by `if (EvaluateCurrentState())`: a *feature-enabled* path with stricter reference-counting / locking / state-validation, and a *feature-disabled* path that uses the older, looser handling (raw pointer reads, missing checks, no reference). The patched build **deletes the gate and keeps only the feature-enabled (safer) path** in all 9 functions, and empties the driver's feature-descriptor table so the staging machinery no longer references this feature at all. Per the classification rules, *a removed feature gate that folds all callers to the safe path binary-wide is a delivered fix* — so this is delivered, not staged.

The most security-relevant delivered effect is on the **guest-reachable inbound-accept path**: `VmbusTlNotifyListenerAccept` now always checks the listener accept-guard byte (`endpoint+0x128`) before dispatching the accept callback, and `VmbusTlProcessNewConnectionForListener` now always requires the endpoint accepting-state byte (`endpoint+0x1a9`) before creating an inbound connection. The remaining seven functions fold to safer refcount/lock handling on the **loopback (in-host, host-local)** path.

**What the original report got wrong.** It never identified `EvaluateCurrentState()` as a feature-management gate — it called it an "opaque state predicate" and reframed the change as a listener-lifetime *race* (CWE-362 → CWE-416). It then built a use-after-free → controlled-indirect-call → guest-to-host VM-escape exploit chain (pool grooming, KASLR leak, ROP, SMEP/HVCI/CFG bypass, PoC playbook). **None of that is evidenced by the diff.** The accept callback is dispatched on a listener object that is kept alive by a reference the function itself takes (a try-reference that only proceeds when the object's refcount is already ≥ 1), so no use-after-free of that object is shown; the guard byte at `+0x128` is a *logical* "accept-not-allowed / closing" state flag, not a liveness/free indicator. The proven primitive is a **missing state-validation on a guest-reachable path**, now enforced — real, but modest, defense-in-depth. All of the report's low-level anchors (field offsets, trace ordinals, status codes, the two branch structures) are accurate and are preserved below; only the interpretation and severity have been corrected.

---

## 2. Change Summary

### 2.1 LOW — Guest-reachable listener/endpoint accept-state validation made unconditional (feature-gate removal)
- **Affected functions:** `VmbusTlNotifyListenerAccept` (unpatched `sub_1C0005F18` → patched `sub_1C0005C68`) and `VmbusTlProcessNewConnectionForListener` (unpatched `sub_1C0019E60` → patched `sub_1C0019DB0`).
- **Mechanism (real):** Both functions are gated by `EvaluateCurrentState()`:
  ```c
  // hvsocket_unpatched.c
  _BOOL8 EvaluateCurrentState() {
      EvaluateFeature((unsigned int **)&reg_FeatureDescriptors_a);
      return g_Feature_1542768955_57582472_cachedstate != 1;   // Velocity feature cached state
  }
  ```
  `EvaluateFeature` → `EvaluateCurrentStateFromRegistry` reads
  `\Registry\MACHINE\System\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides`.
  This is the standard Windows feature-staging (Velocity) plumbing. The patched build removes every `EvaluateCurrentState()` call site and empties the feature table (see §9), so the previously feature-enabled path runs unconditionally.
- **Delivered effect — `VmbusTlNotifyListenerAccept`:** In the unpatched build the listener accept-guard byte at `endpoint+0x128` is checked *only* on the feature-enabled branch; on the feature-disabled branch the CAS-referenced accept path jumps straight to the accept-dispatch callback without it. The patched build always checks the guard and returns `0xC0000236` (STATUS_CONNECTION_REFUSED) when set, so the callback never fires for a listener in the accept-not-allowed state.
- **Delivered effect — `VmbusTlProcessNewConnectionForListener`:** In the unpatched build the endpoint accepting-state byte at `endpoint+0x1a9` is *read only when the feature is enabled* and the refusal only fires when the feature is enabled; the patched build reads it unconditionally and hard-requires it before `VmbusTlCreateConnection`, returning `0xC0000236` otherwise.
- **Attacker reachability:** `VmbusTlNotifyListenerAccept` is invoked from `VmbusTlInboundConnectComplete` (`sub_1C00027E8`), i.e. on completion of a guest-initiated inbound connection, and `VmbusTlProcessNewConnectionForListener` runs on the guest-driven inbound `VmbusTlProcessNewConnection` path. hvsocket is guest-reachable (a VM guest drives inbound connects), so this is a real validation-on-guest-input hardening.
- **Proven primitive (corrected):** On the pre-patch feature-disabled path, an inbound accept could be dispatched, or an inbound connection created/associated, against a listener/endpoint whose state flags indicate it is closing / not accepting. This is a **state-validation / lifecycle-consistency gap**. No memory-corruption consequence is demonstrated by the diff: the endpoint object is reference-held across the callback, so the report's use-after-free and controlled-indirect-call claims are **not substantiated**. Severity of the proven primitive: **Low** (guest-reachable state-validation hardening, no demonstrated memory-safety impact).

### 2.2 LOW / INFORMATIONAL — Loopback endpoint lifetime handling made unconditional (host-local)
- **Affected functions:** `VmbusTlLoopbackAcceptConnection`, `VmbusTlLoopbackSend`, `VmbusTlLoopbackNotifyReceiveConsumed`, `VmbusTlLoopbackSetupConnection`, `VmbusTlLoopbackDisconnect`, plus `VmbusTlProviderListen` and `VmbusTlCommonConnectCompletion`.
- **Mechanism (real):** Same feature-gate fold. In each case the patched build keeps the feature-enabled branch, which does proper reference-counting / locking / cleanup, and drops the feature-disabled branch, which used raw pointer reads (no reference), skipped a spinlock, or skipped a cleanup step. See §8 for the per-function detail.
- **Reachability / severity:** The loopback path is **in-host AF_HYPERV (host-to-host)**, not driven from a guest across the trust boundary, so these folds are host-local robustness/lifetime hardening. Severity **Low → Informational**; they do not raise the maximum severity above §2.1.

---

## 3. Pseudocode Diff

### 3.1 VmbusTlNotifyListenerAccept (`sub_1C0005F18` → `sub_1C0005C68`)
```c
// UNPATCHED — VmbusTlNotifyListenerAccept @ 0x1C0005F18
v5 = (_QWORD *)(a1 + 304);                 // +0x130 inbound-connection refcount
if ( EvaluateCurrentState() )              // <-- Velocity feature gate (feature ENABLED)
{
    // try-reference CAS on *(a1+0x130); succeeds only if refcount was >= 1
    for ( i = *v5 + 1; i > 1; i = v6 + 1 ) {
        v6 = _InterlockedCompareExchange64(v5, i, v6);
        if ( v8 == v6 ) {
            if ( *(_BYTE *)(a1 + 296) == 0 )   // +0x128 accept-guard CHECK (only here)
                goto LABEL_15;                  //   -> accept
            goto LABEL_12;                      // guard set -> error 0xC0000236
        }
    }
    ... reference-failed error paths ...
}
else                                        // <-- feature DISABLED (default/legacy path)
{
    // try-reference CAS on *(a1+0x130)
    for ( j = *v5 + 1; j > 1; j = v16 + 1 ) {
        v16 = _InterlockedCompareExchange64(v5, j, v16);
        if ( v18 == v16 ) {
LABEL_15:                                       // ACCEPT — NO +0x128 guard check on this path
            ...
            v13 = (*(__int64 (__fastcall **)(__int64, _QWORD *))(*(_QWORD *)(a1 + 336) + 8LL))(
                       *(_QWORD *)(a1 + 352), v23);   // accept-dispatch callback (sink)
            ...
        }
    }
}
```
```c
// PATCHED — VmbusTlNotifyListenerAccept @ 0x1C0005C68  (feature gate removed)
// single path, no EvaluateCurrentState()
for ( i = *(a1+304) + 1; ; ... )                  // try-reference CAS on +0x130
    ...
if ( *(_BYTE *)(a1 + 296) != 0 )                  // +0x128 accept-guard ALWAYS checked
{
    v7 = -1073741258;                             // 0xC0000236 STATUS_CONNECTION_REFUSED
    return v7;                                     // callback NEVER fires when guard set
}
v12 = (*(...)(*(_QWORD *)(a1 + 336) + 8LL))(*(_QWORD *)(a1 + 352), v18);  // accept only if guard clear
```

**Key changes:**
- The unpatched feature-**disabled** branch reaches `LABEL_15` (the accept-dispatch callback) without ever executing `if (*(_BYTE *)(a1 + 296) == 0)`. Only the feature-**enabled** branch checks the guard.
- The patched build removes the `EvaluateCurrentState()` split entirely and always evaluates the accept-guard `endpoint+0x128`, returning `0xC0000236` before the callback when it is set.
- The endpoint object is reference-held across the callback on both branches (the CAS is a try-reference that only proceeds when refcount ≥ 1), so the change closes a *state-check* gap, not a demonstrated free-then-use.

### 3.2 VmbusTlProcessNewConnectionForListener (`sub_1C0019E60` → `sub_1C0019DB0`)
```c
// UNPATCHED — @ 0x1C0019E60
ExAcquireFastMutexUnsafe(&endpoint[1]);
    if ( EvaluateCurrentState() )                 // <-- feature gate
        v13 = *((_BYTE *)&endpoint[26].Next + 9); //   +0x1a9 accepting-state byte, read ONLY if enabled
    v31 = *((_BYTE *)&endpoint[11].Next + 9);      //   +0xb9
    v67 = *((_BYTE *)&endpoint[11].Next + 10);     //   +0xba
ExReleaseFastMutexUnsafe(&endpoint[1]);
    if ( EvaluateCurrentState() && v13 == 0 )      // refusal only when feature enabled (trace 588)
        return 0xC0000236;
    if ( v31 == 0 ) goto create;                   // -> VmbusTlCreateConnection
    return 0xC0000236;                             // trace 596
```
```c
// PATCHED — @ 0x1C0019DB0  (feature gate removed)
ExAcquireFastMutexUnsafe(&endpoint[1]);
    v28 = *((_BYTE *)&endpoint[26].Next + 9);      // +0x1a9 read UNCONDITIONALLY
    v29 = *((_BYTE *)&endpoint[11].Next + 9);      // +0xb9
    v65 = *((_BYTE *)&endpoint[11].Next + 10);     // +0xba
ExReleaseFastMutexUnsafe(&endpoint[1]);
    if ( v28 == 0 ) return 0xC0000236;             // HARD requirement (trace 572)
    if ( v29 == 0 ) goto create;                   // -> VmbusTlCreateConnection
    return 0xC0000236;                             // trace 579
```

**Key changes:**
- Unpatched reads `endpoint+0x1a9` and enforces it only when the feature is enabled (`EvaluateCurrentState() && v13 == 0`); patched always reads it and hard-requires it (`if (v28 == 0) refuse`).
- Trace ordinals shift `588/596 → 572/579` (these are just diagnostic line numbers, not security-relevant).
- Note: IDA models `_SLIST_ENTRY` with a 16-byte stride here, so `endpoint[26].Next + 9 = 0x1a9`, `endpoint[11].Next + 9/10 = 0xb9/0xba`, and `&endpoint[1] = endpoint+0x10` (the fast mutex). These match the byte offsets quoted throughout.

---

## 4. Assembly Analysis

### 4.1 VmbusTlNotifyListenerAccept

**Unpatched — feature split and the guard-less accept-dispatch on the disabled branch:**
```asm
0x1c0005f18 | call    0x1c0001d78            ; EvaluateCurrentState()  == Velocity feature check
            | lea     r12, [rel 0x1c000f430]
            | mov     esi, 0xc0000236        ; STATUS_CONNECTION_REFUSED (default return)
            | lea     r14, [rel 0x1c000f468]
            | lea     rdi, [rbx+0x130]        ; &inbound-connection refcount (try-reference target)
            | test    eax, eax
            | je      0x1c00060a0            ; feature==0 -> DISABLED branch (no [rbx+0x128] guard)
            ; ... try-reference CAS: lock cmpxchg qword [rdi], rcx ...
0x1c000600b | ; accept-dispatch prologue (reached from LABEL_15 on the disabled branch)
            | mov     rcx, qword [rbx+0x160]  ; arg1[0x2c] = callback context
            | lea     rax, [rel 0x1c000e000]  ; &VmbusTlProviderConnectDispatch
            | call    qword [rel 0x1c00152b0] ; (*(*(rbx+0x150)+8))(*(rbx+0x160), &var_a8)  accept callback
            | ...
            | cmp     byte [rbx+0x128], 0x0   ; accept-guard — present ONLY on the enabled branch
            | jne     0x1c0005fda            ; -> error 0xC0000236
```
Annotations (corrected):
- `call 0x1c0001d78` is `EvaluateCurrentState()`, i.e. the read of Velocity feature `1542768955_57582472`. It selects feature-enabled vs feature-disabled behavior — **not** a runtime lifecycle race predicate.
- On the feature-disabled branch the accept-dispatch callback at `call qword [rel 0x1c00152b0]` runs without a preceding `cmp byte [rbx+0x128], 0`. The object is nonetheless reference-held by the try-reference CAS above (`lock cmpxchg qword [rbx+0x130]`), so this is a missing *state* check, not a demonstrated free-then-use.

**Patched — single common path with the guard before the callback:**
```asm
; PATCHED @ 0x1C0005C68 — no EvaluateCurrentState(); single try-reference then:
cmp     byte [rbx+0x128], 0x0   ; always executed
jne     0x1c0005d18            ; -> return 0xC0000236 (STATUS_CONNECTION_REFUSED)
; only if guard clear:
call    qword [rel 0x...]       ; accept-dispatch callback
```

### 4.2 VmbusTlProcessNewConnectionForListener
```asm
; UNPATCHED @ 0x1C0019E60 (gate region, pseudo-anchored):
;   ExAcquireFastMutexUnsafe(&endpoint[0x10]);
;   call EvaluateCurrentState  ; feature check
;   test eax,eax / (if set) movzx r?, byte [endpoint+0x1a9]   ; accepting-state read ONLY if feature enabled
;   ExReleaseFastMutexUnsafe(&endpoint[0x10]);
;   call EvaluateCurrentState  ; feature check again; refuse (0xC0000236, trace 588) only if enabled && byte==0
;   ... else gate on byte[endpoint+0xb9]; create via VmbusTlCreateConnection
; PATCHED @ 0x1C0019DB0:
;   movzx r?, byte [endpoint+0x1a9]   ; read UNCONDITIONALLY
;   test / jz -> return 0xC0000236 (trace 572)   ; hard requirement, no feature check
```

---

## 5. Trigger / Behavioral Conditions
There is no attacker "trigger" in the exploit sense — the patch changes a *default behavior*, it does not fix a race the attacker wins with timing. The observable behavioral delta is:

1. On the host, create an AF_HYPERV (`HV_PROTOCOL_RAW`) listening socket bound to a service GUID and `listen()`.
2. From a guest, `connect()` to that service; the inbound connection is processed host-side via `VmbusTlProcessNewConnection → VmbusTlProcessNewConnectionForListener` and completed via `VmbusTlInboundConnectComplete → VmbusTlNotifyListenerAccept`.
3. Bring the listener/endpoint into the "not accepting / closing" state (`byte[endpoint+0x1a9] == 0` and/or `byte[endpoint+0x128] != 0`).
4. **Pre-patch, feature disabled:** the accept-dispatch callback can still fire (`VmbusTlNotifyListenerAccept`) and/or an inbound connection can still be created (`VmbusTlProcessNewConnectionForListener`) despite the non-accepting state. **Pre-patch, feature enabled**, and **post-patch unconditionally:** the driver returns `0xC0000236` and refuses.

**Note:** Whether the pre-patch field build actually exhibited the looser behavior depends on the default/registry state of Velocity feature `1542768955_57582472`, which is not resolvable from the decompiled code (the default lives in the feature descriptor data). The patch makes the stricter behavior permanent regardless.

---

## 6. Exploit Primitive & Development Notes (corrected)
- **Proven primitive:** A guest-reachable **state-validation gap**. On the pre-patch feature-disabled path the accept-dispatch callback (`(*(*(endpoint+0x150)+8))(*(endpoint+0x160), &localbuf)`) can be dispatched, or an inbound connection created, on a listener/endpoint that is closing / not accepting. The patch enforces the state check unconditionally.
- **What is NOT supported by the diff (removed from the original report):**
  - *Use-after-free.* The accept path is guarded by a try-reference on `endpoint+0x130` that only proceeds when the object's refcount is already ≥ 1, so the endpoint is alive during the callback. The function pointer and context read at `endpoint+0x150 / +0x160` are fields of that live object; the diff does not show them being freed within any window. `endpoint+0x128` is a logical "accept-not-allowed" flag, not a free/liveness marker.
  - *Controlled indirect call / arbitrary function-pointer hijack.* The callback dispatches through a listener-owned dispatch object on a live, reference-held endpoint; nothing in the diff shows attacker control of that pointer or its context.
  - *Pool grooming, KASLR leak, ROP/stack-pivot, token/ACL corruption, SMEP/SMAP/CFG/CET/HVCI/VBS bypass, guest-to-host VM escape, "PoC available".* These are fabricated exploit narrative unsupported by any evidence in the diff and are removed.
- **Realistic outcome:** At most, acceptance of an inbound connection or dispatch of an accept callback on a listener/endpoint in a non-accepting/closing state — a robustness/lifecycle-consistency issue on guest-driven input. Any memory-safety consequence beyond that is unproven and would require live analysis of the listener close/teardown path (which is not part of this diff).

---

## 7. Debugger Notes
Assume WinDbg/KD attached. RVAs assume analysis base `0x1c0000000`; subtract it to feed `bp hvsocket+<rva>`. Note patched addresses differ from unpatched (the patched function starts at `0x1C0005C68`).

### 7.1 VmbusTlNotifyListenerAccept
```text
bp hvsocket!VmbusTlNotifyListenerAccept    ; rcx=arg1 (listener/endpoint), rdx=arg2 (incoming conn)
; Inspect the fields the patch now gates on:
db @rcx+0x128 L1        ; accept-guard flag  (patched refuses accept when non-zero)
dq @rcx+0x130 L1        ; inbound-connection refcount (try-referenced; >= 1 means object is live)
dq @rcx+0x150 L1        ; accept-dispatch object; [that+8] = called function pointer
dq @rcx+0x160 L1        ; callback context (first arg to the dispatch callback)
```
Distinguish unpatched vs patched behavior by whether `cmp byte [rbx+0x128],0` executes before the `call qword [rel ...]` accept-dispatch. On the patched build the guard always precedes the call and the call is skipped (returns `0xC0000236`) when the guard is set. Do **not** expect a freed-pool value at `poi(@rcx+0x150)+8` — the object is reference-held; the earlier report's freed-pool expectation is unsubstantiated.

### 7.2 VmbusTlProcessNewConnectionForListener
```text
bp hvsocket!VmbusTlProcessNewConnectionForListener
db <endpoint>+0x1a9 L1   ; accepting-state byte; patched hard-requires non-zero before VmbusTlCreateConnection
db <endpoint>+0xb9  L1    ; state field
db <endpoint>+0xba  L1    ; state field
```
Unpatched (feature disabled): `VmbusTlCreateConnection` can proceed with `byte[endpoint+0x1a9] == 0`. Patched: returns `0xC0000236` (trace ordinal 572/579) and no connection is created.

**Struct / offset notes (verified against both builds):**
```text
endpoint/listener object (pool tag 'Vnpi' = 0x69706E56):
  +0x08  object refcount
  +0x128 accept-guard flag            ; VmbusTlNotifyListenerAccept refuses accept when set (patched)
  +0x130 inbound-connection refcount  ; try-referenced (CAS), object alive while >= 1
  +0x150 accept-dispatch object       ; [+8] = called function pointer
  +0x160 callback context             ; first arg to the accept-dispatch callback
  +0x1a9 accepting-state byte         ; VmbusTlProcessNewConnectionForListener hard-requires (patched)
gate helper: EvaluateCurrentState() @ 0x1C0001D78 = Velocity feature 1542768955_57582472
```

---

## 8. Changed Functions — Full Triage
All 9 changed functions are the **same feature-gate fold**: the `EvaluateCurrentState()` (feature `1542768955_57582472`) branch is removed and the previously feature-enabled (safer) path is kept. An independent light diff (§11) confirmed **no independent new bounds/length/authorization/overflow check** was introduced in any of them.

- **VmbusTlNotifyListenerAccept** (`0x1C0005F18` → `0x1C0005C68`, sim 0.8058): **Primary security-relevant fold.** Guard byte `endpoint+0x128` now always checked before the accept-dispatch callback; returns `0xC0000236` when set. Guest-reachable. Severity **Low** (state-validation, no proven corruption). See §2.1/3.1/4.1.
- **VmbusTlProcessNewConnectionForListener** (`0x1C0019E60` → `0x1C0019DB0`, sim 0.9758): **Security-relevant fold.** Endpoint accepting-state byte `endpoint+0x1a9` now unconditionally read and hard-required before `VmbusTlCreateConnection`. Guest-reachable. Severity **Low**. See §2.1/3.2/4.2.
- **VmbusTlProviderListen** (`0x1C001E420` → `0x1C001E290`, sim 0.5854): Largest structural diff, but it is the feature fold plus churn. Patched keeps the feature-enabled listen path (early base-endpoint requirement `if (v5 >= 0) → 0xC0000010` "Required base endpoint not present", trace 191, and the 3-way refcount-release cleanup). Also incidental: `VmbusTlCreateListenEndpoint` inlined to `VmbusTlCreateEndpoint(...,3,...)`, `ExchangeAdd(-1)`→`Decrement64` codegen, trace renumbering. Host setup path. **Not independently security-relevant.**
- **VmbusTlLoopbackAcceptConnection** (`0x1C001B630` → `0x1C001B530`, sim 0.7703): Feature fold only. The "reference the endpoint delivery queue first and bail `0xC000020D` if NULL before `VmbusTlCreateObject`" behavior the earlier report flagged as a *new* check was **already the feature-enabled path in the unpatched build** (unpatched lines ~13591-13605); the fold merely drops the feature-disabled path that read the delivery-queue pointer raw (`*((_QWORD*)P + 87)`) without a reference. Loopback = **host-local**. Severity **Informational**.
- **VmbusTlLoopbackSend** (sim 0.8744): Feature fold; keeps the refcounted delivery-queue path (reference then release, bail with an error status if NULL). Host-local. Informational.
- **VmbusTlLoopbackNotifyReceiveConsumed** (sim 0.8456): Feature fold; keeps the refcounted path over the raw-pointer disabled path. Host-local. Informational.
- **VmbusTlLoopbackSetupConnection** (sim 0.9501): Feature fold; keeps the mutex-protected delivery-queue reference-release + `VmbusTlLoopbackSetEndpointDeliveryQueue(a2,0)` cleanup over the disabled path's bare `*(a2+696)=0`. Host-local. Informational.
- **VmbusTlLoopbackDisconnect** (sim 0.9158): Feature fold; patched unconditionally takes the endpoint spinlock around `*(v3+104)=0`, folding to the stricter-locking path. Host-local. Informational.
- **VmbusTlCommonConnectCompletion** (sim 0.9619): Feature fold; the `EvaluateCurrentState() &&` conjunct is dropped from `if (EvaluateCurrentState() && (*(_DWORD*)(a1+528) & 0x80) != 0)`, so the connection-reference release + `VmbusTlQueueEndpointAction(...,9)` now runs whenever the `0x80` flag is set. Trace ordinal `582→580`. **Not independently security-relevant.**

---

## 9. Feature-Staging Table (why this is *delivered*, not *staged*)
- The gate helper `EvaluateCurrentState()` (`0x1C0001D78`) reads Velocity feature `g_Feature_1542768955_57582472`; it appears at ~20 call sites in the unpatched build and **zero** in the patched build.
- The feature initializer confirms the table was emptied:
  ```c
  // UNPATCHED
  for ( i = &reg_FeatureDescriptors_a; i < &reg_FeatureDescriptors_z; ++i ) { ... EvaluateFeature(i); ... }
  // PATCHED  (rbc_InitializeFeatureStaging)
  for ( i = &reg_FeatureDescriptors_z; i < &reg_FeatureDescriptors_z; ++i ) { ... }   // start == end: loop never runs
  ```
  In the patched build the descriptor range is empty (`_z`..`_z`), so no feature (including `1542768955_57582472`) is registered or evaluated. `g_Feature_1542768955_57582472` and `reg_FeatureDescriptors_a` no longer exist in the patched image.
- Per the classification rule, *a removed feature gate that folds all callers to the safe path binary-wide is a delivered fix*. This is therefore **delivered** — the stricter behavior runs unconditionally in the patched build — not staged behind a disabled gate.

---

## 10. Unmatched Functions
- **Removed (unpatched only):** None
- **Added (patched only):** None
- **Implication:** The fix is entirely in-place control-flow simplification (deletion of the `EvaluateCurrentState()` feature branches), not a new sanitizer function. No separate KIR gate; the corrected checks execute unconditionally.

---

## 11. Independent Light-Diff Pass (mandatory)
Using the `changed_functions` list, all 9 functions were grepped in both `.c` builds and diffed by eye (the 7 non-primary ones via a dedicated pass). Findings:
- **7/7 non-primary functions are feature-gate-fold only.** Every fold selects the branch previously behind the enabled feature, which in each case is the safer one (proper refcount/lifetime handling in `LoopbackAcceptConnection`, `LoopbackSend`, `LoopbackNotifyReceiveConsumed`, `LoopbackSetupConnection`; stricter spinlock coverage in `LoopbackDisconnect`; the base-endpoint requirement + full cleanup in `ProviderListen`; the extra ref-release/queue-action in `CommonConnectCompletion`).
- **No omitted security-relevant change was found.** No new bounds check, length/authorization validation, or integer-overflow guard exists independently of the fold. The earlier report's one *added-check* claim (`LoopbackAcceptConnection` delivery-queue reference) was refuted: it is pre-existing feature-enabled behavior.
- Remaining differences across all 9 are trace-ordinal renumbering, register/variable renaming, `ExchangeAdd(-1)`↔`Decrement64` codegen, function inlining (`VmbusTlCreateListenEndpoint`), and Hex-Rays argument-count artifacts — not security.

---

## 12. Confidence & Caveats
- **Confidence:** high (for the corrected reading).
- **Rationale:**
  - `EvaluateCurrentState()` is unambiguously a Windows Feature-Management (Velocity) gate: it calls `EvaluateFeature`/`EvaluateCurrentStateFromRegistry`, which query `...\Microsoft\FeatureManagement\Overrides`, and returns `g_Feature_1542768955_57582472_cachedstate != 1`.
  - The patched build removes every call site and empties the descriptor table (`_z`..`_z`), so the fold is binary-wide and unconditional — a delivered fix.
  - All quoted offsets, trace ordinals, status codes and branch structures were verified in both `.c` builds; only the interpretation (feature gate, not a race) and severity (Low, not High) are changed.
- **What the diff does NOT establish (and is therefore not claimed):** any use-after-free, controlled indirect call, or guest-to-host escalation. The endpoint is reference-held across the accept callback; the accept-guard byte is a logical state flag, not a liveness marker.
- **Indeterminate from the diff:** the default (registry) enablement state of feature `1542768955_57582472` in the unpatched build, and hence whether shipped unpatched systems ran the looser path by default. The exact Windows build/KB is also unresolved and is not guessed.
- **To verify before asserting any higher impact:** live analysis of the listener/endpoint close-teardown path to determine whether the accept-dispatch sub-object (`endpoint+0x150`) or context (`endpoint+0x160`) can be freed while the endpoint reference is held. The diff alone does not show this.
