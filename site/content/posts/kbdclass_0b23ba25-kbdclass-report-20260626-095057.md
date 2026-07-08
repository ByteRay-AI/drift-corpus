Title: kbdclass.sys — KernelMode RequestorMode bypass of the SeTcbPrivilege check in KeyboardClassCreate (CWE-863) fixed
Date: 2026-06-26
Slug: kbdclass_0b23ba25-kbdclass-report-20260626-095057
Category: Corpus
Author: Argus
Summary: KB5073723

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `kbdclass_unpatched.sys` |
| Patched binary | `kbdclass_patched.sys` |
| Overall similarity | **0.6565** (moderate divergence, dominated by a recompile) |
| Matched functions | 91 |
| Changed functions | 71 |
| Identical functions | 20 |
| Unmatched (each direction) | 0 |

**Verdict:** The patched image is a broad recompile of the Windows keyboard class driver. The overwhelming majority of the divergence is non-behavioral: software-tracing (WPP) macro reformatting, `ExAllocatePoolWithTag` → `ExAllocatePool2` modernization, helper extraction/inlining, and register/control-flow churn. Exactly one security-relevant behavioral change was delivered:

- **Finding A — Medium: authorization-check bypass in `KeyboardClassCreate`.** The unpatched create handler passes the IRP's `RequestorMode` directly to `SeSinglePrivilegeCheck(SeTcbPrivilege, …)`. For a `KernelMode` requestor, that call succeeds without inspecting the caller's token, so a kernel-mode create that has requested user-level access checks (`SL_FORCE_ACCESS_CHECK`) still receives the driver's "trusted" marker, which is the gate for reading raw keyboard input. The patch forces the check to run as `UserMode` whenever that flag is set.

The previously-suspected use-after-free / TOCTOU race in `KeyboardClassRemoveDevice` was investigated and is **not** a real change: the relevant code is logically identical in both builds (see Finding B below, retained and downgraded).

---

## 2. Vulnerability Summary

### Finding A — Medium: Authorization-check bypass in `KeyboardClassCreate`

- **Severity:** Medium
- **CWE:** CWE-863 (Incorrect Authorization)
- **Vulnerability class:** Privilege-check bypass via `RequestorMode` confusion for kernel-mode callers
- **Affected function (unpatched):** `KeyboardClassCreate` @ `0x1C0001CA0`
- **Patched equivalent:** `sub_1400039F0` @ `0x1400039F0`
- **Entry point:** `IRP_MJ_CREATE` (open of `\Device\KeyboardClassN`)

**Root cause.** In the unpatched build the create handler reaches the following (decompiled) test:

```c
if ( *(_QWORD *)v5 == *(_QWORD *)(v5 + 8)
     && SeSinglePrivilegeCheck((LUID)7LL, v2->RequestorMode) != 0 )   // v2 = IRP
{
    ...
    CurrentStackLocation->FileObject->FsContext2 = DriverEntry;       // "trusted" marker
    ++*(_DWORD *)(v5 + 80);
    ...
}
```

`SeSinglePrivilegeCheck` is called with `IRP->RequestorMode`. When the requestor is `KernelMode` (value `0`), `SeSinglePrivilegeCheck` returns TRUE without examining the caller's token. As a result, a kernel-mode `IRP_MJ_CREATE` — including one issued by a driver or system component that has explicitly requested that the open be access-checked as if it came from user mode (`SL_FORCE_ACCESS_CHECK`, i.e. `OBJ_FORCE_ACCESS_CHECK`) on behalf of a lower-privileged user — passes the `SeTcbPrivilege` gate regardless of that user's token. The handler then writes the "trusted" marker to `FileObject->FsContext2` (offset `+0x20`).

That marker is what authorizes reading raw keyboard input: `KeyboardClassRead` (`0x1C0001410`) returns `STATUS_PRIVILEGE_NOT_HELD` (`0xC0000061`) unless `FileObject->FsContext2 == DriverEntry`. So the bypass grants an unprivileged deputy access to keystrokes it should not be able to read.

**The fix.** The patched handler reads the current I/O stack location's `Flags` byte and isolates `SL_FORCE_ACCESS_CHECK` (bit 0), then forces the privilege check to run as `UserMode` when that flag is set:

```c
v9 = CurrentStackLocation->Flags & 1;          // SL_FORCE_ACCESS_CHECK
...
if ( v9 != 0 )
    RequestorMode = 1;                          // force UserMode
else
    RequestorMode = v4->RequestorMode;
if ( SeSinglePrivilegeCheck((LUID)7LL, RequestorMode) != 0 )
{
    ... FileObject->FsContext2 = sub_140011080; ...   // trusted marker (patched sentinel)
}
```

It also extends the pre-existing exclusive-open denial to kernel-mode callers that set the flag, and calls a new audit helper `sub_140005AB0` when `RequestorMode == KernelMode && SL_FORCE_ACCESS_CHECK` before returning `STATUS_ACCESS_DENIED` (`0xC0000022`).

Direction is correct: the patched build is strictly stricter (a kernel-mode create that asked to be checked as user mode now actually gets its token checked).

**Attacker-reachable call chain:**
1. A kernel-mode component (driver or system service) issues `IRP_MJ_CREATE` on `\Device\KeyboardClassN` on behalf of a user, using `OBJ_FORCE_ACCESS_CHECK` (`SL_FORCE_ACCESS_CHECK` set in the create stack location).
2. I/O Manager dispatches `IRP_MJ_CREATE` → `KeyboardClassCreate @ 0x1C0001CA0`.
3. `movzx edx, byte [rbx+0x40]` @ `0x1C0001D49` loads `RequestorMode` (`0` = KernelMode).
4. `call SeSinglePrivilegeCheck` @ `0x1C0001D61` returns TRUE for KernelMode.
5. `mov [rdx+0x20], rcx` @ `0x1C0001D8F` writes the trusted marker to `FsContext2`; subsequent `IRP_MJ_READ` on the handle is now permitted.

### Finding B — No security-relevant change: `KeyboardClassRemoveDevice` wait-wake IRP handling

- **Severity:** None (informational)
- **Affected function (unpatched):** `KeyboardClassRemoveDevice` @ `0x1C0004F2C`
- **Patched equivalent:** `sub_140001C60` @ `0x140001C60`

**Finding.** The wait-wake IRP cancellation sequence in `KeyboardClassRemoveDevice` was examined for a use-after-free / TOCTOU race across the spinlock release. The sequence is present, but it is **identical in behavior between the two builds**, so the patch delivers no change here. Both builds:

1. atomically set the state field at `dev_ext+0x140` to `1` (returning if it was already non-zero),
2. acquire the spinlock at `dev_ext+0x48`,
3. read the wait-wake IRP pointer from `dev_ext+0x128` and, if present and the cancel flag at `dev_ext+0x130` is clear, set that flag and keep the pointer,
4. release the spinlock,
5. call `IoCancelIrp` on the kept pointer,
6. `xchg` the state at `dev_ext+0x140` to `2`, and if the old value was `3`, call **`IofCompleteRequest`** on the IRP.

The final call at `0x1C0004FBC` is `IofCompleteRequest` (complete the IRP), not `IoFreeIrp`; no IRP is freed in this function and there is no double-free site here. The pointer read under the lock and used after release is the standard wait-wake cancellation idiom: ownership of the IRP is arbitrated by the `dev_ext+0x140` state machine (values `1`/`2`/`3`) together with the `dev_ext+0x130` cancel flag, so the completion routine (`KeyboardClassWaitWakeComplete`) and this path cannot both own the IRP. The only difference in the patched `sub_140001C60` is a De Morgan inversion of one `if` (the null/already-cancelled case is split into its own branch); the locking, the calls, and the state transitions are unchanged. No work-item deferral is introduced.

---

## 3. Pseudocode Diff

### Finding A — `KeyboardClassCreate` (privilege-check bypass)

```c
// --- UNPATCHED KeyboardClassCreate (key section) ---
CurrentStackLocation->Parameters.Create.Options &= ~1u;
if ( *(_QWORD *)v5 == *(_QWORD *)(v5 + 8)
     && SeSinglePrivilegeCheck((LUID)7LL, v2->RequestorMode) != 0 )   // KernelMode → TRUE
{
    v9 = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(v5 + 160));
    CurrentStackLocation->FileObject->FsContext2 = DriverEntry;       // grant trusted marker
    ++*(_DWORD *)(v5 + 80);
    KeReleaseSpinLock((PKSPIN_LOCK)(v5 + 160), v9);
}

// --- PATCHED equivalent (sub_1400039F0) ---
v9 = CurrentStackLocation->Flags & 1;                                 // SL_FORCE_ACCESS_CHECK
...
if ( v4->RequestorMode == 0 && v9 != 0 )                             // kernel caller asked for user check
    sub_140005AB0(...);                                              // audit, then STATUS_ACCESS_DENIED
...
CurrentStackLocation->Parameters.Create.Options &= ~1u;
if ( *(_QWORD *)v8 == *(_QWORD *)(v8 + 8) )
{
    if ( v9 != 0 )                 RequestorMode = 1;                 // FORCE UserMode
    else                          RequestorMode = v4->RequestorMode;
    if ( SeSinglePrivilegeCheck((LUID)7LL, RequestorMode) != 0 )      // token actually checked
    {
        ... FileObject->FsContext2 = sub_140011080; ...              // trusted marker
    }
}
```

### Finding B — `KeyboardClassRemoveDevice` (identical in both builds)

```c
// --- UNPATCHED KeyboardClassRemoveDevice ---
if ( _InterlockedExchange((volatile __int32 *)(a1 + 320), 1) == 0 ) {   // +0x140 state
    v3 = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(a1 + 72));           // +0x48
    v4 = *(IRP **)(a1 + 296);                                          // +0x128 WW IRP
    if ( v4 != nullptr && *(_BYTE *)(a1 + 304) == 0 ) {                 // +0x130 cancel flag
        *(_BYTE *)(a1 + 304) = 1;
        v1 = v4;
    }
    KeReleaseSpinLock((PKSPIN_LOCK)(a1 + 72), v3);
    if ( v1 != nullptr )
        IoCancelIrp(v1);
    v5 = _InterlockedExchange((volatile __int32 *)(a1 + 320), 2);       // state := 2, old value
    if ( v1 != nullptr && v5 == 3 )
        IofCompleteRequest(v1, 0);                                      // COMPLETE (not free)
}

// --- PATCHED equivalent (sub_140001C60) — logically identical ---
if ( _InterlockedExchange((volatile __int32 *)(a1 + 320), 1) == 0 ) {
    v2 = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(a1 + 72));
    v3 = *(IRP **)(a1 + 296);
    if ( v3 == nullptr || *(_BYTE *)(a1 + 304) != 0 ) {                 // inverted branch only
        KeReleaseSpinLock((PKSPIN_LOCK)(a1 + 72), v2);
        _InterlockedExchange((volatile __int32 *)(a1 + 320), 2);
    } else {
        *(_BYTE *)(a1 + 304) = 1;
        KeReleaseSpinLock((PKSPIN_LOCK)(a1 + 72), v2);
        IoCancelIrp(v3);
        if ( _InterlockedExchange((volatile __int32 *)(a1 + 320), 2) == 3 )
            IofCompleteRequest(v3, 0);
    }
}
```

---

## 4. Assembly Analysis

### Finding A — `KeyboardClassCreate` @ `0x1C0001CA0` (unpatched)

```asm
; === UNPATCHED kbdclass_unpatched!KeyboardClassCreate (key sequence) ===
0x1C0001D49  movzx edx, byte ptr [rbx+40h]        ; EDX = IRP->RequestorMode (0=Kernel, 1=User)
0x1C0001D4D  mov   qword ptr [rsp+..], 7           ; SeTcbPrivilege LUID (7)
0x1C0001D59  mov   rcx, qword ptr [rsp+..]         ; RCX = PrivilegeValue
0x1C0001D61  call  cs:__imp_SeSinglePrivilegeCheck ; KernelMode → returns TRUE (no token check)
0x1C0001D6D  test  al, al
0x1C0001D6F  jz    loc_1C0001DAC
0x1C0001D71  lea   rcx, [rbp+0A0h]                 ; device-extension spinlock
0x1C0001D78  call  cs:__imp_KeAcquireSpinLockRaiseToDpc
0x1C0001D84  mov   rdx, [r15+30h]                  ; RDX = FileObject
0x1C0001D88  lea   rcx, DriverEntry                ; trusted marker = DriverEntry (0x1C000F080)
0x1C0001D8F  mov   [rdx+20h], rcx                  ; FileObject->FsContext2 := marker
```

```asm
; === PATCHED kbdclass_patched!sub_1400039F0 (the fix) ===
0x140003A3F  movzx edi, byte ptr [r14+2]           ; r14 = current I/O stack location; +2 = Flags
0x140003A44  and   dil, 1                           ; isolate SL_FORCE_ACCESS_CHECK (bit 0)
...
0x140003AB2  mov   qword ptr [rsp+..], 7            ; SeTcbPrivilege LUID (7)
0x140003ABE  test  dil, dil                          ; flag set?
0x140003AC1  jnz   loc_140003D2B                     ;   -> force UserMode
0x140003AC7  movzx edx, byte ptr [rbx+40h]          ; else: actual IRP->RequestorMode
0x140003ACB  mov   rcx, qword ptr [rsp+..]           ; PrivilegeValue
0x140003AD3  call  cs:SeSinglePrivilegeCheck
0x140003AFE  lea   rcx, sub_140011080               ; trusted marker (patched sentinel)
0x140003B05  mov   [rdx+20h], rcx                    ; FileObject->FsContext2 := marker
...
0x140003D2B  mov   dl, 1                              ; force PreviousMode = UserMode
0x140003D2D  jmp   loc_140003ACB                      ; ...into SeSinglePrivilegeCheck
; audit + deny path for a kernel caller that set SL_FORCE_ACCESS_CHECK:
0x140003C1A  mov   r15d, 0C0000022h                  ; STATUS_ACCESS_DENIED
0x140003C2D  cmp   [rbx+40h], r12b                    ; RequestorMode == 0 (KernelMode)?
0x140003C37  test  dil, dil                            ; SL_FORCE_ACCESS_CHECK set?
0x140003C47  call  sub_140005AB0                       ; audit
```

**Key annotations:**
- Unpatched `0x1C0001D49` / `0x1C0001D61` — `RequestorMode` is loaded straight into the privilege check; KernelMode makes the check succeed without a token examination.
- Patched `0x140003A3F`/`0x140003A44` — the driver now reads `SL_FORCE_ACCESS_CHECK` from the create stack location's `Flags`.
- Patched `0x140003D2B` — when that flag is set, `PreviousMode` is forced to `UserMode` before `SeSinglePrivilegeCheck`, so the effective (possibly impersonated) token is validated.
- `0x1C0001D8F` / `0x140003B05` — the "trusted" marker written to `FileObject->FsContext2`; this is the capability granted by the check.

### Finding B — `KeyboardClassRemoveDevice` @ `0x1C0004F2C` (unpatched)

```asm
; === UNPATCHED kbdclass_unpatched!KeyboardClassRemoveDevice ===
0x1C0004F43  xchg  eax, [rcx+140h]                 ; state := 1, eax := old state
0x1C0004F49  test  eax, eax
0x1C0004F4B  jnz   loc_1C0004FC8                   ; already engaged -> skip
0x1C0004F4D  add   rcx, 48h
0x1C0004F51  call  cs:__imp_KeAcquireSpinLockRaiseToDpc
0x1C0004F5D  mov   rdx, [rbx+128h]                 ; read wait-wake IRP under lock
0x1C0004F64  test  rdx, rdx
0x1C0004F67  jz    loc_1C0004F7C
0x1C0004F69  cmp   [rbx+130h], dil                 ; cancel flag == 0 ?
0x1C0004F70  jnz   loc_1C0004F7C
0x1C0004F72  mov   byte ptr [rbx+130h], 1          ; set cancel flag
0x1C0004F79  mov   rdi, rdx                        ; keep the pointer
0x1C0004F7C  mov   dl, al
0x1C0004F7E  lea   rcx, [rbx+48h]
0x1C0004F82  call  cs:__imp_KeReleaseSpinLock
0x1C0004F8E  test  rdi, rdi
0x1C0004F91  jz    loc_1C0004FA2
0x1C0004F96  call  cs:__imp_IoCancelIrp            ; IoCancelIrp(kept ptr)
0x1C0004FA2  mov   eax, 2
0x1C0004FA7  xchg  eax, [rbx+140h]                 ; state := 2, eax := old state
0x1C0004FAD  test  rdi, rdi
0x1C0004FB0  jz    loc_1C0004FC8
0x1C0004FB2  cmp   eax, 3
0x1C0004FB5  jnz   loc_1C0004FC8
0x1C0004FB9  mov   rcx, rdi
0x1C0004FBC  call  cs:__imp_IofCompleteRequest     ; COMPLETE the IRP (not IoFreeIrp)
```

The patched equivalent `sub_140001C60` @ `0x140001C60` performs the same reads, the same lock release, the same `IoCancelIrp`, the same `xchg` on `+0x140`, and the same conditional `IofCompleteRequest`; only the branch structure differs. This function is not a delivered security change. (The `IoCancelIrp` → conditional `IoFreeIrp`-on-state-`3` pattern that superficially resembles a double-free lives in a different routine — the SetLEDs-cancel helper, unpatched-inline vs patched `sub_140001B70` — and it too is byte-for-byte identical between the two builds.)

---

## 5. Trigger Conditions

### Finding A — `KeyboardClassCreate` privilege-check bypass

1. A kernel-mode component opens `\Device\KeyboardClassN` on behalf of a user using `OBJ_FORCE_ACCESS_CHECK`, so the create arrives with `RequestorMode == KernelMode (0)` and `SL_FORCE_ACCESS_CHECK` set in the create stack location.
2. The device-extension precondition `*(dev_ext) == *(dev_ext+8)` (the branch that reaches the privilege check) holds.
3. In the unpatched driver, `SeSinglePrivilegeCheck(SeTcbPrivilege, KernelMode)` returns TRUE regardless of the impersonated token, so `FileObject->FsContext2` is set to the trusted marker.
4. **Observable difference:** on the unpatched build, `FileObject->FsContext2` equals the `DriverEntry` sentinel (`0x1C000F080`) after the create, and `IRP_MJ_READ` on the handle returns keyboard input; on the patched build the same create returns `STATUS_ACCESS_DENIED` and the marker is not set.

### Finding B — `KeyboardClassRemoveDevice`

No trigger: the code is identical across builds; there is no behavioral change to exercise.

---

## 6. Impact & Notes

### Finding A — information disclosure

- **Capability:** the trusted marker (`FileObject->FsContext2 == DriverEntry`) is the gate for reading raw `KEYBOARD_INPUT_DATA` through `IRP_MJ_READ` (`KeyboardClassRead` otherwise returns `STATUS_PRIVILEGE_NOT_HELD`). The bypass lets an unprivileged confused-deputy scenario read keystrokes without the requesting user holding `SeTcbPrivilege`.
- **Scope:** limited to callers that reach the driver as `KernelMode` with `SL_FORCE_ACCESS_CHECK` set — i.e. a kernel-mode deputy opening the device for a user. Ordinary user-mode `CreateFile` already arrives as `UserMode` and was always checked correctly.
- **No memory-corruption or escalation primitive** is associated with this finding; it is a logical authorization weakness (information disclosure).

### Finding B

No impact; no change.

---

## 7. Verification Notes

- The genuine change is confined to the create path. Confirm on the unpatched build that `SeSinglePrivilegeCheck` at `0x1C0001D61` is reached with `RequestorMode` from `[IRP+0x40]`, and on the patched build (`sub_1400039F0`) that `PreviousMode` is overwritten with `1` at `0x140003D2B` when the stack-location `Flags & 1` bit is set.
- Confirm that `DriverEntry` (`0x1C000F080`, unpatched) written to `FileObject->FsContext2` is the same sentinel that `KeyboardClassRead` (`0x1C0001410`) compares against before permitting a read.
- The device-extension offsets referenced (`+0x48` spinlock, `+0x128` wait-wake IRP, `+0x130` cancel flag, `+0x140` state) are consistent across both builds.

---

## 8. Changed Functions — Full Triage

| Function (unpatched) | Patched equivalent | Change type | Note |
|---|---|---|---|
| `KeyboardClassCreate` | `sub_1400039F0` | **Security (Medium)** | Forces `UserMode` for `SeSinglePrivilegeCheck` when `SL_FORCE_ACCESS_CHECK` is set; adds audit `sub_140005AB0` and a `STATUS_ACCESS_DENIED` path. |
| `KeyboardClassRemoveDevice` | `sub_140001C60` | No security change | Wait-wake cancel sequence logically identical; only a De Morgan branch inversion. Completes (not frees) the IRP. |
| `KeyboardClassWaitWakeComplete` | `sub_140004B80` | No security change | Same spinlock, same two-slot pending-IRP match at `+0x138`/`+0x128`, same status dispatch. Tracing gating only. |
| `KeyboardClassPowerComplete` | `sub_1400018B0` | No security change | The inline SetLEDs-IRP cancel block is lifted verbatim into helper `sub_140001B70`; return values and remove-lock conditions match. No work items introduced. |
| `KeyboardClassWWPowerUpComplete` | `sub_140004F50` | No security change | `ExAllocatePoolWithTag(NonPagedPoolNx, 0x20, 'KbdC')` → `ExAllocatePool2(0x40, 0x20, 'KbdC')` (same size/tag), error path inlined. |
| `KeyboardClassPower` | `sub_1400031D0` | No security change | Same removed-device guard, same MinorFunction handling and wait-wake arming; control-flow churn only. |
| `KeyboardClassServiceCallback` | `sub_1400022F0` | Behavioral (non-security) | `KeyboardClassDequeueRead` inlined; cancel-safe `_InterlockedExchange64(entry-8,0)` check and ring-buffer arithmetic preserved. Low similarity is tracing/inlining. |
| `KeyboardClassDeviceControl` | — | Cosmetic | `ExAllocatePoolWithTag → ExAllocatePool2`, WPP tracing, switch-table reorg. IOCTLs unchanged. |
| `KeyboardClassRead` | — | Cosmetic | Trusted-marker check (`DriverEntry == FsContext2`) preserved. WPP/layout only. |
| `KeyboardClassClose` | — | Cosmetic | Trusted-counter decrement / marker clear preserved. |
| `KeyboardClassCleanup` | — | Cosmetic | Variable renaming + WPP only. |
| `KbdEnableDisablePort` | — | Cosmetic | `ExAllocatePoolWithTag → ExAllocatePool2`. |
| `KbdInitializeDataQueue` | — | Cosmetic | WPP tracing reformatting; queue logic identical. |
| `KeyboardClassReadCopyData` | `sub_140002CA0` | Cosmetic | WPP tracing reformatting; memcpy/buffer math identical. |

**Summary of the cosmetic cluster:** the remaining changed functions are dominated by `ExAllocatePool2` modernization, WPP tracing reformatting, switch-table reorganization, helper extraction/inlining, and register-allocation churn. None introduce behavioral changes affecting security.

---

## 9. New / Referenced Helpers

There are no added or removed functions in the diff (`unmatched_unpatched: 0`, `unmatched_patched: 0`). Two helpers are central to the create-path fix:

- `sub_140005AB0` — audit helper invoked by the patched create path when a kernel-mode caller sets `SL_FORCE_ACCESS_CHECK` (called at `0x140003C47`, before returning `STATUS_ACCESS_DENIED`).
- `sub_140011080` — the patched build's "trusted" marker sentinel written to `FileObject->FsContext2` (the counterpart of `DriverEntry`/`0x1C000F080` in the unpatched build).

Note: `ExAllocatePool2` zero-initializes its allocations whereas `ExAllocatePoolWithTag` did not; this is immaterial in every affected path because each allocation is fully initialized before use. It is a modernization side effect, not a targeted fix.

---

## 10. Confidence & Caveats

**Confidence:** High that the create-path authorization change is real and correctly directed (patched build stricter), and high that the wait-wake / power IRP lifecycle carries no delivered security change (every such function was matched by content and compared).

**Caveats:**
- Reachability of Finding A depends on the existence of a kernel-mode deputy that opens the keyboard device with `SL_FORCE_ACCESS_CHECK` on behalf of a user; ordinary user-mode opens are unaffected and were always checked correctly.
- The exact `SL_FORCE_ACCESS_CHECK` bit position (`IO_STACK_LOCATION.Flags & 1` for `IRP_MJ_CREATE`) and the `FILE_OBJECT.FsContext2` offset (`+0x20`) match the observed code but should be reconciled against the target build's public structure layouts if instrumenting.
- The device-extension state machine (`+0x140` values `1`/`2`/`3`) and cancel flag (`+0x130`) that arbitrate the wait-wake IRP were confirmed identical in both builds.
