Title: atapi.sys — Missing 0xFF floating-bus status check in AtapiNoDeviceConnected (CWE-755) fixed
Date: 2026-06-28
Slug: atapi_9b3e7eec-atapi-report-20260628-214002
Category: Corpus
Author: Argus
Summary: KB5087545
Severity: Low
KBDate: 2026-05-12

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `atapi_unpatched.sys` (image base `0x1C0000000`) |
| Patched binary | `atapi_patched.sys` |
| Overall similarity | **0.9583** |
| Matched functions | 51 |
| Changed functions | **18** |
| Identical functions | 33 |
| Unmatched (either direction) | 0 |

**Verdict:** The only behavioral change is a new `0xFF` (floating-bus / no-device) status check added at the entry of `AtapiNoDeviceConnected` (unpatched `sub_1C0001FC8` → patched `sub_1C0001FD8`). In the unpatched build a `0xFF` status returned by the callee is classified as "no error"; the patched callee classifies it as an error. Both ATA-command callers already pre-checked `0xFF` before calling, so the delivered delta is limited to a narrow window: when the status transitions to `0xFF` inside the callee's own retry loop. This is an error-handling correctness fix (CWE-755) of low severity. Everything else in the diff is compiler-level churn (register allocation, `test`→`bt` rewrites, loop-counter restructure, and a `mov al`→`movzx eax` codegen change that is semantically identical in both builds).

---

## 2. Vulnerability Summary

### Finding #1 — Missing 0xFF floating-bus status check in `AtapiNoDeviceConnected (sub_1C0001FC8)`

- **Severity:** Low
- **Class:** CWE-755 (improper handling of an exceptional condition)
- **Affected function:** `atapi!AtapiNoDeviceConnected (sub_1C0001FC8)` (patched as `atapi!AtapiNoDeviceConnected (sub_1C0001FD8)`)

**Root cause.** In ATA/ATAPI, reading the status port when no device is electrically present returns `0xFF` — the bus floats and pull-up resistors drive all data lines high. The unpatched status classifier treats only `0x7F` (diagnostic) and `0x00` (when `arg3 != 0`) as conditions to act on; a `0xFF` status falls straight through to the `return 0` (no-error) path.

Both ATA-command callers (`AtapiSendAtaIdentify (sub_1C00020C0)` and `AtapiSendAtaCommand (sub_1C0002200)`) pre-check `0xFF` with an explicit `cmp ...,0xff; je error` before the call, so a `0xFF` present at call time is already handled by the caller. The gap the patch closes is a narrow window: `AtapiNoDeviceConnected` itself re-reads the status register inside its retry loop and writes the new value back through `*arg2`, but never re-checks the re-read value for `0xFF`:

```
do {
    AtaPortStallExecution(0x1388);
    *arg2 = AtaPortReadPortUchar(status_port);   // may become 0xFF here
    ...
} while (...);
// unpatched: only 0x7F is re-checked after the loop
```

The retry loop is entered only when the initial status is `0x7F`, or `0x00` with `arg3 != 0`. If the device becomes electrically absent during the poll window, `*arg2` is updated to `0xFF` but the function still returns `0` ("no error").

**Effect of the change.** In the unpatched build, a `0xFF` that appears inside the loop makes the callee return `0`; the caller then re-reads the (now `0xFF`) status and, via its signed-comparison branch (`0xFF` has the sign bit set), routes to result code `6` instead of the device-error result code `5` that the caller's own `0xFF` pre-check produces. In the patched build the callee returns `1` for `0xFF`, so the caller routes to result code `5`. The demonstrable difference is therefore the classification of a removed/absent device during that window: retry-class (`6`) versus device-error (`5`). No memory-safety primitive, information disclosure, or attacker-controlled write is produced by this change.

**Entry point & data flow (paths verified by call targets in the disassembly):**

1. The storage stack dispatches an IRB (`IDE_REQUEST_BLOCK`) into the miniport's start-I/O handler `AtapiHwStartIo (sub_1C0001700)`.
2. ATA command state handlers `AtapiSendAtaIdentify (sub_1C00020C0)` / `AtapiSendAtaCommand (sub_1C0002200)` poll the device status register.
3. Each handler calls `AtapiNoDeviceConnected (sub_1C0001FC8)(arg1, &status, arg3, arg4)` to classify the status.
4. Inside the callee, if the initial status was `0x7F` (or `0x00` with `arg3`), the loop re-reads the status port; if the device becomes absent during that window `*arg2` becomes `0xFF` and, in the unpatched build, the function returns "no error".

The status classifier is also reachable from the interrupt-driven PIO path (`AtapiHwInterrupt (sub_1C0001790)` → `AtapiProcessInterrupt (sub_1C0002AA0)`), but the `0xFF`-handling change is confined to `AtapiNoDeviceConnected` itself.

---

## 3. Pseudocode Diff

### `AtapiNoDeviceConnected (sub_1C0001FC8)` (unpatched) vs. `AtapiNoDeviceConnected (sub_1C0001FD8)` (patched)

```c
// === UNPATCHED AtapiNoDeviceConnected (sub_1C0001FC8) ===
char AtapiNoDeviceConnected(void *arg1, char *arg2, char arg3, char arg4)
{
    char status = *arg2;
    char result = 0;                                   // default: NO ERROR

    if (status == 0x7F || (arg3 && status == 0x00)) {  // only these enter the loop
        for (int i = 0; i < 3; i++) {
            AtaPortStallExecution(0x1388);
            status = AtaPortReadPortUchar(*(arg1 + 0x48));
            *arg2 = status;                            // may become 0xFF here
            if (status != initial_status) break;
        }
        // ... arg3 secondary read, then:
        result = (status == 0x7F);                     // only re-checks 0x7F
    }
    // 0xFF (whether at entry or re-read in the loop) falls through -> returns 0
    return result;
}

// === PATCHED AtapiNoDeviceConnected (sub_1C0001FD8) ===
char AtapiNoDeviceConnected(void *arg1, char *arg2, char arg3, char arg4)
{
    char status = *arg2;
    char result = 0;

    if (status == 0xFF)        // NEW: floating bus / no device present
        return 1;              // NEW: classify as error immediately

    if (status == 0x7F || (arg3 && status == 0x00)) { /* same loop body */ }

    return result;
}
```

### Caller change (`AtapiSendAtaIdentify (sub_1C00020C0)`, `AtapiSendAtaCommand (sub_1C0002200)`)

```c
// === UNPATCHED caller ===
status = read_status();
if (status == 0xFF) goto device_error;       // explicit pre-check (callee lacks 0xFF handling)
if (AtapiNoDeviceConnected(...)) goto ...;

// === PATCHED caller ===
status = read_status();
if (AtapiNoDeviceConnected(...)) goto ...;    // callee handles 0xFF itself; pre-check removed
```

### `mov al` → `movzx eax` codegen change — **no behavioral effect**

```asm
// UNPATCHED (AtapiSendAtaCommand 0x1c00023a3)
mov   al, byte [rcx+rdi+0xb]   ; load multiplier byte
test  al, al
je    skip
movzx eax, al                  ; zero-extension here, before imul
imul  esi, eax

// PATCHED (AtapiSendAtaCommand 0x1c00023d0)
movzx eax, byte [rcx+rdi+0xb]  ; zero-extension at load time
test  al, al
je    skip
imul  esi, eax
```

The unpatched path already executes `movzx eax, al` before `imul esi, eax`, so the value entering the multiplication is identical in both builds. The patch merely hoists the zero-extension into the load. This is a pure compiler-output difference with no semantic change. The identical pattern appears in `AtapiProcessInterrupt (sub_1C0002AA0)` (unpatched `mov al, [rcx+rbp+0xb]` at `0x1c0002c25`, followed by `movzx eax, al; imul r14d, eax`).

---

## 4. Assembly Analysis

### `AtapiNoDeviceConnected (sub_1C0001FC8)` — unpatched (missing 0xFF handling)

```asm
; ---- AtapiNoDeviceConnected @ 0x1C0001FC8 ----
0x1c0001fe5: mov     bpl, [rdx]                 ; status byte -> bpl
0x1c0001fe8: xor     dil, dil                   ; default return = 0 (no error)
0x1c0001feb: mov     r12b, r9b                  ; arg4
0x1c0001fee: mov     r14b, r8b                  ; arg3
0x1c0001ff1: mov     r15, rdx                   ; arg2 (status pointer)
0x1c0001ff4: mov     rsi, rcx                   ; arg1
0x1c0001ff7: cmp     bpl, 7Fh                   ; checks ONLY 0x7F
0x1c0001ffb: jz      0x1c000200f                ;   -> retry loop
0x1c0001ffd: test    r8b, r8b                   ; arg3 == 0?
0x1c0002000: jz      0x1c0002098                ;   yes -> return 0  (0xFF NOT caught)
0x1c0002006: test    bpl, bpl                   ; status == 0x00?
0x1c0002009: jnz     0x1c0002098                ;   non-zero (incl. 0xFF) -> return 0

; retry loop (entered for 0x7F, or 0x00 with arg3)
0x1c000200f: xor     ebx, ebx
0x1c0002011: lea     edi, [rbx+1]
0x1c0002014: mov     ecx, 1388h
0x1c0002019: call    cs:__imp_AtaPortStallExecution
0x1c0002025: mov     rcx, [rsi+48h]             ; status port handle
0x1c0002029: call    cs:__imp_AtaPortReadPortUchar
0x1c0002035: mov     [r15], al                  ; *arg2 = re-read status (can be 0xFF)
0x1c0002038: cmp     al, bpl
0x1c000203b: jnz     0x1c0002044
0x1c000203d: add     ebx, edi
0x1c000203f: cmp     ebx, 3
0x1c0002042: jl      0x1c0002014

; post-loop tail (0x1c0002044..0x1c0002090 include an arg3 secondary read)
0x1c0002092: cmp     al, 7Fh                    ; only 0x7F re-checked
0x1c0002094: setz    dil                        ; 0xFF -> dil stays 0

; return path
0x1c0002098: mov     rbx, [rsp+38h+arg_0]
0x1c000209d: mov     al, dil                    ; return value (0 for 0xFF)
0x1c00020b3: pop     r15
0x1c00020b5: pop     r14
0x1c00020b7: pop     r12
0x1c00020b9: retn
```

### Patched counterpart (`AtapiNoDeviceConnected (sub_1C0001FD8)`) — the new entry guard

```asm
; ---- AtapiNoDeviceConnected @ 0x1C0001FD8 ----
0x1c0001ff5: mov     bl, [rdx]                  ; status -> bl
0x1c0001ff7: xor     dil, dil
...
0x1c0002006: cmp     bl, 0FFh                   ; NEW: floating-bus detection
0x1c0002009: jnz     0x1c0002015                ;   not 0xFF -> normal flow
0x1c000200b: mov     edi, 1                     ;   return value = 1 (error)
0x1c0002010: jmp     0x1c00020b3                ;   return 1
0x1c0002015: cmp     bl, 7Fh                    ; existing 0x7F check
0x1c0002018: jz      0x1c000202b
```

### Caller-side change (`AtapiSendAtaIdentify (sub_1C00020C0)`)

```asm
; UNPATCHED (0x1C00020C0)               ; PATCHED (0x1C00020E0)
0x1c0002164: cmp dl, 0FFh               ; (pre-check removed)
0x1c0002167: jz  0x1c00021da            ; (pre-check removed)
0x1c0002174: call 0x1c0001fc8           ; 0x1c0002187: call 0x1c0001fd8
```

The same `cmp al, 0FFh; jz` pre-check is removed from `AtapiSendAtaCommand` (unpatched at `0x1c000226c`, absent in the patched build before its `call AtapiNoDeviceConnected` at `0x1c0002286`).

---

## 5. Trigger Conditions

The window the patch closes requires all of the following:

1. An I/O operation reaches `AtapiNoDeviceConnected (sub_1C0001FC8)` with an initial status of `0x7F` (device entering diagnostic) or `0x00` with `arg3 != 0`. This is what causes the function to enter its retry loop.
2. During the loop's `AtaPortStallExecution(0x1388)` poll window (three iterations, `0x1c0002014`–`0x1c0002042`), the status port begins reading `0xFF`, i.e. the device becomes electrically absent. In practice this means a physical hot-unplug of a device backed by this miniport, or hardware/emulation that returns `0x7F` to the first status poll and `0xFF` to a later poll.
3. No specific IOCTL code, buffer layout, or IRB field value is needed on the request itself; the condition is a device/timing state, not attacker-controlled input data.

**Observable difference between builds:**

- Unpatched: `AtapiNoDeviceConnected` returns `0` (`al = 0`) even though `byte [r15] == 0xFF`; the caller routes to result code `6`.
- Patched: `AtapiNoDeviceConnected` returns `1` for a `0xFF` status; the caller routes to result code `5` (the same device-error code its own `0xFF` pre-check produces).

---

## 6. Impact Assessment

**Delivered effect:** correct classification of a floating-bus / absent-device status inside `AtapiNoDeviceConnected`'s retry loop. In the unpatched build this narrow window classified an absent device as retry-class rather than device-error. The realistic worst case is a reliability issue — the driver may retry rather than fail a request on a removed device or one presenting a crafted status sequence — reachable only through physical device removal or malicious/emulated hardware, not through unprivileged software input. The change produces no memory corruption, information disclosure, or control-flow primitive.

The callers already guard `0xFF` present at call time, so this is a defense-in-depth hardening that also covers the re-read case. That combination is why the severity is Low.

---

## 7. Debugger Verification

Assume a kernel debugger attached to the **unpatched** `atapi.sys`. Rebase the addresses below to the loaded image base.

### Breakpoints

```
; Status classifier entry
bp atapi+0x1FC8

; Inside the retry loop
bp atapi+0x2029            ; AtaPortReadPortUchar call — al holds the re-read status
bp atapi+0x2035            ; *arg2 = al — confirm 0xFF is written back unchecked

; Post-loop classification
bp atapi+0x2092            ; 'cmp al, 0x7f' — verify 0xFF is not caught here
bp atapi+0x209d            ; 'mov al, dil' — return value; 0 for 0xFF in unpatched

; Caller pre-checks (present in unpatched)
bp atapi+0x2164            ; AtapiSendAtaIdentify 'cmp dl, 0xff'
bp atapi+0x226c            ; AtapiSendAtaCommand 'cmp al, 0xff'
```

### What to inspect

| Stop | Register / Memory | Check |
|---|---|---|
| `atapi+0x1FC8` (entry) | `rdx` → `[rdx]` | Initial status byte. `0x7F` or `0x00` means the retry loop will run. |
| `atapi+0x2029` | `rcx` = `[rsi+0x48]` | The status port handle being read. |
| `atapi+0x2035` | `al`, `[r15]` | Confirm `*arg2` is set to the re-read status (`0xFF`) with no check. |
| `atapi+0x2092` | `al` | `setz dil` sets `dil=1` only for `al == 0x7F`; `al=0xFF` leaves `dil=0`. |
| `atapi+0x209d` | `dil` | Return value: `0` for `0xFF` in the unpatched binary; `1` in the patched binary (via the new `0x2006` guard). |

### Deterministic repro

At `atapi+0x2029`, step over the `AtaPortReadPortUchar` call, set `al = 0xff`, and continue. In the unpatched binary the function returns `dil == 0` while `byte [r15] == 0xFF`; in the patched binary the entry guard at `0x2006` (or the same value re-read) yields a return of `1`.

### Verified structure offsets

```
IDE_REQUEST_BLOCK (IRB):
  +0x06  Target        ; device ID (mov dl, [rdx+6] in the callers)
  +0x10  Flags         ; read as 'mov edx, [rbx+10h]' and bit-tested

Channel extension:
  +0x48                ; status I/O port handle (read in the retry loop)
  per-device entry at (Target + 3) * 0x38:
    +0x0B  sector-size multiplier
    +0x20  block size
```

---

## 8. Changed Functions — Full Triage

**Behavioral / security-relevant:**

- `AtapiNoDeviceConnected (sub_1C0001FC8)` (sim 0.94) — **the fix.** Adds `cmp bl, 0FFh; jnz; mov edi, 1; jmp ret` at function entry (`0x1c0002006`–`0x1c0002010`). Rest of the body unchanged. Status variable moved from `rbp` to `rbx`.
- `AtapiSendAtaIdentify (sub_1C00020C0)` (sim 0.88) — Removes the inlined `cmp dl, 0xff; jz` pre-check (`0x1c0002164`), delegating `0xFF` handling to the callee. Register reallocation.
- `AtapiSendAtaCommand (sub_1C0002200)` (sim 0.95) — Removes its own `cmp al, 0xff; jz` pre-check (`0x1c000226c`) for the same reason. Also contains the `mov al` → `movzx eax` codegen change at `0x1c00023a3`/`0x1c00023d0`, which is behaviorally identical (see below).

**Compiler-output / non-security:**

- `AtapiProcessInterrupt (sub_1C0002AA0)` (sim 0.92) — Same `mov al` → `movzx eax` codegen change (`0x1c0002c25` → `0x1c0002c3f`); the unpatched path already zero-extends via `movzx eax, al` before `imul r14d, eax` at `0x1c0002c37`, so behavior is unchanged. Also control-flow restructuring and `test ... & 0x200` → `bt ..., 9` instruction equivalences.
- `AtapiSendAtapiCommand (sub_1C0002500)` (sim 0.94) — Register allocation only; transfer-count clamp (`>= 0x10000` → `0xFFFE`) unchanged.
- `AtapiHandleMiniportCommand (sub_1C000272C)` (sim 0.91) — Nested `if-else` flattened; same comparisons.
- `WaitOnBusyUntil (sub_1C00012C8)` (sim 0.92) — Error-handler invocation moved inline; identical observable behavior. (Status polling routine.)
- `AtapiInitializeDevice (sub_1C0001D64)` (sim 0.93) — Loop-counter arithmetic restructured.
- `AtapiWaitStatusAsync (sub_1C0003730)` (sim 0.98), `AtapiResetAtapiDevices (sub_1C00039C0)` (sim 0.97), `AtapiHwStartIo (sub_1C0001700)` (sim 0.97), `AtapiSetDmaTransferModeAsync (sub_1C0003C80)` (sim 0.97), `AtapiHwBuildIo (sub_1C0001690)` (sim 0.97), `AtapiSetBlockSizeAsync (sub_1C0003EC0)` (sim 0.98), `AtapiSetupGeometryAsync (sub_1C0003DF0)` (sim 0.98), `AtapiSetPioTransferModeAsync (sub_1C0003BD0)` (sim 0.99), `__GSHandlerCheckCommon (sub_1C0003FFC)` (sim 0.99), `AtapiCompleteRequest (sub_1C0002DDC)` (sim 0.99) — All compiler-output churn: shifted function-pointer addresses for self-references and callees, `test ... & 0x200` → `bt ..., 9`, loop-counter arithmetic, stack-init reordering, and an alignment-check type widening. No semantic change.

---

## 9. Unmatched Functions

None. `unmatched_unpatched = 0`, `unmatched_patched = 0`. No added sanitizers, removed checks, or new mitigations beyond the inline `0xFF` test in `AtapiNoDeviceConnected (sub_1C0001FD8)`.

---

## 10. Confidence & Caveats

**Confidence: HIGH** that the primary change is the added `0xFF` status check in `AtapiNoDeviceConnected`. The diff is unambiguous: a new `cmp bl, 0FFh; jnz; mov edi, 1; jmp ret` block at function entry, and both callers shed their own `0xFF` pre-checks because the callee now owns that classification.

**Caveats:**

- The `mov al` → `movzx eax` change in `AtapiSendAtaCommand (sub_1C0002200)` and `AtapiProcessInterrupt (sub_1C0002AA0)` is behaviorally identical in both builds: the unpatched code performs `movzx eax, al` before the multiplication (`0x1c00023b4`, `0x1c0002c37`), so the multiplier value entering `imul` is the same. This is a compiler-output difference, not a security change.
- The result-code interpretation (`5` = device error, `6` = retry-class) is read from the caller's branch structure: `5` is the code produced by the caller's own `0xFF` pre-check, and `6` is the code reached when the callee returns `0` and the caller's signed status test then routes an absent (`0xFF`) device. The caller dispatch chain (`AtapiHwStartIo` → `AtapiSendAtaIdentify` / `AtapiSendAtaCommand`) is inferred from call targets in the disassembly.
- Reachability of the closed window depends on device/hardware timing (physical removal or crafted-hardware status sequences), not on software-supplied request data.
