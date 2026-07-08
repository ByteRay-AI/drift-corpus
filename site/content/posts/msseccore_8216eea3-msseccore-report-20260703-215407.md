Title: msseccore.sys — No security-relevant change (recompile with a redundant field zero and an integrity-check flag-constant tweak)
Date: 2026-07-03
Slug: msseccore_8216eea3-msseccore-report-20260703-215407
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: None
KBDate: 2026-03-10

---

## 1. Overview

| Field | Value |
|-------|-------|
| Unpatched Binary | `msseccore_unpatched.sys` |
| Patched Binary | `msseccore_patched.sys` |
| Overall Similarity | 0.897 (89.7%) |

**Verdict:** This patch is a recompilation. Two deliberate, non-cosmetic differences exist, but neither fixes nor introduces a reachable vulnerability:

1. `SecAllocateKernelApcObject` adds one instruction — `mov byte [rbx+0x70], 0` — immediately after a `memset(ctx, 0, 0xB0)` that already zeroes offset `+0x70` in both builds. The store is redundant defensive code, not a fix for a stale value or use-after-free.
2. `SecKernelIntegrityCheck` changes one flags constant in the code-integrity verification request from `0xA000008` to `0xA000006`. This value is passed to the registered code-integrity callback, not to `MmProtectDriverSection`, and its security semantics are not determinable from the binaries. The requested signing level (a separate, bounded parameter) is unchanged.

The remaining changed functions are compiler codegen churn (inline zeroing replaced with `memset` calls, register allocation, stack-frame and symbol-layout shifts).

---

## 2. Vulnerability Summary

### Finding 1: Redundant explicit zero of the rundown flag in `SecAllocateKernelApcObject` (No security-relevant change)

- **Severity:** None (defensive no-op)
- **Vulnerability Class:** None demonstrable
- **Affected Function:** `SecAllocateKernelApcObject` — `0x1C0001884` (unpatched) / `0x1C0001878` (patched)

**What actually changed:**

`SecAllocateKernelApcObject` allocates a `0xB0`-byte APC context object from a lookaside list (`SecApcSupportLookasideList`) or, on miss, from pool. On the common path both builds call `memset(ctx, 0, 0xB0)` and then write three fields: the type tag at `+0x00` (`0xB0DF03`), the refcount at `+0x60` (`1`), and the parent pointer at `+0x68`. The patched build adds one further instruction at `0x1C0001946`: `mov byte [rbx+0x70], 0`.

Offset `+0x70` is byte 112 of the object; the preceding `memset` clears bytes `0x00`–`0xAF` (176 bytes), so `+0x70` is already zero after the memset in **both** builds. `memset` here is an ordinary external call (`call memset`), so the compiler cannot elide the zeroing of any byte inside it. The added store therefore writes `0` to a byte that is already `0`. It has no runtime effect.

There is no stale-value condition to fix. The `+0x70` flag lifecycle is balanced in both builds: it is set to `1` only by `SecInsertQueueKernelApcObject` at `0x1C0001AEB` after `ExAcquireRundownProtection` succeeds; it is consumed by `SecFreeKernelApcObject` (which calls `ExReleaseRundownProtection` when the flag is non-zero); and on the next allocation the `memset` re-zeroes it before any field is written. A recycled lookaside entry cannot carry a stale `1` past the memset.

### Finding 2: Code-integrity verification flag constant changed in `SecKernelIntegrityCheck` (No demonstrable security-relevant change)

- **Severity:** None demonstrable
- **Vulnerability Class:** None demonstrable
- **Affected Function:** `SecKernelIntegrityCheck` — `0x1C0008178` (unpatched) / `0x1C00081B8` (patched)

**What actually changed:**

`SecKernelIntegrityCheck` builds a `0x40`-byte request structure on the stack and passes it (with a separate output buffer) to the function pointer at `qword_1C0007008`. That pointer is the code-integrity verification callback: it is populated by `SecKernelIntegrityCallback` (`0x1C00010C0` / `0x1C0001080`), and `SecIsKernelIntegrityEnabled` simply tests whether it is non-null. It is **not** `MmProtectDriverSection`.

The only behavioural difference is one constant in the request structure: the field at struct offset `+0x08` changes from `0xA000008` (unpatched) to `0xA000006` (patched). This is a flags word in the verification request, not a page-protection value; `PAGE_WRITECOPY` does not appear here. The caller-supplied signing level (`a1`, validated to be `< 6`) is written to a different field of the same structure (offset `+0x30`) and is unchanged. The remaining differences in this function are codegen (the field-by-field stack zeroing in the unpatched build is replaced by two `memset` calls in the patched build).

The meaning of the individual bits of the `0xA000008` / `0xA000006` flags word — and hence whether this change is a tightening, a relaxation, or neutral — cannot be determined from these two binaries. No security direction is asserted.

---

## 3. Pseudocode Diff

### Finding 1: `SecAllocateKernelApcObject`

```c
// UNPATCHED SecAllocateKernelApcObject @ 0x1C0001884
// PATCHED   SecAllocateKernelApcObject @ 0x1C0001878
// The two builds are identical on the init path except for the one added store.
ctx = ExpInterlockedPopEntrySList(&SecApcSupportLookasideList);
if (!ctx)
    ctx = <pool allocate>;               // guarded indirect call
if (!ctx) return NULL;

memset(ctx, 0, 0xB0);                    // zeroes bytes 0x00..0xAF, incl. +0x70
*(uint32*)(ctx + 0x00) = 0xB0DF03;       // type tag
*(uint64*)(ctx + 0x60) = 1;              // refcount
*(uint64*)(ctx + 0x68) = parent;         // parent pointer
// PATCHED ONLY:  *(uint8*)(ctx + 0x70) = 0;   // redundant: memset already cleared it
InterlockedIncrement64(parent + 0x10);
return ctx;
```

### Finding 1: Cleanup and queue paths (unchanged in both builds)

```c
// SecFreeKernelApcObject @ 0x1C00019BC / 0x1C0001980  (identical logic)
if (LOBYTE(ctx[0x70]) != 0)
    ExReleaseRundownProtection((ctx->parent) + 0x08);   // matched release
SecDereferenceKernelClient(ctx->parent);
// ... push ctx back to lookaside or free ...

// SecInsertQueueKernelApcObject @ 0x1C0001A68 / 0x1C0001A60  (identical logic)
if (ExAcquireRundownProtection((ctx->parent) + 0x08)) {  // matched acquire
    *(uint8*)(ctx + 0x70) = 1;                            // set flag at 0x1C0001AEB
    KeInsertQueueApc(&ctx->KAPC, ...);
}
```

### Finding 2: `SecKernelIntegrityCheck`

```c
// UNPATCHED SecKernelIntegrityCheck @ 0x1C0008178
// PATCHED   SecKernelIntegrityCheck @ 0x1C00081B8
req[0]        = 0x40;            // structure size
req[0x08]     = 0xA000008;       // UNPATCHED flags word
// req[0x08]  = 0xA000006;       // PATCHED  flags word  (only behavioural change)
req[0x10]    = 0x80000;
req[0x30]    = signing_level;    // caller arg a1, validated < 6 (unchanged)
req[0x34]    = 0x10;
req[0x38]    = data_ptr;
do {
    status = ((verify_cb)qword_1C0007008)(req, out);   // CI verification callback
} while (status == 0xC0000016 /* retry */ && ++i <= 5);
```

---

## 4. Assembly Analysis

### Finding 1: init path — the single added instruction

```asm
; UNPATCHED SecAllocateKernelApcObject @ 0x1C0001884
00000001C0001931  xor     edx, edx
00000001C0001933  mov     r8d, 0B0h                ; size = 176
00000001C0001939  mov     rcx, rbx
00000001C000193C  call    memset                   ; zeroes bytes 0x00..0xAF (incl. +0x70)
00000001C0001941  mov     rcx, rbp
00000001C0001944  mov     dword ptr [rbx], 0B0DF03h ; +0x00 type tag
00000001C000194A  mov     [rbx+60h], rbp           ; +0x60 refcount = 1
00000001C000194E  mov     [rbx+68h], rdi           ; +0x68 parent pointer
00000001C0001952  lock xadd [rdi+10h], rcx         ; no store to [rbx+70h]

; PATCHED SecAllocateKernelApcObject @ 0x1C0001878
00000001C0001930  call    memset                   ; same 0xB0-byte zero
00000001C0001935  mov     rcx, rbp
00000001C0001938  mov     dword ptr [rbx], 0B0DF03h ; +0x00 type tag
00000001C000193E  mov     [rbx+60h], rbp           ; +0x60 refcount = 1
00000001C0001942  mov     [rbx+68h], rdi           ; +0x68 parent pointer
00000001C0001946  mov     byte ptr [rbx+70h], 0    ; ADDED — redundant (already 0)
00000001C000194A  lock xadd [rdi+10h], rcx
```

### Finding 1: flag consumer and producer (byte-identical between builds)

```asm
; SecFreeKernelApcObject @ 0x1C00019BC (unpatched) / 0x1C0001980 (patched)
00000001C00019CA  cmp     byte ptr [rcx+70h], 0
00000001C00019D1  jz      short loc_1C00019E7      ; skip release if 0
00000001C00019D3  mov     rcx, [rcx+68h]           ; parent
00000001C00019D7  add     rcx, 8                   ; EX_RUNDOWN_REF at parent+0x08
00000001C00019DB  call    cs:__imp_ExReleaseRundownProtection

; SecInsertQueueKernelApcObject @ 0x1C0001A68 (unpatched) / 0x1C0001A60 (patched)
00000001C0001AD7  call    cs:__imp_ExAcquireRundownProtection
00000001C0001AE3  test    al, al
00000001C0001AE5  jz      short loc_1C0001B0B      ; failure → no flag set
00000001C0001AEB  mov     byte ptr [rbx+70h], 1    ; flag set only after acquire succeeds
```

### Finding 2: the flags-constant change

```asm
; UNPATCHED SecKernelIntegrityCheck @ 0x1C0008178
00000001C0008231  mov     [rbp+57h+var_70], 40h        ; req size = 0x40
00000001C0008239  mov     [rbp+57h+var_68], 0A000008h  ; flags word (changed)
00000001C0008241  mov     [rbp+57h+var_60], 80000h
00000001C0008260  mov     rax, cs:qword_1C0007008      ; CI verification callback
00000001C000826F  call    cs:__guard_dispatch_icall_fptr

; PATCHED SecKernelIntegrityCheck @ 0x1C00081B8
00000001C000826F  mov     [rbp+57h+var_70], 40h
00000001C0008277  mov     [rbp+57h+var_68], 0A000006h  ; flags word (changed)
00000001C000827F  mov     [rbp+57h+var_60], 80000h
00000001C000829E  mov     rax, cs:qword_1C0007008      ; same callback pointer
00000001C00082AD  call    cs:__guard_dispatch_icall_fptr
```

---

## 5. Trigger Conditions

Neither difference is a reachable vulnerability, so there is no trigger.

- **Finding 1:** The added `mov byte [rbx+0x70], 0` writes a byte that the preceding `memset` already cleared in both builds. No input state causes different behaviour between the two binaries.
- **Finding 2:** The request-flag constant differs, but the meaning of the changed bits cannot be established from these binaries, and the signing level the caller requests is validated and passed identically in both builds.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive. Finding 1 is a redundant store over an already-zeroed byte; Finding 2 is an opaque flag-constant change with no demonstrable effect on the code-integrity decision. There is no use-after-free, no rundown refcount imbalance (acquire/release are matched in both builds), and no page-protection weakening in this patch.

---

## 7. Debugger Notes

To observe the two differences directly:

```
lm vm msseccore
bp msseccore+0x1946   ; PATCHED: the added mov byte [rbx+0x70], 0 (redundant)
bp msseccore+0x193c   ; UNPATCHED: memset(ctx, 0, 0xB0) — inspect db rbx+0x70 l1 afterward (== 0)
```

At the `SecAllocateKernelApcObject` breakpoint, `db rbx+0x70 l1` reads `0x00` after the `memset` returns in the unpatched build, confirming the byte is already clear before the patched build's added store would run.

For Finding 2, break on `SecKernelIntegrityCheck` and inspect the request structure built on the stack; the field at struct offset `+0x08` holds `0xA000008` (unpatched) or `0xA000006` (patched). The call target at `qword_1C0007008` is the code-integrity verification callback registered by `SecKernelIntegrityCallback`.

---

## 8. Changed Functions — Full Triage

### Deliberate constant / instruction changes (not security-relevant)

| Function (Unpatched → Patched) | Change | Assessment |
|---|---|---|
| `SecAllocateKernelApcObject` (`0x1C0001884` → `0x1C0001878`) | Adds `mov byte [rbx+0x70], 0` after a `memset(ctx,0,0xB0)` that already zeroes `+0x70`. | Redundant defensive store; no runtime effect. Not a security fix. |
| `SecKernelIntegrityCheck` (`0x1C0008178` → `0x1C00081B8`) | Request flags word at struct `+0x08` changes `0xA000008` → `0xA000006`; field-by-field stack init replaced by two `memset` calls. | Opaque flag-constant change passed to the code-integrity callback; security direction not determinable. |
| `SecAllocatePoolWithTag` (`0x1C0001050` → `0x1C0001008`) | Fallback `ExAllocatePoolWithTag` pool-type argument changes `0x600` → `0x200`. | Both retain the non-executable bit (`0x200` = NonPagedPoolNx); only the raise-on-failure flag (`0x400`) is dropped. Not a security change. |

### Compiler codegen churn (non-behavioural)

- `memmove` (`0x1C0001C80`): different instruction sequence for the same block-move; identical semantics.
- `__GSHandlerCheckCommon` (`0x1C0001BCC`): `movzx edx` replaced with `mov dl` + `movzx eax, dl`; identical byte semantics.
- `SecCreateKernelClient` (`0x1C0008378`): inline `xorps`/`movups` zeroing replaced with a `memset` call.
- `SecRegisterKernelExtension` (`0x1C0008304` → `0x1C00082F0`): inline `and …, 0` zeroing replaced with a `memset` call.
- `SecCreateDriverValidationKernelEcp` (`0x1C0008560` → `0x1C00085FC`): inline zeroing replaced with a `memset` call; symbol/layout addresses shifted.
- `SecValidateDriverFileSignatureLevel` (`0x1C000169C` → `0x1C00014C0`): inline zeroing replaced with `memset`; same `IoQueryFullDriverPath` / `IoCreateFileEx` / `SecIsWindowsSigned` logic and status codes.
- `SecBindHost` (`0x1C00010E0` → `0x1C00010B0`): register allocation differences (an immediate `1` materialised via a register vs. inline); same logic.
- `DriverEntry` (`0x1C000A078` → `0x1C000A008`): stack-frame layout shift and inline-vs-`memset` version-info zeroing; same version check and lookaside setup.
- `DriverUnload` / `SecUninitializeKernelInterface`: relocated call/branch targets only.

---

## 9. Unmatched Functions

No functions were added or removed between the two builds. Every function in the unpatched image has a content match in the patched image (frequently at a different address); every function in the patched image is accounted for.

---

## 10. Confidence & Caveats

**Confidence:** High that this patch delivers no security-relevant change.

**Rationale:**
- The `+0x70` store added to `SecAllocateKernelApcObject` follows a full `0xB0`-byte `memset` in both builds; offset `0x70` (byte 112) is within the memset range (176 bytes), so the byte is already zero. `memset` is an external call and cannot be elided per-byte by the compiler. The rundown-flag producer (`SecInsertQueueKernelApcObject`, `0x1C0001AEB`) and consumer (`SecFreeKernelApcObject`) are byte-identical in both builds, and acquire/release are matched, so there is no imbalance to exploit.
- `qword_1C0007008` is the registered code-integrity verification callback, not `MmProtectDriverSection`; the changed constant `0xA000008` → `0xA000006` is a request-flags word, not a page-protection value, so no `PAGE_WRITECOPY`/copy-on-write weakening is present.

**Caveat:**
- The exact bit-level meaning of the `0xA000008` / `0xA000006` flags word in the code-integrity request is not recoverable from these two binaries. This report therefore makes no claim about whether that one-value change tightens, relaxes, or leaves unchanged the effective integrity decision; it records only the factual difference.
