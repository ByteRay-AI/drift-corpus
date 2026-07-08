Title: http.sys — No security-relevant change (feature-staged QUIC frame length-check guard, old path retained)
Date: 2026-06-28
Slug: http_d26aca0f-http-report-20260628-234324
Category: Corpus
Author: Argus
Summary: KB5083769
Severity: Informational

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `http_unpatched.sys` |
| **Patched binary** | `http_patched.sys` |
| **Overall similarity** | 0.9923 |
| **Matched functions** | 4408 |
| **Changed functions** | 2 |
| **Identical functions** | 4406 |
| **Unmatched (each direction)** | 0 / 0 |

**Verdict:** The patch does **not** deliver a security fix. It adds a new Windows feature-staging gate, `UxKirQuicParseLengthCheck` (backed by the WIL feature `Feature_1164959034`), around the second variable-length-integer read in the generic HTTP/3 (QUIC) frame-header parser `UxQuicParseFrame`. When the gate is enabled, a zero-remaining-length guard is applied before the read; when the gate is disabled, the parser executes the **identical** pre-existing read path. The old code path is fully retained behind the gate, so this is a staged/rollback-capable change, not a delivered fix. The underlying read it guards is a 1-byte over-read of one byte past the currently buffered stream data, whose value is discarded and does not affect control flow or output; no reachable impact is demonstrable from the binaries.

---

## 2. Vulnerability Summary

### Finding 1 — Feature-gated zero-length guard added to `UxQuicParseFrame` (not delivered)

- **Severity:** Informational (no delivered security-relevant change)
- **Class:** Guarded 1-byte over-read (nature: CWE-125), value discarded; guard is feature-gated with the old path retained
- **Affected function:** `UxQuicParseFrame` — unpatched `@ 0x1400FD714`, patched `@ 0x1400FD794`
- **Entry point:** Remote HTTP/3 (QUIC) stream data (control stream and request/other streams)

#### What the function does

`UxQuicParseFrame` is the generic HTTP/3 (QUIC) frame-header parser. It reads two QUIC variable-length integers from the front of a frame: the frame **type** and the frame **length**, then dispatches to a per-type handler. The frame types handled here are the standard HTTP/3 types dispatched at the tail of the function: Data, Headers, CancelPush, Settings, PushPromise, Goaway, and MaxPushId (via `UxpQuicParseDataFrame`, `UxpQuicParseHeadersFrame`, `UxpQuicParseCancelPushFrame`, `UxpQuicParseSettingsFrame`, `UxpQuicParsePushPromiseFrame`, `UxpQuicParseGoawayFrame`, `UxpQuicParseMaxPushIdFrame`). There is no PRIORITY-frame handling in this function.

#### The read that is guarded

After the **type** varint is parsed by `UxpQuicParseVariableLengthInteger`, the code computes `remaining = length - consumed` and then, for frame types that carry a length field, reads the first byte of the **length** varint to learn its encoded size. In the unpatched build this read is performed without a prior check that `remaining != 0`:

Unpatched decompilation (`UxQuicParseFrame @ 0x1400FD714`):

```c
// remaining = a4 - consumed;  v23 = &a3[consumed]
if ( v25 < 1 << (*v23 >> 6) )   // *v23 dereferenced unconditionally
    goto LABEL_21;               // (v25 == remaining)
```

When a frame body consists of exactly one type varint and no length byte (`remaining == 0`), `v23` points one byte past the currently buffered stream data and `*v23` reads that byte. The result is right-shifted by 6 to derive a size threshold; because `remaining == 0`, the subsequent comparison always routes to the "incomplete frame" path. The byte value has no effect on control flow or on returned data.

The **first** (type) varint read at the top of the function is already guarded against zero length by short-circuit evaluation:

```c
if ( a4 == 0 || a4 < 1 << (*a3 >> 6) )   // a4 == 0 short-circuits before *a3
```

#### What the patch changes

The patched build introduces a new global gate `UxKirQuicParseLengthCheck` and rewrites the guarded read as:

Patched decompilation (`UxQuicParseFrame @ 0x1400FD794`):

```c
if ( (UxKirQuicParseLengthCheck == 0 || v25 != 0) && v25 >= 1 << (*v23 >> 6) )
{
    // parse length varint...
}
```

- **Gate disabled (`UxKirQuicParseLengthCheck == 0`):** the left operand is true via short-circuit, so `*v23` is dereferenced regardless of `remaining` — byte-for-byte the same behavior as the unpatched build. The old path is retained.
- **Gate enabled (`UxKirQuicParseLengthCheck != 0`):** the guard requires `v25 != 0` before `*v23` is evaluated, so the read is skipped when `remaining == 0`.

`UxKirQuicParseLengthCheck` is initialized in `UxStartEnvironmentModule` from a WIL feature-staging query:

```c
UxKirQuicParseLengthCheck = (unsigned int)Feature_1164959034__private_IsEnabledDeviceUsageNoInline() != 0;
```

This is a Known-Issue-Rollback / feature-staging gate. Neither the gate variable nor `Feature_1164959034` exists in the unpatched build. Because the change is gated and the pre-existing read path is preserved when the gate is off, the patch does not deliver a security-relevant behavioral change; its default runtime effect depends on external feature state that cannot be determined from the binary.

#### Reachable-impact assessment

`UxQuicParseFrame` is called from the QUIC stream receive paths `UxpQuicReceiveControlStreamReceiveEvent` (`@ 0x1400FBCF4`) and `UxpQuicStreamParseReceiveBuffer` (`@ 0x140106404`). In both callers, the buffer argument is a pointer into a QUIC stream reassembly buffer (`base + offset`) and the length argument is the count of currently buffered bytes. The guarded read therefore reads one byte past the *buffered data length*, which is not demonstrably past the end of the pool allocation. No page-fault, information disclosure, or other reachable impact is demonstrable from the binaries: the over-read byte is shifted and used only as a size threshold that, at `remaining == 0`, always routes to the benign "incomplete frame" path.

---

## 3. Pseudocode Diff

```c
// === UNPATCHED UxQuicParseFrame @ 0x1400FD714 ===
// After type varint parsed; consumed bytes in v43, remaining in v25.
v23 = &a3[v43];        // pointer just past the type varint
v25 = a4 - v43;        // remaining bytes (can be 0)
// ...frame-type acceptance checks...
if ( v25 < 1 << (*v23 >> 6) )   // *v23 read even when v25 == 0
    goto LABEL_21;              // route to incomplete-frame path
// parse length varint...

// === PATCHED UxQuicParseFrame @ 0x1400FD794 ===
v23 = &a3[v43];
v25 = a4 - v43;
// ...same frame-type acceptance checks...
if ( (UxKirQuicParseLengthCheck == 0 || v25 != 0)   // gate off => old behavior
     && v25 >= 1 << (*v23 >> 6) )                    // *v23 read
{
    // parse length varint...
}
// UxKirQuicParseLengthCheck set in UxStartEnvironmentModule:
//   UxKirQuicParseLengthCheck = Feature_1164959034__private_IsEnabledDeviceUsageNoInline() != 0;
```

The only functional change is the added `UxKirQuicParseLengthCheck == 0 || v25 != 0` term. When the gate is off, `*v23` is still evaluated exactly as in the unpatched build.

---

## 4. Assembly Analysis

### Unpatched `UxQuicParseFrame @ 0x1400FD714` — read region

```asm
; First (type) varint read is guarded by a zero test:
00000001400FD7C4  test    r15d, r15d          ; r15d = length
00000001400FD7C7  jnz     short loc_1400FD817
00000001400FD7C9  mov     byte ptr [r12], 1   ; length 0 -> incomplete, no deref
...
00000001400FD817  movzx   ecx, byte ptr [rsi] ; type-varint first byte (guarded)
00000001400FD81F  shr     ecx, 6
00000001400FD822  shl     eax, cl
00000001400FD824  cmp     r15d, eax
00000001400FD827  jb      short loc_1400FD7C9
00000001400FD837  call    UxpQuicParseVariableLengthInteger  ; parse type

; Compute remaining after the type varint:
00000001400FD84C  mov     ecx, [rbp+37h+arg_18]  ; consumed bytes
00000001400FD853  add     rsi, rcx               ; advance past type varint
00000001400FD85C  sub     r15d, ecx              ; r15d = remaining (can be 0)

; Frame-type acceptance checks:
00000001400FD886  cmp     rdi, 0Eh               ; rdi = frame type value
00000001400FD88A  jnb     short loc_1400FD8DD
00000001400FD88C  mov     ecx, [rbp+37h+arg_0]
00000001400FD88F  lea     rdx, byte_14018E4C8
00000001400FD89D  test    [rdi+rdx], al          ; type allowed?
00000001400FD8A0  jnz     short loc_1400FD8DD

; Second (length) varint size read — NO zero guard:
00000001400FD8DD  movzx   ecx, byte ptr [rsi]    ; reads 1 byte; OOB of buffered
                                                 ; data when remaining == 0
00000001400FD8E5  shr     ecx, 6
00000001400FD8E8  shl     eax, cl
00000001400FD8EA  cmp     r15d, eax              ; remaining >= size?
00000001400FD8ED  jnb     short loc_1400FD900    ; yes -> parse length varint
00000001400FD8EF  mov     rdi, [rbp+37h+arg_20]  ; no -> incomplete-frame path
00000001400FD8F6  mov     byte ptr [r12], 1
00000001400FD8FB  jmp     loc_1400FDAE7
```

### Patched `UxQuicParseFrame @ 0x1400FD794` — gated region

```asm
; Same frame-type acceptance checks reach loc_1400FD95D, then:
00000001400FD95D  cmp     cs:UxKirQuicParseLengthCheck, 0   ; feature-staging gate
00000001400FD964  jz      short loc_1400FD97C               ; gate off -> old read
00000001400FD966  test    r14d, r14d                        ; gate on: remaining==0?
00000001400FD969  jnz     short loc_1400FD97C               ; nonzero -> read
00000001400FD96B  mov     rdi, [rbp+37h+arg_20]             ; zero -> safe exit,
00000001400FD972  mov     byte ptr [r12], 1                 ; no read performed
00000001400FD977  jmp     loc_1400FDB75

00000001400FD97C  movzx   ecx, byte ptr [rsi]               ; length-varint size read
00000001400FD984  shr     ecx, 6
00000001400FD987  shl     eax, cl
00000001400FD989  cmp     r14d, eax
00000001400FD98C  jb      short loc_1400FD96B
00000001400FD98E  lea     r9, [rbp+37h+var_78]              ; parse length varint
00000001400FD99C  call    UxpQuicParseVariableLengthInteger
```

**Delta:** the patched build inserts `cmp cs:UxKirQuicParseLengthCheck, 0 / jz` and, on the gate-enabled branch, `test r14d, r14d / jnz` before the `movzx ecx, byte ptr [rsi]` read (the read itself moves to `loc_1400FD97C`). When the gate is zero, control jumps straight to the unconditional read, matching the unpatched behavior. The remaining-length register is `r15d` in the unpatched build and `r14d` in the patched build.

---

## 5. Trigger Conditions

To reach the guarded read at all, an HTTP/3 (QUIC) frame must arrive on a control or request stream whose available body is exactly one frame-type varint with no length byte, for a frame type that carries a length field (type value `>= 0x0E`, or a type whose bit is set in the acceptance table `byte_14018E4C8`). After the type varint is consumed, `remaining == 0` and the length-varint size read executes.

This condition is what the added `UxKirQuicParseLengthCheck` guard suppresses when the feature is enabled. When the feature is disabled, the read occurs exactly as in the unpatched build.

---

## 6. Impact

- The over-read is a single byte one position past the buffered stream data. The callers supply a pointer into a QUIC stream reassembly buffer, so this is not demonstrably past the pool allocation.
- The read byte is right-shifted by 6 and used only to derive a size threshold. Because `remaining == 0` on the triggering path, the comparison always fails and control routes to the benign "incomplete frame" handling. The byte value does not influence control flow or returned data.
- No page-fault (denial of service), information disclosure, memory corruption, or other reachable impact is demonstrable from the binaries.
- The change is gated behind a WIL feature-staging / Known-Issue-Rollback flag with the old path fully retained, so the patch delivers no security-relevant behavioral change by default.

---

## 7. Changed Functions — Full Triage

### `UxQuicParseFrame` — unpatched `@ 0x1400FD714`, patched `@ 0x1400FD794` (similarity 0.9718)
- **Change:** Added a feature-staging gate `UxKirQuicParseLengthCheck` and, on the gate-enabled branch, a `test r14d, r14d` zero-remaining guard before the length-varint size read at `loc_1400FD97C` (unpatched read at `0x1400FD8DD`). When the gate is off, the pre-existing unconditional read is executed.
- **Behavioral impact:** None by default; the change is gated and the old path is retained. When the gate is enabled it skips a benign 1-byte over-read on zero-remaining frames.

### `UxStartEnvironmentModule` — unpatched `@ 0x1400BCA70`, patched `@ 0x1400BCAC0` (similarity 0.9726)
- **Change:** Environment/feature initialization. The patched build adds one line initializing the new gate: `UxKirQuicParseLengthCheck = Feature_1164959034__private_IsEnabledDeviceUsageNoInline() != 0;`, plus its associated WPP trace. This is the source of the gate used in `UxQuicParseFrame`.
- **Behavioral impact:** Adds feature-staging state; no delivered security change.

The only other differences between the two builds are the added WIL feature stubs `Feature_1164959034__private_IsEnabledDeviceUsageNoInline` / `Feature_1164959034__private_IsEnabledFallback` and compiler-generated WPP trace-helper name variants; no other function logic changed.

---

## 8. Unmatched Functions

- **Removed from unpatched:** none.
- **Added in patched:** the WIL feature stubs `Feature_1164959034__private_IsEnabledDeviceUsageNoInline` and `Feature_1164959034__private_IsEnabledFallback` (feature-staging plumbing for the new gate). No mitigation helpers were removed.

---

## 9. Confidence & Caveats

**Confidence: High** that this is feature-staged servicing churn rather than a delivered fix.

- The gate `UxKirQuicParseLengthCheck` and the WIL feature `Feature_1164959034` are new to the patched build and absent from the unpatched build.
- The gate-off branch executes the same read as the unpatched build (`cmp cs:UxKirQuicParseLengthCheck, 0 / jz loc_1400FD97C` then `movzx ecx, byte ptr [rsi]`); the decompiled `UxKirQuicParseLengthCheck == 0 || v25 != 0` term confirms the old dereference is retained.
- The default runtime state of `Feature_1164959034` is set outside the binary (feature configuration), so whether the guard is active at runtime cannot be determined here.
- The guarded read's over-read of a single byte past buffered stream data has no demonstrable reachable impact from the binaries.

**Verified against the binaries:**

1. Callers of `UxQuicParseFrame`: `UxpQuicReceiveControlStreamReceiveEvent @ 0x1400FBCF4` and `UxpQuicStreamParseReceiveBuffer @ 0x140106404`; the buffer/length arguments are a QUIC stream reassembly pointer and its buffered byte count.
2. The frame-type dispatch handles Data/Headers/CancelPush/Settings/PushPromise/Goaway/MaxPushId; there is no PRIORITY-frame handling in this function.
3. The gate is initialized in `UxStartEnvironmentModule` from `Feature_1164959034__private_IsEnabledDeviceUsageNoInline()`.

---

*End of report.*
