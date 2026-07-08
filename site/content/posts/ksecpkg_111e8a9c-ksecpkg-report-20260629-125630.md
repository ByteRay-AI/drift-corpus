Title: ksecpkg.sys — Missing minimum-length validation before TLS/DTLS record header reads (CWE-125) fixed
Date: 2026-06-29
Slug: ksecpkg_111e8a9c-ksecpkg-report-20260629-125630
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: Medium
KBDate: 2026-06-09

---

## 1. Overview

| Item | Value |
|---|---|
| Title | ksecpkg.sys — Windows Kernel Security Support Provider (Schannel TLS/DTLS record decryption) |
| Unpatched binary | `ksecpkg_unpatched.sys` (image base `0x1c000000`) |
| Patched binary | `ksecpkg_patched.sys` (image base `0x140000000`) |
| Overall similarity | 0.6942 |
| Matched functions | 458 |
| Changed | 294 |
| Identical | 164 |
| Unmatched (unpatched) | 0 |
| Unmatched (patched) | 0 |

**Diff statistics:** 164 fully identical functions, 294 changed, 0 added, 0 removed (per the reported match set; the raw function-header counts are 490 in the unpatched image and 535 in the patched image, reflecting new C++/library symbols the patched build introduces).

**One-sentence verdict:** The patch adds explicit minimum-record-length checks (`>= 5` for a TLS record header, `>= 0xD`/13 for a DTLS record header) before the Schannel record-decryption handlers dereference fixed header byte offsets of an attacker-supplied record; the unpatched build guarded those reads only with a cipher-overhead comparison that does not guarantee the record is long enough, allowing an out-of-bounds read of the input buffer for a truncated record. The two functions originally flagged in this report (`DigestKernelHTTPHelper` and `strcat_s`) are, on inspection, semantics-preserving compiler churn and carry no security-relevant change.

---

## 2. Vulnerability Summary

### Finding #1 — Missing minimum-length check before TLS/DTLS record header reads (MEDIUM) — the delivered fix

- **Severity:** Medium
- **CWE:** CWE-125 (Out-of-bounds Read)
- **Class:** Missing length validation before fixed-offset dereference of attacker-controlled input
- **Functions (matched; patched build is stricter):**
  - `Tls13DecryptHandler` @ `0x1C000ADC4` (unpatched) ↔ `0x140001680` (patched)
  - `TlsDecryptHandler` @ `0x1C0001770` ↔ `0x140001980`
  - `SslUnsealMessageStream` @ `0x1C0001330` ↔ `0x140001120`
  - `SslUnsealMessageConnection` @ `0x1C000A6BC` ↔ `0x140004D50`
  - plus a new extracted helper `TlsDecryptMessage` in the patched build that carries the same checks
- **Entry point:** Schannel record decryption on an established TLS/DTLS context (`SslUnsealMessage*` / `Tls*DecryptHandler`), processing an inbound encrypted record whose bytes are attacker-controlled.

**Root cause.** These handlers parse an inbound TLS/DTLS record. They read fixed byte offsets from the record buffer to determine the record type/version and the declared record length: offsets `+1`, `+3`, `+4` for a TLS record header (needs at least 5 bytes) and offsets `+0xB` and `+0xC` for a DTLS record header (needs at least 13 bytes, because the DTLS record header carries the sequence bytes there). In the unpatched build the only length check performed before these reads is `cbBuffer >= cipher_overhead`, where `cipher_overhead` is a context-derived value (`ctx[0x40] + ctx[0x44]`). That comparison does not guarantee the record contains the bytes at the fixed header offsets, so a truncated record that satisfies `cbBuffer >= cipher_overhead` but is shorter than the header still reaches `movzx ..., byte ptr [rec+0xB]` / `[rec+0xC]` (or `[rec+3]`/`[rec+4]`), reading past the end of the input buffer.

The patched build inserts an explicit minimum-length gate immediately before those reads:

- `cmp <record-length>, 5` / `jb <error>` before the TLS header reads, and
- `cmp <record-length>, 0Dh` / `jb <error>` before the DTLS header reads,

returning `STATUS_INVALID_TOKEN` (`0x80090318`) for a record too short to hold the header. The same two constants are added at every record-parse entry point listed above.

This is an out-of-bounds **read** (the header bytes feed a record-length computation that is then re-validated against `cbBuffer`), not a write. Impact is a kernel out-of-bounds read of a few bytes adjacent to the record buffer; the leaked bytes influence a length that is subsequently bounds-checked, so the primary risk is a read fault / limited information influence rather than a controlled disclosure. Reachability of a true out-of-bounds access depends on the negotiated cipher's `cipher_overhead` being smaller than the header length; the fix adds the header-length floor unconditionally across all entry points.

### Finding #2 — Digest kernel helper element loop (NO SECURITY-RELEVANT CHANGE)

- **Severity:** None (was reported High)
- **Class:** Compiler refactoring of a semantically-equivalent condition
- **Function:** `DigestKernelHTTPHelper` @ `0x1C0006F00` (unpatched) ↔ `0x14000956C` (patched)

**What actually happens.** The function copies selected entries from a **fixed internal 24-entry table** at `[arg1+0xA2]` into a local scratch structure. The loop counter `edx` is initialized to `0` (from the zeroed `r12d`) and iterated while `edx < 0x18` (24) — a compile-time constant, not a value taken from any token. `edx` is the **loop index**, not an element "type" from attacker input. Both builds copy an entry only when the index is **not** one of `{7, 8, 10}` and the entry's leading `word` (`[rcx-2]`) is non-zero:

- Unpatched expresses the skip set as `(edx-7) & 0xFFFFFFFC == 0` (i.e. `edx ∈ {7,8,9,10}`) combined with `edx != 9`, selecting exactly `{7,8,10}`.
- Patched expresses the identical skip set as `edx == 8`, `edx == 10`, `edx == 7`.

These cover the **identical value set** `{7,8,10}`; no index is newly rejected or accepted, and the copy targets/strides/null-check are unchanged. The only other differences are that the patched build **inlined** the sequence-number helper `DigestKernelGetNextSeqNumber` (@ `0x1C0006E90`), whose body performs the same fast-mutex-protected increment of the counter at `[ctx+0x54]`, and register reallocation (`rsi`/`rdi` swapped). No behavioral change, no added/removed validation, no reachable primitive.

### Finding #3 — `strcat_s` bounded concatenation (NO SECURITY-RELEVANT CHANGE)

- **Severity:** None (was reported Medium)
- **Class:** Dead-code removal / compiler churn
- **Function:** `strcat_s` @ `0x1C0003480` (unpatched) ↔ `0x140005768` (patched)

**What actually happens.** This is a standard bounded string-concatenation routine (`char *dst, rsize_t SizeInBytes, const char *Src`). The copy loop writes one byte, returns success on the source NUL, otherwise decrements `SizeInBytes` and, at `0`, returns error `34` (`ERANGE`) and resets `*dst = 0`. It performs exactly `SizeInBytes - strlen(dst)` writes, all in bounds. There is **no off-by-one in either build.** The unpatched and patched decompilations are logically identical; the only instruction-level delta is removal of dead instructions (`mov rax,rdx; test rax,rax` in the scan loop and an unreachable `test rdx,rdx; jnz` in the copy loop where `rdx` is provably `0`). The reported "`else if (!arg2) break`" one-iteration-late break does not exist; it is a misreading of that dead pair. Every caller supplies a compile-time constant size (`0x3001` / `0x1001`), so the bound is not attacker-controlled.

---

## 3. Pseudocode Diff

### Finding #1 — TLS/DTLS record header length gate

```c
// UNPATCHED — reads fixed header offsets guarded only by cipher-overhead
overhead = ctx[0x40] + ctx[0x44];
if (cbBuffer < overhead) return STATUS_INVALID_TOKEN;   // only length check
ver_hi = rec[1];                                        // read offset 1
if (is_dtls(ver_hi)) {
    len = (rec[0xB] << 8) | rec[0xC];                   // reads offsets 11,12 — NO >=13 guard
} else {
    len = (rec[3]   << 8) | rec[4];                     // reads offsets 3,4  — NO >=5 guard
}
if (cbBuffer < len + ctx[0x44]) return STATUS_INVALID_TOKEN;  // re-check AFTER the reads

// PATCHED — explicit minimum record length before the header reads
overhead = ctx[0x40] + ctx[0x44];
if (cbBuffer < overhead) return STATUS_INVALID_TOKEN;
if (cbBuffer < 5)   return STATUS_INVALID_TOKEN;        // NEW: TLS header floor
ver_hi = rec[1];
if (is_dtls) {
    if (cbBuffer < 0xD) return STATUS_INVALID_TOKEN;    // NEW: DTLS header floor (13)
    len = (rec[0xB] << 8) | rec[0xC];
} else {
    len = (rec[3] << 8) | rec[4];
}
if (cbBuffer < len + ctx[0x44]) return STATUS_INVALID_TOKEN;
```

### Finding #2 — `DigestKernelHTTPHelper` element loop (both builds identical in effect)

```c
// UNPATCHED — skip set {7,8,10} via range test + edx!=9
for (edx = 0; edx < 0x18; edx++, entry += 0x10) {       // 0x18 is a constant bound
    if (((edx - 7) & ~3) == 0 && edx != 9) continue;    // edx in {7,8,10} -> skip
    if (entry->w0 == 0) continue;
    out_a[edx] = entry->w0; out_b[edx] = entry->w1; out_c[edx] = *(u64*)&entry->data;
}
// PATCHED — identical skip set {7,8,10} via explicit compares
for (edx = 0; edx < 0x18; edx++, entry += 0x10) {
    if (edx == 8 || edx == 10 || edx == 7) continue;    // same set {7,8,10}
    if (entry->w0 == 0) continue;
    out_a[edx] = entry->w0; out_b[edx] = entry->w1; out_c[edx] = *(u64*)&entry->data;
}
```

### Finding #3 — `strcat_s` (unpatched and patched decompile identically)

```c
if (a1 == nullptr || SizeInBytes == 0) return 22;
if (Src != nullptr) {
    v3 = a1;
    while (*v3 != 0) { ++v3; if (--SizeInBytes == 0) goto err22; }
    v4 = v3 - Src;
    while (1) {
        v5 = *Src; Src[v4] = *Src; ++Src;
        if (v5 == 0) return 0;                              // NUL copied -> done, in bounds
        if (--SizeInBytes == 0) { v6 = 34; goto err; }      // exact boundary -> ERANGE
    }
}
```

---

## 4. Assembly Analysis

### Finding #1 — `Tls13DecryptHandler`, header-parse region

```
; === UNPATCHED (0x1C000AE4C .. 0x1C000AEAC) ===
0x1C000AE4C  mov     r8d, [rsi+4]         ; r8d = cbBuffer (record length)
0x1C000AE50  mov     edx, [rcx+40h]       ; ctx[0x40]
0x1C000AE53  mov     r9d, [rcx+44h]       ; ctx[0x44]
0x1C000AE57  add     edx, r9d             ; edx = cipher overhead
0x1C000AE5E  cmp     r8d, edx
0x1C000AE61  jnb     0x1C000AE70          ; ONLY guard: cbBuffer >= overhead
...error 80090318
0x1C000AE70  movzx   eax, byte ptr [rdi+2]   ; read rec[2]  (no >=3 guard)
0x1C000AE74  movzx   ecx, byte ptr [rdi+1]   ; read rec[1]
0x1C000AE82  cmp     al, 0FEh                ; DTLS version?
0x1C000AE8E  movzx   ecx, byte ptr [rdi+0Bh] ; DTLS: read rec[11]  (no >=13 guard)
0x1C000AE92  movzx   eax, byte ptr [rdi+0Ch] ; DTLS: read rec[12]
0x1C000AE98  movzx   ecx, byte ptr [rdi+3]   ; TLS:  read rec[3]   (no >=5 guard)
0x1C000AE9C  movzx   eax, byte ptr [rdi+4]   ; TLS:  read rec[4]
0x1C000AEA5  lea     r12d, [rcx+r9]          ; declared len + ctx[0x44]
0x1C000AEA9  cmp     r8d, r12d               ; re-check cbBuffer >= len (AFTER the reads)

; === PATCHED (0x1400016F8 .. 0x140001878) ===
0x1400016F8  mov     edx, [rdx+4]         ; edx = cbBuffer (record length)
0x14000170A  cmp     edx, r10d            ; cbBuffer >= overhead (as before)
0x14000170D  jb      0x14000187D          ; -> 80090318
0x140001723  cmp     edx, 5               ; NEW: TLS header floor
0x140001726  jb      0x1400018F3          ; -> [rdi+4]=5, 80090318
0x14000172C  cmp     byte ptr [r14+1], 0FEh
0x14000174F  movzx   ecx, byte ptr [r14+3]   ; TLS read (now guarded by >=5)
0x140001754  movzx   eax, byte ptr [r14+4]
0x140001865  cmp     edx, 0Dh             ; NEW: DTLS header floor (13)
0x140001868  jb      0x140001908          ; -> [rdi+4]=0Dh, 80090318
0x14000186E  movzx   ecx, byte ptr [r14+0Bh] ; DTLS read (now guarded by >=13)
0x140001873  movzx   eax, byte ptr [r14+0Ch]
```

The unpatched function contains no `cmp <length-register>, 5` or `cmp <length-register>, 0Dh` anywhere; the reads at offsets `0xB`/`0xC` and `3`/`4` are reached with only the cipher-overhead comparison in front of them. The patched function adds both floors before the corresponding reads.

**Same fix, same two constants, at every record-parse entry point** (patched addresses; the corresponding unpatched functions contain neither compare):

| Function | Patched `cmp …, 5` | Patched `cmp …, 0Dh` |
|---|---|---|
| `TlsDecryptHandler` @ `0x140001980` | `0x1400019FD` | `0x140001A3A` |
| `SslUnsealMessageStream` @ `0x140001120` | `0x140001234`, `0x14000154E` | `0x140001385`, `0x140001587` |
| `SslUnsealMessageConnection` @ `0x140004D50` | `0x140004F8F` | `0x140004FDC` |

Unpatched header reads that these floors now guard (examples): `TlsDecryptHandler` reads `[r8+0Bh]`/`[r8+0Ch]` @ `0x1C00051D9`/`0x1C00051DE`; `SslUnsealMessageStream` reads `[rdx+0Bh]`/`[rdx+0Ch]` @ `0x1C00014F0`/`0x1C00014F4`; `SslUnsealMessageConnection` reads `[rdi+0Bh]`/`[rdi+0Ch]` @ `0x1C000A8FC`/`0x1C000A900` — none preceded by a `>= 5`/`>= 0xD` compare in the unpatched build.

### Finding #2 — `DigestKernelHTTPHelper` loop tail (both builds; equivalent)

```
; === UNPATCHED (0x1C00071E3) ===              ; === PATCHED (0x14000986B) ===
lea   eax, [rdx-7]                              cmp   edx, r11d        ; r11d = 8
test  eax, 0FFFFFFFCh   ; edx in {7,8,9,10}?    jz    0x1400098A4      ; edx==8 -> skip
jnz   0x1C00071F2       ; not in set -> copy    cmp   edx, 0Ah
cmp   edx, r11d         ; edx == 9?             jz    0x1400098A4      ; edx==10 -> skip
jnz   0x1C000721C       ; edx in {7,8,10}->skip cmp   edx, 7
                                                jz    0x1400098A4      ; edx==7 -> skip
; both then copy indices 0-6,9,11-23 when [rcx-2] != 0; stride 0x10; bound cmp edx,18h
```

The patched build also inlines the sequence-number counter; the inlined body matches the unpatched helper `DigestKernelGetNextSeqNumber` @ `0x1C0006E90` instruction-for-instruction (same `KeEnterCriticalRegion` / `ExAcquireFastMutexUnsafe` / `inc [ctx+54h]` / release / leave).

### Finding #3 — `strcat_s` copy loop (both builds; equivalent)

```
; === UNPATCHED (0x1C00034B4) ===              ; === PATCHED (0x1400057B4) ===
mov   al, [r8]                                  mov   al, [r8]
mov   [r9+r8], al                               mov   [r9+r8], al
inc   r8                                        inc   r8
test  al, al                                    test  al, al
jz    0x1C00034D2   ; NUL -> success            jz    0x1400057CD   ; NUL -> success
sub   rdx, 1                                    sub   rdx, 1
jnz   0x1C00034B4                               jnz   0x1400057B4
test  rdx, rdx      ; DEAD (rdx==0)             lea   ebx, [rdx+22h] ; 34 = ERANGE
jnz   0x1C00034D2   ; DEAD (never taken)
lea   ebx, [rdx+22h] ; 34 = ERANGE
```

Identical write-then-decrement-then-check order; the unpatched-only `test rdx,rdx; jnz` pair is unreachable and was removed.

---

## 5. Trigger Conditions

### Finding #1 (TLS/DTLS record OOB read)

1. Establish a TLS or DTLS context handled by the kernel Schannel provider so that inbound records are decrypted through `SslUnsealMessage*` / `Tls*DecryptHandler`.
2. Send an encrypted record whose declared/actual buffer length (`cbBuffer`, the SPBuffer length field at `+4`) satisfies `cbBuffer >= cipher_overhead` (`ctx[0x40]+ctx[0x44]`) but is shorter than the header the parser dereferences: fewer than 5 bytes for a TLS record, or fewer than 13 bytes for a record whose version byte marks it DTLS (`rec[1] == 0xFE`).
3. **Unpatched observation:** execution reaches `movzx ..., byte ptr [rec+0xB]` / `[rec+0xC]` (or `[rec+3]`/`[rec+4]`) and reads past the end of the record buffer.
4. **Patched observation:** the new `cmp <len>, 5` / `cmp <len>, 0Dh` returns `STATUS_INVALID_TOKEN` (`0x80090318`) before the read.

Whether step 2 is achievable in practice depends on the negotiated cipher's `cipher_overhead` being smaller than the header length.

### Findings #2 and #3

No trigger distinguishes the two builds. `DigestKernelHTTPHelper`'s loop bound and skip set are compile-time constants identical across builds; `strcat_s`'s bound is a caller-supplied constant and both builds terminate at the same byte with the same `ERANGE` result.

---

## 6. Exploit Primitive & Development Notes

### Finding #1

- **Primitive:** Kernel out-of-bounds read (CWE-125) of a few bytes past an attacker-supplied TLS/DTLS record buffer, reached before the fixed-offset header fields are validated for presence.
- **Reachable effect:** the out-of-bounds bytes form a declared record length that is then re-checked against `cbBuffer`, so the realistic outcome is a read fault (denial of service) or a length/parsing decision influenced by adjacent memory, rather than a controlled information disclosure. No write primitive is present in this change.
- **Constraints:** requires an active TLS/DTLS context on the kernel Schannel path and a record short enough to slip under the header length while still passing the cipher-overhead check.

### Findings #2 and #3

No exploit primitive. Both are semantics-preserving compiler output differences (predicate re-encoding plus helper inlining; dead-code removal). There is nothing to weaponize and no mitigation analysis applies.

---

## 7. Verification Notes

### Finding #1

- `Tls13DecryptHandler`: unpatched guard `cmp r8d, edx` @ `0x1C000AE5E`; unguarded DTLS reads `[rdi+0Bh]`/`[rdi+0Ch]` @ `0x1C000AE8E`/`0x1C000AE92`. Patched adds `cmp edx, 5` @ `0x140001723` and `cmp edx, 0Dh` @ `0x140001865` before the corresponding reads at `0x14000174F`/`0x140001754` and `0x14000186E`/`0x140001873`.
- Confirm the unpatched functions `TlsDecryptHandler` (`0x1C0001770`), `SslUnsealMessageStream` (`0x1C0001330`), and `SslUnsealMessageConnection` (`0x1C000A6BC`) contain no `cmp <len>, 5` or `cmp <len>, 0Dh`, while their patched counterparts do (addresses in the table in §4).

### Finding #2 — `DigestKernelHTTPHelper`

- Unpatched loop tail `0x1C00071E3`–`0x1C0007225`; patched `0x14000986B`–`0x1400098AD`. Indices `{7,8,10}` skip, all others copy under the same null-word condition. Sequence counter: unpatched `call` @ `0x1C0007176` → helper `0x1C0006E90`; patched inlined `0x1400097D3`–`0x140009803`.

### Finding #3 — `strcat_s`

- Unpatched copy loop `0x1C00034B4`–`0x1C00034D0`; patched `0x1400057B4`–`0x1400057CB`. Identical write-then-check order; the unpatched `test rdx,rdx; jnz` @ `0x1C00034C8` is unreachable (`rdx == 0` on fall-through). Both return `34` at the boundary after the last in-bounds write.

---

## 8. Changed Functions — Full Triage

| Function | Change type | Note |
|---|---|---|
| `Tls13DecryptHandler` @ `0x1C000ADC4` | **security_relevant** | Adds `cmp <len>,5` / `cmp <len>,0Dh` floors before header reads at offsets `1/3/4` (TLS) and `0xB/0xC` (DTLS); unpatched guarded only by `cbBuffer >= cipher_overhead`. CWE-125 OOB read hardening. |
| `TlsDecryptHandler` @ `0x1C0001770` | **security_relevant** | Same minimum-length floors added (`cmp edx,5` @ `0x1400019FD`, `cmp edx,0Dh` @ `0x140001A3A`). |
| `SslUnsealMessageStream` @ `0x1C0001330` | **security_relevant** | Same floors added at two record-parse sites (`0x140001234`/`0x14000154E` and `0x140001385`/`0x140001587`). |
| `SslUnsealMessageConnection` @ `0x1C000A6BC` | **security_relevant** | Same floors added (`cmp ecx,5` @ `0x140004F8F`, `cmp ecx,0Dh` @ `0x140004FDC`). |
| `DigestKernelHTTPHelper` @ `0x1C0006F00` | **no_security_change** | `{7,8,10}` skip predicate re-encoded (identical value set); `DigestKernelGetNextSeqNumber` inlined (same fast-mutex counter); register reallocation. No behavioral change. |
| `strcat_s` @ `0x1C0003480` | **no_security_change** | Dead-code removal only; copy bounds and `ERANGE` behavior identical; size is a compile-time constant. No off-by-one in either build. |
| `DigestCreateChalResp` @ `0x1C00083CC` | behavioral | Digest response builder; fixed `0x3001`/`0x1001` constant buffers with `sprintf_s`/`strcat_s`. Reorganized; no security boundary change. |
| `wil_details_FeatureReporting_IncrementOpportunityInCache` @ `0x1C00042CC` | cosmetic | WIL feature-usage telemetry; register reallocation. Not a security fix. |
| `wil_details_FeatureReporting_IncrementUsageInCache` @ `0x1C00043B4` | cosmetic | WIL feature-usage telemetry; register reallocation. Not a security fix. |
| `NtLmInitKernelContext` @ `0x1C001D530` | cosmetic | `rdx`/`rcx` swaps; allocation sizes bounded (`< 0xffff`) in both builds. |
| `KerbMakeSignatureToken` @ `0x1C00229F0` | behavioral | Kerberos signature-token formatting reorganized as part of the crypto refactor; no bounds/validation added or removed. |

The remainder of the 294-function diff is servicing/compiler rebuild churn: a new `KerberosCryptoPolicy` C++ class hierarchy with `unique_ptr`/`vector<WrapBuffer>` scaffolding, SymCrypt-style crypto wrappers (`Sha256Wrap*`, `Sha384Wrap*`, `Sha512Wrap*`, `CngRsa32Compat_*`) replacing the older `des*`/`md5Des*`/`md25*` routines, WIL feature-staging gates (`Feature_Servicing_KsecpkgArgonSiloFix`, `Feature_385562938`), and TraceLogging/telemetry. Other record-adjacent functions (`der_read_length`, `DeserializeContextWorker`, `g_verify_token_header`, `DTLSCheckRecordValidity`, `TlsParseAlertMessage`, `SPCountCertificates`) were reviewed and carry equivalent bounds logic (a couple add only null-pointer guards), not a bounds/overflow fix.

---

## 9. Unmatched Functions

```
removed: []
added:   [TlsDecryptMessage]   ; extracted record-decrypt helper present only in the patched build; carries the same >=5 / >=0xD length floors
```

The reported match set lists no added/removed functions. At the symbol level the patched build introduces new C++/library and feature-staging symbols (crypto-policy classes, SymCrypt wrappers, WIL feature gates, telemetry) and drops the older standalone `des*`/`md5Des*` crypto helpers, and it extracts `TlsDecryptMessage` as a shared record-decrypt helper. Aside from the length-floor fix carried into `TlsDecryptMessage`, these are consistent with a library/servicing rebuild rather than additional vulnerability fixes.

---

## 10. Confidence & Caveats

**Confidence:** High.

- **Strongly evidenced:**
  - The added `cmp <length>, 5` and `cmp <length>, 0Dh` floors are present in every patched record-parse entry point and absent from every unpatched counterpart; the unpatched builds reach `movzx ..., byte ptr [rec+0xB]`/`[rec+0xC]` (and `[rec+3]`/`[rec+4]`) with only a cipher-overhead comparison in front. The direction is correct (patched is stricter) and the operation is a read (CWE-125).
  - `DigestKernelHTTPHelper`'s loop is a compile-time-bounded index over a fixed table; both builds skip the identical set `{7,8,10}`; the sequence-counter change is inlining of a helper with the same locking.
  - `strcat_s` decompiles identically in both builds; the only delta is dead-code removal, and its size argument is a compile-time constant.

- **Caveats:**
  - Whether the TLS/DTLS length-floor fix corresponds to a reachable out-of-bounds access (versus defense-in-depth) depends on whether the negotiated cipher's `cipher_overhead` (`ctx[0x40]+ctx[0x44]`) can be smaller than the 5-/13-byte header; that lower bound was not established here. Severity is rated Medium accordingly (kernel OOB read, network-adjacent TLS/DTLS surface, no write primitive, leaked bytes feed a re-validated length).
  - The overall diff reflects a large servicing/compiler rebuild; the remaining changed functions were reviewed for added/removed bounds or validation and found to be library/feature-staging/telemetry churn or semantics-preserving refactors.
