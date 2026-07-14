Title: vmstorfl.sys — Guest-triggerable OOB write in Hyper-V host SCSI sense-data translation (missing SRB offset/length validation)
Date: 2026-06-09
Slug: vmstorfl_e11d050c-vmstorfl-report-20260714-163647
Category: Corpus
Author: Argus
Summary: KB5094128
Severity: High
KBDate: 2026-06-09

## 1. Overview

| Item | Value |
|---|---|
| Unpatched binary | vmstorfl_unpatched.sys |
| Patched binary | vmstorfl_patched.sys |
| Overall similarity | 0.8246 |
| Matched functions | 78 |
| Changed functions | 36 |
| Identical functions | 42 |
| Unmatched (unpatched / patched) | 0 / 0 |

**Verdict:** The patch hardens `sub_1C00034A0`, the SCSI sense-data translation routine for guest virtual-SCSI completions arriving over VMBus, which in the unpatched build performs a `memset` (and follow-on fixed-offset writes) to a destination sense buffer using an attacker-controlled length taken from an SRB field with only a lower-bound check — enabling a guest to force an out-of-bounds write into host non-paged pool.

Of the 36 reported changed functions, only one is genuinely the security fix: `sub_1C00034A0` (patched `sub_1C000363C`). Two others (`sub_1C0004780`/`sub_1C0005040` and `sub_1C0004AC0`/`sub_1C0005300`) are the re-optimized `memmove`/`memset` primitives — the corruption *sinks* of the vulnerable routine, not vulnerabilities themselves. `sub_1C00022F0` and `sub_1C0003D58` are the unmodified-in-substance caller/dispatch chain that documents reachability. `FxStubBindClasses` (`sub_1C000333C`) is unrelated WDF loader hardening. The fix is entirely concentrated in the sense-translation routine, which the patch rewrites to discriminate the extended `STORAGE_REQUEST_BLOCK` layout and to bounds-check descriptor offsets against the SRB `DataTransferLength` before dereferencing.

---

## 2. Vulnerability Summary

### 2.1 HIGH — Out-of-bounds write / SRB layout type-confusion (CWE-787 -> CWE-119 -> CWE-843)
- **Affected function:** `sub_1C00034A0` (unpatched @ `0x1c00034a0`), `sub_1C000363C` (patched) — translates SCSI sense data between descriptor format (0x72/0x73) and fixed format (0x70/0x71) for a guest SRB completion.
- **Root cause:** The routine takes both the destination sense buffer pointer and the write length directly from attacker-influenced SRB fields with no upper bound and no layout discrimination.
  - `*(arg3+0x20)` — destination `SenseInfoBuffer` pointer (used as memset/memmove dest)
  - `*(arg3+0xb)` — sense length, a full byte (0x00–0xFF), used as the memset count
  - `*(arg2+0x15)` — source `SenseInfoBufferLength` (the field the fastfail *actually* guards, `<= 0x14`)
  - `*(arg2+0x18)` — DataTransferLength clamp value
  - `*(arg2+0x1c)` — source sense buffer; low 7 bits select descriptor vs fixed format

The dangerous operation is the memset with an unchecked count:
```c
movzx r8d, dl        // count = *(arg3+0xb), attacker byte 0x12..0xFF
mov   rcx, rsi       // dest  = *(arg3+0x20)
xor   edx, edx
call  sub_1c0004ac0  // memset(dest, 0, count)  <-- OOB write
```
- **Why exploitable:** A malicious guest fully controls the length byte `*(arg3+0xb)` (0x12 through 0xFF) and the fields that determine which memory is treated as the destination pointer. The only guard on the memset length is a *lower* bound (`cmp dl,0x12; jb`); the upper-bound `__fastfail` (`cmp bpl,0x14; ja`) validates a **different** field (`*(arg2+0x15)`). The destination lives in host non-paged pool, so an oversized length zero-writes up to ~255 bytes past the sense allocation. The unpatched code additionally never checks for the extended `STORAGE_REQUEST_BLOCK` (SrbType) layout, so an attacker can supply the extended form and have fixed-offset field reads misparsed, giving control over which bytes become the "pointer" and "length."
- **What the patch does:** The patched routine (`sub_1C000363C`) adds `STORAGE_REQUEST_BLOCK` discrimination via `*(arg3+2) == 0x28`, reads length from `+0x3c` (extended) vs `+0x10` (legacy) accordingly, and performs a bounds-checked walk over SRB extension descriptors at `*(rbx + (idx<<2) + 0x78)`, validating each offset (`offset >= 0x80 && offset < DataTransferLength`, `offset+0x28 <= len`, `offset+0x38 <= len`) BEFORE dereferencing to locate the true sense buffer and length. The copy is re-routed through the rewritten helper `sub_1C0005040` with the validated pointer.
- **Attacker-reachable entry point:** Hyper-V guest virtual SCSI (StorVSC) request completion delivered over a VMBus channel to host `vmstorfl.sys`.
- **Call chain:**
  1. VMBus channel packet (guest SRB completion)
  2. `sub_1C0003D58` (VMBus storage packet dispatcher)
  3. `sub_1C00022F0` (SCSI request completion handler; calls `VmbChannelGetPointer`, dispatches on opcode `arg2==1`)
  4. `sub_1C00034A0` (SCSI sense-data translation)
  5. `sub_1C0004AC0` (memset) / `sub_1C0004780` (memmove) — corruption sink at `0x1c000357e`

---

## 3. Pseudocode Diff

### 3.1 sub_1C00034A0 (patched: sub_1C000363C)
```c
// UNPATCHED — sub_1C00034A0 @ 0x1c00034a0
uint64_t result = *(arg2 + 0x18);
if (*(arg3 + 0x10) < result) __fastfail(0x3a);
*(arg3 + 0x10) = result;
*(arg3 + 3)   = *(arg2 + 0xe);
if (*(arg2 + 0xf) != 2) return result;          // require sense present

vmb = VmbChannelGetPointer();
uint8_t rbp = *(arg2 + 0x15);                   // SOURCE SenseInfoBufferLength
if (rbp > 0x14) __fastfail(0x3a);               // upper bound on the WRONG field
uint8_t *src = arg2 + 0x1c;
uint8_t cl = *src & 0x7f;                        // sense response code
...
char rdx = *(arg3 + 0xb);                        // attacker-controlled DEST length
if (flag) {
    void *dest = *(arg3 + 0x20);                 // attacker-influenced dest pointer
    if (arg2 != -0x1c && rbp && dest && rdx >= 0x12) {   // ONLY a lower bound on rdx
        if ((cl - 0x72) <= 1) {                          // descriptor format 0x72/0x73
            sub_1c0004ac0(dest, 0, rdx);                 // memset(dest, 0, up to 0xFF) OOB
            *dest = ...; *(dest+2) ^= ...; *(dest+7) = 0xa;
            *(dest+0xc) = r12; *(dest+0xd) = r14;
        }
    }
    *(arg3 + 0xb) = 0x12;
} else if (rdx >= rbp) {
    sub_1c0004780(*(arg3 + 0x20), arg2 + 0x1c, rbp);     // memmove(dest, src, len<=0x14)
    *(arg3 + 0xb) = *(arg2 + 0x15);
}
```
```c
// PATCHED — sub_1C000363C (behavioral reconstruction)
// 1. Discriminate SRB layout
bool extended = (*(arg3 + 2) == 0x28);           // STORAGE_REQUEST_BLOCK marker
uint32_t len  = extended ? *(uint32_t*)(arg3 + 0x3c)
                         : *(uint32_t*)(arg3 + 0x10);   // = DataTransferLength (r9)

// 2. Bounds-checked descriptor walk to find the REAL sense buffer
for (idx = 0; ...; idx++) {
    uint32_t offset = *(uint32_t*)(rbx + (idx << 2) + 0x78);
    if (offset >= 0x80 && offset < len &&        // offset within DataTransferLength
        offset + 0x28 <= len &&                  // header fits
        offset + 0x38 <= len) {                  // sense region fits
        r14_1 = base + offset;                   // validated sense pointer
        ... locate validated length ...
        sub_1c0005040(r14_1, ...);               // copy via rewritten helper, in-bounds
    }
}
```

**Key changes:**
- Unpatched dangerous line: `sub_1c0004ac0(dest, 0, *(arg3+0xb))` — zero-fill of up to 255 bytes to an unvalidated destination guarded only by `>= 0x12`.
- Patched trusts a length derived from the discriminated SRB layout (`+0x3c` vs `+0x10`) and only writes to a pointer proven to sit inside `[0x80, DataTransferLength)` with `offset+0x28`/`offset+0x38` still inside the buffer.
- No unchecked fallback remains: the copy is re-routed through `sub_1C0005040` using the validated pointer `r14_1`, so the raw `*(arg3+0x20)` / `*(arg3+0xb)` path is eliminated.

---

## 4. Assembly Analysis

### 4.1 sub_1C00034A0 (unpatched @ 0x1c00034a0)

**Unpatched — the fastfail on the wrong field, then the unbounded memset:**
```asm
0x1c00034bd  mov eax, dword [rdx+0x18]     ; result = *(arg2+0x18) DataTransferLength
0x1c00034c6  cmp dword [r8+0x10], eax
0x1c00034ca  jb  0x1c000368e               ; __fastfail if *(arg3+0x10) < result
0x1c00034e2  cmp al, 0x2 ; jne 0x1c0003652 ; require *(arg2+0xf) == 2
0x1c00034ea  call qword [rel 0x1c00082c8]  ; VmbChannelGetPointer
0x1c00034f6  mov bpl, byte [rsi+0x15]      ; rbp = *(arg2+0x15) SOURCE sense len
0x1c00034fd  cmp bpl, 0x14 ; ja 0x1c000368e ; fastfail on WRONG field
0x1c0003507  lea rbx, [rsi+0x1c]           ; src sense = arg2+0x1c
0x1c000350b  mov cl, byte [rbx] ; and cl, 0x7f
0x1c000352d  mov dl, byte [rdi+0xb]        ; dl = *(arg3+0xb) attacker length
0x1c0003538  mov rsi, qword [rdi+0x20]     ; rsi = *(arg3+0x20) dest SenseInfoBuffer
0x1c0003560  cmp dl, 0x12 ; jb 0x1c000364e ; ONLY a lower bound on dl
0x1c0003569  sub cl, 0x72 ; cmp cl, 0x1 ; ja 0x1c000364e  ; descriptor 0x72/0x73
0x1c0003575  movzx r8d, dl                 ; count = *(arg3+0xb), up to 0xFF
0x1c0003579  mov rcx, rsi ; xor edx, edx
0x1c000357e  call 0x1c0004ac0              ; memset(dest, 0, count) -> OOB WRITE
0x1c0003583..0x1c000364a  writes to [rsi],[rsi+2],[rsi+7],[rsi+0xc],[rsi+0xd]
0x1c0003681  call 0x1c0004780              ; memmove path (len <= 0x14)
0x1c000368e  mov ecx, 0x3a ; int 0x29      ; __fastfail(FAST_FAIL_INVALID_BUFFER_ACCESS)
```
Annotations:
- `0x1c00034fd`: the only upper-bound fastfail — but it checks `*(arg2+0x15)` (source length), NOT the memset length.
- `0x1c0003560`: the only guard on the memset length `*(arg3+0xb)` is a lower bound (`>= 0x12`); there is no upper bound and no comparison against the allocation size of the destination.
- `0x1c000357e`: the vulnerable instruction — `memset(*(arg3+0x20), 0, *(arg3+0xb))` writes up to 255 zero bytes to an attacker-influenced pointer.

**Patched — the added descriptor-walk bounds checks:**
```asm
; sub_1c000363c (patched) key added logic
;   *(arg3+2) == 0x28  -> extended STORAGE_REQUEST_BLOCK, length from +0x3c else +0x10
;   walk *(rbx + (idx<<2) + 0x78):
;     rcx >= 0x80 && rcx < r9            (r9 = DataTransferLength)
;     offset + 0x28 <= r9
;     offset + 0x38 <= r9
;   only then dereference to obtain validated sense pointer r14_1
;   copy re-routed through sub_1c0005040 with r14_1
```
Annotations:
- The comparisons around `0x1c0003703`/`0x1c000372b` (`offset < r9`, `offset+0x28 <= r9`, `offset+0x38 <= r9`) are the added mitigation.
- The patched path bails / rejects the descriptor if any bound fails, and never falls back to the raw `*(arg3+0x20)`/`*(arg3+0xb)` copy — the unchecked path is removed.

---

## 5. Trigger Conditions
1. **Reach the target.** From inside a Hyper-V guest, open the virtual SCSI / StorVSC path (a synthetic SCSI disk/controller exposed to the VM) so that request completions are delivered to host `vmstorfl.sys` over a VMBus channel.
2. Issue a SCSI command whose completion returns sense data, driving `sub_1C0003D58 -> sub_1C00022F0` with opcode `arg2 == 1`, which calls `sub_1C00034A0`.
3. Set the SRB completion fields:
   - `*(arg2+0xf) == 2` — selects the sense-processing path.
   - `(*(arg2+0x1c) & 0x7f) ∈ {0x72, 0x73}` — descriptor-format response code so the conversion/memset branch is taken.
   - `*(arg3+0xb) >= 0x12` and as large as `0xFF` — the memset count; the backing `SenseInfoBuffer` must be smaller than this.
   - `*(arg3+0x20)` points to (or is misparsed to point to) an undersized sense buffer.
   - `*(arg3+0x10) >= *(arg2+0x18)` and `*(arg2+0x15) <= 0x14` — satisfy the two `__fastfail` checks so execution reaches the memset.
4. The type-confusion boundary: sending an extended `STORAGE_REQUEST_BLOCK` (SrbType != 0 / marker `0x28`) that the unpatched code misparses lets you further control which bytes are treated as the sense pointer and length.
5. **Fire:** the branch at `0x1c0003530` (`test al,al`) is taken with `al != 0`, `0x1c0003569` passes (descriptor code), and `memset(*(arg3+0x20), 0, *(arg3+0xb))` executes at `0x1c000357e`.
6. **Observable effect.** Zero-write of up to ~255 bytes past the `SenseInfoBuffer` allocation in host non-paged pool. Expect a bugcheck — `BAD_POOL_HEADER`, `KERNEL_MODE_HEAP_CORRUPTION`, or (with Driver Verifier special pool on `vmstorfl.sys`) a page-fault access violation exactly at the buffer tail.

**Notes:** Distinguish the vulnerable path from the safe memmove path by watching `test al,al` at `0x1c0003530`: `al != 0` -> memset/conversion path (vulnerable); `al == 0` -> memmove path (bounded to `<= 0x14`). The arg mapping is set by the caller `sub_1c00022f0`, which invokes `sub_1c00034a0(arg1, arg3_caller, rdi)` where `rdi = *(arg4+0x18)` is the destination response (`arg3`) and `arg3_caller` is the source SRB (`arg2`).

---

## 6. Exploit Primitive & Development Notes
- **Primitive:** Out-of-bounds zero-write (followed by a handful of fixed-offset sense-byte writes at `[rsi]`, `[rsi+2]`, `[rsi+7]`, `[rsi+0xc]`, `[rsi+0xd]`) of up to ~255 bytes past the `SenseInfoBuffer` allocation in host non-paged pool. The attacker controls the length (0x12–0xFF) and, via SRB layout confusion, influences the destination pointer.
- **Turning it into a full exploit:**
  1. Groom the host non-paged pool so an attacker-chosen victim object is adjacent to the `SenseInfoBuffer` allocation; issue many synthetic SCSI completions to place buffers deterministically.
  2. Corrupt a victim object's leading fields with zeros (e.g. a pointer, `LIST_ENTRY`, refcount, or type/flags field) — a zero-write is a "nulling" primitive, most powerful against fields where zero is dangerous (refcount, size, discriminator).
  3. If layout confusion via the extended `STORAGE_REQUEST_BLOCK` lets the destination pointer itself be steered, escalate from relative OOB toward a more targeted write of the follow-on sense bytes (which include constants like `0xa` and register values).
  4. Convert the corrupted object into a control-flow or data-only hijack (freed pointer, function pointer table, or object header) to achieve guest-to-host code execution / VM escape, or a pool-metadata corruption for privilege escalation.
- **Mitigations to consider:**
  - **kASLR:** Applies to host kernel; the primitive itself needs no address knowledge (relative pool write). A separate info leak is required to defeat KASLR for a code-execution path.
  - **SMEP / SMAP:** Irrelevant to a pool-only data corruption; matters only if pivoting to a ROP/user-mapping stage.
  - **CFG / CET:** Prefer a data-only target (object fields, tokens) to avoid indirect-call guards; the zero-write favors nulling security-relevant fields.
  - **HVCI / VBS:** Code-injection is blocked; a data-only variant (corrupting a victim object to escalate) survives HVCI.
  - **Pool hardening:** Modern pool integrity checks may catch header corruption; aim the OOB write at adjacent *object* fields rather than pool headers to avoid immediate detection.
- **Realistic outcome:** Reliable guest-to-host DoS (host bugcheck) with certainty; guest-to-host privilege escalation / VM escape is plausible with heap grooming and a separate info leak.

---

## 7. Debugger PoC Playbook
Assume WinDbg/KD attached to the host running the UNPATCHED `vmstorfl.sys`.

### 7.1 sub_1C00034A0 (unpatched @ 0x1c00034a0)

**Breakpoints:**
```text
bp vmstorfl+0x34a0    ; entry: rdx=arg2 (source SRB), r8=arg3 (dest response)
bp vmstorfl+0x357e    ; memset sink: rcx=dest, r8b=count (the OOB length)
bp vmstorfl+0x3681    ; memmove path: confirm which branch executed
```
Rebase note: the addresses above are RVAs derived from the analysis base `0x1c0000000` (entry `0x1c00034a0` -> `+0x34a0`, sink `0x1c000357e` -> `+0x357e`, memmove `0x1c0003681` -> `+0x3681`). If the loaded module base differs, subtract the analysis base `0x1c0000000` from each analysis address to recover the RVA.

**Inspect at each breakpoint:**
- **At +0x34a0 (entry):** `rdx` = arg2 (source SRB/sense), `r8` = arg3 (destination). Read the gating fields.
```text
db rdx+0xf L1      ; must be 0x02 (sense present)
db rdx+0x15 L1     ; source SenseInfoBufferLength, must be <= 0x14
db r8+0xb L1       ; attacker DEST length used by memset
dq r8+0x20 L1      ; destination SenseInfoBuffer pointer
db rdx+0x1c L1     ; sense response code; low 7 bits must be 0x72/0x73
```
- **At +0x357e (memset sink):** `rcx` = dest = `*(arg3+0x20)`, `r8b` = count = `*(arg3+0xb)`. The smoking gun is `r8b` (0x12–0xFF) exceeding the true pool allocation size of `rcx`.
```text
r r8              ; count
!pool @rcx        ; check allocation size backing the destination
```

**Trigger setup (from user mode / guest):**
1. Inside the guest, obtain access to the synthetic SCSI/StorVSC device (a handle to the virtual disk/controller).
2. Issue a SCSI command whose completion carries descriptor-format sense data:
```text
sense response code  (arg2+0x1c & 0x7f) = 0x72 or 0x73
dest sense length    (arg3+0xb)         = 0x40..0xFF   (>= 0x12, oversized)
backing SenseInfoBuffer                 = undersized (e.g. 0x12 bytes)
source SenseInfoBufferLength (arg2+0x15) <= 0x14
arg3+0x10 >= arg2+0x18 (DataTransferLength clamp)
arg2+0xf = 0x02
```
3. Deliver via the guest StorVSC miniport -> VMBus channel; the host dispatches `sub_1c0003d58 -> sub_1c00022f0 (opcode==1) -> sub_1c00034a0`. Repeat to groom pool if pursuing more than DoS.

**Expected observation:** At `+0x357e`, `r8` (count) exceeds the `!pool` allocation size of `rcx`. On continue, a zero-write runs past the buffer -> bugcheck (`BAD_POOL_HEADER`, `KERNEL_MODE_HEAP_CORRUPTION`, or a special-pool AV at the buffer tail with Driver Verifier enabled on `vmstorfl.sys`).

**Struct / offset notes:**
```text
arg2 (source SRB / sense struct):
  +0x0e  byte    copied to *(arg3+3)
  +0x0f  byte    == 2 selects sense path
  +0x15  byte    SenseInfoBufferLength (guarded <= 0x14 — NOT the memset length)
  +0x18  dword   DataTransferLength (clamp value)
  +0x1c  bytes   source sense buffer; &0x7f => response code (0x72/0x73 descriptor)

arg3 (destination response struct):
  +0x02  byte    == 0x28 marks extended STORAGE_REQUEST_BLOCK (patched checks this)
  +0x0b  byte    DEST sense length -> memset count (attacker, 0x12..0xFF)
  +0x10  dword   compared vs arg2+0x18 (legacy DataTransferLength)
  +0x20  qword   destination SenseInfoBuffer pointer
  +0x3c  dword   extended DataTransferLength (patched path)

helpers: sub_1c0004ac0 = memset(dest, fill, count); sub_1c0004780 = memmove(dest, src, len)
branch @ 0x1c0003530 test al,al: al!=0 -> vulnerable memset path; al==0 -> memmove path
```

---

## 8. Changed Functions — Full Triage
- **sub_1C00034A0 -> sub_1C000363C** (similarity 0.4221, security_relevant): The vulnerable sense-translation routine. Unpatched performs `memset(*(arg3+0x20), 0, *(arg3+0xb))` with only a `>= 0x12` lower-bound check and no SRB-layout discrimination. Patched adds `*(arg3+2)==0x28` extended-SRB detection, length selection (`+0x3c` vs `+0x10`), and a bounds-checked descriptor walk (`offset>=0x80 && offset<DataTransferLength`, `offset+0x28<=len`, `offset+0x38<=len`) before dereferencing, routing the copy through the validated pointer.
- **sub_1C0004AC0 -> sub_1C0005300** (similarity 0.599, behavioral): The inlined `memset(dest, fill, count)` primitive, re-implemented with SSE zero-fill loops. It is the exact corruption *sink* — it performs the out-of-bounds zero-write when handed the unvalidated length — but is not vulnerable in isolation.
- **sub_1C0004780 -> sub_1C0005040** (similarity 0.2828, behavioral): The inlined `memmove`/`memcpy` primitive, fully re-implemented with new SSE unrolling and small-size fast paths. Sink for the (bounded) sense-copy path; the patched version is the routine the fixed code re-routes copies through.
- **sub_1C00022F0 -> sub_1C00022C0** (similarity 0.9826, behavioral): The VMBus SCSI completion/response handler; calls `VmbChannelGetPointer`, fetches the request from `*(arg4+0x18)`, and dispatches `sub_1C00034A0` when `arg2==1`. Establishes that arg2/arg3 of the vulnerable function are guest-controlled SRB structures. Substantively unchanged.
- **sub_1C0003D58 -> sub_1C00041BC** (similarity 0.9124, behavioral): The VMBus storage packet dispatcher that routes packets to the completion handler `sub_1C00022F0`. Upstream reachability node; not itself a fix.
- **sub_1C000333C (FxStubBindClasses)** (similarity 0.1362, behavioral): WDF class-bind loop stub; adds NULL / `*i != 0x50` guards, `DbgPrintEx` diagnostics, and a `0xc000007b` return on malformed class info. Internal WDF loader hardening with no external attack surface.

*Collapsed note on non-security changes:* The remaining changed functions are the re-optimized copy/fill primitives (sinks), the unchanged caller/dispatch chain, and an unrelated WDF loader stub — the only meaningful security diff is `sub_1C00034A0 -> sub_1C000363C`.

---

## 9. Unmatched Functions
- **Removed (unpatched only):** None
- **Added (patched only):** None
- **Implication:** The patch is entirely additive within the existing `sub_1C00034A0` body — no new sanitizer function was introduced as a separate symbol and none removed. The fix (SRB-type discrimination plus the bounds-checked descriptor walk) was inlined into the rewritten `sub_1C000363C`, and the copy helpers were re-optimized in place. There is no feature-flag or KIR gating evident; the hardening is unconditional in the patched routine.

---

## 10. Confidence & Caveats
- **Confidence:** high
- **Rationale:**
  - The unpatched arithmetic is unambiguous: `memset(*(arg3+0x20), 0, *(arg3+0xb))` with only a lower-bound `cmp dl,0x12; jb` and an upper-bound fastfail (`cmp bpl,0x14`) demonstrably applied to a *different* field (`*(arg2+0x15)`).
  - The patch idiom is textbook: add layout discrimination (`*(arg3+2)==0x28`) plus explicit `offset < DataTransferLength` / `offset+0x28 <= len` / `offset+0x38 <= len` bounds before dereferencing — precisely closing the missing upper bound.
  - The caller chain (`sub_1C0003D58 -> sub_1C00022F0` at opcode 1) cleanly establishes that arg2/arg3 originate from guest SRB data over VMBus.
- **Assumptions made:**
  - The exact SRB field-to-offset mapping (`+0xb` = dest sense length, `+0x20` = dest buffer pointer, `+0x15` = source sense length) is inferred from the disassembly and the standard SRB/STORAGE_REQUEST_BLOCK layouts; field names are approximate.
  - The destination `SenseInfoBuffer` resides in host non-paged pool; the precise pool type/tag was not confirmed from the diff.
  - Full guest controllability of `*(arg3+0xb)` and `*(arg3+0x20)` in the completion path (vs values overwritten by host code before reaching the routine) is assumed based on the caller passing the guest SRB through.
- **To verify before a PoC:**
  1. Confirm the actual pool allocation backing `*(arg3+0x20)` and its size at the `0x1c000357e` memset call (via `!pool` / Driver Verifier special pool on `vmstorfl.sys`).
  2. Verify the exact guest-side StorVSC/VMBus message fields that map to `*(arg2+0xf)`, `*(arg2+0x15)`, `*(arg2+0x1c)`, `*(arg3+0xb)`, and `*(arg3+0x20)`, and that they survive unmodified to the sense-translation routine.
  3. Reproduce the bugcheck on the unpatched build with an oversized `*(arg3+0xb)` and confirm the fault address lands at the tail of the sense allocation.
