Title: dumpfve.sys — No security-relevant change (WIL feature-staging framework adds a variant-override value)
Date: 2026-06-28
Slug: dumpfve_a71680ba-dumpfve-report-20260628-225907
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Informational
KBDate: 2026-03-10

## 1. Overview

- **Unpatched binary:** `dumpfve_unpatched.sys`
- **Patched binary:** `dumpfve_patched.sys`
- **Driver:** `dumpfve.sys` — BitLocker Drive Encryption Crashdump Filter (loaded during crash dump stack initialization).
- **Overall similarity score:** **0.9862** (extremely high; patch is tightly scoped).
- **Diff statistics:**
  - Matched: **133**
  - Changed: **3** (framework evolution; see below — not security-relevant)
  - Identical: **130**
  - Unmatched (each direction): **0 / 0**

**One-sentence verdict:** These three functions are the standard Windows Implementation Library (WIL) feature-staging framework (`rbc_InitializeFeatureStaging`, `EvaluateCurrentState`, `EvaluateCurrentStateFromRegistry`, `QueryFeatureOverride`) that reads developer feature-flag overrides from the admin-only `FeatureManagement\Overrides` key; the patch recompiles a newer WIL that adds support for a second, byte-range-clamped variant-override value (registry value name with a `_variant` suffix). The `<= 0xFF` check guards this newly introduced value, which has no counterpart in the unpatched build — it is not remediation of a pre-existing unbounded read. The unpatched reader never stores a raw 32-bit value: it reduces its single override to a `{1,2}` tristate before storing. No attacker-controlled unbounded value exists in the unpatched binary; this is a framework feature addition, not a security fix.

---

## 2. Vulnerability Summary

### Finding #1 — WIL Feature-Staging Variant-Override Value Clamp (Severity: Informational — not a vulnerability)

- **Severity:** Informational (no attacker-controlled unbounded value in either build; the override key is admin/SYSTEM-only by design)
- **Vulnerability class:** None as shipped. The original CWE-20 / CWE-697 framing does not hold: the unpatched build stores only a `{1,2}` tristate, and the patched `<= 0xFF` clamp guards a value that does not exist in the unpatched build.
- **Affected function:** `QueryFeatureOverride (sub_1C0008BF0)` (registry reader), reachable via `EvaluateCurrentStateFromRegistry (sub_1C0008B70)` → `EvaluateCurrentState (sub_1C0008B3C)` → `rbc_InitializeFeatureStaging (sub_1C0008CD8)` → `DumpPreInitialize`
- **What the code actually does:**
  The unpatched registry reader calls `RtlQueryRegistryValuesEx` against
  `\Registry\MACHINE\System\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides`,
  retrieving a `REG_DWORD` whose **name** is the decimal string of a (deobfuscated) feature ID compiled into the driver. This is the standard WIL feature-staging override lookup. The raw 32-bit value (`var_C0` at `[rbp-0x69]`) is immediately reduced to either `1` (if the value was zero) or `2` (if non-zero) — i.e., an on/off tristate — and only that `{1,2}` value is written to `*arg2` via `mov dword [rbx], ecx` at `0x1c0008ca6`. The raw DWORD is never stored, so there is nothing to range-check; a `cmp eax, 0xff` on the primary value would be meaningless because the value is already clamped to `{1,2}`.
  The caller (`EvaluateCurrentStateFromRegistry (sub_1C0008B70)`) commits this `{1,2}` state atomically via `lock cmpxchg dword [rsi], ecx` at `0x1c0008bc9` into WIL's cached feature-enabled-state field (the standard WIL caching pattern).
  The patch (newer WIL revision):
  - Adds a **second** registry query, using the same `FeatureManagement\Overrides` key and a single `RtlQueryRegistryValuesEx` call, for a variant-override value whose value name has a `_variant` suffix appended (`RtlCopyUnicodeString` + `RtlAppendUnicodeToString`). This query and its output parameter **do not exist in the unpatched build**.
  - Adds an `if (v13 <= 0xFF)` clamp (`cmp eax, 0xff; ja skip` at `0x1c0008da5`) before accepting that new variant-override value, because it is stored as a byte. This is validation built into a new value, not a fix for a previously-unbounded read.
  - Initializes the secondary output to `0x80000000` (sentinel = "not queried") and only overwrites it with the registry value if the clamp passes; stores it via `mov dword [r14], eax` at `0x1c0008dac`, then `mov byte [rdi], al` (byte-width) and `movzx ecx, byte [rsp+0x40]`.

- **Entry point:** `DumpPreInitialize` (exported, `0x1c0008b10`) — invoked by the kernel when the crash dump stack is initialized (BSOD, manual crash, or hibernation path). It reaches this WIL feature-staging init only for the driver's own compiled-in feature flags.

- **Call chain (WIL feature-staging init):**
  1. `DumpPreInitialize` (`0x1c0008b10`) — driver entry called by kernel.
  2. `rbc_InitializeFeatureStaging (sub_1C0008CD8)` (`0x1c0008cd8`) — iterates the compiled-in feature table at `reg_FeatureDescriptors_z`.
  3. `EvaluateCurrentState (sub_1C0008B3C)` (`0x1c0008b3c`, unpatched) — dispatcher; checks if feature state is already initialized (state==0 ⇒ query needed).
  4. `EvaluateCurrentStateFromRegistry (sub_1C0008B70)` (`0x1c0008b70`, unpatched) — middle layer; **deobfuscates** the feature ID via XOR/bswap/ROR chain (`0x1c0008b94`–`0x1c0008ba5`), then calls the reader.
  5. `QueryFeatureOverride (sub_1C0008BF0)` (`0x1c0008bf0`, unpatched) — registry reader; performs `RtlQueryRegistryValuesEx` against `FeatureManagement\Overrides` with value name = decimal string of deobfuscated ID; reduces the returned DWORD to a `{1,2}` tristate and propagates that (the raw DWORD is not stored, so no range check applies).

---

## 3. Pseudocode Diff

### `QueryFeatureOverride (sub_1C0008BF0)` (unpatched reader) vs `QueryFeatureOverride (sub_1C0008C34)` (patched reader)

```c
// ================= UNPATCHED: QueryFeatureOverride (sub_1c0008bf0) =================
int64_t QueryFeatureOverride (sub_1c0008bf0)(uint32_t arg1, int32_t* arg2)
{
    // ... build RTL_QUERY_REGISTRY_TABLE with ONE entry ...
    // Entry[0].Name            = String.Buffer   // decimal feature ID
    // Entry[0].Flags           = 0x124           // REQUIRED | DIRECT (type-checked)
    // Entry[0].DefaultType     = 0x4000000
    // Entry[0].EntryContext    = &var_C0

    rax_3 = RtlQueryRegistryValuesEx(
        0,
        "\\Registry\\MACHINE\\System\\CurrentControlSet\\Policies"
        "\\Microsoft\\FeatureManagement\\Overrides",
        &var_a8,            // query table
        0, 0);

    if (rax_3 < 0) {
        *arg2 = 0;          // failure path: nothing to validate
        return 0;
    }

    // SUCCESS PATH: raw DWORD collapsed to on/off tristate; raw value not stored.
    *arg2 = (var_C0 == 0) ? 1 : 2;     // stores {1,2} only; nothing to range-check
    return 1;
}

// ================= PATCHED: QueryFeatureOverride (sub_1c0008c34) =================
int64_t QueryFeatureOverride (sub_1c0008c34)(uint32_t arg1,
                      int32_t  arg2,   // NEW: variant-query flag
                      int32_t* arg3,   // primary out
                      int32_t* arg4)   // NEW: secondary out (byte-sized, bounded)
{
    // ... expanded query table (0xa8 bytes, two entries) ...
    // Entry[0]: primary feature (same as before)
    // Entry[1]: variant, value name = "<id>_variant" (suffix appended)

    *arg4 = 0x80000000;                  // sentinel: "not yet validated"
    status = RtlQueryRegistryValuesEx(...);

    if (status >= 0) {
        *arg3 = (var_160 == 0) ? 1 : 2;

        if (arg2) {                      // only if caller wants the variant value
            int32_t v = var_15C;         // second registry DWORD
            if (v <= 0xff)               // *** ADDED BOUNDS CHECK ***
                *arg4 = v;               // store only if within byte range
            // else: leave *arg4 at the 0x80000000 sentinel
        }
        return 1;
    }
    return 0;
}
```

### `EvaluateCurrentStateFromRegistry (sub_1C0008B70)` (middle layer) — diff highlights

```c
// UNPATCHED: signature (arg1, arg2, int32_t* state)
//   - Calls reader with &arg_8 only.
//   - lock cmpxchg [state], ecx   // commits (1|2) to persistent state.

// PATCHED: signature (arg1, arg2, arg3, char arg4_default, char* arg5_out)
//   - Initializes arg_8 = 0x80000000 (sentinel).
//   - Passes &arg_8 as the FOURTH output parameter (byte-sized).
//   - Only writes *arg5 = arg_8 (as a byte: mov byte [rdi], al)
//     if arg_8 != 0x80000000.
//   - The lock cmpxchg for the primary state was MOVED to the caller
//     (EvaluateFeature (sub_1C0008BBC)), decoupling the atomic commit from the registry read.
```

### `EvaluateCurrentState (sub_1C0008B3C)` → `EvaluateFeature (sub_1C0008BBC)` (dispatcher) — diff highlights

```c
// UNPATCHED dispatcher (44 bytes):
//   if (*primary_state == 0)
//       EvaluateCurrentStateFromRegistry (sub_1C0008B70)(...);    // reader commits state via internal cmpxchg

// PATCHED dispatcher (112 bytes) — adds second atomic state:
//   if (*primary_state == 0 && *secondary_state == 0x80000000) {
//       EvaluateCurrentStateFromRegistry (sub_1C0008B3C)(...);    // reader validates byte, returns via arg
//       lock cmpxchg [primary_state],   ecx        // primary commit
//       ecx = movzx byte [rsp+0x40]                  // *** zero-extend ***
//       lock cmpxchg [secondary_state], ecx         // secondary commit
//                                                     // expected=0x80000000
//   }
```

---

## 4. Assembly Analysis

### `QueryFeatureOverride (sub_1C0008BF0)` — UNPATCHED registry reader (stores {1,2} tristate)

```asm
0x1c0008bf0: mov  qword [rsp+0x18], rbx
0x1c0008bf5: mov  qword [rsp+0x20], rdi
0x1c0008bfa: push rbp
0x1c0008bfb: lea  rbp, [rsp-0x57]
0x1c0008c00: sub  rsp, 0xf0
0x1c0008c07: mov  rax, qword [rel 0x1c0014000]    ; __security_cookie
0x1c0008c0e: xor  rax, rsp
0x1c0008c11: mov  qword [rbp+0x47], rax
0x1c0008c15: xor  edi, edi
0x1c0008c17: mov  dword [rbp-0x61], 0x200000       ; String.MaximumLength
0x1c0008c1e: mov  rbx, rdx                         ; rbx = arg2 (OUT ptr)
0x1c0008c21: mov  dword [rbp-0x69], edi            ; var_C0 = 0
0x1c0008c24: lea  rax, [rbp+0x27]
0x1c0008c28: lea  r8,  [rbp-0x61]
0x1c0008c2c: mov  qword [rbp-0x59], rax            ; String.Buffer
0x1c0008c30: lea  edx, [rdi+0xa]                   ; base 10
0x1c0008c33: call qword [rel 0x1c0016060]          ; RtlIntegerToUnicodeString
0x1c0008c3a: nop  dword [rax+rax]
0x1c0008c3f: xor  edx, edx
0x1c0008c41: lea  r8d, [rdi+0x70]                  ; sizeof table = 0x70
0x1c0008c45: lea  rcx, [rbp-0x49]                  ; &query_table
0x1c0008c49: call 0x1c0009200                      ; memset(table, 0, 0x70)
0x1c0008c4e: mov  rax, qword [rbp-0x59]
0x1c0008c52: lea  r8,  [rbp-0x49]                  ; r8 = query_table
0x1c0008c56: mov  qword [rbp-0x39], rax            ; Entry[0].Name
0x1c0008c5a: lea  rdx, [registry path string]      ; "\Registry\MACHINE\...\FeatureManagement\Overrides"
0x1c0008c61: lea  rax, [rbp-0x69]
0x1c0008c65: mov  dword [rbp-0x41], 0x124          ; Flags
0x1c0008c6c: xor  r9d, r9d
0x1c0008c6f: mov  qword [rbp-0x31], rax            ; Entry[0].EntryContext = &var_C0
0x1c0008c73: xor  ecx, ecx
0x1c0008c75: mov  dword [rbp-0x29], 0x4000000      ; DefaultType
0x1c0008c7c: mov  qword [rbp-0x21], rdi
0x1c0008c80: mov  dword [rbp-0x19], edi
0x1c0008c83: mov  qword [rsp+0x20], rdi
0x1c0008c88: call qword [rel 0x1c0016000]          ; RtlQueryRegistryValuesEx
0x1c0008c8f: nop  dword [rax+rax]
0x1c0008c94: test eax, eax
0x1c0008c96: js   0x1c0008caa                      ; on failure -> error path
; ===== SUCCESS PATH =====
0x1c0008c98: mov  eax, dword [rbp-0x69]            ; eax = raw registry DWORD (immediately collapsed below)
0x1c0008c9b: neg  eax                              ; sets CF if value != 0
0x1c0008c9d: lea  eax, [rdi+0x1]                   ; eax = 1
0x1c0008ca0: sbb  ecx, ecx                         ; ecx = -CF  (0 or -1)
0x1c0008ca2: neg  ecx                              ; ecx = 0 or 1
0x1c0008ca4: add  ecx, eax                         ; ecx = 1 (value==0) or 2 (!=0)
0x1c0008ca6: mov  dword [rbx], ecx                 ; stores {1,2} tristate only; raw DWORD not stored
                                                   ; patch adds cmp 0xff on a DIFFERENT, new value, not here
0x1c0008ca8: jmp  0x1c0008cae
; ===== FAILURE PATH =====
0x1c0008caa: mov  dword [rbx], edi                 ; *arg2 = 0
0x1c0008cac: xor  eax, eax
; ===== EPILOGUE =====
0x1c0008cae: mov  rcx, qword [rbp+0x47]
0x1c0008cb2: xor  rcx, rsp
0x1c0008cb5: call 0x1c00064c0                      ; __security_check_cookie
0x1c0008cba: lea  r11, [rsp+0xf0]
0x1c0008cc2: mov  rbx, qword [r11+0x20]
0x1c0008cc6: mov  rdi, qword [r11+0x28]
0x1c0008cca: mov  rsp, r11
0x1c0008ccd: pop  rbp
0x1c0008cce: retn
```

### `QueryFeatureOverride (sub_1C0008C34)` — PATCHED key addition (the bounds check)

```asm
; After RtlQueryRegistryValuesEx succeeds and second value is queried:
0x1c0008da1: mov  eax, dword [rsp+0x34]   ; eax = second registry DWORD (var_15C)
0x1c0008da5: cmp  eax, 0xff               ; *** ADDED BOUNDS CHECK: <= 0xFF ***
0x1c0008daa: ja   0x1c0008db5             ; skip storage if value > 0xFF
0x1c0008dac: mov  dword [r14], eax        ; *arg4 = validated value
0x1c0008daf: jmp  0x1c0008db5
```

### `EvaluateCurrentStateFromRegistry (sub_1C0008B70)` — UNPATCHED middle layer (deobfuscation + atomic commit)

```asm
0x1c0008b70: mov  rax, rsp
0x1c0008b73: mov  qword [rax+0x10], rbx
0x1c0008b77: mov  qword [rax+0x18], rsi
0x1c0008b7b: push rdi
0x1c0008b7c: sub  rsp, 0x20
0x1c0008b80: xor  edi, edi
0x1c0008b82: mov  rsi, r8                       ; rsi = arg3 (state ptr)
0x1c0008b85: cmp  edx, 0x1
0x1c0008b88: mov  dword [rax+0x8], edi          ; arg_8 = 0
0x1c0008b8b: mov  ebx, edi
0x1c0008b8d: lea  rdx, [rax+0x8]                ; rdx = &arg_8
0x1c0008b91: setne bl                           ; rbx = (arg2 != 1)
0x1c0008b94: xor  ecx, 0x74161a4e               ; feature ID deobfuscation
0x1c0008b9a: bswap ecx
0x1c0008b9c: xor  ecx, 0x8fb23d4f
0x1c0008ba2: ror  ecx, 0xff
0x1c0008ba5: xor  ecx, 0x833ea8ff
0x1c0008bab: call 0x1c0008bf0                   ; reader (UNVALIDATED)
0x1c0008bb0: test eax, eax
0x1c0008bb2: je   0x1c0008bc4
0x1c0008bb4: cmp  dword [rsp+0x30], edi         ; check arg_8
0x1c0008bb8: je   0x1c0008bc4
0x1c0008bba: cmp  dword [rsp+0x30], 0x1
0x1c0008bbf: mov  ebx, edi
0x1c0008bc1: setne bl                           ; rbx = (arg_8 != 1)
0x1c0008bc4: lea  ecx, [rbx+0x1]                ; ecx = rbx + 1  (1 or 2)
0x1c0008bc7: xor  eax, eax                      ; expected = 0
0x1c0008bc9: lock cmpxchg dword [rsi], ecx      ; *** atomic commit ***
0x1c0008bcd: mov  ecx, dword [rsi]
0x1c0008bcf: cmp  ecx, 0x1
0x1c0008bd2: mov  rbx, qword [rsp+0x38]
0x1c0008bd7: mov  rsi, qword [rsp+0x40]
0x1c0008bdc: setne dil
0x1c0008be0: mov  eax, edi
0x1c0008be2: add  rsp, 0x20
0x1c0008be6: pop  rdi
0x1c0008be7: retn
```

### `EvaluateFeature (sub_1C0008BBC)` — PATCHED dispatcher (dual atomic state)

```asm
0x1c0008bbc: mov  qword [rsp+0x10], rbx
0x1c0008bc1: push rdi
0x1c0008bc2: sub  rsp, 0x30
0x1c0008bc6: mov  rbx, qword [rcx]              ; primary state ptr
0x1c0008bc9: mov  rdi, qword [rcx+0x18]         ; secondary state ptr (NEW)
0x1c0008bcd: mov  r11d, dword [rcx+0x8]         ; feature ID
0x1c0008bd1: mov  edx,  dword [rcx+0x10]        ; flag (NEW)
0x1c0008bd4: mov  eax,  dword [rbx]
0x1c0008bd6: mov  r8d,  dword [rcx+0xc]
0x1c0008bda: mov  r9b,  byte  [rcx+0x20]        ; byte default (NEW)
0x1c0008bde: mov  r10d, dword [rdi]             ; *secondary_state
0x1c0008be1: test eax, eax
0x1c0008be3: jne  0x1c0008c21
0x1c0008be5: cmp  r10d, 0x80000000              ; check sentinel (NEW)
0x1c0008bec: jne  0x1c0008c21
0x1c0008bee: lea  rax, [rsp+0x40]
0x1c0008bf3: mov  byte [rsp+0x40], r9b          ; arg_8 = byte default
0x1c0008bf8: mov  ecx, r11d
0x1c0008bfb: mov  qword [rsp+0x20], rax
0x1c0008c00: call 0x1c0008b3c                   ; reader (validates byte)
0x1c0008c05: neg  eax
0x1c0008c07: sbb  ecx, ecx
0x1c0008c09: neg  ecx
0x1c0008c0b: inc  ecx
0x1c0008c0d: xor  eax, eax
0x1c0008c0f: lock cmpxchg dword [rbx], ecx      ; primary commit
0x1c0008c13: movzx ecx, byte [rsp+0x40]         ; *** zero-extend byte *** (NEW)
0x1c0008c18: mov  eax, 0x80000000               ; expected sentinel (NEW)
0x1c0008c1d: lock cmpxchg dword [rdi], ecx      ; secondary commit (NEW)
```

---

## 5. Trigger Conditions

1. **Obtain a privileged handle to the registry.** Open `HKLM\System\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides` with write access. The default ACL on this key grants write only to administrators / SYSTEM.

2. **Identify a target feature ID.** The driver embeds an obfuscated feature table at `reg_FeatureDescriptors_z`. Each entry stores a feature ID at offset `0x08` that is deobfuscated at runtime via:
   ```
   id = XOR(bswap(XOR(id_raw, 0x74161a4e)), 0x8fb23d4f)
   id = ROR(id, 0xff)
   id = XOR(id, 0x833ea8ff)
   ```
   The **registry value name** is the decimal ASCII string of the deobfuscated ID.

3. **Create or modify the override value.** Set a `REG_DWORD` value whose name is the decimal feature ID. Note: on the unpatched driver the primary value is collapsed to a `{1,2}` tristate regardless of magnitude (the raw DWORD is not stored), so a large value does not produce an out-of-range stored value. The `<= 0xFF` clamp on the patched build applies only to the newly introduced second (`_variant`-suffixed) variant-override value, which has no unpatched counterpart.

4. **Force re-initialization of the crash dump stack** so that `DumpPreInitialize` is invoked:
   - Trigger a manual bugcheck (`KeBugCheckEx`), or
   - Use hibernation (which exercises the crash dump stack), or
   - Force driver reload (rare; only on system restart with crash dump configured).

5. **Ordering notes.** The registry query runs only when `*primary_state == 0` (first call). Once the `lock cmpxchg` commits a non-zero state, subsequent invocations short-circuit. This is the standard WIL cached-feature-state pattern.

6. **Observable effect (not an exploit):**
   - In a debugger, the breakpoint at `0x1c0008c98` will show `EAX` holding the raw registry DWORD.
   - At `0x1c0008ca6`, `ECX` is `1` or `2` (the collapsed tristate), never the raw value, and that is what is stored.
   - At `0x1c0008bc9`, the `lock cmpxchg` commits the `{1,2}` value into WIL's cached state.
   - Functional effect: the driver's own feature flag is set on/off according to a developer override placed in an admin-only key — the intended behavior of the WIL feature-staging system, not an attacker primitive.

---

## 6. Exploit Primitive & Development Notes

- **Primitive class:** None. There is no unbounded value and no memory-corruption primitive. The unpatched reader stores only a `{1,2}` tristate; the patched second value is a byte clamped to `<= 0xFF`. This is the WIL feature-staging framework, not an attacker-controllable state.
- **What an admin can do (by design):** Toggle the driver's own feature flag on/off by writing a developer override into the admin/SYSTEM-only `FeatureManagement\Overrides` key. This is the documented purpose of WIL feature staging, available to anyone who already holds the required privilege.
- **Security impact:**
  - None demonstrated. The value stored is a `{1,2}` on/off tristate (or, in the patched build, a clamped byte); an admin can flip the driver's feature flags exactly as the feature-staging system intends.
  - No information disclosure or memory-corruption path follows from the change reviewed here; the earlier speculation to that effect is not supported by the code.
- **Follow-up review notes (to confirm no downstream impact):**
  1. The consumers of the persistent state fields (`*rsi` / `*rbx` / `*rdi` in the dispatcher) read only the cached `{1,2}` primary state and the byte-sized variant state; both are already range-bounded before storage.
  2. The obfuscated feature table at `reg_FeatureDescriptors_z` holds the driver's own compiled-in feature IDs; the override key gates only these driver-owned flags.
- **Relevant constraints:**
  - **Privilege requirement (admin/SYSTEM on HKLM):** The `FeatureManagement\Overrides` key is admin/SYSTEM-writable by default ACL; this is a developer feature-flag mechanism, not an unprivileged input surface.
  - **Patch itself** is purely a value-range check on a newly introduced byte value; it does not remove or relax any check present in the unpatched build.

---

## 7. Debugger PoC Playbook

This section assumes WinDbg/KD attached to the **unpatched** `dumpfve_unpatched.sys`.

### Recommended breakpoints (paste-ready)

```text
bp dumpfve_unpatched!QueryFeatureOverride (sub_1C0008BF0)           ; reader entry; RCX=obfuscated id, RDX=&out
bp dumpfve_unpatched!QueryFeatureOverride (sub_1C0008BF0)+0x88       ; RtlQueryRegistryValuesEx call site (0x1c0008c88)
bp dumpfve_unpatched!QueryFeatureOverride (sub_1C0008BF0)+0x98       ; mov eax,[rbp-0x69]   <-- raw registry DWORD (admin/SYSTEM-writable)
bp dumpfve_unpatched!QueryFeatureOverride (sub_1C0008BF0)+0xa6       ; mov [rbx],ecx  <-- stores {1,2} tristate only
bp dumpfve_unpatched!EvaluateCurrentStateFromRegistry (sub_1C0008B70)+0x3b       ; call reader with DEOBFUSCATED ECX
bp dumpfve_unpatched!EvaluateCurrentStateFromRegistry (sub_1C0008B70)+0x59       ; lock cmpxchg [rsi],ecx  <-- atomic commit
bp dumpfve_unpatched!DumpPreInitialize        ; driver entry from kernel
```

### What to inspect at each breakpoint

| Address | Inspect | Why |
|---|---|---|
| `0x1c0008bf0` | `rcx` (obfuscated ID), `rdx` (out ptr) | Catch every feature query; log which feature is being read. |
| `0x1c0008c88` | `r8` → `RTL_QUERY_REGISTRY_TABLE`; `r8+0x00` = `Name` ptr; `r8+0x18` = `EntryContext` (= `&var_C0`) | Verify which registry value name is being requested and where the DWORD will land. |
| `0x1c0008c98` | `eax` (raw registry DWORD), `[rbp-0x69]` (var_C0) | See the registry DWORD (admin/SYSTEM-writable) before it is collapsed to `{1,2}`. |
| `0x1c0008ca6` | `ecx` (1 or 2), `rbx` (`*arg2` target) | Confirm the stored value is the {1,2} tristate, not the raw DWORD. |
| `0x1c0008bab` | `ecx` (deobfuscated feature ID) | Recover the plaintext feature ID for cross-referencing with the registry value you set. |
| `0x1c0008bc9` | `rsi` (persistent state ptr), `ecx` (new value), `eax` (expected=0) | Confirm atomic commit; persisting the bad state. |

### Key instruction offsets

- `0x1c0008c88` — `call qword [rel 0x1c0016000]` (`RtlQueryRegistryValuesEx`)
- `0x1c0008c98` — `mov eax, dword [rbp-0x69]` — reads raw registry DWORD (admin/SYSTEM-writable value)
- `0x1c0008ca6` — `mov dword [rbx], ecx` — stores the {1,2} tristate (raw DWORD not stored)
- `0x1c0008bc9` — `lock cmpxchg dword [rsi], ecx` — commits to persistent state
- `0x1c0008b94`–`0x1c0008ba5` — feature ID deobfuscation chain (XOR `0x74161a4e` → `bswap` → XOR `0x8fb23d4f` → `ROR 0xff` → XOR `0x833ea8ff`)
- Patched-only: `0x1c0008da5` — `cmp eax, 0xff` (the added bounds check)
- Registry path string: `\Registry\MACHINE\System\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides` (passed as the second argument to `RtlQueryRegistryValuesEx`)
- Feature table: `reg_FeatureDescriptors_z` (start of the table iterated by `rbc_InitializeFeatureStaging (sub_1C0008CD8)`)

### Trigger setup (user-mode prep, then force kernel path)

1. From an elevated PowerShell session, decode a feature ID by setting a breakpoint at `0x1c0008b94` and stepping through the deobfuscation chain. Record the decimal plaintext.
2. Set the override value:
   ```powershell
   $key = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides"
   New-Item -Path $key -Force | Out-Null
   Set-ItemProperty -Path $key -Name "<decrypted-feature-id>" -Value 0x100 -Type DWord
   ```
   Any non-zero value sets the primary state to `2`; the magnitude is not retained (the primary override is collapsed to `{1,2}` in both builds).
3. Force the crash dump stack to initialize. Options:
   - Trigger a manual bugcheck (test-signing `KeBugCheck` driver, or `NotMyFault`).
   - Initiate hibernation (`shutdown /h`) — exercises the dump stack.
   - Reboot and let the crash dump filter re-init.
4. At the breakpoint inside `DumpPreInitialize`, allow the iterator to reach the matching feature entry. The success path will hit `0x1c0008c98` → `0x1c0008ca6` → `0x1c0008bc9`.

### Expected runtime observation

- At `0x1c0008c98`: `EAX` = the raw DWORD you wrote (e.g., `0x00000100`).
- At `0x1c0008ca6`: `ECX` = `2` (any non-zero input collapses to `2`), `RBX` = caller stack slot; the dword is stored.
- At `0x1c0008bc9`: `lock cmpxchg` succeeds; `[rsi]` now contains `2` persistently.
- Functional effect: the driver's own feature flag for that ID is set on/off. The stored value is the `{1,2}` tristate regardless of the magnitude written; no unbounded value reaches downstream consumers, so there is no memory-safety consequence to observe.

### Struct / table notes

- **RTL_QUERY_REGISTRY_TABLE entry layout (used here):**
  - `+0x00` `Name` (`PWSTR`) — points at the decimal-string buffer (`String.Buffer`).
  - `+0x08` `Flags` (`ULONG`) — set to `0x124` (REQUIRED | DIRECT with type check).
  - `+0x10` `DefaultType` (`ULONG`) — `0x4000000`.
  - `+0x18` `EntryContext` (`PVOID`) — `&var_C0` (the DWORD destination).
  - `+0x20` `DefaultData` (`PVOID`) — NULL.
  - `+0x28` `DefaultLength` (`ULONG`) — 0.
- **Compiled feature table at `reg_FeatureDescriptors_z`** (consumed by `rbc_InitializeFeatureStaging (sub_1C0008CD8)`):
  - `+0x00` `state_ptr` (primary) — pointer to a `LONG` initialized to 0.
  - `+0x08` `feature_id` (obfuscated) — passed through the XOR/bswap/ROR chain.
  - `+0x0C` `arg2` flag (passed to middle layer).
  - `+0x10` patched-only `flag`.
  - `+0x18` patched-only `secondary_state_ptr` (initialized to `0x80000000`).
  - `+0x20` patched-only `byte_default`.

---

## 8. Changed Functions — Full Triage

### `QueryFeatureOverride (sub_1C0008BF0)` → `QueryFeatureOverride (sub_1C0008C34)` (registry reader)
- **Similarity:** 0.3538
- **Change type:** framework evolution (not security-relevant)
- **Notes:** Signature expanded from `(arg1, *arg2)` to `(arg1, arg2, *arg3, *arg4)`; the query table grows from a one-entry (0x70-byte) table to a two-entry (0xa8-byte) table (single `RtlQueryRegistryValuesEx` call, same `FeatureManagement\Overrides` key); the second entry queries a WIL variant-override value whose value name has `_variant` appended via `RtlCopyUnicodeString`+`RtlAppendUnicodeToString`. Adds `cmp eax, 0xff; ja skip` (`0x1c0008da5`) before storing this **new** byte value into `*arg4`, pre-initialized to `0x80000000`. The clamp validates a value that does not exist in the unpatched build; it is not a fix for a previously-unbounded read. The primary override remains a `{1,2}` tristate in both builds.

### `EvaluateCurrentStateFromRegistry (sub_1C0008B70)` → `EvaluateCurrentStateFromRegistry (sub_1C0008B3C)` (middle layer)
- **Similarity:** 0.7063
- **Change type:** framework evolution (not security-relevant)
- **Notes:** Signature expanded from `(arg1, arg2, *state)` to `(arg1, arg2, arg3, char arg4_default, char* arg5_out)` to thread the new variant byte through. Initializes `arg_8 = 0x80000000` (sentinel) and passes its address as the new fourth output to the reader. Writes `*arg5 = arg_8` (as a **byte**: `mov byte [rdi], al` at `0x1c0008ba7`) only when `arg_8 != 0x80000000`. The `lock cmpxchg` for the primary state has been moved to the caller (the dispatcher). These are refactors of the WIL caching flow, not a security change.

### `EvaluateCurrentState (sub_1C0008B3C)` → `EvaluateFeature (sub_1C0008BBC)` (dispatcher)
- **Similarity:** 0.1085
- **Change type:** framework evolution (not security-relevant)
- **Notes:** Restructured to cache a second WIL feature-state field. Reads new fields from the feature-table entry: `arg1[3]` (`+0x18`, secondary state pointer) and `arg1[4]` (`+0x20`, byte default). Adds the guard `if (!result && *rdi == 0x80000000)` so the secondary state is queried only when both the primary state is unset AND the secondary state is still at sentinel. Performs **two** atomic updates: `lock cmpxchg [primary], ecx` (value 1 or 2) and `lock cmpxchg [secondary], ecx` with `ecx = movzx byte [rsp+0x40]` and expected = `0x80000000`. The `movzx` zero-extends the validated low byte. This is the standard WIL cached-state commit extended to a second field, not a security fix.

### Cosmetic / register-allocation deltas
Minor epilogue reorderings and stack-slot renumbering accompany the signature expansion; none of these are independently exploitable. The `__security_check_cookie` prologue/epilogue is preserved on both sides.

---

## 9. Unmatched Functions

- **Removed from unpatched:** none.
- **Added in patched:** none.

There is no added sanitizer function and no removed mitigation. The change is confined to the three WIL feature-staging functions and reflects a newer WIL revision that supports a variant-override value; no defensive check was removed and none was added to a pre-existing attacker-reachable path.

---

## 10. Confidence & Caveats

- **Confidence:** **High** that the `cmp eax, 0xff; ja` insertion is real and unambiguous in the patched disassembly. **High** that it does **not** constitute a security fix: these are the WIL feature-staging framework functions, and the clamp guards a newly introduced variant-override value that has no counterpart in the unpatched build.
- **Assessment of security impact:** None as shipped. The raw DWORD read in the unpatched reader is reduced to a `{1,2}` on/off tristate before being cached, so there is no unbounded value to exploit and nothing for a `<= 0xFF` check to fix on the primary path. The patched *secondary* path (the byte-valued variant override) is the only place the clamp applies, and that path does **not exist** in the unpatched binary — so it cannot represent a fixed unpatched vulnerability. The `FeatureManagement\Overrides` key is admin/SYSTEM-writable by design (a developer feature-flag mechanism), not an attacker-controlled input surface.
- **Assumptions:**
  - The call chain `DumpPreInitialize → rbc_InitializeFeatureStaging (sub_1C0008CD8) → EvaluateCurrentState (sub_1C0008B3C) → EvaluateCurrentStateFromRegistry (sub_1C0008B70) → QueryFeatureOverride (sub_1C0008BF0)` is confirmed against the disassembly of both builds (`DumpPreInitialize` calls `rbc_InitializeFeatureStaging`, which iterates `reg_FeatureDescriptors_z` calling the dispatcher, which reaches the middle layer and reader).
  - The feature ID deobfuscation sequence (`XOR 0x74161a4e / bswap / XOR 0x8fb23d4f / ROR 0xff / XOR 0x833ea8ff`) is confirmed in the disassembly and decompilation of `EvaluateCurrentStateFromRegistry` in both builds.
  - Privilege model assumes default HKLM ACLs (admin/SYSTEM write on the `FeatureManagement\Overrides` key).
- **To verify before PoC:**
  - Walk the feature table at `reg_FeatureDescriptors_z` to enumerate every obfuscated ID and its corresponding consumer; some IDs may have more interesting downstream effects than others.
  - Confirm which downstream functions read the persistent state via `movzx ecx, byte [...]` (byte-width) vs `mov ecx, dword [...]` (full dword) to determine whether the primary boolean can transitively corrupt anything beyond the 0/1/2 tristate.
  - Identify whether any of the consumers handle the secondary (byte-sized) state in the patched binary in a way that could become memory-corrupting if the value were out of range — this would elevate the patched path's check from defensive hardening to direct exploit mitigation.
  - Test trigger paths (manual bugcheck vs hibernation vs reboot) to confirm which actually exercises the `state==0` first-call path.
