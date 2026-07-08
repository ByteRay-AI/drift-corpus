Title: cmimcext.sys — Out-of-bounds pool read via miscalculated ETW descriptor size (CWE-125) in CmCompleteInitMachineConfig fixed
Date: 2026-06-28
Slug: cmimcext_bc467f64-cmimcext-report-20260628-215521
Category: Corpus
Author: Argus
Summary: KB5082123

---

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `cmimcext_unpatched.sys` |
| Patched binary | `cmimcext_patched.sys` |
| Overall similarity | 0.9795 |
| Matched functions | 40 |
| Changed functions | 1 |
| Identical functions | 39 |
| Unmatched (either direction) | 0 |

**Verdict:** A single security-relevant change in `CmCompleteInitMachineConfig` corrects a units confusion (`UNICODE_STRING.Length` is in bytes but the ETW logger treats its length arguments as character counts and doubles them), causing `EtwWriteTransfer` to describe up to 2× the valid byte length of each name buffer when logging machine configuration entries. The corrective code (a conditional halving of the lengths) is present in the patched build but gated behind the servicing feature flag `Feature_Servicing_IMCMemoryCorruptionFix_61262757`; the original, unhalved path is retained for when the feature is not enabled. Real-world impact is limited: the two entry points are boot-time initialization exports, the input is the admin/setup-controlled `\REGISTRY\MACHINE\INITIALMACHINECONFIG` hive, and the over-read bytes surface only in an ETW trace that requires administrator rights to consume. Severity is therefore **Low**.

---

## 2. Vulnerability Summary

### Finding #1 — Out-of-Bounds Pool Read via Doubled ETW Descriptor Size

- **Severity:** Low (CWE-125 out-of-bounds read / kernel information disclosure; boot-time init path, admin/setup-controlled input, admin-only ETW consumer)
- **CWE:** CWE-125 (Out-of-bounds Read)
- **Vulnerability class:** Out-of-bounds read / kernel pool overread / information disclosure
- **Affected function:** `CmCompleteInitMachineConfig @ 0x1c0007030` (unpatched)
- **Sink:** `McTemplateK0hzr0hzr2 @ 0x1c00012a0` → `McGenEventWrite @ 0x1c000111c` → `EtwWriteTransfer`

**Root cause.** The linked list rooted at `CmpImcAllowEventQueueHead` is populated by `CmSetInitMachineConfig` via `ImpApplyMachineConfiguration @ 0x1c0007428` / `ImpAddAllowListEvent @ 0x1c00098a8`. Each 0x38-byte node holds two `UNICODE_STRING` structures: key-name at `+0x18` (Length, MaximumLength at `+0x1a`, buffer at `+0x20`) and value-name at `+0x28` (Length, MaximumLength at `+0x2a`, buffer at `+0x30`). Each buffer is allocated with `ExAllocatePoolWithTag(PagedPool, MaximumLength, 'IMCP')` to `UNICODE_STRING.MaximumLength` bytes (the `NumberOfBytes` argument is read from `[r14+2]` / `[rsi+2]`, the `MaximumLength` field), and `RtlCopyUnicodeString` writes `Length` valid bytes into it.

When `CmCompleteInitMachineConfig` logs each node through ETW, it passes `node+0x18` and `node+0x28` directly to `McTemplateK0hzr0hzr2 @ 0x1c00012a0`. The logging function treats those arguments as **character counts** and unconditionally doubles them (`add eax, eax` at `0x1c00012e8` and `0x1c0001309`) to compute `EVENT_DATA_DESCRIPTOR.Size`. Because the values are already in bytes, the resulting `Size` is **2× the valid byte length**. `EtwWriteTransfer` then reads that many bytes from each PagedPool buffer. When `2*Length` exceeds the buffer's `MaximumLength` allocation (the common case, since registry-derived names typically have `MaximumLength ≈ Length`), the read runs past the end of the allocation by up to `Length` bytes.

**The patch** inserts a call to `EvaluateCurrentState @ 0x1c000166c` at the top of the loop body. That helper is a feature-staging gate: it calls `EvaluateFeature` on the servicing feature `Feature_Servicing_IMCMemoryCorruptionFix_61262757` and returns non-zero when the fix is enabled. When it returns non-zero, the code halves the byte lengths (`shr cx,1` / `shr r9w,1`) *before* calling `McTemplateK0hzr0hzr2`. The internal doubling in the ETW template then re-produces the correct byte counts. The doubling behavior is unchanged in `McTemplateK0hzr0hzr2` itself — only the caller's pre-scaling changes, and only when the feature is enabled. When the feature is not enabled, `EvaluateCurrentState` returns 0 and the original unhalved (over-reading) path is taken. This is a staged servicing rollout, not an unconditional fix.

**Entry point and data flow:**

1. `CmSetInitMachineConfig` (exported, `0x1c0009010`) enumerates registry keys under `\REGISTRY\MACHINE\INITIALMACHINECONFIG` and populates the `data_1c00030b0` list via `ImpApplyMachineConfiguration (sub_1c0007428)` / `ImpAddAllowListEvent (sub_1c00098a8)`.
2. `ImpAddAllowListEvent (sub_1c00098a8)` allocates a 0x38-byte node (`PagedPool`, tag `'IMCP'`), copies the key/value `UNICODE_STRING` structures into `+0x18` / `+0x28`, and copies each buffer into freshly allocated pool of `MaximumLength` bytes (`RtlCopyUnicodeString` fills `Length` valid bytes).
3. `CmCompleteInitMachineConfig` (exported, `0x1c0007030`) walks the list and, for each non-flagged node with the appropriate ETW mask bits set in `data_1c0003128`, passes the raw byte-lengths at `+0x18` / `+0x28` and the buffer pointers at `+0x20` / `+0x30` into `McTemplateK0hzr0hzr2 (sub_1c00012a0)`.
4. `McTemplateK0hzr0hzr2 (sub_1c00012a0)` (`0x1c00012a0`) computes `cbSize = arg4 * 2` and `cbSize = arg_30 * 2`, populates two `EVENT_DATA_DESCRIPTOR`s, and calls `McGenEventWrite (sub_1c000111c)`.
5. `McGenEventWrite (sub_1c000111c)` invokes `EtwWriteTransfer`, which reads `2*Length` bytes from each PagedPool buffer — running up to `Length` bytes past the `MaximumLength` allocation whenever `2*Length > MaximumLength`.

---

## 3. Pseudocode Diff

```c
// ============================================================
// UNPATCHED — CmCompleteInitMachineConfig (loop body excerpt)
// ============================================================
for (node *i = list_head; i != &list_head; i = i->Flink) {
    if (i->flag == 0) {
        if (data_1c0003128 & 0x1) {
            template = &data_1c0002240;
            goto log;
        }
    } else if (data_1c0003128 & 0x2) {
        template = &data_1c0002210;
log:
        // ❌ VULN: passes raw UNICODE_STRING.Length (BYTES) directly.
        //          McTemplateK0hzr0hzr2 (sub_1c00012a0) will treat these as char counts and
        //          double them, producing cbSize = 2 * Length.
        McTemplateK0hzr0hzr2 (sub_1c00012a0)(
            /* rcx */ session_handle,
            /* rdx */ template,
            /* r8  */ reg_handle,
            /* r9  */ i->key_name.Length,         // bytes, NOT halved
            /* stk */ i->key_name.Buffer,
            /* stk */ i->value_name.Length);       // bytes, NOT halved
    }
}

// ============================================================
// PATCHED — same loop body, with feature-gate check + halving
// ============================================================
for (node *i = list_head; i != &list_head; i = i->Flink) {
    if (EvaluateCurrentState (sub_1c000166c)() != 0) {                    // ✅ NEW: feature-staging gate (IMCMemoryCorruptionFix)
        // Safe path: pre-halve so the sink's doubling reproduces the
        // correct byte count.
        uint16_t key_len_chars   = i->key_name.Length   >> 1;  // ✅ NEW
        uint16_t value_len_chars = i->value_name.Length >> 1;  // ✅ NEW

        McTemplateK0hzr0hzr2 (sub_1c00012a0)(..., key_len_chars, ..., value_len_chars);
        continue;
    }
    // Legacy path: byte-lengths passed raw (still vulnerable if reached).
    ...
}

// ============================================================
// SINK (McTemplateK0hzr0hzr2 (sub_1c00012a0)) — UNCHANGED IN BOTH BINARIES
// ============================================================
uint32_t key_cb   = (uint32_t)arg4       * 2;   // ❌ doubles the input
uint32_t value_cb = (uint32_t)arg_30     * 2;   // ❌ doubles the input

EVENT_DATA_DESCRIPTOR desc[2];
desc[0].cbSize = key_cb;     // 2 * byte-length  → overread
desc[1].cbSize = value_cb;   // 2 * byte-length  → overread

McGenEventWrite (sub_1c000111c)(...);          // -> EtwWriteTransfer reads cbSize bytes
```

The diff makes the units bug explicit: `UNICODE_STRING.Length` is documented as a **byte** count, but `McTemplateK0hzr0hzr2 (sub_1c00012a0)` assumes its length arguments are **WideChar** counts and multiplies by 2 to convert to bytes. The unpatched caller passes byte counts; the patched caller conditionally divides by 2 first so the sink's multiply reproduces the original byte count.

---

## 4. Assembly Analysis

### 4.1 Vulnerable call setup (unpatched loop body)

```asm
00000001C0007065  cmp     [rbx+10h], dil                ; node->flag check
00000001C0007069  jz      short loc_1C000707D
00000001C000706B  test    cs:...InitMachineConfigEnableBits, 2
00000001C0007072  jz      short loc_1C00070B2
00000001C0007074  lea     rdx, IMC_ETW_EVENT_IMC_VALUE_SET
00000001C000707B  jmp     short loc_1C000708D
; no EvaluateCurrentState call, no shr — lengths passed raw:
00000001C000708D  mov     rax, [rbx+30h]                ; value-name.Buffer
00000001C0007091  movzx   r9d, word ptr [rbx+18h]       ; key-name Length IN BYTES (not halved)
00000001C0007096  mov     [rsp+48h+var_18], rax
00000001C000709B  movzx   eax, word ptr [rbx+28h]       ; value-name Length IN BYTES (not halved)
00000001C000709F  mov     word ptr [rsp+48h+var_20], ax
00000001C00070A4  mov     rax, [rbx+20h]                ; key-name.Buffer
00000001C00070A8  mov     [rsp+48h+BugCheckParameter4], rax
00000001C00070AD  call    McTemplateK0hzr0hzr2          ; sink doubles the lengths
```

### 4.2 Patched call setup (same loop body, with the fix)

```asm
00000001C0007068  call    EvaluateCurrentState          ; NEW feature-staging gate
00000001C000706D  mov     cl, [rbx+10h]
00000001C0007070  test    eax, eax                      ; feature enabled?
00000001C0007072  jz      short loc_1C00070D5           ; -> legacy (unhalved) path
00000001C0007074  test    cl, cl
00000001C0007076  jz      short loc_1C00070AC
00000001C0007078  test    cs:...InitMachineConfigEnableBits, 2
00000001C000707F  jz      loc_1C0007130
00000001C0007085  movzx   ecx, word ptr [rbx+28h]       ; value-name Length (bytes)
00000001C0007089  mov     rax, [rbx+30h]                ; value-name Buffer
00000001C000708D  movzx   r9d, word ptr [rbx+18h]       ; key-name Length (bytes)
00000001C0007092  shr     cx, 1                         ; NEW: halve value-name length
00000001C0007095  mov     [rsp+48h+var_18], rax
00000001C000709A  shr     r9w, 1                        ; NEW: halve key-name length
00000001C000709E  mov     word ptr [rsp+48h+var_20], cx
00000001C00070A3  lea     rdx, IMC_ETW_EVENT_IMC_VALUE_SET
00000001C00070AA  jmp     short loc_1C0007122
00000001C0007122  mov     rax, [rbx+20h]                ; key-name Buffer
00000001C0007126  mov     [rsp+48h+BugCheckParameter4], rax
00000001C000712B  call    McTemplateK0hzr0hzr2          ; sink doubles the halved lengths -> correct
```

The `test eax, eax` / `jz loc_1C00070D5` at `0x1c0007070`/`0x1c0007072` falls through to a second copy of the setup (at `0x1c00070d5`+) that reads `[rbx+18h]` / `[rbx+28h]` **without** the `shr` halving — the retained legacy path used when the feature is disabled.

### 4.3 Sink (`McTemplateK0hzr0hzr2 @ 0x1c00012a0`) — byte-identical in both binaries

```asm
00000001C00012E0  movzx   eax, r9w                      ; arg4 = key-name length (bytes in vuln path)
00000001C00012E8  add     eax, eax                      ; DOUBLES the value
00000001C00012F2  mov     [rbp+3Fh+var_38], eax         ; EVENT_DATA_DESCRIPTOR.Size = 2 * input
00000001C0001305  movzx   eax, [rbp+3Fh+arg_28]         ; value-name length
00000001C0001309  add     eax, eax                      ; DOUBLES again
00000001C000130F  mov     [rbp+3Fh+var_18], eax         ; EVENT_DATA_DESCRIPTOR.Size = 2 * input
00000001C000131B  call    McGenEventWrite               ; -> EtwWriteTransfer (Size bytes read)
```

The root-cause instruction (`add eax, eax` at `0x1c00012e8`) is **not** modified by the patch. The patch changes only the caller: when the feature is enabled it pre-halves the byte counts so the sink's doubling reproduces the original byte count.

> Note: only the security-relevant fragments of `CmCompleteInitMachineConfig` are reproduced here; the remainder is pool-freeing and list teardown logic (`ExFreePoolWithTag` calls at `0x1c0007160`/`0x1c0007172`/`0x1c0007183` in the unpatched build, fail-fast `int 0x29` at `0x1c000726e`, and the list-unlink at `0x1c0007142`+).

---

## 5. Trigger Conditions

1. **Reach the target interface.** `cmimcext.sys` is a kernel-mode DLL loaded during OS initialization. The attack surface is the pair of exported routines `CmSetInitMachineConfig` (`0x1c0009010`) and `CmCompleteInitMachineConfig` (`0x1c0007030`).
2. **Populate the configuration list.** `CmSetInitMachineConfig` reads keys under `\REGISTRY\MACHINE\INITIALMACHINECONFIG` (and related paths). At least one entry must produce a node whose key-name or value-name `UNICODE_STRING.Length` is non-zero.
3. **Ensure ETW logging is enabled.** The globals `data_1c0003128` bit 1 (key-flagged branch) and/or bit 2 (event template `0x1c0002210`) must be set. These are populated by the ETW enable callback for the provider (`Microsoft-Windows-CoreSystem-InitMachineConfig`, GUID at `data_1c0002258`).
4. **Fire the sink.** Invoke `CmCompleteInitMachineConfig`. The unpatched binary has no feature gate in the loop and always passes the raw byte-lengths, so the old raw-byte path is always taken. Every non-empty node triggers an overread of up to its own `UNICODE_STRING.Length` past the buffer allocation.
5. **Observable effect.** Without Special Pool the over-read is silent: adjacent PagedPool bytes are copied into the ETW event payload, observable only by a consumer of the `Microsoft-Windows-CoreSystem-InitMachineConfig` trace session (an administrator-level operation). With Special Pool enabled for tag `'IMCP'` (`0x50434d49`), a name buffer placed at the end of a pool page has its guard page immediately after it, so the doubled read can fault and bugcheck instead of leaking. Both outcomes require the boot-time init path to run over an `INITIALMACHINECONFIG` entry with a non-zero name length.

---

## 6. Exploit Primitive & Development Notes

### Primitive
- **Type:** Out-of-bounds pool read, bounded by the buffer's own valid length, performed twice per node (once for key-name buffer, once for value-name buffer).
- **Size:** The over-read describes `2*Length` bytes for a buffer allocated at `MaximumLength`; the amount read past the allocation is `2*Length - MaximumLength` (up to `Length` bytes when `MaximumLength ≈ Length`). It is not attacker-scalable beyond the string's own length.
- **Output channel:** The over-read bytes appear in the ETW event payload for the `Microsoft-Windows-CoreSystem-InitMachineConfig` provider.

### Reachability and impact bounds
- **Not a low-privilege surface.** `CmSetInitMachineConfig` and `CmCompleteInitMachineConfig` are boot-time machine-configuration exports invoked during OS/setup initialization, not IOCTL handlers reachable from an unprivileged process.
- **Input is administrator/setup-controlled.** The name lengths that drive the over-read come from `\REGISTRY\MACHINE\INITIALMACHINECONFIG`; populating that hive already requires the privileges used during deployment/setup.
- **Disclosure requires an admin consumer.** The leaked bytes only become visible to whoever consumes the `Microsoft-Windows-CoreSystem-InitMachineConfig` trace session, which requires administrator rights.
- No privilege boundary is crossed by an unprivileged attacker, and the read is bounded and read-only. There is no demonstrable path from this bug to arbitrary read/write, KASLR defeat, or code execution. Microsoft nonetheless classifies it as a memory-safety defect worth servicing (`Feature_Servicing_IMCMemoryCorruptionFix_61262757`).

---

## 7. Debugger PoC Playbook

This playbook assumes WinDbg/KD attached to a target running `cmimcext_unpatched.sys`.

### Breakpoints

```text
bp cmimcext_unpatched!CmCompleteInitMachineConfig
bp cmimcext_unpatched!McTemplateK0hzr0hzr2
bp cmimcext_unpatched+0x70ad      ; vulnerable call site inside CmCompleteInitMachineConfig
bp cmimcext_unpatched+0x12e8      ; the doubling instruction inside the sink
bp cmimcext_unpatched+0x131b      ; call McGenEventWrite -> EtwWriteTransfer
```

| Breakpoint | Why |
|---|---|
| `CmCompleteInitMachineConfig` entry | Confirm `rbx` is loaded from a non-empty list head at `CmpImcAllowEventQueueHead` (`mov rbx, cs:CmpImcAllowEventQueueHead` at `0x1c000705c`). |
| `+0x70ad` | The vulnerable call to `McTemplateK0hzr0hzr2`. At this point the arguments are already in registers/on the stack and reflect unhalved byte lengths. |
| `McTemplateK0hzr0hzr2` | The sink. `r9w` holds the key-name byte length; the value-name byte length is passed on the stack (read at `[rbp+3Fh+arg_28]`). |
| `+0x12e8` | The `add eax, eax`. Single-step to see `eax` double; compare against the buffer's `MaximumLength` allocation. |
| `+0x131b` | The final `call McGenEventWrite` (→ `EtwWriteTransfer`). The two `EVENT_DATA_DESCRIPTOR.Size` values are already in place at frame slots `var_38` and `var_18`. |

### What to inspect

- **At `+0x70ad`:**
  - `r9w` — key-name `UNICODE_STRING.Length` in **bytes** (e.g., `0x28` = 40 bytes). Will be doubled.
  - `word [rsp+0x28]` — value-name `UNICODE_STRING.Length` in **bytes**. Will be doubled.
  - `qword [rsp+0x20]` — key-name buffer pointer; run `!pool <addr>` and read the allocation's `MaximumLength`.
  - `qword [rsp+0x30]` — value-name buffer pointer; likewise.
- **At `+0x12e8` (inside sink):**
  - `eax` just before `add eax, eax` — equals `r9w` from the caller.
  - `eax` just after — equals `2 * r9w`. This becomes `EVENT_DATA_DESCRIPTOR.Size` (stored to frame slot `var_38`).
- **Cross-check (confirmation):**
  ```
  !pool <key_name_buffer>
  ```
  Compare `2 * Length` (the descriptor `Size`) against the buffer's `MaximumLength`. When `2 * Length > MaximumLength`, the difference is the number of bytes read past the allocation.

### Key offsets

| Offset | Meaning |
|---|---|
| `0x1c0007065` | Loop body start (`cmp byte [rbx+0x10], dil`). |
| `0x1c000708d`–`0x1c00070ad` | Vulnerable call setup. The patched binary inserts `call 0x1c000166c` at `0x1c0007068` and `shr cx,1`/`shr r9w,1` at `0x1c0007085`/`0x1c0007092` exactly here. |
| `0x1c00012e8` | The doubling `add eax, eax` for key-name length. Unchanged in patch. |
| `0x1c0001309` | The doubling `add eax, eax` for value-name length. Unchanged in patch. |
| `0x1c000131b` | `call McGenEventWrite (sub_1c000111c)` → `EtwWriteTransfer`. |

### Trigger setup from user mode / debugger

1. **Populate the registry hive** so `CmSetInitMachineConfig` will create nodes:
   ```
   HKLM\INITIALMACHINECONFIG\<Key> = <value>
   ```
   Choose names whose `Length` is a multiple of 2 and large enough to be interesting (e.g., 0x40 bytes).
2. **Enable ETW** for the provider:
   ```
   logman start "imc" -p {<GUID from data_1c0002258>} 0 0 -ets
   ```
   This sets the appropriate bits in `data_1c0003128`.
3. **Force the driver to re-process:**
   - Reload the driver / re-init via the export. If only kernel callers can invoke `CmCompleteInitMachineConfig` directly, induce it via the OS init path that consumes `INITIALMACHINECONFIG` (e.g., Sysprep generalize, or any path that re-runs init-machine-config).
4. **Optional — Special Pool to confirm reproducibility:**
   ```
   verifier /flags 0x1 /driver cmimcext.sys
   ```
   Then trigger. If a name buffer is placed at the end of a special-pool page, the doubled read reaches the guard page and faults.

### Expected observation

- **Without Special Pool:** ETW events captured by the consumer contain `2 * Length` bytes per name; when `2 * Length > MaximumLength`, the tail of that data is pool bytes lying past the name buffer's allocation.
- **With Special Pool:** the read into the ETW buffer faults at the guard page immediately after the name buffer, producing a page-fault bugcheck at the copy. (The exact bugcheck code is not asserted here; it is whatever the memory manager raises for a read beyond a special-pool allocation.)

### Node layout (0x38 bytes, PagedPool, tag `'IMCP'` = `0x50434d49`)

| Offset | Size | Field |
|---|---|---|
| `+0x00` | 8 | `Flink` |
| `+0x08` | 8 | `Blink` |
| `+0x10` | 1 | flag byte |
| `+0x18` | 2 | key-name `UNICODE_STRING.Length` (bytes) |
| `+0x1a` | 2 | key-name `MaximumLength` |
| `+0x20` | 8 | key-name `Buffer` |
| `+0x28` | 2 | value-name `Length` (bytes) |
| `+0x2a` | 2 | value-name `MaximumLength` |
| `+0x30` | 8 | value-name `Buffer` |

The key-name and value-name `Buffer` allocations are **separate** `ExAllocatePoolWithTag(PagedPool, MaximumLength, 'IMCP')` calls — each `MaximumLength` bytes, holding `Length` valid bytes. The descriptor's `2*Length` size over-reads up to `Length` bytes past the valid data (crossing the allocation boundary when `2*Length > MaximumLength`).

---

## 8. Changed Functions — Full Triage

### `CmCompleteInitMachineConfig` (similarity 0.8867, security-relevant)
- Inserted a call to `EvaluateCurrentState (sub_1c000166c)()` at the top of the linked-list iteration loop. This helper is new in the patched build (inserted at `0x1c000166c`, shifting the following functions down); it queries the servicing feature `Feature_Servicing_IMCMemoryCorruptionFix_61262757` via `EvaluateFeature` and returns non-zero when the fix is enabled.
- Added a conditional halving of the node's `+0x18` and `+0x28` fields (`shr cx,1`, `shr r9w,1`) before invoking `McTemplateK0hzr0hzr2 (sub_1c00012a0)`, so that the sink's internal doubling reproduces the correct byte count.
- The legacy (still-vulnerable) raw-byte path is preserved for the case where `EvaluateCurrentState (sub_1c000166c)()` returns 0. This is the retained old code path that makes the change a staged rollout rather than an unconditional fix.
- The patched build adds the feature-descriptor global `g_Feature_Servicing_IMCMemoryCorruptionFix_61262757_FeatureDescriptorDetails` (referenced by `EvaluateCurrentState` at `0x1c0001670`/`0x1c000167c`), which is not present in the unpatched build.

> Cosmetic / register-allocation differences within the same function (e.g., the patched version shuffles `cl`/`r9w` reads to accommodate the new halving) are not enumerated separately; they are a direct consequence of the same logical change.

No other functions changed. The remaining 39 matched functions are byte-identical.

---

## 9. Unmatched Functions

None reported by the matcher. Note that the feature-gate helper `EvaluateCurrentState (sub_1c000166c)` is present only in the patched build; it is inserted at `0x1c000166c` and shifts the subsequent functions (e.g., `rbc_InitializeFeatureStaging`, previously at `0x1c000166c`, moves to `0x1c0001698`). This is a relocation of unchanged code, not a removal.

---

## 10. Confidence & Caveats

**Confidence: High.**

Rationale:
- The doubling `add eax, eax` is unambiguous in the disassembly and is preserved verbatim in the patched binary.
- The `UNICODE_STRING.Length` semantics (bytes) are documented and confirmed by `ImpAddAllowListEvent (sub_1c00098a8)`, which allocates the buffers to `MaximumLength` bytes and copies `Length` valid bytes via `RtlCopyUnicodeString`.
- The patched caller's halving matches the sink's multiplication factor one-to-one, leaving no other plausible explanation for the change.

Assumptions / items to verify before committing to a PoC:
1. **Caller of `CmCompleteInitMachineConfig`.** The function is exported, so user-mode or other-driver invocation is plausible in principle, but the actual trigger path observed in production is via OS initialization consuming `\REGISTRY\MACHINE\INITIALMACHINECONFIG`. Verify the call chain with `x cmimcext!*` and static cross-references to the export.
2. **ETW mask bits.** The conditions gating the logging branches (`data_1c0003128` bits 1 and 2) are populated by the ETW enable callback. Confirm that enabling the trace session actually sets these bits in the target build.
3. **`EvaluateCurrentState (sub_1c000166c)` semantics.** The patched binary always invokes it, but it is a feature-staging gate (`Feature_Servicing_IMCMemoryCorruptionFix_61262757`); when that servicing feature is not enabled it returns 0 and the patched binary still takes the legacy raw-byte path. The fix is therefore active only when the feature is rolled out. Confirm experimentally that the patched driver's ETW events actually carry correctly sized descriptors under the target feature-enablement state.
4. **Feature enablement.** Because the corrective halving is gated behind `Feature_Servicing_IMCMemoryCorruptionFix_61262757`, the patched binary still runs the over-reading path when that feature is not enabled at runtime. `EvaluateCurrentState` returns "apply fix" when the cached feature state (`[rax]` at `0x1c0001683`) is not equal to 1.
5. **Severity.** The rating is **Low**: the over-read is bounded by the name's own length, read-only, reached only through boot-time initialization exports over admin/setup-controlled `INITIALMACHINECONFIG` input, and observable only by an administrator-level ETW consumer. No unprivileged attacker crosses a privilege boundary, and no arbitrary-read/write, KASLR-defeat, or code-execution path is demonstrable.
