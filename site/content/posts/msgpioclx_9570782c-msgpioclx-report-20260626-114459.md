Title: msgpioclx.sys — No security-relevant change (PoFx registration structure layout/version update)
Date: 2026-06-26
Slug: msgpioclx_9570782c-msgpioclx-report-20260626-114459
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: None

---

## 1. Overview

| Field | Value |
|---|---|
| **Unpatched binary** | `msgpioclx_unpatched.sys` |
| **Patched binary** | `msgpioclx_patched.sys` |
| **Overall similarity** | 0.9929 |
| **Matched functions** | 360 |
| **Changed functions** | 3 |
| **Identical functions** | 357 |
| **Unmatched (unpatched)** | 0 |
| **Unmatched (patched)** | 0 |

**Verdict:** The patch enlarges the `PO_FX_DEVICE` power-framework registration buffer by 8 bytes, inserts a new DWORD field (initialized to `1`) at offset `0x08`, and shifts every subsequent field down by 8 bytes. This is a registration-structure layout/version update. No attacker-reachable security impact is demonstrable from the driver binaries alone: both builds stamp the same version value (`1`) at offset `0x00`, the buffer is filled with the same fixed compile-time callback pointers and component count in both builds, and the outcome of any layout difference depends entirely on the kernel's `PoFxRegisterPrimaryDevice` parser, which is not part of these binaries. The change is treated as coordinated servicing (driver recompiled against an updated structure definition), not a delivered security fix.

---

## 2. Change Summary

### Finding 1 — No security-relevant change: PoFx registration structure layout update

**Class:** Structure layout / version update in the PoFx device-registration path.

**Affected functions:**
- `GpiopGetBaseRegistrationBufferSize` (base allocation size `0x68` → `0x70`)
- `GpiopInitializePrimaryDevice` (fields shifted +8; new DWORD field at `0x08`)
- `GpiopInitializeIdleStateBufferAndCount` (per-component field offsets shifted to match)

**What actually changed:** The unpatched driver allocates and fills a `PO_FX_DEVICE` registration buffer with this observable layout (`rcx` = buffer base):

- Base buffer size = `0x68`.
- `[buf+0x00]` = `1`; `[buf+0x04]` = component count.
- Callback pointers at `0x08` (`GpioClxBankActiveConditionCallback`), `0x10` (`GpioClxBankIdleConditionCallback`), `0x18` (`GpioClxBankIdleStateCallback`), `0x20` (`GpioClxDevicePowerRequiredCallback`), `0x28` (`GpioClxDevicePowerNotRequiredCallback`), `0x38` (`GpioClxCriticalTransitionCallback`).
- `[buf+0x30]` zeroed; `DeviceContext` at `0x40`.
- Per component: `IdleStateCount` at `P+i*32+0x58`, `IdleStates` pointer at `P+(i+3)*32`.

The patched driver uses this layout:

- Base buffer size = `0x70` (+8).
- `[buf+0x00]` = `1`; `[buf+0x04]` = component count.
- New DWORD field = `1` inserted at `[buf+0x08]`.
- All six callback pointers shifted +8 bytes (`ActiveConditionCallback` `0x08` → `0x10`, etc.).
- `[buf+0x38]` zeroed; `DeviceContext` moves `0x40` → `0x48`.
- Per component: `IdleStates` pointer at `P+i*32+0x68`, `IdleStateCount` at `P+(i+3)*32`.

The callback targets, component count, and device-context value written are identical in both builds; only the destination offsets and the extra `0x08` DWORD differ. The value at offset `0x00` (the `PO_FX_DEVICE.Version` field passed to `PoFxRegisterPrimaryDevice`) is `1` in both builds.

**Why this is not scored as a vulnerability:** Judging which layout the running kernel treats as correct requires the kernel's `PoFxRegisterPrimaryDevice` implementation, which is not in these binaries. Both builds declare the same version value, the buffer contents are fixed at compile time (no attacker-controlled input reaches these fields), and a driver whose registration layout genuinely mismatched the kernel it shipped with would fail during ordinary GPIO device start rather than present an attacker-tunable primitive. The most supportable reading is a coordinated recompile of the driver against an updated `PO_FX_DEVICE` definition. No demonstrable, attacker-reachable memory-corruption primitive is present in the driver code.

**Entry point (context):** `GpioClxEvtDeviceSelfManagedIoInit` — the WDF `EvtDeviceSelfManagedIoInit` callback, invoked by the PnP manager during GPIO controller device start.

**Call chain (context):**
1. `GpioClxEvtDeviceSelfManagedIoInit` @ `0x1c0003ed0`
2. `GpiopRegisterWithPowerFramework` @ `0x1c0025b10`
3. `GpiopGetBaseRegistrationBufferSize` @ `0x1c0013c14`
4. `ExAllocatePoolWithTag`
5. `GpiopInitializePrimaryDevice` @ `0x1c0013c44` (unpatched) / `0x1c0013c40` (patched)
6. `GpiopInitializeIdleStateBufferAndCount` @ `0x1c0013c20`
7. `GpiopRegisterPrimaryDeviceInternal` @ `0x1c0013ca4` → `PoFxRegisterPrimaryDevice`

---

## 3. Decompilation Diff

### GpiopGetBaseRegistrationBufferSize

```c
// ── UNPATCHED ──
int GpiopGetBaseRegistrationBufferSize() { return 104; }   // 0x68

// ── PATCHED ──
int GpiopGetBaseRegistrationBufferSize() { return 112; }   // 0x70 (+8)
```

### GpiopInitializePrimaryDevice

```c
// ── UNPATCHED (callbacks start at 0x08, no field at 0x08) ──
//   a1 = buffer base, a2 = component count, a9 = device context
{
    *(_QWORD *)(a1 + 48) = 0;                                 // [buf+0x30] = 0
    *(_QWORD *)(a1 + 24) = GpioClxBankIdleStateCallback;      // 0x18
    *(_QWORD *)(a1 + 8)  = GpioClxBankActiveConditionCallback;// 0x08
    *(_QWORD *)(a1 + 16) = GpioClxBankIdleConditionCallback;  // 0x10
    *(_QWORD *)(a1 + 32) = GpioClxDevicePowerRequiredCallback;// 0x20
    *(_QWORD *)(a1 + 40) = GpioClxDevicePowerNotRequiredCallback;// 0x28
    *(_QWORD *)(a1 + 64) = a9;                                // DeviceContext @ 0x40
    *(_QWORD *)(a1 + 56) = GpioClxCriticalTransitionCallback; // 0x38
    *(_DWORD *)a1 = 1;                                        // [buf+0x00] = 1
    *(_DWORD *)(a1 + 4) = a2;                                 // component count
}

// ── PATCHED (new DWORD at 0x08, everything from 0x08 shifted +8) ──
{
    *(_QWORD *)(a1 + 56) = 0;                                 // [buf+0x38] = 0
    *(_DWORD *)a1 = 1;                                        // [buf+0x00] = 1
    *(_DWORD *)(a1 + 8) = 1;                                  // NEW DWORD @ 0x08 = 1
    *(_QWORD *)(a1 + 32) = GpioClxBankIdleStateCallback;      // 0x20
    *(_QWORD *)(a1 + 16) = GpioClxBankActiveConditionCallback;// 0x10
    *(_QWORD *)(a1 + 24) = GpioClxBankIdleConditionCallback;  // 0x18
    *(_QWORD *)(a1 + 40) = GpioClxDevicePowerRequiredCallback;// 0x28
    *(_QWORD *)(a1 + 48) = GpioClxDevicePowerNotRequiredCallback;// 0x30
    *(_QWORD *)(a1 + 72) = a9;                                // DeviceContext @ 0x48
    *(_QWORD *)(a1 + 64) = GpioClxCriticalTransitionCallback; // 0x40
    *(_DWORD *)(a1 + 4) = a2;                                 // component count
}
```

### GpiopInitializeIdleStateBufferAndCount

```c
// ── UNPATCHED ──
//   a1 = base, a2 = comp_idx, a3 = idle_states_ptr, a4 = idle_count
{
    *(_DWORD *)(32LL*a2 + a1 + 88) = a4;   // count at i*32 + 0x58
    *(_QWORD *)(32LL*(a2+3) + a1)  = a3;   // ptr   at (i+3)*32
}

// ── PATCHED (component fields shifted to match new header) ──
{
    *(_QWORD *)(32LL*a2 + a1 + 104) = a3;  // ptr   at i*32 + 0x68
    *(_DWORD *)(32LL*(a2+3) + a1)   = a4;  // count at (i+3)*32
}
```

---

## 4. Assembly Analysis

### GpiopGetBaseRegistrationBufferSize — Size Constant

**Unpatched @ `0x1c0013c14`:**
```asm
00000001C0013C14  mov     eax, 68h
00000001C0013C19  retn
```

**Patched @ `0x1c0013c14`:**
```asm
00000001C0013C14  mov     eax, 70h
00000001C0013C19  retn
```

> **Note:** Only the immediate operand changed (`0x68` → `0x70`), so a structure-only diff scored this function as identical (similarity = 1.0).

---

### GpiopInitializePrimaryDevice — Field Offsets

**Unpatched @ `0x1c0013c44`:**
```asm
00000001C0013C44  and     qword ptr [rcx+30h], 0
00000001C0013C49  lea     rax, GpioClxBankIdleStateCallback
00000001C0013C50  mov     [rcx+18h], rax
00000001C0013C54  lea     rax, GpioClxBankActiveConditionCallback
00000001C0013C5B  mov     [rcx+8], rax
00000001C0013C5F  lea     rax, GpioClxBankIdleConditionCallback
00000001C0013C66  mov     [rcx+10h], rax
00000001C0013C6A  lea     rax, GpioClxDevicePowerRequiredCallback
00000001C0013C71  mov     [rcx+20h], rax
00000001C0013C75  lea     rax, GpioClxDevicePowerNotRequiredCallback
00000001C0013C7C  mov     [rcx+28h], rax
00000001C0013C80  mov     rax, [rsp+arg_40]
00000001C0013C85  mov     [rcx+40h], rax
00000001C0013C89  lea     rax, GpioClxCriticalTransitionCallback
00000001C0013C90  mov     [rcx+38h], rax
00000001C0013C94  mov     dword ptr [rcx], 1
00000001C0013C9A  mov     [rcx+4], edx
00000001C0013C9D  retn
```

**Patched @ `0x1c0013c40`:**
```asm
00000001C0013C40  and     qword ptr [rcx+38h], 0
00000001C0013C45  mov     eax, 1
00000001C0013C4A  mov     [rcx], eax
00000001C0013C4C  mov     [rcx+8], eax
00000001C0013C4F  lea     rax, GpioClxBankIdleStateCallback
00000001C0013C56  mov     [rcx+20h], rax
00000001C0013C5A  lea     rax, GpioClxBankActiveConditionCallback
00000001C0013C61  mov     [rcx+10h], rax
00000001C0013C65  lea     rax, GpioClxBankIdleConditionCallback
00000001C0013C6C  mov     [rcx+18h], rax
00000001C0013C70  lea     rax, GpioClxDevicePowerRequiredCallback
00000001C0013C77  mov     [rcx+28h], rax
00000001C0013C7B  lea     rax, GpioClxDevicePowerNotRequiredCallback
00000001C0013C82  mov     [rcx+30h], rax
00000001C0013C86  mov     rax, [rsp+arg_40]
00000001C0013C8B  mov     [rcx+48h], rax
00000001C0013C8F  lea     rax, GpioClxCriticalTransitionCallback
00000001C0013C96  mov     [rcx+40h], rax
00000001C0013C9A  mov     [rcx+4], edx
00000001C0013C9D  retn
```

Both builds write `1` to `[rcx+0x00]` (the version field) and the component count to `[rcx+0x04]`. The patched build adds `mov [rcx+8], eax` (`= 1`) and moves each callback and the device context 8 bytes higher.

---

### GpiopInitializeIdleStateBufferAndCount — Component Field Offsets

**Unpatched @ `0x1c0013c20`:**
```asm
00000001C0013C20  mov     eax, edx
00000001C0013C22  shl     rax, 5
00000001C0013C26  mov     r10d, edx
00000001C0013C29  mov     [rax+rcx+58h], r9d     ; IdleStateCount at i*32+0x58
00000001C0013C2E  lea     rax, [r10+3]
00000001C0013C32  shl     rax, 5
00000001C0013C36  mov     [rax+rcx], r8          ; IdleStates ptr at (i+3)*32
00000001C0013C3A  retn
```

**Patched @ `0x1c0013c20`:**
```asm
00000001C0013C20  mov     r10d, edx
00000001C0013C23  lea     rax, [r10+3]
00000001C0013C27  shl     r10, 5
00000001C0013C2B  shl     rax, 5
00000001C0013C2F  mov     [r10+rcx+68h], r8      ; IdleStates ptr at i*32+0x68
00000001C0013C34  mov     [rax+rcx], r9d         ; IdleStateCount at (i+3)*32
00000001C0013C38  retn
```

---

### GpiopRegisterWithPowerFramework — Allocation & Call Sequence (context, unchanged)

```asm
; UNPATCHED @ 0x1c0025b10
00000001C0025B28  movzx   r9d, word ptr [rcx+2D8h]    ; num_banks from device extension
00000001C0025B33  call    GpiopGetBaseRegistrationBufferSize
00000001C0025B3E  shl     edx, 5                       ; num_banks * 32
00000001C0025B48  lea     edi, [rdx-19h]
00000001C0025B4F  add     edi, eax                     ; += base size (0x68)
00000001C0025B51  and     edi, 0FFFFFFF8h              ; align 8
00000001C0025B8A  lea     ecx, [rdi+rax*8]
00000001C0025B94  call    ExAllocatePoolWithTag
00000001C0025C03  call    GpiopInitializePrimaryDevice
00000001C0025C3F  call    GpiopInitializeIdleStateBufferAndCount
00000001C0025CB6  call    GpiopRegisterPrimaryDeviceInternal  ; → PoFxRegisterPrimaryDevice
```

This caller is byte-identical between the two builds; only the size constant it receives from `GpiopGetBaseRegistrationBufferSize` (`0x68` vs `0x70`) differs.

---

## 5. Trigger Conditions

The registration path runs during ordinary GPIO controller device start: the WDF framework invokes `GpioClxEvtDeviceSelfManagedIoInit`, which reaches `GpiopRegisterWithPowerFramework`, which allocates and fills the `PO_FX_DEVICE` buffer and passes it to `PoFxRegisterPrimaryDevice`. The buffer contents are fixed at compile time (callback addresses within `msgpioclx.sys`, a component count derived from the device's bank count, and a device-context pointer). No IOCTL or other attacker-controlled input reaches the changed fields. Whether the layout difference between builds produces any misbehavior depends on how the running kernel's `PoFxRegisterPrimaryDevice` parses the structure, which cannot be determined from these driver binaries.

---

## 6. Impact Assessment

No attacker-reachable primitive is demonstrable from the driver binaries:

- The only inputs to the changed functions are the buffer pointer, the compile-time callback addresses, the component count, and the device-context pointer. None are attacker-tunable.
- Both builds stamp the same version value (`1`) at offset `0x00`, the field `PoFxRegisterPrimaryDevice` uses to identify the structure layout. Claims that the kernel would treat one build's buffer as a different structure version cannot be confirmed without the kernel image.
- The effect of any layout mismatch is a property of the out-of-scope kernel PoFx parser, not of code contained in `msgpioclx.sys`.

Consequently, no severity, CWE, or exploit primitive is assigned. The change is recorded as a structure layout/version update in the PoFx registration path.

---

## 7. Verification Notes

To reproduce the observation on the binaries themselves:

- `GpiopGetBaseRegistrationBufferSize` @ `0x1c0013c14`: `mov eax, 0x68` (unpatched) vs `mov eax, 0x70` (patched).
- `GpiopInitializePrimaryDevice` @ `0x1c0013c44`/`0x1c0013c40`: patched adds `mov [rcx+8], eax` (`= 1`) and moves every callback and the device context +8 bytes; both write `1` at `[rcx+0]` and the component count at `[rcx+4]`.
- `GpiopInitializeIdleStateBufferAndCount` @ `0x1c0013c20`: per-component `IdleStates` pointer moves from `(i+3)*32` to `i*32+0x68`, and `IdleStateCount` moves from `i*32+0x58` to `(i+3)*32`.

### Observed field layout — unpatched vs patched registration buffer

| Unpatched offset | Content | Patched offset | Content |
|---|---|---|---|
| `0x00` | version = 1 (DWORD) | `0x00` | version = 1 (DWORD) |
| `0x04` | component count | `0x04` | component count |
| `0x08` | ActiveConditionCallback | `0x08` | **new DWORD = 1** |
| `0x10` | IdleConditionCallback | `0x10` | ActiveConditionCallback |
| `0x18` | IdleStateCallback | `0x18` | IdleConditionCallback |
| `0x20` | PowerRequiredCallback | `0x20` | IdleStateCallback |
| `0x28` | PowerNotRequiredCallback | `0x28` | PowerRequiredCallback |
| `0x30` | zeroed | `0x30` | PowerNotRequiredCallback |
| `0x38` | CriticalTransitionCallback | `0x38` | zeroed |
| `0x40` | DeviceContext | `0x40` | CriticalTransitionCallback |
| — | (component array begins at header end) | `0x48` | DeviceContext |

Per-component fields (relative to component base):

| Unpatched | Field | Patched |
|---|---|---|
| `+0x58` | IdleStateCount (DWORD) | `+0x60` |
| `(i+3)*32` | IdleStates pointer (QWORD) | `i*32+0x68` |

---

## 8. Changed Functions — Full Triage

### 1. `GpiopGetBaseRegistrationBufferSize` — similarity: 1.0

- **Change type:** Constant operand only (`0x68` → `0x70`).
- **What changed:** The base allocation size for the PoFx registration buffer, increased by 8 bytes to match the enlarged structure layout.
- **Note:** A structure-only diff scored this identical because only the immediate operand changed.

### 2. `GpiopInitializePrimaryDevice` — similarity: 0.6961

- **Change type:** Field layout update.
- **What changed:** A new DWORD field (`= 1`) inserted at offset `0x08`; all six callback pointers shifted +8 bytes; `DeviceContext` shifted `0x40` → `0x48`; the zeroed field shifted `0x30` → `0x38`; `CriticalTransitionCallback` shifted `0x38` → `0x40`.
- **Behavioral note:** Same callback targets, same component count, same device context — only offsets and the extra `0x08` field differ.

### 3. `GpiopInitializeIdleStateBufferAndCount` — similarity: 0.6795

- **Change type:** Component field offset adjustment.
- **What changed:** `IdleStates` pointer moved from `(i+3)*32` to `i*32+0x68`; `IdleStateCount` moved from `i*32+0x58` to `(i+3)*32`. Register allocation changed as a side effect (`r10` now holds `comp_idx*32`).
- **Behavioral note:** Same count and pointer values written; only the destination offsets changed to match the enlarged component-array base.

---

## 9. Unmatched Functions

No functions were added or removed. An independent content diff of both builds confirms the change is confined to the three functions above; no other function differs, and no new sanitizer, guard, or mitigation was introduced.

---

## 10. Confidence & Caveats

**Confidence: High** on the mechanical description: the patched build inserts a DWORD field at `0x08`, shifts every subsequent field +8 bytes, and enlarges the base allocation by 8 bytes. This is verified against both the decompilation and the disassembly.

**On security impact:** Not demonstrable from these binaries. The version value at offset `0x00` is `1` in both builds, the buffer is filled with fixed compile-time data, and any consequence of the layout change lives in the kernel's `PoFxRegisterPrimaryDevice` parser, which is out of scope. The change is consistent with the driver being recompiled against an updated `PO_FX_DEVICE` structure definition (coordinated servicing) and is not scored as a vulnerability. Establishing any reachable impact would require analyzing the specific kernel build's PoFx registration parser — outside the scope of a driver-to-driver diff.
