Title: ialpss2i_i2c.sys — No security-relevant change (hardware-support gate relaxed in CheckSupportedHardware)
Date: 2026-06-26
Slug: ialpss2i_i2c_3f1f9ec7-ialpss2i_i2c-report-20260626-002321
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: None

### 1. Overview
- **Unpatched Binary:** `ialpss2i_i2c_unpatched.sys`
- **Patched Binary:** `ialpss2i_i2c_patched.sys`
- **Overall Similarity Score:** 0.9476
- **Diff Statistics:** 169 matched functions (70 identical, 99 changed), 0 unmatched functions in either direction.
- **Verdict:** The only behavioral change in the diff is inside `CheckSupportedHardware`: the patched build **accepts** an Intel I2C controller identified as hardware version 4 with PCI revision ID below `0xF0`, a combination the unpatched build **rejected** with `STATUS_DEVICE_DATA_ERROR`. This relaxes a device-support gate; it does not add, remove, or alter any memory-safety or attacker-reachable behavior. No security-relevant change.

---

### 2. Change Summary
- **Severity:** None (no security impact).
- **Change Class:** Hardware-support / device-compatibility gate relaxation.
- **Affected Function:** `CheckSupportedHardware` (unpatched `0x14001373C`, patched `0x1400136A4`).

**What actually changed:**
`CheckSupportedHardware` reads a hardware "version" value into the device context at offset `+0x44` and a PCI revision value into `+0x48`, then runs a chain of version/revision comparisons against the threshold `0xF0`. The single reject sentinel `mov r14d, 0C0000260h` (`STATUS_DEVICE_DATA_ERROR`) exists at address `0x140013B92` in **both** builds.

Comparing every reachable version/revision path across the two builds, all outcomes are identical except one cell:

| version | rev ≥ 0xF0 | rev < 0xF0 (unpatched) | rev < 0xF0 (patched) |
|---|---|---|---|
| 2 | accept | accept | accept |
| 3 | reject | accept | accept |
| 4 | accept | **reject** | **accept** |
| 5 | accept | accept | accept |
| 6 | reject | accept | accept |
| 7 | accept | accept | accept |
| other | reject | reject | reject |

The unpatched build routes `{version 4, revision < 0xF0}` through the version dispatch until it falls into the generic reject at `0x140013B92`. The patched build handles `{version 4, revision < 0xF0}` directly in the version-4 branch and returns success. This is a relaxation (previously-rejected hardware is now accepted), not a hardening.

**Why this is not a security finding:**
- The direction is the opposite of a safety gate being added: the patched driver is *less* restrictive, accepting hardware the unpatched driver refused.
- The version and revision values originate from hardware identity (PCI configuration space / device enumeration), not from attacker-controllable software input. There is no IOCTL or user-mode path that sets these values.
- No memory-safety primitive (no OOB read/write, no UAF, no integer overflow) is introduced or removed. The change is purely which `NTSTATUS` the function returns for one hardware-identity combination.

**Call Chain:**
1. PnP Manager enumerates the device and invokes the WDF `EvtDriverDeviceAdd` callback `OnDeviceAdd` (`0x140001000`).
2. `OnDeviceAdd` calls `CheckSupportedHardware` at `0x1400012DE` (unpatched) / `0x1400012D4` (patched).
3. `CheckSupportedHardware` calls `GetHardwareVersion`, `GetHardwareRevision`, `GetHardwareInstance`, stores the results into the device context, and runs the version/revision dispatch.

The only caller of `CheckSupportedHardware` is `OnDeviceAdd`.

---

### 3. Pseudocode Diff

```c
// UNPATCHED CheckSupportedHardware — version 4 with revision < 0xF0 is REJECTED
// (falls through the version dispatch into the generic error sentinel)
int CheckSupportedHardware(PDEVICE_CONTEXT ctx) {
    // ... GetHardwareVersion / GetHardwareRevision / GetHardwareInstance ...
    int version  = ctx->version;   // +0x44
    int revision = ctx->revision;  // +0x48
    // version == 4:
    //   revision >= 0xF0 -> success trace, STATUS_SUCCESS
    //   revision <  0xF0 -> no branch handles it -> generic reject
    // ...
    return STATUS_DEVICE_DATA_ERROR; // 0xC0000260 reached for {v4, rev<0xF0}
}
```

```c
// PATCHED CheckSupportedHardware — version 4 with revision < 0xF0 is now ACCEPTED
int CheckSupportedHardware(PDEVICE_CONTEXT ctx) {
    // ... GetHardwareVersion / GetHardwareRevision / GetHardwareInstance ...
    int version  = ctx->version;   // +0x44
    int revision = ctx->revision;  // +0x48
    if (version == 4) {
        // revision >= 0xF0 -> success trace (id 0x18), STATUS_SUCCESS
        // revision <  0xF0 -> success trace (id 0x17), STATUS_SUCCESS  <-- now accepted
    }
    // ...
    return STATUS_SUCCESS; // for {v4, rev<0xF0}
}
```

The `STATUS_DEVICE_DATA_ERROR` sentinel itself is unchanged; only the reachability of the version-4 low-revision case differs.

---

### 4. Assembly Analysis

**Unpatched `CheckSupportedHardware` (`0x14001373C`) — version 4 handling**
`ecx` holds `0xF0` (set earlier at `0x14001393D  mov ecx, 0F0h`); the revision is at `[rdi+48h]`.
```
0000000140013A3B  cmp     eax, 4
0000000140013A3E  jnz     short loc_140013AB7      ; not version 4
0000000140013A40  cmp     [rdi+48h], ecx           ; revision vs 0xF0
0000000140013A43  jb      short loc_140013A79      ; revision < 0xF0
; revision >= 0xF0 falls through here -> success trace (id 0x17)
...
0000000140013A79  cmp     eax, 4
0000000140013A7C  jnz     short loc_140013AB7
0000000140013A7E  cmp     [rdi+48h], ecx
0000000140013A81  jb      short loc_140013AB7      ; revision < 0xF0 -> dispatch continues
; from loc_140013AB7 the version==4 value fails every remaining version test
; (5,6,5,7) and lands on the generic reject:
0000000140013B92  mov     r14d, 0C0000260h         ; STATUS_DEVICE_DATA_ERROR
```

**Patched `CheckSupportedHardware` (`0x1400136A4`) — version 4 handling**
```
00000001400139AD  cmp     eax, 4
00000001400139B0  jnz     loc_140013A49            ; not version 4
00000001400139B6  cmp     dword ptr [rdi+48h], 0F0h; revision vs 0xF0
00000001400139BD  jnb     short loc_140013A04      ; revision >= 0xF0 -> success trace (id 0x18)
; revision < 0xF0 falls through here -> success trace (id 0x17), then:
00000001400139FA  mov     edx, 17h
00000001400139FF  jmp     loc_140013B7C            ; WPP_SF_ds trace, then success tail
```

**Error sentinel present identically in both builds**
```
; unpatched
0000000140013B92  mov     r14d, 0C0000260h
; patched
0000000140013B92  mov     r14d, 0C0000260h
```
The reject value is not introduced by the patch. What changed is that the patched version-4 branch handles `revision < 0xF0` locally and returns success, so that combination no longer reaches `0x140013B92`.

---

### 5. Trigger Conditions

The differing code path is reached only when the device is enumerated as hardware version 4 with a PCI revision ID below `0xF0`. These values come from the physical device / PCI configuration space during PnP enumeration and are read by `GetHardwareVersion` / `GetHardwareRevision`. They are hardware-identity values; there is no software-controlled input path (no IOCTL, no user-mode buffer) that influences them. The observable difference: on such hardware the unpatched driver fails to initialize (returns `STATUS_DEVICE_DATA_ERROR`), while the patched driver initializes normally.

---

### 6. Exploit Primitive

None. No memory-corruption, information-disclosure, or privilege primitive is present. The change only alters which `NTSTATUS` `CheckSupportedHardware` returns for one hardware-identity combination, and in the direction of accepting more hardware rather than rejecting it.

---

### 7. Debugger Observation Notes

To observe the difference on hardware (or an environment) that enumerates version 4 with revision `< 0xF0`:
- `bp ialpss2i_i2c!CheckSupportedHardware`
- After the `GetHardware*` calls, inspect the device-context version at `+0x44` (watch for `4`) and revision at `+0x48` (watch for a value `< 0xF0`).
- Inspect `r14d` at the function epilogue (`0x140013BC9` unpatched / `0x140013BC7` patched): unpatched returns `0xC0000260`, patched returns `0` (`STATUS_SUCCESS`).

---

### 8. Changed Functions — Full Triage

Out of 99 changed functions, 98 contain only cosmetic or compiler-generated differences:
- WPP/ETW trace GUID renames (WPP hash changes) and trace-message-id restructuring.
- Compiler template renames (e.g. `Template_hqqxq` → `McTemplateK0hqqxq`).
- Branch-to-branchless and register-allocation differences in functions such as `ControllerInitialize`, `GetCurrentDmaTransferLeft`, and `ControllerProcessInterrupts`.

`CheckSupportedHardware` (similarity 0.7273, the lowest in the diff) is the only function with a behavioral difference, and that difference is the hardware-support gate relaxation described above — not a security fix.

---

### 9. Unmatched Functions
There are no added or removed functions (`unmatched_unpatched: 0`, `unmatched_patched: 0`). No new mitigation is introduced and no existing sanitization is removed.

---

### 10. Confidence & Caveats
- **Confidence:** High. Both builds were traced instruction-by-instruction through the full version/revision dispatch of `CheckSupportedHardware`. The complete outcome table is identical except for `{version 4, revision < 0xF0}`, which flips from reject (unpatched) to accept (patched). The `STATUS_DEVICE_DATA_ERROR` sentinel at `0x140013B92` is present in both builds.
- **Interpretation:** Offsets `+0x44` (version) and `+0x48` (revision) in the device context are inferred from the store sequence following the `GetHardware*` calls and the comparison against `0xF0`. The exact silicon-marketing meaning of "version 4" is not needed for the verdict: the direction of the change (previously-rejected hardware now accepted) and the absence of any attacker-controlled input path make this a device-support adjustment, not a security-relevant change.
