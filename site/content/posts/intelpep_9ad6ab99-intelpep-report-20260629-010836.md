Title: intelpep.sys — idle-state reporting refactor and device/processor struct-layout revision
Date: 2026-06-29
Slug: intelpep_9ad6ab99-intelpep-report-20260629-010836
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: Unknown
KBDate: 2026-03-10

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `intelpep_unpatched.sys` |
| Patched binary | `intelpep_patched.sys` |
| Overall similarity | 0.9906 |
| Matched functions | 156 / 156 |
| Changed functions (by content) | 9 |
| Unmatched (added / removed) | 0 / 0 |

**Verdict:** The patch is a data-structure layout revision that ripples through nine functions, plus two behavioral changes in the PoFx (Windows Power Framework) power-management notification callbacks: `PepNotifyPpmQueryPlatformState` now excludes idle states whose disabled-flag byte is set from the reported platform-state list, and `PepNotifyPpmQueryCapabilities` gained an on-demand allocation path for the enlarged per-processor context. None of these is a memory-safety fix. The output-buffer writes in the reporting loop are bounded by the same driver-internal count (`PepKnownDeviceCount`) in both builds, and the changed synchronization/array offsets are a consistent struct-field shift applied to every consumer, not a wrong-pointer bug. All changes live in firmware/ACPI/PoFx callback paths, not on an untrusted IOCTL surface.

---

## 2. Change Analysis

### Finding 1 — Missing disabled-state filter in the platform-state reporting loop (functional, not a memory-safety change)

- **Severity:** None (functional correctness / defense-in-depth)
- **Class:** No security-relevant change (idle-state list content refinement)
- **Affected function:** `PepNotifyPpmQueryPlatformState` (unpatched `@ 0x1C0002430`, loop at `0x1C00024F0`–`0x1C0002530`; patched `@ 0x1C00024A0`, loop at `0x1C0002562`–`0x1C00025AD`)
- **Entry point:** PoFx `PEP_NOTIFY_PPM_QUERY_PLATFORM_STATE` notification callback.

**What changed.** The handler iterates the driver-internal device list `PepKnownDeviceList` (0x30-byte entries, count `PepKnownDeviceCount`) and, for each entry whose participation flag at `entry+0x18` is nonzero, writes a 16-byte record into the notification output structure (`a2+8`, i.e. `v3 = a2+2`). The patched build adds two instructions that dereference the pointer at `entry+0x28` and skip the entry when the pointed-to byte is nonzero:

```asm
0x1C0002577  mov  rax, [rdx+28h]     ; load disabled-flag pointer
0x1C000257B  cmp  byte ptr [rax], 0  ; is the state disabled?
0x1C000257E  jnz  short loc_1C00025A3 ; if so, skip this entry
```

**Why this is not an out-of-bounds write.** In both builds the loop is bounded by `PepKnownDeviceCount`, and the record index is `(counter+2)*2` in 8-byte units where `counter` increments only for entries that pass the filter. The patched build's filter can only *reduce* the number of records written; the set of emitted entries is a strict subset of the unpatched set. The worst case (all entries participating, none disabled) produces an identical number of records in both builds, so the maximum write extent is unchanged. There is therefore no buffer-bound difference: if a buffer overflow were possible in the unpatched build, the same all-enabled input would overflow the patched build too. `PepKnownDeviceCount` and the device list are populated by the driver from platform/ACPI data during initialization and are not attacker-controlled, and the notification output structure carries no caller-supplied size that the filter could exceed. The change is a functional refinement of *which* idle states are reported to PoFx (currently-disabled states are no longer listed), not a bounds fix.

### Finding 2 — Lock and state-array offsets shifted by +8 (struct-layout revision, not a wrong-pointer bug)

- **Severity:** None (recompilation churn)
- **Class:** No security-relevant change (data-structure layout change)
- **Affected function:** `PepNotifyPpmQueryPlatformState`; the same shift also appears in `PepNotifyPpmCstStates` and other consumers of the two revised structures.

**What changed.** The unpatched handler reads the ERESOURCE lock pointer from `deviceCtx+0x50` and indexes the state-ID array at `deviceCtx+0x58`; the patched handler reads them from `deviceCtx+0x58` and `deviceCtx+0x60` (`deviceCtx = *(a1+0x28)`). This is not a corrected wrong-pointer read: the sibling notification handler `PepNotifyPpmCstStates` reads the very same fields and shifted by the identical +8 in the patch (lock `[rdi+0x50]`→`[rdi+0x58]`, array `[rdi+0x58]`→`[rdi+0x60]`). Both consumers move in lockstep, so each build is internally consistent — the unpatched build has the lock at +0x50 and both functions read +0x50; the patched build has it at +0x58 and both read +0x58. The cause is an 8-byte field inserted before offset 0x50 in the device-context structure. A separate structure, the per-processor context, likewise grew from 0xB0 to 0xB8 bytes, shifting fields across several unrelated functions (see §8). This is servicing/recompilation layout churn, not incorrect synchronization or a use of the wrong resource.

---

## 3. Pseudocode Diff

```c
// ============== UNPATCHED — PepNotifyPpmQueryPlatformState @ 0x1C0002430 ==============
// Lock acquire (offset 0x50 in this build's device-context layout):
(*(WdfFunctions_01015 + 0x9C8))(WdfDriverGlobals,
                                *(rbp + 0x50),   // lock @ deviceCtx+0x50 (this build)
                                0);              // ExAcquireResourceExclusiveLite

// State-ID search loop (array base 0x58 in this build's layout):
for (i = 0; i < 10; i++) {
    if (*(rbp + i*8 + 0x58) == state->id) {      // array @ deviceCtx+0x58 (this build)
        matched = i; break;
    }
}

// Reporting loop (no disabled-state filter):
for (idx = 0; idx < PepKnownDeviceCount; idx++) {
    entry = &PepKnownDeviceList[idx];            // 0x30-byte entries
    if (entry->participate /* +0x18 */) {
        rcx = (counter + 2) * 2;
        counter++;
        *(v3 + rcx*8)      = entry->value;        // +0x10, bounded by PepKnownDeviceCount
        v3[rcx*2 + 4]      = v3[4];               // state_id byte
        *(&v3[rcx*2 + 2]+1)= 0x101;               // flags word
    }
}

// ============== PATCHED — PepNotifyPpmQueryPlatformState @ 0x1C00024A0 ==============
// Lock acquire (offset 0x58 after the struct grew by 8 bytes):
(*(WdfFunctions_01015 + 0x9C8))(WdfDriverGlobals,
                                *(rbp + 0x58),   // lock @ deviceCtx+0x58 (new layout)
                                0);

// State-ID search loop (array base 0x60 in the new layout):
for (i = 0; i < 10; i++) {
    if (*(rbp + i*8 + 0x60) == state->id) {      // array @ deviceCtx+0x60 (new layout)
        matched = i; break;
    }
}

// Reporting loop WITH disabled-state filter (functional refinement):
for (idx = 0; idx < PepKnownDeviceCount; idx++) {
    entry = &PepKnownDeviceList[idx];
    if (entry->participate /* +0x18 */) {
        if (*(*(entry + 0x28)) != 0)             // NEW: skip currently-disabled states
            continue;
        rcx = (counter + 2) * 2;
        counter++;
        *(v3 + rcx*8)      = entry->value;
        v3[rcx*2 + 4]      = v3[4];
        *(&v3[rcx*2 + 2]+1)= 0x101;
    }
}
```

The record-write arithmetic is identical between builds; the only behavioral difference is the added `entry+0x28` dereference-and-skip. The offset constants (`0x50`→`0x58`, `0x58`→`0x60`) reflect the device-context layout revision, not corrected addressing.

---

## 4. Assembly Analysis

### Unpatched — `PepNotifyPpmQueryPlatformState @ 0x1C0002430` (annotated)

```asm
; === Prologue / arg setup ===
0x1C0002430  mov  [rsp+8],  rbx
0x1C0002435  mov  [rsp+10h], rbp
0x1C000243A  mov  [rsp+18h], rsi
0x1C000243F  push rdi
0x1C0002440  sub  rsp, 20h
0x1C0002444  mov  eax, [rdx]                 ; eax = *a2 (state index)
0x1C0002446  lea  rdi, [rdx+8]               ; rdi = a2+8 = output base
0x1C000244C  cmp  eax, cs:PepNumPlatformStates
0x1C0002452  jnb  short loc_1C0002463
0x1C0002454  lea  rbx, [rax+rax*2]
0x1C0002458  shl  rbx, 5                     ; index*0x60
0x1C000245C  add  rbx, cs:qword_1C0037348    ; &state_table[index]
0x1C0002463  and  qword ptr [rdi], 0
0x1C0002467  mov  sil, 0Ah                   ; default matched = 10
0x1C000246A  mov  eax, [rbx]
0x1C000246C  mov  [rdi+0Ch], eax
0x1C000246F  mov  eax, [rbx+4]
0x1C0002472  mov  [rdi+10h], eax
0x1C0002475  mov  rbp, [rcx+28h]             ; rbp = device context = *(a1+0x28)
0x1C0002479  test rbp, rbp
0x1C000247C  jz   short loc_1C00024D9

; === Lock acquire (device-context layout: lock @ +0x50) ===
0x1C000247E  mov  rax, cs:WdfFunctions_01015
0x1C0002488  mov  rdx, [rbp+50h]             ; lock @ deviceCtx+0x50 (this build)
0x1C000248C  mov  rcx, cs:WdfDriverGlobals
0x1C0002493  mov  rax, [rax+9C8h]            ; ExAcquireResourceExclusiveLite
0x1C000249A  call cs:__guard_dispatch_icall_fptr

; === State-ID search loop (array @ +0x58) ===
0x1C00024A0  mov  edx, [rbx+8]               ; edx = state->id
0x1C00024A3  xor  cl, cl
0x1C00024A5  movzx eax, cl
0x1C00024A8  cmp  [rbp+rax*8+58h], edx       ; array @ deviceCtx+0x58 (this build)
0x1C00024AC  jz   short loc_1C00024B7
0x1C00024AE  inc  cl
0x1C00024B0  cmp  cl, sil
0x1C00024B3  jb   short loc_1C00024A5
0x1C00024B5  jmp  short loc_1C00024BA
0x1C00024B7  mov  sil, cl

; === Lock release (device-context layout: lock @ +0x50) ===
0x1C00024BA  mov  rax, cs:WdfFunctions_01015
0x1C00024C1  mov  rdx, [rbp+50h]             ; lock @ deviceCtx+0x50 (this build)
0x1C00024C5  mov  rcx, cs:WdfDriverGlobals
0x1C00024CC  mov  rax, [rax+9D0h]            ; ExReleaseResourceLite
0x1C00024D3  call cs:__guard_dispatch_icall_fptr

; === Output setup ===
0x1C00024D9  mov  eax, [rdi+18h]
0x1C00024DC  xor  r8d, r8d                   ; output counter = 0
0x1C00024DF  xor  edx, edx                   ; table index = 0
0x1C00024E1  mov  [rdi+14h], eax
0x1C00024E4  mov  [rdi+8], sil               ; matched state_id
0x1C00024E8  cmp  cs:PepKnownDeviceCount, edx
0x1C00024EE  jz   short loc_1C0002532

; === Reporting loop (no disabled-state filter) ===
0x1C00024F0  lea  rax, [rdx+rdx*2]
0x1C00024F4  shl  rax, 4                      ; idx*0x30
0x1C00024F8  add  rax, cs:PepKnownDeviceList
0x1C00024FF  cmp  byte ptr [rax+18h], 0       ; entry participates?
0x1C0002503  jz   short loc_1C0002528
0x1C0002505  mov  rax, [rax+10h]              ; entry->value
0x1C0002509  mov  ecx, r8d
0x1C000250C  add  rcx, 2
0x1C0002510  add  rcx, rcx                    ; (counter+2)*2
0x1C0002513  inc  r8d
0x1C0002516  mov  [rdi+rcx*8], rax            ; write value (index bounded by PepKnownDeviceCount)
0x1C000251A  mov  al, [rdi+8]
0x1C000251D  mov  [rdi+rcx*8+8], al           ; write state_id
0x1C0002521  mov  word ptr [rdi+rcx*8+9], 101h ; write flags
0x1C0002528  inc  edx
0x1C000252A  cmp  edx, cs:PepKnownDeviceCount
0x1C0002530  jb   short loc_1C00024F0

; === Epilogue ===
0x1C0002532  mov  rbx, [rsp+30h]
0x1C0002537  mov  rbp, [rsp+38h]
0x1C000253C  mov  rsi, [rsp+40h]
0x1C0002541  add  rsp, 20h
0x1C0002545  pop  rdi
0x1C0002546  retn
```

### Patched — added disabled-state filter and shifted offsets

```asm
; Reporting loop with the new filter (patched @ 0x1C00024A0):
0x1C0002562  lea  rdx, [r8+r8*2]
0x1C0002566  shl  rdx, 4
0x1C000256A  add  rdx, cs:PepKnownDeviceList  ; &entry[idx]
0x1C0002571  cmp  byte ptr [rdx+18h], 0       ; participates?
0x1C0002575  jz   short loc_1C00025A3
0x1C0002577  mov  rax, [rdx+28h]              ; NEW: load disabled-flag pointer
0x1C000257B  cmp  byte ptr [rax], 0           ; NEW: is the state disabled?
0x1C000257E  jnz  short loc_1C00025A3         ; NEW: skip currently-disabled states
0x1C0002580  mov  rax, [rdx+10h]
0x1C0002584  mov  ecx, r9d
0x1C0002587  add  rcx, 2
0x1C000258B  add  rcx, rcx
0x1C000258E  inc  r9d
0x1C0002591  mov  [rdi+rcx*8], rax
0x1C0002595  mov  al, [rdi+8]
0x1C0002598  mov  [rdi+rcx*8+8], al
0x1C000259C  mov  word ptr [rdi+rcx*8+9], 101h
0x1C00025A3  inc  r8d
0x1C00025A6  cmp  r8d, cs:PepKnownDeviceCount
0x1C00025AD  jb   short loc_1C0002562

; Shifted device-context offsets (new struct layout):
0x1C00024F8  mov  rdx, [rbp+58h]              ; lock @ deviceCtx+0x58 (was +0x50)
0x1C0002531  mov  rdx, [rbp+58h]              ; release path, same field
0x1C0002518  cmp  [rbp+rax*8+60h], edx        ; array @ deviceCtx+0x60 (was +0x58)
```

The register renaming (`edx`→`r8d` for the table index, `r8d`→`r9d` for the output counter) is a scheduling side effect of the two added instructions; it does not change behavior.

---

## 5. Reachability

1. The function is a PoFx power-management notification callback (`PEP_NOTIFY_PPM_QUERY_PLATFORM_STATE`), invoked by the Windows kernel power framework, not through an IOCTL. There is no user-mode buffer, size, or index that reaches this code as attacker-controlled input.
2. The iterated list (`PepKnownDeviceList`) and its count (`PepKnownDeviceCount`) are driver-internal state populated during initialization from platform/ACPI data. The participation and disabled flags reflect firmware/platform configuration, not attacker input.
3. Because the record index is bounded by `PepKnownDeviceCount` in both builds and the patched filter only removes records, no additional write extent is reachable in the unpatched build relative to the patched build. There is no reachable out-of-bounds primitive.

---

## 6. Exploit Primitive & Development Notes

No exploitable primitive is present. The reporting-loop change cannot overflow the notification output because both builds bound the record count by the same driver-internal `PepKnownDeviceCount` and the patched build writes a strict subset of the unpatched records. The offset changes are a consistent structure-layout revision, not a wrong-pointer read, so they do not corrupt or mis-lock memory in either build. There is no attacker-controlled input on this PoFx callback path and therefore no local-privilege-escalation chain to develop.

---

## 7. Inspection Notes

These are the concrete instruction sites that distinguish the two builds, for anyone wishing to confirm the change on a live target. They are diagnostic anchors, not a proof-of-concept — no crash or overflow is expected from either build under normal platform operation.

- **`0x1C0002577`–`0x1C000257E` (patched)** — `mov rax,[rdx+28h]; cmp byte [rax],0; jnz skip` — the added disabled-state filter; absent from the unpatched loop between `0x1C00024FF` and `0x1C0002505`.
- **`0x1C0002488` (unpatched) / `0x1C00024F8` (patched)** — lock pointer load, `[rbp+0x50]` vs `[rbp+0x58]`.
- **`0x1C00024C1` (unpatched) / `0x1C0002531` (patched)** — lock pointer load on the release path, same field.
- **`0x1C00024A8` (unpatched) / `0x1C0002518` (patched)** — state-ID array compare, `[rbp+rax*8+0x58]` vs `[rbp+rax*8+0x60]`.
- **`0x1C0002516` (unpatched) / `0x1C0002591` (patched)** — the record value write; the index `(counter+2)*2` is bounded by `PepKnownDeviceCount` in both builds.

### Struct / offset notes

- **Device entry** (0x30 bytes, `PepKnownDeviceList`): `+0x10` value QWORD written to output; `+0x18` participation flag (byte); `+0x28` pointer to a disabled-flag byte (dereferenced only in the patched build).
- **Entry count** at `PepKnownDeviceCount` (DWORD).
- **Platform-state table** (0x60-byte entries at `qword_1C0037348`), indexed by `*a2`.
- **Device context** (`*(a1+0x28)`): the ERESOURCE lock and the 10-entry state-ID array moved by +8 bytes between builds (lock 0x50→0x58, array 0x58→0x60). `PepNotifyPpmCstStates` reads the same fields at the same, matching offsets in each build.
- **Per-processor context**: grew from 0xB0 to 0xB8 bytes in the patch (see §8), shifting fields in several temperature/veto/enumeration routines.

---

## 8. Changed Functions — Full Triage

Nine functions differ by content between the builds. Every difference is either a consequence of the two structure-layout revisions (per-processor context `0xB0`→`0xB8`; device context +8 before offset 0x50) or a functional refinement of the same power-management callbacks. None is a memory-safety fix.

| Function | Change | Nature |
|---|---|---|
| `PepNotifyPpmQueryPlatformState` | Added disabled-state filter (`entry+0x28` deref-and-skip); lock/array offsets +8. | Functional refinement + layout shift; no bounds change. |
| `PepNotifyPpmCstStates` | Lock offset `+0x50`→`+0x58`, array `+0x58`→`+0x60`. | Device-context layout shift; consistent with the sibling handler. |
| `PepInitializeProcessorContext` | Context size `imul …,0xB0`→`0xB8`; `[rsi+0x50]`→`[rsi+0x58]`. | Per-processor context struct growth. |
| `PepNotifyPpmQueryCapabilities` | New branch: when `*(a2+0xB)!=0`, allocate a 0xB8 processor context, zero it, init a WDF lock (`WdfFunctions+0x9C0`) and link it at `a1+0x28`; lock/field offsets shifted. | On-demand allocation of the enlarged context; constant 0xB8 size. Functional/init, not a security fix. |
| `PepNotifyPpmEnumerateBootVetoes` | `imul …,0xB0`→`0xB8`; index field `[rbx+rax]`→`[rbx+rax+4]`; `[r8+8]`→`[r8+0x10]`. | Per-processor context struct growth. |
| `PepNotifyPpmParkSelection` | `[rcx+4]`→`[rcx+8]`. | Field shift in the revised layout. |
| `PepPlatformIdleVetoReference` | `[rcx+0x48]`→`[rcx+0x50]`. | Field shift in the revised layout. |
| `PepCollectProcessorTemperature` | `xchg eax,[r8+4]`→`[r8+8]`. | Per-processor context field shift. |
| `PepScheduleTemperatureCollection` | `imul …,0xB0`→`0xB8`; `[rdi+rax]`→`[rdi+rax+4]`; `add rcx,8`→`add rcx,0x10`. | Per-processor context struct growth. |

`memset` also relocated but is byte-for-byte identical in content (only its internal `locret_` label addresses moved); it is not a behavioral change. The remaining functions are content-identical across the two builds.

---

## 9. Unmatched Functions

- **Removed:** none.
- **Added:** none.

No new sanitizers, bounds checks, or mitigation helpers were introduced. The added code is the disabled-state filter and the on-demand context allocation described above.

---

## 10. Confidence & Caveats

**Confidence: High.** The instruction-level diff is unambiguous: the reporting-loop record index is bounded by `PepKnownDeviceCount` in both builds and the patched filter can only reduce the emitted set, so no out-of-bounds write is introduced or removed; and the `+8` offset shifts appear consistently across `PepNotifyPpmQueryPlatformState`, `PepNotifyPpmCstStates`, and the per-processor context consumers, which identifies them as a structure-layout revision rather than a corrected wrong-pointer read.

- The exact semantics of the disabled-flag byte at `entry+0x28` are inferred from the dereference-and-skip pattern; regardless of its precise meaning, its effect is to remove entries from the reported list, which cannot enlarge the write extent.
- The two revised structures (device context; per-processor context 0xB0→0xB8) are reconstructed from the offset deltas across the nine changed functions; the direction and magnitude (+8) are consistent everywhere they appear.
- All affected code runs from PoFx/ACPI power-management notification callbacks, not from an untrusted IOCTL surface.
